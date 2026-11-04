"""Integration: `emulate` explicit-ABI arg placement for an UNPROTOTYPED target (#381).

The ADR-066 `args` auto-placement needs a RESOLVED calling convention (`set_function_signature`
first) — a raw/stripped binary whose convention Ghidra cannot resolve fails closed. #381 adds
`arg_registers`: the caller's own ABI register order, so an unprototyped function can be called by
placing each `args[i]` into `arg_registers[i]` directly. This gates that end-to-end: import a raw
`int add(a,b)` blob, **do NOT give it a signature**, then `emulate(call=True, args=[5,7],
arg_registers=["ECX","EDX"])` must place 5+7 and return 12. A regression (ignoring `arg_registers`,
or still requiring a prototype) re-surfaces as `ok=False` or a wrong/absent return value. The schema
rules (arg_registers-requires-call+args, must-cover-every-arg, cap) are the hermetic unit coverage.
Benign synthetic blob only (master §5). integration-marked (the default unit run SKIPS it).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

import pytest

pytestmark = pytest.mark.integration

_ENGINE_ENV = "VIVARIUM_CONTAINER_ENGINE"
_DEFAULT_ENGINE = "podman"
_SRC_MOUNT_ENV = "VIVARIUM_WORKER_SRC_MOUNT"
_RUN_TIMEOUT_SECONDS = 300
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: x86-64 `int add(int a, int b)`: mov eax,ecx (89 c8) ; add eax,edx (01 d0) ; ret (c3). The blob
#: reads ECX/EDX + returns EAX — so an explicit arg_registers=["ECX","EDX"] places 5+7 → EAX=12
#: WITHOUT any recovered prototype (the #381 unprototyped-target path).
_ADD_BLOB_HEX = "89c801d0c3"
_PROCESSOR = "x86:LE:64:default"
_BASE_ADDR = 0x1000

_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
BLOB = bytes.fromhex("__ADD_BLOB_HEX__")
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x1000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "add.bin")
    with open(path, "wb") as handle:
        handle.write(BLOB)

    backend = PyGhidraBackend()
    backend.import_binary({
        "source_ref": path, "loader": "binary", "processor": PROCESSOR,
        "base_addr": BASE_ADDR, "entry": BASE_ADDR,
    })
    backend.analyze({"timeout_seconds": 120})

    # NO set_function_signature — the function is UNPROTOTYPED. Explicit ABI via arg_registers.
    start = hex(BASE_ADDR)
    out = backend.emulate({
        "start": start, "call": True, "args": [5, 7],
        "arg_registers": ["ECX", "EDX"], "read_registers": ["EAX"],
    })
    return {
        "return_value": out.get("return_value"),
        "registers": {r["name"]: r["value"] for r in (out.get("registers") or [])},
        "stop_reason": out.get("stop_reason"),
    }


try:
    result = {"ok": True, "data": main()}
except Exception as exc:  # surface ANY failure as a parseable, fail-closed envelope.
    result = {"ok": False, "error": "{}: {}".format(type(exc).__name__, exc),
              "traceback": traceback.format_exc()}

sys.stdout.write("\n" + MARKER + json.dumps(result) + "\n")
sys.stdout.flush()
os._exit(0)
""".replace("__ADD_BLOB_HEX__", _ADD_BLOB_HEX)


def _engine() -> str:
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    cmd = [
        engine,
        "run",
        "--rm",
        "--network=none",
        "--memory=3g",
        "--read-only",
        "--tmpfs",
        "/work/project:rw,noexec,nosuid,nodev,mode=1777,size=2g",
        "--tmpfs",
        "/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size=1g",  # noqa: S108
        "--env",
        "VIVARIUM_WORKER_PROJECT_DIR=/work/project",
        "--env",
        f"VIVARIUM_DRIVER_PROCESSOR={_PROCESSOR}",
        "--env",
        f"VIVARIUM_DRIVER_BASE_ADDR={hex(_BASE_ADDR)}",
    ]
    src_mount = os.environ.get(_SRC_MOUNT_ENV, "").strip()
    if src_mount:
        cmd += [
            "--volume",
            f"{src_mount}:/host-repo:ro",
            "--env",
            "PYTHONPATH=/host-repo/src:/host-repo",
        ]
    cmd += ["--entrypoint", "python", image, "-c", _DRIVER]
    return cmd


def _parse_marker_json(stdout: str) -> dict[str, Any]:
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line in worker stdout:\n{stdout[-2000:]}"
    try:
        parsed: dict[str, Any] = json.loads(lines[-1][len(_MARKER) :])
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise AssertionError(f"marker payload not valid JSON: {exc}") from exc
    return parsed


def test_emulate_explicit_abi_on_unprototyped_fn(worker_image: str) -> None:
    """`emulate(args, arg_registers=…)` must call an UNPROTOTYPED function + return 12 (#381)."""
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image)
    try:
        proc = subprocess.run(  # noqa: S603 — argv list, no shell; engine + image operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"emulate explicit-ABI run timed out after {_RUN_TIMEOUT_SECONDS}s\n{captured[-2000:]}"
        )

    if proc.returncode != 0:
        pytest.fail(f"worker exited {proc.returncode}\n--- stderr ---\n{proc.stderr[-2000:]}")

    envelope = _parse_marker_json(proc.stdout)
    assert envelope.get("ok") is True, (
        f"emulate explicit-ABI reported failure (#381 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert int(data.get("return_value") or 0) == 12, (
        f"expected arg_registers=['ECX','EDX'] to place 5+7 and return 12 on the unprototyped "
        f"function; got {data!r}"
    )
