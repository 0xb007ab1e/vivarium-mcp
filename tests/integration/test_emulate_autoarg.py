"""Integration: `emulate` auto arg-placement on a real worker (ADR-066 follow-up).

Regression + capability gate for the ``emulate`` ``args`` field: with ``call=True`` the worker
places each integer argument into the target function's parameter storage per its RESOLVED calling
convention (the caller ``set_function_signature``'d it — a raw binary's convention is null, proven).
Proven live:

    * craft a tiny x86-64 ``int add(int a, int b) { return a + b; }`` reading the two registers the
      program's compiler spec resolves the params to (ECX, EDX — verified live); import it raw,
      analyze, give it a resolved ``(int, int) -> int`` signature, then ``emulate(call=True,
      args=[5, 7])`` auto-places 5 + 7 into that storage and returns 12. A regression in the
      arg-placement re-surfaces as ``ok=False`` or a wrong return value.

Why a gated in-container test (not a unit test): the placement resolves ``VariableStorage`` off the
program's compiler spec + runs the p-code interpreter (JVM/PyGhidra edge, TB3, ADR-001) — the pure
schema rules (args-requires-call, cap) are the hermetic unit coverage. Gating + fixture posture
mirror ``test_import_emulate.py``: ``integration``-marked (the default unit run SKIPS it), runs only
when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No real
malware — the input is a tiny synthetic x86-64 code blob written in-container (master §5).

Honored environment (same as the other gated integration tests):
    * ``VIVARIUM_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``VIVARIUM_WORKER_IMAGE`` — the pinned-by-digest worker image ref (conftest fixture).
    * ``VIVARIUM_CONTAINER_ENGINE`` — container CLI to invoke (default ``podman``).
    * ``VIVARIUM_WORKER_SRC_MOUNT`` — OPTIONAL dev hook: bind the working tree over the image.
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

#: x86-64 `int add(int a, int b)`:  mov eax,ecx (89 c8) ; add eax,edx (01 d0) ; ret (c3).
#: The raw BinaryLoader program's default compiler spec resolves the two int params to ECX + EDX
#: (verified live), and the return to EAX — so the blob reads ECX/EDX to match the storage the
#: auto-placement targets. args=[5,7] -> ECX=5, EDX=7 -> EAX=12 (proves placement follows the
#: RESOLVED VariableStorage, not a hardcoded register assumption).
_ADD_BLOB_HEX = "89c801d0c3"
_PROCESSOR = "x86:LE:64:default"
_BASE_ADDR = 0x1000

# --- the in-container driver ---------------------------------------------------------------------
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
    backend.import_binary(
        {
            "source_ref": path,
            "loader": "binary",
            "processor": PROCESSOR,
            "base_addr": BASE_ADDR,
            "entry": BASE_ADDR,
        }
    )
    backend.analyze({"timeout_seconds": 120})

    # Give the function a resolved (int, int) -> int prototype (default convention) so the ABI
    # arg storage (EDI, ESI) is known — the exact precondition auto arg-placement relies on.
    start = hex(BASE_ADDR)
    backend.set_function_signature(
        {
            "function": start,
            "return_type": {"base": "int"},
            "parameters": [
                {"name": "a", "type": {"base": "int"}},
                {"name": "b", "type": {"base": "int"}},
            ],
        }
    )

    out = backend.emulate(
        {"start": start, "call": True, "args": [5, 7], "read_registers": ["EAX"]}
    )
    return {
        "return_value": out.get("return_value"),
        "registers": {r["name"]: r["value"] for r in (out.get("registers") or [])},
        "stop_reason": out.get("stop_reason"),
    }


try:
    result = {"ok": True, "data": main()}
except Exception as exc:  # surface ANY failure as a parseable, fail-closed envelope.
    result = {
        "ok": False,
        "error": "{}: {}".format(type(exc).__name__, exc),
        "traceback": traceback.format_exc(),
    }

sys.stdout.write("\n" + MARKER + json.dumps(result) + "\n")
sys.stdout.flush()
os._exit(0)
""".replace("__ADD_BLOB_HEX__", _ADD_BLOB_HEX)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the network-isolated container-run argv driving the auto-arg emulation in ``image``."""
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
        "/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size=1g",  # noqa: S108 — in-container tmpfs.
        "--env",
        "VIVARIUM_WORKER_PROJECT_DIR=/work/project",
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
    """Extract + parse the single marker-prefixed JSON object from ``stdout``."""
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line found in worker stdout:\n{stdout[-2000:]}"
    payload = lines[-1][len(_MARKER) :]
    try:
        parsed: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive: marker present but corrupt
        raise AssertionError(f"marker payload was not valid JSON: {exc}\n{payload!r}") from exc
    return parsed


def test_emulate_auto_arg_placement_on_real_worker(worker_image: str) -> None:
    """``emulate(call=True, args=[5, 7])`` must auto-place args per the ABI and return 12.

    Drives the in-container backend: craft ``int add(int, int)``, import raw, analyze, set a
    resolved ``(int, int) -> int`` signature, then emulate with ``args=[5, 7]``. Asserts ``ok`` and
    that the return value (and EAX) is ``12`` — the args reached the resolved param registers via
    ``VariableStorage``. A regression re-surfaces as ``ok=False`` or a wrong result.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"emulate auto-arg run timed out after {_RUN_TIMEOUT_SECONDS}s "
            f"(engine={engine}, image={worker_image})\n--- stderr tail ---\n{captured[-2000:]}"
        )

    if proc.returncode != 0:
        pytest.fail(
            f"worker run exited {proc.returncode} (engine={engine}, image={worker_image})\n"
            f"--- stderr tail ---\n{proc.stderr[-2000:]}\n"
            f"--- stdout tail ---\n{proc.stdout[-1000:]}"
        )

    envelope = _parse_marker_json(proc.stdout)
    assert envelope.get("ok") is True, (
        f"emulate auto-arg reported failure (ADR-066 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    return_value = data.get("return_value")
    assert return_value is not None, f"no return_value from the call: {data!r}"
    assert int(str(return_value), 16) == 12, (
        f"expected add(5, 7) == 12 via auto arg-placement; got return_value={return_value!r} "
        f"(registers={data.get('registers')!r})"
    )
