"""Integration: interprocedural local decode recovery on a real worker (ADR-082, #398).

Capability gate for the ADR-082 cross-function detection extension to ``deobfuscate_strings``
(``xor_decode``). The decoder's per-byte transform lives in a HELPER function: the entry loops and
`call`s `helper(buf, i)`, and the `INT_XOR` + `STORE` are in the helper, not the entry. The ADR-049
emulation already steps into in-program callees, so recovery only needs DETECTION to span the callee
— ADR-082 walks the bounded call graph for the decode signals.

This writes a tiny x86-64 interprocedural decoder, imports it raw, analyzes, then asserts:
  * with the default call-depth the plaintext ``"Hello!"`` is recovered (the helper's XOR is found);
  * with ``max_call_depth=0`` (entry-only) it is NOT recovered — proving the cross-function walk is
    what enables it (not some single-function fallback).

Why a gated in-container test (not a unit test): the p-code walk + decode-loop emulation are the
JVM/PyGhidra edge (TB3, ADR-001), only validatable against a real Ghidra worker; the pure
filter/selection cores are hermetically unit-tested. ``integration``-marked (the default unit run
SKIPS it); runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are
available. No real malware — a tiny synthetic x86-64 blob written in-container (master §5).

This test is added to the live-regression hard-gate list only at the worker **repin** (the pinned
worker must carry the ADR-082 code first — the worker-change-validation-recipe).

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

_EXPECTED = "Hello!"
_PROCESSOR = "x86:LE:64:default"
_BASE_ADDR = 0x1000

# A tiny headerless x86-64 INTERPROCEDURAL XOR decoder (ADR-082): entry@0x1000 sets rdi=buf(0x1030),
# loops i=0..5 CALLing helper@0x1020; the helper does `al=buf[i]; al^=0x41; buf[i]=al; ret` — so the
# INT_XOR + STORE live in the CALLEE. CT = "Hello!" ^ 0x41 at 0x1030. Entry-only detection finds no
# decode op; the ADR-082 call-graph walk finds it in the helper.
_INTERPROC_BLOB_HEX = (
    "48bf301000000000000031c9e80f000000ffc183f9067cf4c3000000000000008a040f344188040fc3"
    "0000000000000009242d2d2e600000"
)

_DRIVER_INTERPROC = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
BLOB = bytes.fromhex("__INTERPROC_BLOB_HEX__")
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x1000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "interproc.bin")
    with open(path, "wb") as handle:
        handle.write(BLOB)

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": PROCESSOR,
         "base_addr": BASE_ADDR, "entry": BASE_ADDR}
    )
    backend.analyze({"timeout_seconds": 120})
    deep = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["xor_decode"], "min_length": 4}
    )
    entry_only = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["xor_decode"], "min_length": 4,
         "max_call_depth": 0}
    )
    return {"deep": deep.get("strings") or [], "entry_only": entry_only.get("strings") or []}


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
""".replace("__INTERPROC_BLOB_HEX__", _INTERPROC_BLOB_HEX)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str, driver: str) -> list[str]:
    """Build the network-isolated container-run argv driving ``driver`` in ``image``."""
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
    cmd += ["--entrypoint", "python", image, "-c", driver]
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


def _has_hit(strings: list[dict[str, Any]]) -> bool:
    """Whether an xor_decode recovery of the expected plaintext is present."""
    return any(
        s.get("technique") == "xor_decode" and _EXPECTED in str(s.get("text", "")) for s in strings
    )


def test_deobfuscate_interprocedural_on_real_worker(worker_image: str) -> None:
    """``deobfuscate_strings`` recovers a decoder whose XOR lives in a called helper (ADR-082).

    With the default call-depth the helper's XOR is found and ``"Hello!"`` recovered; with
    ``max_call_depth=0`` (entry-only) it is NOT recovered — proving the cross-function walk is what
    enables it. A regression (no callee scan, or the walk not bounded/working) re-surfaces as the
    deep recovery missing or the entry-only recovery wrongly succeeding.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image, _DRIVER_INTERPROC)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"interprocedural run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"interprocedural reported failure (ADR-082 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert _has_hit(data.get("deep") or []), (
        f"expected a cross-function xor_decode recovery of {_EXPECTED!r}; got {data.get('deep')!r}"
    )
    assert not _has_hit(data.get("entry_only") or []), (
        f"entry-only (max_call_depth=0) must NOT recover the interprocedural decoder; "
        f"got {data.get('entry_only')!r}"
    )
