"""Integration: self-modifying unpacker recovery on a real worker (ADR-084, #399).

Capability gate for the opt-in ``unpack`` technique. A self-modifying unpacker decodes bytes into a
writable (executable) region at runtime and then EXECUTES them; the recovered strings are produced
by the unpacked code, not sitting in the static image. Ghidra's p-code emulator re-translates
self-modified code on execution (verified by probe), so the ADR-049 sandbox runs the unpacker + the
unpacked code; ``unpack`` emulates the chosen function and extracts the printable strings that
appeared in post-run writable memory.

This writes a tiny x86-64 self-modifying unpacker (a loop XOR-patches 49 bytes into the following
code region, falls through, and executes the now-decoded instructions, which write ``"Hello!"`` to a
data buffer at 0x1050), imports it raw, analyzes, then asserts:
  * ``unpack`` recovers ``"Hello!"`` with ``technique="unpack"`` (no key/encoding/stages);
  * the default ``xor_decode`` does NOT recover it (the output is not a static write target — it is
    written by the unpacked code);
  * a whole-program ``unpack`` (no ``function``) is REJECTED (CWE-400 cost guard).

Why a gated in-container test (not a unit test): the emulation (incl. self-modified-code
re-translation) is the JVM/PyGhidra edge (TB3, ADR-001), only validatable against a real Ghidra
worker; the pure post-run string extraction (``core.multidecode.extract_changed_strings``) is
hermetically unit-tested. ``integration``-marked (the default unit run SKIPS it); runs only when
``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No real malware —
a tiny synthetic x86-64 blob written in-container (master §5).

This test is added to the live-regression hard-gate list only at the worker **repin** (the pinned
worker must carry the ADR-084 code first — the worker-change-validation-recipe).

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

# A tiny headerless x86-64 SELF-MODIFYING unpacker (ADR-084): entry loops XORing 49 patch bytes in
# place with 0xAA (self-modifying), then falls through into the now-decoded patch at 0x1012 — which
# is `mov byte [0x1050+i], "Hello!"[i]` x6 ; ret — writing "Hello!" to the data buffer at 0x1050.
# Only `unpack` (emulate + scan post-run memory) recovers it; the output is not a static write ref.
_UNPACK_BLOB_HEX = (
    "ba1210000031c980340aaaffc183f9317cf56cae8ffabaaaaae26cae8ffbbaaaaacf6cae8ff8baaaaac6"
    "6cae8ff9baaaaac66cae8ffebaaaaac56cae8fffbaaaaa8b690000000000000000000000000000000000"
    "000000000000000000000000"
)

_DRIVER_UNPACK = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
BLOB = bytes.fromhex("__UNPACK_BLOB_HEX__")
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x1000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "unpack.bin")
    with open(path, "wb") as handle:
        handle.write(BLOB)

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": PROCESSOR,
         "base_addr": BASE_ADDR, "entry": BASE_ADDR}
    )
    backend.analyze({"timeout_seconds": 120})
    unpack = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["unpack"], "min_length": 4}
    )
    keyed = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["xor_decode"], "min_length": 4}
    )
    rejected = False
    try:
        backend.deobfuscate_strings({"techniques": ["unpack"], "min_length": 4})
    except Exception:
        rejected = True
    return {
        "unpack": unpack.get("strings") or [],
        "keyed": keyed.get("strings") or [],
        "whole_program_rejected": rejected,
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
""".replace("__UNPACK_BLOB_HEX__", _UNPACK_BLOB_HEX)


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


def test_deobfuscate_unpack_on_real_worker(worker_image: str) -> None:
    """``unpack`` recovers a string a self-modifying unpacker produced in memory (ADR-084).

    ``unpack`` recovers ``"Hello!"`` (``technique="unpack"``); the default ``xor_decode`` does NOT
    (the output is not a static write target); a whole-program ``unpack`` is rejected. A regression
    re-surfaces as the unpack recovery missing, xor_decode wrongly succeeding, or the whole-program
    request not being rejected.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image, _DRIVER_UNPACK)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"unpack run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"unpack reported failure (ADR-084 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    unpack_hits = [
        s
        for s in (data.get("unpack") or [])
        if s.get("technique") == "unpack" and _EXPECTED in str(s.get("text", ""))
    ]
    assert unpack_hits, f"expected an unpack recovery of {_EXPECTED!r}; got {data.get('unpack')!r}"
    assert unpack_hits[0].get("decode_key") is None and unpack_hits[0].get("encoding") is None, (
        f"unpack result should carry no key/encoding; got {unpack_hits[0]!r}"
    )
    keyed_hits = [s for s in (data.get("keyed") or []) if _EXPECTED in str(s.get("text", ""))]
    assert not keyed_hits, (
        f"xor_decode must NOT recover a self-modifying unpacker's output; got {data.get('keyed')!r}"
    )
    assert data.get("whole_program_rejected") is True, (
        "a whole-program unpack (no function) must be rejected (CWE-400 cost guard)"
    )
