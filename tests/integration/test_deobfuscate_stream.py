"""Integration: stateful / stream-cipher decode recovery on a real worker (ADR-083, #400).

Capability gate for the opt-in ``stream_decode`` technique. A stateful/stream decoder XORs the
ciphertext with an evolving KEYSTREAM (a register value, not a constant), so the keyed xor
family never detects it — but the ADR-049 emulation reproduces the keystream and decrypts a
SELF-CONTAINED cipher. ``stream_decode`` relaxes detection to a variable key (function-scoped,
opt-in) and recovers the plaintext by the same bounded emulation + printable-changed gate.

This writes a tiny x86-64 self-contained rolling-keystream decoder (``k`` seeded + updated per byte;
``out[i] = ct[i] ^ k``), imports it raw, analyzes, then asserts:
  * ``stream_decode`` recovers ``"Hello!"`` (``technique="stream_decode"``, ``encoding="stream"``)
    with NO ``decode_key`` (a stream cipher has no single key);
  * the default ``xor_decode`` does NOT recover it (the key is variable, not a constant);
  * a whole-program ``stream_decode`` (no ``function``) is REJECTED (CWE-400 cost guard).

Why a gated in-container test (not a unit test): the p-code walk + decode-loop emulation are the
JVM/PyGhidra edge (TB3, ADR-001), only validatable against a real Ghidra worker. ``integration``-
marked (the default unit run SKIPS it); runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real
worker image + engine are available. No real malware — a tiny synthetic x86-64 blob written
in-container (master §5).

This test is added to the live-regression hard-gate list only at the worker **repin** (the pinned
worker must carry the ADR-083 code first — the worker-change-validation-recipe).

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

# A tiny headerless x86-64 self-contained ROLLING-KEYSTREAM decoder (ADR-083): rdx=buf(0x1030),
# bl=k (seed 0x41); per byte: al=buf[i]; al^=bl (VARIABLE key); buf[i]=al; bl+=0x1f. CT at
# 0x1030. The XOR operand is a register (keystream), not a constant — only stream_decode detects it;
# the `add bl,0x1f` is the key update (its output is not stored, so xor_decode's filter ignores it).
_STREAM_BLOB_HEX = (
    "ba3010000031c9b3418a040a30d888040a80c31fffc183f9067ceec3"
    "0000000000000000000000000000000000000000090513f2d2fd0000"
)

_DRIVER_STREAM = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
BLOB = bytes.fromhex("__STREAM_BLOB_HEX__")
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x1000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "stream.bin")
    with open(path, "wb") as handle:
        handle.write(BLOB)

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": PROCESSOR,
         "base_addr": BASE_ADDR, "entry": BASE_ADDR}
    )
    backend.analyze({"timeout_seconds": 120})
    stream = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["stream_decode"], "min_length": 4}
    )
    keyed = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["xor_decode"], "min_length": 4}
    )
    rejected = False
    try:
        backend.deobfuscate_strings({"techniques": ["stream_decode"], "min_length": 4})
    except Exception:
        rejected = True
    return {
        "stream": stream.get("strings") or [],
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
""".replace("__STREAM_BLOB_HEX__", _STREAM_BLOB_HEX)


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


def _has_stream_hit(strings: list[dict[str, Any]]) -> bool:
    """Whether a stream_decode recovery of the expected plaintext (no key) is present."""
    return any(
        s.get("technique") == "stream_decode"
        and s.get("encoding") == "stream"
        and s.get("decode_key") is None
        and _EXPECTED in str(s.get("text", ""))
        for s in strings
    )


def test_deobfuscate_stream_on_real_worker(worker_image: str) -> None:
    """``stream_decode`` recovers a self-contained rolling-keystream decoder (ADR-083).

    ``stream_decode`` recovers ``"Hello!"`` (encoding ``"stream"``, no key); the default
    ``xor_decode`` does NOT (variable key); a whole-program ``stream_decode`` is rejected. A
    regression re-surfaces as the stream recovery missing, xor_decode wrongly succeeding, or the
    whole-program request not being rejected.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image, _DRIVER_STREAM)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"stream_decode run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"stream_decode reported failure (ADR-083 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert _has_stream_hit(data.get("stream") or []), (
        f"expected a stream_decode recovery of {_EXPECTED!r} (encoding=stream, no key); "
        f"got {data.get('stream')!r}"
    )
    keyed_hits = [
        s
        for s in (data.get("keyed") or [])
        if s.get("technique") == "xor_decode" and _EXPECTED in str(s.get("text", ""))
    ]
    assert not keyed_hits, (
        f"xor_decode must NOT recover a variable-key stream decoder; got {data.get('keyed')!r}"
    )
    assert data.get("whole_program_rejected") is True, (
        "a whole-program stream_decode (no function) must be rejected (CWE-400 cost guard)"
    )
