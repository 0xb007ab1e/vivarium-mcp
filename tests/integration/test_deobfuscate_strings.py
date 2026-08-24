"""Integration: stack-string recovery via `deobfuscate_strings` on a real worker (ADR-068).

Regression + capability gate for the ``deobfuscate_strings`` tool (``stack_string`` technique): the
worker walks a function's RAW per-instruction p-code for constant stores to adjacent stack slots and
reassembles the runs into strings. Proven live:

    * write a tiny x86-64 blob that stores ``"Hello!"`` byte-by-byte to adjacent stack slots
      (``mov byte [rsp-N], imm8`` x6, then ``ret``); import it raw, analyze, then
      ``deobfuscate_strings(function=entry, techniques=["stack_string"])`` recovers ``"Hello!"``. A
      regression in the p-code walk / reassembly re-surfaces as ``ok=False`` or the string missing.

Why a gated in-container test (not a unit test): the p-code walk is the JVM/PyGhidra edge (TB3,
ADR-001) — excluded from server unit coverage and only validatable against a real Ghidra worker; the
pure reassembly core (``core.stackstring``) is covered by unit tests. ``xor_decode`` is DEFERRED
(ADR-068); only ``stack_string`` is exercised here. Gating + fixture posture mirror
``test_import_raw_binary.py``: ``integration``-marked (the default unit run SKIPS it), runs only
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

#: The expected recovered stack-string + the raw-import parameters.
_EXPECTED = "Hello!"
_PROCESSOR = "x86:LE:64:default"
_BASE_ADDR = 0x1000

#: A tiny headerless x86-64 blob storing "Hello!" to adjacent stack slots then returning:
#:   mov byte [rsp-0x10], 'H'  C6 44 24 F0 48
#:   mov byte [rsp-0x0f], 'e'  C6 44 24 F1 65
#:   mov byte [rsp-0x0e], 'l'  C6 44 24 F2 6C
#:   mov byte [rsp-0x0d], 'l'  C6 44 24 F3 6C
#:   mov byte [rsp-0x0c], 'o'  C6 44 24 F4 6F
#:   mov byte [rsp-0x0b], '!'  C6 44 24 F5 21
#:   ret                       C3
_BLOB_HEX = "c64424f048c64424f165c64424f26cc64424f36cc64424f46fc64424f521c3"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: write the blob, import it raw (loader=binary
# + processor + base_addr + entry so analysis defines the function), analyze, then recover
# stack-strings from the entry function.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
BLOB = bytes.fromhex("__BLOB_HEX__")
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x1000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "stackstr.bin")
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

    # Prefer the seeded entry function; fall back to a bounded whole-program scan if analysis did
    # not name a function there (both drive the same p-code walk).
    scoped = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["stack_string"], "min_length": 4}
    )
    texts = [str(s.get("text")) for s in (scoped.get("strings") or [])]
    if "__EXPECTED__" not in texts:
        whole = backend.deobfuscate_strings({"techniques": ["stack_string"], "min_length": 4})
        texts = [str(s.get("text")) for s in (whole.get("strings") or [])]
    return {"texts": texts}


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
""".replace("__BLOB_HEX__", _BLOB_HEX).replace("__EXPECTED__", _EXPECTED)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the network-isolated container-run argv driving the recovery in ``image``."""
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


def test_deobfuscate_stack_string_on_real_worker(worker_image: str) -> None:
    """``deobfuscate_strings`` must recover a byte-by-byte stack-string from raw p-code.

    Drives the in-container backend: write an x86-64 blob that builds ``"Hello!"`` on the stack via
    per-byte immediate stores, import it raw, analyze, then recover stack-strings. Asserts ``ok``
    and that ``"Hello!"`` is among the recovered strings. A regression in the raw p-code walk or the
    reassembly re-surfaces as ``ok=False`` or the string missing.

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
            f"deobfuscate_strings run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"deobfuscate_strings reported failure (ADR-068 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    texts = envelope["data"].get("texts") or []
    assert _EXPECTED in texts, (
        f"expected {_EXPECTED!r} among recovered stack-strings; got {texts!r}"
    )
