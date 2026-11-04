"""Integration: multi-stage / chained local decode recovery on a real worker (ADR-081, #379).

Capability gate for the ADR-081 extension to ``deobfuscate_strings`` (``xor_decode``): the ADR-068
MVP emulated the whole decoder but read back only ``min(write_targets)``, so a CHAINED decoder whose
final plaintext lands in a *different* buffer was missed. This writes a tiny x86-64 two-buffer
chained XOR decoder — ``scratch = ct ^ 0x41`` (a NON-printable intermediate) then
``out = scratch ^ 0x80`` (the final plaintext), with ``out`` at a HIGHER address than the
intermediate — imports it raw, analyzes, and asserts the worker now reads back every write buffer,
recovers ``"Hello!"`` from the final one, and reports the ordered ``[xor 0x41, xor 0x80]`` chain.

Why a gated in-container test (not a unit test): the p-code walk + the decode-loop emulation are the
JVM/PyGhidra edge (TB3, ADR-001), only validatable against a real Ghidra worker; the pure selection
+ chain assembly (``core.multidecode``) + schema/builder are unit-tested. ``integration``-marked
(the default unit run SKIPS it); runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker
image + engine are available. No real malware — a tiny synthetic x86-64 blob written in-container
(master §5).

This test is added to the live-regression hard-gate list only at the worker **repin** (the pinned
worker must carry the ADR-081 code first — the worker-change-validation-recipe); until then it runs
on demand with ``VIVARIUM_INTEGRATION=1`` against a locally built worker.

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

# A tiny headerless x86-64 TWO-BUFFER chained XOR decoder (ADR-081): rdx=CT(0x1030),
# rdi=A(0x1040, intermediate), rsi=OUT(0x1050, final). Per byte: al=CT[i]; al^=0x41; A[i]=al;
# al^=0x80; OUT[i]=al. CT = "Hello!" ^ 0x41 ^ 0x80, so A = "Hello!" ^ 0x80 (NON-printable
# intermediate) and OUT = "Hello!". The single-pass MVP read only min(write_targets)=A (garbage)
# and missed this; ADR-081 reads back every write buffer, picks the printable OUT, and reports the
# 2-stage [xor 0x41, xor 0x80] chain.
_MULTISTAGE_BLOB_HEX = (
    "ba30100000bf40100000be5010000031c98a040a344188040f348088040effc183f9067cecc3"
    "0000000000000000000089a4adadaee000000000000000000000000000000000000000000000000000000000000"
    "000000000"
)

_DRIVER_MULTISTAGE = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
BLOB = bytes.fromhex("__MULTISTAGE_BLOB_HEX__")
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x1000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "multidec.bin")
    with open(path, "wb") as handle:
        handle.write(BLOB)

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": PROCESSOR,
         "base_addr": BASE_ADDR, "entry": BASE_ADDR}
    )
    backend.analyze({"timeout_seconds": 120})
    out = backend.deobfuscate_strings(
        {"function": hex(BASE_ADDR), "techniques": ["xor_decode"], "min_length": 4}
    )
    return {"strings": out.get("strings") or []}


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
""".replace("__MULTISTAGE_BLOB_HEX__", _MULTISTAGE_BLOB_HEX)


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


def test_deobfuscate_multistage_on_real_worker(worker_image: str) -> None:
    """``deobfuscate_strings`` recovers a CHAINED two-buffer XOR decoder the MVP missed (ADR-081).

    The decoder XORs a ciphertext into an intermediate buffer (``^0x41`` — NON-printable) then into
    a final buffer (``^0x80``), so the final plaintext lives in a HIGHER buffer than
    ``min(write_targets)``. The single-pass MVP read only the minimum (intermediate) buffer and
    reported not-recovered; ADR-081 reads back every write buffer and recovers ``"Hello!"`` from the
    final one, reporting the ordered 2-stage ``[xor 0x41, xor 0x80]`` chain. A regression (reading
    only the min buffer, or a one-key chain) re-surfaces as a missing string or a wrong ``stages``.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image, _DRIVER_MULTISTAGE)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"multistage xor_decode run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"multistage xor_decode reported failure (ADR-081 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    strings = envelope["data"].get("strings") or []
    hits = [
        s
        for s in strings
        if s.get("technique") == "xor_decode" and _EXPECTED in str(s.get("text", ""))
    ]
    assert hits, f"expected a chained xor_decode recovery of {_EXPECTED!r}; got {strings!r}"
    rec = hits[0]
    stages = rec.get("stages") or []
    assert len(stages) == 2, f"expected a 2-stage chain; got {rec!r}"
    assert [st.get("op") for st in stages] == ["xor", "xor"], f"unexpected ops: {stages!r}"
    assert [st.get("key") for st in stages] == ["0x41", "0x80"], f"unexpected keys: {stages!r}"
