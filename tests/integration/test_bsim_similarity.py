"""Integration: BSim fuzzy similarity on a real worker (ADR-058, v1.8 bsim_similarity).

Regression + capability gate for the ``bsim_similarity`` tool: it generates each function's BSim
feature signature (Ghidra's ``GenSignatures`` + bundled ``medium`` weights) and returns their cosine
similarity in ``[0, 1]``. Proven live:

    * import ``f0`` and an identical ``f1`` plus an unrelated ``f2``; ``bsim_similarity(f0, f1)`` is
      1.0 (identical) while ``bsim_similarity(f0, f2)`` is clearly lower — the fuzzy semantics that
      distinguish this from ``function_hash``'s exact match.

Why a gated in-container test (not a unit test): the BSim signature pipeline (``GenSignatures`` +
the decompiler + the LSH vector factory) is the JVM/PyGhidra edge (TB3, ADR-001) — excluded from
server unit coverage and only validatable against a real Ghidra worker. Gating + fixture posture are
reused verbatim from ``test_import_emulate.py``: ``integration``-marked (the default unit run SKIPS
it), runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are
available. No real malware — the input is a tiny synthetic x86-64 blob.

Honored environment (same as ``test_import_emulate.py``):
    * ``VIVARIUM_INTEGRATION`` — truthy ({1,true,yes,on}) enables the suite (see conftest).
    * ``VIVARIUM_WORKER_IMAGE`` — the pinned-by-digest worker image ref (conftest fixture).
    * ``VIVARIUM_CONTAINER_ENGINE`` — container CLI to invoke (default ``podman``).
    * ``VIVARIUM_WORKER_SRC_MOUNT`` — OPTIONAL dev hook: bind a host repo root read-only over the
      image's installed package (validate working-tree code against the pinned image, no rebuild).
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

#: Generous ceiling for JVM boot + import + two BSim signature generations (each decompiles).
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: import a blob with two identical functions +
# one unrelated one, create them, then `bsim_similarity` for the identical pair + a different pair.
# Ends with an explicit flush + os._exit(0).
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    base = 0x401000
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "bsim.bin")
    f = bytes.fromhex("554889e58b45fc83c00189450089c85dc3")  # a small function
    other = bytes.fromhex("b800000000c3")                    # an unrelated tiny function
    with open(path, "wb") as handle:
        handle.write(f + f + other)  # f0 @0, f1 @len(f), f2 @2*len(f)

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": "x86:LE:64:default",
         "base_addr": base, "entry": base}
    )
    program = backend._require_program()

    from ghidra.program.flatapi import FlatProgramAPI
    fpa = FlatProgramAPI(program)
    space = program.getAddressFactory().getDefaultAddressSpace()
    lf = len(f)
    tx = program.startTransaction("setup")
    for i, off in enumerate((0, lf, 2 * lf)):
        addr = space.getAddress(base + off)
        fpa.disassemble(addr)
        fpa.createFunction(addr, "f%d" % i)
    program.endTransaction(tx, True)

    return {
        "identical": backend.bsim_similarity(
            {"function_a": hex(base + 0), "function_b": hex(base + lf)}
        ),
        "different": backend.bsim_similarity(
            {"function_a": hex(base + 0), "function_b": hex(base + 2 * lf)}
        ),
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
"""


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the container-run argv that drives the BSim comparison in ``image``.

    Mirrors ``test_import_emulate.py``'s posture exactly (network-isolated, capped memory, read-only
    rootfs + tmpfs scratch), then overrides the entrypoint to ``python -c <driver>``.

    Args:
        engine: The container engine binary (``podman``/``docker``).
        image: The worker image reference (pinned by digest in CI; resolved by the fixture).

    Returns:
        The full argv list to pass to :func:`subprocess.run`.
    """
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
    """Extract and parse the single marker-prefixed JSON object from ``stdout``.

    Args:
        stdout: The captured container stdout (JVM/Ghidra log noise interleaved).

    Returns:
        The parsed result envelope (``{"ok": bool, ...}``).

    Raises:
        AssertionError: If no marker line is present or its payload is not valid JSON.
    """
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line found in worker stdout:\n{stdout[-2000:]}"
    payload = lines[-1][len(_MARKER) :]
    try:
        parsed: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive: marker present but corrupt
        raise AssertionError(f"marker payload was not valid JSON: {exc}\n{payload!r}") from exc
    return parsed


def test_bsim_similarity_scores_clones_on_real_worker(worker_image: str) -> None:
    """``bsim_similarity`` must score identical functions at 1.0 and unrelated ones lower (ADR-058).

    Drives the in-container backend: import two identical functions + one unrelated, create them,
    then ``bsim_similarity`` for the identical pair and a different pair. Asserts identical → 1.0,
    unrelated pair clearly lower (< 0.9). A regression re-surfaces as ``ok=False`` or wrong scores.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd,
            capture_output=True,
            text=True,
            timeout=_RUN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:  # don't hang the suite — fail with what we captured.
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"bsim_similarity run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"bsim_similarity reported failure (ADR-058 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    identical = float(data["identical"]["similarity"])
    different = float(data["different"]["similarity"])
    assert identical == pytest.approx(1.0, abs=1e-6), (
        f"identical functions must have BSim similarity 1.0; got {identical}"
    )
    assert different < 0.9, (
        f"an unrelated function pair must score clearly lower than identical; got {different}"
    )
