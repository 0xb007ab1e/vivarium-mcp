"""Integration: whole-program fingerprint on a real worker (ADR-073 D1, program_fingerprint).

Capability + determinism gate for ``program_fingerprint``: the worker computes ``structure_digest``
(SHA-256 over the sorted per-function ExactMnemonics match-hashes), ``import_digest``, and coverage
over a real analyzed program. Proven live with three functions (two identical, one differing only in
an immediate) created in a headerless raw blob:

    * ``structure_digest`` is a 64-hex SHA-256 and is STABLE across two calls (deterministic).
    * With the raw ``binary`` loader there are no imports ⇒ ``import_digest`` is ``None``.
    * ``function_count`` reflects the three created functions.

Why a gated in-container test (not a unit test): the fact-gathering (mnemonic hashers, external
symbols, coverage) is the JVM/PyGhidra edge (TB3, ADR-001) — excluded from server unit coverage and
only validatable against a real Ghidra worker. Gating + fixture posture are reused verbatim from
``test_function_hash.py``: ``integration``-marked (the default unit run SKIPS it), runs only when
``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No real malware —
the input is a tiny synthetic x86-64 blob.
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

#: Generous ceiling for JVM boot + import + analyze + the fingerprint passes.
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: import a blob holding three functions (two
# identical, one differing only in an immediate), create them, then `program_fingerprint` TWICE
# (to assert determinism). Ends with an explicit flush + os._exit(0).
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    base = 0x401000
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "pf.bin")
    # f0: mov eax,5;ret | f1: identical | f2: mov eax,9;ret (same instructions, different immediate)
    with open(path, "wb") as handle:
        handle.write(bytes.fromhex("b805000000c3" "b805000000c3" "b809000000c3"))

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": "x86:LE:64:default",
         "base_addr": base, "entry": base}
    )
    program = backend._require_program()

    from ghidra.program.flatapi import FlatProgramAPI
    fpa = FlatProgramAPI(program)
    space = program.getAddressFactory().getDefaultAddressSpace()
    tx = program.startTransaction("setup")
    for i, off in enumerate((0, 6, 12)):
        addr = space.getAddress(base + off)
        fpa.disassemble(addr)
        fpa.createFunction(addr, "f%d" % i)
    program.endTransaction(tx, True)

    return {
        "fp1": backend.program_fingerprint({}),
        "fp2": backend.program_fingerprint({}),
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
    """Build the container-run argv that drives the fingerprinting in ``image``.

    Mirrors ``test_function_hash.py``'s posture exactly (network-isolated, capped memory, read-only
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


def _is_hex64(value: object) -> bool:
    """Return whether ``value`` is a 64-character lowercase hex string (a SHA-256 digest)."""
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def test_program_fingerprint_is_deterministic_on_real_worker(worker_image: str) -> None:
    """``program_fingerprint`` yields stable, well-formed digests over a real program (ADR-073 D1).

    Drives the in-container backend: import three functions (two identical, one differing only in an
    immediate), create them, then ``program_fingerprint`` twice. Asserts the structure digest is a
    64-hex SHA-256 that is IDENTICAL across the two calls (order-independent, deterministic), that a
    raw import has no ``import_digest``, and that the function count reflects the three functions.

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
            f"program_fingerprint run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"program_fingerprint reported failure (ADR-073 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    fp1, fp2 = envelope["data"]["fp1"], envelope["data"]["fp2"]

    # structure_digest is a SHA-256 hex and is deterministic across calls (the sort makes it so).
    assert _is_hex64(fp1["structure_digest"]), f"structure_digest not sha256-hex: {fp1!r}"
    assert fp1["structure_digest"] == fp2["structure_digest"], (
        f"structure_digest must be deterministic across calls: {fp1!r} vs {fp2!r}"
    )

    # Raw binary loader ⇒ no imports ⇒ import_digest absent/None; counts are stable.
    assert fp1.get("import_digest") is None, f"raw blob should have no imports: {fp1!r}"
    assert fp1["import_count"] == 0
    assert fp1["function_count"] == 3, f"expected the three created functions: {fp1!r}"

    # coverage is present and sane (total addressable bytes > 0).
    assert fp1["coverage"]["total_bytes"] > 0, f"coverage should be populated: {fp1!r}"
