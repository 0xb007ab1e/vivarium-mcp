"""Integration: function match-hashes on a real worker (ADR-057, v1.8 function_hash).

Regression + capability gate for the ``function_hash`` tool: Ghidra's own function hashers
(``ghidra.app.plugin.match`` — the ones behind its function-match/diff feature) at three
granularities. Proven live with three functions:

    * ``f0`` = ``mov eax,5 ; ret``, ``f1`` = an identical copy, ``f2`` = ``mov eax,9 ; ret``
      (differs only in the immediate). ``exact_bytes`` matches f0==f1 but not f2;
      ``exact_instructions`` (operands masked) and ``exact_mnemonics`` match all three.

Why a gated in-container test (not a unit test): the function hashers are the JVM/PyGhidra edge
(TB3, ADR-001) — excluded from server unit coverage and only validatable against a real Ghidra
worker.
Gating + fixture posture are reused verbatim from ``test_import_emulate.py``: ``integration``-marked
(the default unit run SKIPS it), runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker
image + engine are available. No real malware — the input is a tiny synthetic x86-64 blob.

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

#: Generous ceiling for JVM boot + import + disassemble + the hasher calls.
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: import a blob holding three functions (two
# identical, one differing only in an immediate), create them, then `function_hash` each. Ends with
# an explicit flush + os._exit(0).
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    base = 0x401000
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "fh.bin")
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
        "f0": backend.function_hash({"function": hex(base + 0)}),
        "f1": backend.function_hash({"function": hex(base + 6)}),
        "f2": backend.function_hash({"function": hex(base + 12)}),
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
    """Build the container-run argv that drives the function hashing in ``image``.

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


def test_function_hash_matches_clones_on_real_worker(worker_image: str) -> None:
    """``function_hash`` must reflect Ghidra's match semantics across granularities (ADR-057).

    Drives the in-container backend: import three functions (two identical, one differing only in an
    immediate), create them, then ``function_hash`` each. Asserts ``exact_bytes`` splits the
    differing function out while ``exact_instructions`` (operands masked) and ``exact_mnemonics``
    match all three. A regression re-surfaces as ``ok=False`` or wrong equality relations.

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
            f"function_hash run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"function_hash reported failure (ADR-057 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    f0, f1, f2 = data["f0"], data["f1"], data["f2"]

    # exact_bytes: the two identical functions match; the differing-immediate one does NOT.
    assert f0["exact_bytes"] == f1["exact_bytes"], (
        f"identical functions should share bytes hash: {data!r}"
    )
    assert f0["exact_bytes"] != f2["exact_bytes"], (
        f"a different immediate must change exact_bytes: {data!r}"
    )

    # exact_instructions (operands masked) + exact_mnemonics: all three match (same instructions).
    assert f0["exact_instructions"] == f1["exact_instructions"] == f2["exact_instructions"], (
        f"operand-masked instruction hash should match all three: {data!r}"
    )
    assert f0["exact_mnemonics"] == f1["exact_mnemonics"] == f2["exact_mnemonics"], (
        f"mnemonic hash should match all three: {data!r}"
    )
