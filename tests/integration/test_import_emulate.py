"""Integration: bounded p-code emulation runs against a real worker (ADR-049, v1.8 emulate).

Regression + capability gate for the ``emulate`` tool: Ghidra's ``EmulatorHelper`` INTERPRETS lifted
p-code — no native execution, no syscalls, no I/O — so a HOSTILE program cannot escape the worker,
and the program DB is never mutated (read-effect-only). Two paths are proven live on one loaded
program:

    1. **Correctness / readback** — a tiny x86-64 blob that computes ``RAX = 5 + 3`` and stops at
       the ``ret`` via ``stop_at``; the register readback must equal ``8`` with ``stop_reason``
       ``"stop-address"``.
    2. **DoS bound (abuse)** — an infinite ``jmp $`` loop bounded by a small ``max_steps``;
       emulation must terminate at exactly ``max_steps`` with ``stop_reason`` ``"max-steps"``. This
       is the hostile-code containment guarantee (CWE-400) — a runaway program stops at the step cap
       (the wall-clock kill backs it), not left to spin.

Why a gated in-container test (not a unit test): ``EmulatorHelper`` is the JVM/PyGhidra edge (TB3,
ADR-001) — excluded from server unit coverage and only validatable against a real Ghidra worker.
Gating + fixture posture are reused verbatim from ``test_import_raw_binary.py``: ``integration``-
marked (the default unit run SKIPS it), runs only when ``VIVARIUM_INTEGRATION`` is truthy AND a real
worker image + engine are available. No real malware — the analyzed input is a tiny **synthetic
x86-64 code blob** the driver writes in-container (master §5).

Honored environment (same as ``test_import_raw_binary.py``):
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

#: Generous ceiling for JVM boot + BinaryLoader + two emulation runs.
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: Import parameters the driver applies + the test asserts against.
_PROCESSOR = "x86:LE:64:default"
_BASE_ADDR = 0x400000
#: Small step budget for the infinite-loop case — proves the DoS bound terminates a runaway program.
_LOOP_MAX_STEPS = 500

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: write ONE headerless x86-64 blob holding a
# compute-8 region followed by an infinite-loop region, import it (loader='binary'), then run
# `emulate` twice on the same loaded program — once with stop_at (readback) and once with a small
# max_steps over the loop (DoS bound). Prints one marker-prefixed JSON line, self-reports failures.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x400000"), 0)
LOOP_MAX_STEPS = int(os.environ.get("VIVARIUM_DRIVER_LOOP_MAX_STEPS", "500"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    # One blob, two regions:
    #   base+0 : b8 05 00 00 00   mov eax, 5
    #   base+5 : 83 c0 03         add eax, 3      -> RAX == 8
    #   base+8 : c3               ret             (stop_at target — stop BEFORE executing ret)
    #   base+9 : eb fe            jmp $           (infinite loop — the DoS-bound target)
    blob = b"\xb8\x05\x00\x00\x00\x83\xc0\x03\xc3\xeb\xfe"
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "emu.bin")
    with open(path, "wb") as handle:
        handle.write(blob)

    backend = PyGhidraBackend()
    out = {}
    out["import"] = backend.import_binary(
        {
            "source_ref": path,
            "loader": "binary",
            "processor": PROCESSOR,
            "base_addr": BASE_ADDR,
            "entry": BASE_ADDR,
        }
    )
    # 1) Correctness: run the compute-8 region, stop at the `ret`, read RAX back.
    out["compute"] = backend.emulate(
        {
            "start": hex(BASE_ADDR),
            "set_registers": {},
            "write_memory": [],
            "max_steps": 1000,
            "stop_at": hex(BASE_ADDR + 8),
            "read_registers": ["RAX"],
            "read_memory": [],
        }
    )
    # 2) DoS bound: run the infinite loop under a small step cap; must stop at max-steps.
    out["loop"] = backend.emulate(
        {
            "start": hex(BASE_ADDR + 9),
            "set_registers": {},
            "write_memory": [],
            "max_steps": LOOP_MAX_STEPS,
            "stop_at": None,
            "read_registers": [],
            "read_memory": [],
        }
    )
    return out


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
"""


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the container-run argv that drives the emulation in ``image``.

    Mirrors ``test_import_raw_binary.py``'s posture exactly (network-isolated, capped memory,
    read-only rootfs + tmpfs scratch), then overrides the entrypoint to ``python -c <driver>``.

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
        "--env",
        f"VIVARIUM_DRIVER_PROCESSOR={_PROCESSOR}",
        "--env",
        f"VIVARIUM_DRIVER_BASE_ADDR={hex(_BASE_ADDR)}",
        "--env",
        f"VIVARIUM_DRIVER_LOOP_MAX_STEPS={_LOOP_MAX_STEPS}",
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


def test_emulate_runs_bounded_on_real_worker(worker_image: str) -> None:
    """P-code emulation must compute correctly, honor ``stop_at``, and cap a runaway loop (ADR-049).

    Drives the in-container backend: import one x86-64 blob, then ``emulate`` twice — (1) compute
    ``RAX = 5 + 3`` stopping at the ``ret`` (assert ``RAX == 8`` and ``stop_reason ==
    "stop-address"``); (2) run an infinite ``jmp $`` under a small ``max_steps`` (assert
    ``stop_reason == "max-steps"`` and ``steps_executed == max_steps`` — the DoS bound terminated
    the hostile loop). A regression re-surfaces here as ``ok=False``, a wrong register value, or a
    loop that did not stop at the cap.

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
            f"emulate run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"emulate reported failure (ADR-049 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    # 1) Correctness: RAX == 8, stopped at the ret address.
    compute = data.get("compute", {})
    assert compute.get("stop_reason") == "stop-address", (
        f"expected stop_reason 'stop-address' at the ret; got {compute.get('stop_reason')!r}"
    )
    regs = {r["name"]: r["value"] for r in compute.get("registers", [])}
    assert "RAX" in regs, f"RAX not read back: {compute!r}"
    assert int(regs["RAX"], 16) == 8, f"expected RAX == 8 (5 + 3); got 0x{regs['RAX']}"

    # 2) DoS bound: the infinite loop terminated at exactly max_steps.
    loop = data.get("loop", {})
    assert loop.get("stop_reason") == "max-steps", (
        f"expected the infinite loop to stop at the step cap; got {loop.get('stop_reason')!r} "
        f"(a hostile loop that does NOT hit the cap is a containment regression — CWE-400)"
    )
    assert loop.get("steps_executed") == _LOOP_MAX_STEPS, (
        f"expected steps_executed == {_LOOP_MAX_STEPS}; got {loop.get('steps_executed')!r}"
    )
