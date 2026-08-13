"""Integration: recovered stack-frame layout on a real worker (ADR-054, v1.8 stack_frame).

Regression + capability gate for the ``stack_frame`` tool: after auto-analysis, Ghidra's Stack
analyzer populates a function's ``Function.getStackFrame()`` with its recovered locals + stack
parameters (offset, name, type, size). Proven live:

    * import a stack-using blob (``push rbp; mov rbp,rsp; mov [rbp-4],5; mov eax,[rbp-4]; ...``),
      ``session_analyze``, then ``stack_frame`` → a recovered local at a negative frame offset with
      size 4 (``local_c``, ``undefined4`` in the grounded run).

The frame is only populated AFTER analysis (the driver analyzes first) — an un-analyzed function
returns an empty variable list by design.

Why a gated in-container test (not a unit test): ``Function.getStackFrame`` + the Stack analyzer are
the JVM/PyGhidra edge (TB3, ADR-001) — excluded from server unit coverage and only validatable
against a real Ghidra worker. Gating + fixture posture are reused verbatim from
``test_import_emulate.py``: ``integration``-marked (the default unit run SKIPS it), runs only when
``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No real malware —
the input is a tiny synthetic x86-64 blob.

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

#: Generous ceiling for JVM boot + import + full auto-analysis (which populates the stack frame).
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: import a stack-using blob, run full
# auto-analysis (the Stack analyzer populates the frame + creates the function), then `stack_frame`.
# Ends with an explicit flush + os._exit(0) so a lingering JVM thread never blocks shutdown.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    base = 0x401000
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "frame.bin")
    # push rbp; mov rbp,rsp; mov dword[rbp-4],5; mov eax,[rbp-4]; pop rbp; ret  (a real stack local)
    with open(path, "wb") as handle:
        handle.write(bytes.fromhex("554889e5c745fc050000008b45fc5dc3"))

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": path, "loader": "binary", "processor": "x86:LE:64:default",
         "base_addr": base, "entry": base}
    )
    backend.analyze({"profile": "default"})  # the Stack analyzer populates the frame + makes the fn
    return backend.stack_frame({"function": hex(base)})


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
    """Build the container-run argv that drives the stack-frame read in ``image``.

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


def test_stack_frame_recovers_a_local_on_real_worker(worker_image: str) -> None:
    """``stack_frame`` returns the Stack analyzer's recovered variables after analysis (ADR-054).

    Drives the in-container backend: import a stack-using blob, ``session_analyze``, then
    ``stack_frame``. Asserts a recovered local exists at a negative frame offset with size 4 (the
    ``mov [rbp-4],5`` variable) and that ``frame_size`` is set. A regression re-surfaces as
    ``ok=False`` or an empty frame.

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
            f"stack_frame run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"stack_frame reported failure (ADR-054 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    assert int(data.get("frame_size", 0)) > 0, f"expected a non-zero frame_size; got {data!r}"
    variables = data.get("variables", [])
    assert variables, f"expected >=1 recovered stack variable after analysis; got {data!r}"

    # The `mov [rbp-4],5` local: a negative-offset variable of size 4.
    locals_size4 = [
        v for v in variables if int(v.get("stack_offset", 0)) < 0 and int(v.get("size", 0)) == 4
    ]
    assert locals_size4, f"expected a size-4 local at a negative offset; got {variables!r}"
