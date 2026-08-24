"""Integration: function-granularity `binary_diff` on a real worker (ADR-067, v1.9 binary_diff).

Regression + capability gate for the ``binary_diff`` tool: Ghidra loads TWO binaries fresh in one
worker, analyzes each, pairs functions by name, and reports added/removed/changed. Proven live:

    * write two IDENTICAL synthetic ARM ELFs; ``binary_diff(a, b, match_by="name")`` returns an
      empty diff — ``summary.added == summary.removed == summary.changed == 0`` and all three entry
      lists empty (identical programs have no deltas). A regression in the two-program load / pair /
      compare pipeline re-surfaces as ``ok=False`` or a spurious non-zero delta.

Why a gated in-container test (not a unit test): the diff pipeline (two fresh domain-file loads +
two auto-analyses + the name-pairing comparison over the loaded programs) is the JVM/PyGhidra edge
(TB3, ADR-001) — excluded from server unit coverage and only validatable against a real Ghidra
worker. Gating + fixture posture are reused verbatim from ``test_version_track.py``:
``integration``-marked (the default unit run SKIPS it), runs only when ``VIVARIUM_INTEGRATION`` is
truthy AND a real worker image + engine are available. No real malware — the inputs are two copies
of a tiny synthetic ARM ELF.

Honored environment (same as ``test_version_track.py``):
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

#: Generous ceiling for JVM boot + TWO imports + TWO auto-analyses + the diff.
_RUN_TIMEOUT_SECONDS = 420

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: A 239-byte synthetic ARM ELF (from ``tests/_fixtures/binaries.synthetic_arm32_elf`` — embedded
#: so the in-container driver is self-contained; the ``tests`` tree is NOT in the worker image).
#: Ghidra analyzes it into ``ARM:LE:32:v8`` with one function; two copies diff to nothing.
_ARM_ELF_HEX = (
    "7f454c4601010100000000000000000002002800010000005400010034000000770000000002000534002000010028"
    "000300020001000000000000000000010000000100ef000000ef00000005000000001000"
    "0000bf00bf00bf00bf00bf00bf00bf00bf7047002e74657874002e73687374727461620000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000"
    "0600000054000100540000001200000000000000000000000200000000000000070000000300000000000000000000"
    "00660000001100000000000000000000000100000000000000"
)

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: write two identical ELFs, then diff them
# by name. Ends with an explicit flush + os._exit(0) — the two-program pipeline's non-daemon JVM
# threads otherwise keep the process alive and lose buffered stdout.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
ARM_ELF = bytes.fromhex("__ARM_ELF_HEX__")


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path_a = os.path.join(project_dir, "a.bin")
    path_b = os.path.join(project_dir, "b.bin")
    for path in (path_a, path_b):
        with open(path, "wb") as handle:
            handle.write(ARM_ELF)

    backend = PyGhidraBackend()
    return backend.binary_diff(
        {
            "program_a": path_a,
            "program_b": path_b,
            "match_by": "name",
            "max_entries": 100,
        }
    )


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
""".replace("__ARM_ELF_HEX__", _ARM_ELF_HEX)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the network-isolated container-run argv driving the diff in ``image``.

    Mirrors ``test_version_track.py``'s posture exactly (network-isolated, capped memory,
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


def test_binary_diff_identical_programs_on_real_worker(worker_image: str) -> None:
    """``binary_diff`` of two identical programs must report an empty diff (no false deltas).

    Drives the in-container backend: write two identical synthetic ARM ELFs, then
    ``binary_diff(a, b, match_by="name")``. Asserts ``ok`` and that every category count and entry
    list is empty — two byte-identical programs have no added/removed/changed functions. A
    regression in the two-program load / name-pairing / comparison pipeline re-surfaces as
    ``ok=False`` (e.g. the throwaway-project load lifecycle breaking) or a spurious non-zero delta.

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
    except subprocess.TimeoutExpired as exc:  # don't hang the suite — fail with what we captured.
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"binary_diff run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"binary_diff reported failure (ADR-067 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    summary = data.get("summary") or {}
    assert int(summary.get("added", -1)) == 0, f"identical programs added a function: {data!r}"
    assert int(summary.get("removed", -1)) == 0, f"identical programs removed a function: {data!r}"
    assert int(summary.get("changed", -1)) == 0, f"identical programs changed a function: {data!r}"
    assert (data.get("added") or []) == [], f"non-empty added list on identical inputs: {data!r}"
    assert (data.get("removed") or []) == [], (
        f"non-empty removed list on identical inputs: {data!r}"
    )
    assert (data.get("changed") or []) == [], (
        f"non-empty changed list on identical inputs: {data!r}"
    )
