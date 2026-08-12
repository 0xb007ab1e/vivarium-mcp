"""Integration: raw/headerless binary import applies against a real worker (ADR-045, F1).

Regression + capability gate for the loader-hint feature: ``session_import`` with
``loader="binary"`` must drive Ghidra's ``BinaryLoader`` with an allow-listed ``processor``
``LanguageID`` and rebase a headerless image to ``base_addr`` — the bare-metal firmware case the
v1.8 external run could not load (finding F1).

Why a gated in-container test (not a unit test): the ``BinaryLoader`` + ``setImageBase`` call is the
JVM/PyGhidra edge (TB3, ADR-001) — excluded from server unit coverage and only validatable against a
real Ghidra worker. Gating + fixture posture are reused verbatim from
``test_set_function_signature.py``: ``integration``-marked (the default unit run SKIPS it), runs
only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No real
malware — the analyzed input is a tiny **synthetic Thumb code blob** the driver writes in-container
(master §5).

Honored environment (same as ``test_set_function_signature.py``):
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

#: Generous ceiling for JVM boot + BinaryLoader + the rebase write.
_RUN_TIMEOUT_SECONDS = 300

#: Sentinel framing the single JSON result line on stdout, so the parser ignores JVM/Ghidra noise.
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: The raw import parameters the driver applies + the test asserts against.
_PROCESSOR = "ARM:LE:32:Cortex"
_BASE_ADDR = 0x10000000

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: write a tiny headerless Thumb blob (NOPs +
# `bx lr`) to the writable tmpfs, import it with loader='binary' + processor + base_addr (the exact
# ADR-045 raw path), then read program_metadata + memory_map to prove the language was applied and
# the image was rebased. Prints one marker-prefixed JSON line and self-reports failures.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "ARM:LE:32:Cortex")
BASE_ADDR = int(os.environ.get("VIVARIUM_DRIVER_BASE_ADDR", "0x10000000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    # A tiny headerless Thumb blob: eight NOP (0xbf00 -> 00 bf) then BX LR (0x4770 -> 70 47).
    blob = b"\x00\xbf" * 8 + b"\x70\x47"
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "raw_fw.bin")
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
            # Seed an entry at the base (first instruction) so the addExternalEntryPoint branch
            # (ADR-045) is exercised live — a throw there surfaces as ok=False.
            "entry": BASE_ADDR,
        }
    )
    out["metadata"] = backend.program_metadata({})
    out["memory_map"] = backend.memory_map({})
    # Regression for #292: read_bytes must return the ACTUAL loaded bytes (not a silent zero-fill).
    # The first 8 bytes at base are the first four Thumb NOPs -> "00bf" x4.
    out["read_bytes"] = backend.read_bytes({"address": hex(BASE_ADDR), "length": 8})
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
    """Build the container-run argv that drives the raw import in ``image``.

    Mirrors ``test_set_function_signature.py``'s posture exactly (network-isolated, capped memory,
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


def test_raw_binary_import_applies_on_real_worker(worker_image: str) -> None:
    """A headerless raw image must load via ``BinaryLoader`` at the requested language + base.

    Drives the in-container backend: write a tiny Thumb blob → import with ``loader="binary"``,
    ``processor="ARM:LE:32:Cortex"``, ``base_addr=0x10000000`` → read metadata + memory map. Asserts
    the program's architecture matches the requested ``LanguageID`` (BinaryLoader used it) and a
    memory block starts at ``base_addr`` (the image was rebased) — a regression re-surfaces here as
    ``ok=False`` or a mismatched architecture/base instead of silently passing.

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
            f"raw import run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"raw import reported failure (ADR-045 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]

    # BinaryLoader honored the requested LanguageID.
    architecture = str(data.get("metadata", {}).get("architecture") or "")
    assert architecture == _PROCESSOR, (
        f"expected architecture {_PROCESSOR!r} (BinaryLoader used the hint); got {architecture!r}"
    )

    # The image was rebased to base_addr — some memory block starts there.
    blocks = data.get("memory_map", {}).get("blocks") or []
    starts = {str(b.get("start")) for b in blocks}
    expected_start = format(_BASE_ADDR, "08x")
    assert any(expected_start in s for s in starts), (
        f"expected a memory block at base_addr {hex(_BASE_ADDR)} (image rebased); "
        f"got block starts {sorted(starts)!r}"
    )

    # Regression for #292: read_bytes returns the ACTUAL loaded bytes, not a silent zero-fill.
    read = data.get("read_bytes", {})
    assert read.get("data") == "00bf00bf00bf00bf", (
        f"read_bytes did not return the loaded Thumb bytes (#292 zero-fill regression?); "
        f"got {read!r}"
    )
    assert read.get("truncated") is False, (
        f"read_bytes over mapped memory should not truncate: {read!r}"
    )
