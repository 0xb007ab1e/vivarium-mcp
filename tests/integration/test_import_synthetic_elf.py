"""Integration: a clean synthetic 32-bit ARM ELF imports + analyzes on a real worker (v1.8 F5).

F5 investigated the report that a *readelf-clean, section-bearing* 32-bit ARM/RISC-V ELF failed to
import (with no surfaced cause). Reproduction on current HEAD (post-F4, so the worker exception is
now diagnosable) shows a clean synthetic ARM ET_EXEC **imports and analyzes correctly** — the
failure does not reproduce for the primary case. This test pins that as a **positive regression
gate**: the synthetic ARM ELF fixture (``tests/_fixtures/binaries.synthetic_arm32_elf``) must import
via the AUTO loader, be recognized as ARM, and yield a function — so any future regression in the
32-bit ARM container path (the original F5 symptom) is caught in CI.

Gating + fixture posture mirror ``test_import_raw_binary.py`` / ``test_set_function_signature.py``:
``integration``-marked, runs only when ``VIVARIUM_INTEGRATION`` is truthy with a real worker image +
engine. No real malware — the input is a synthetic, benign ELF built in-process (master §5); the
worker receives it as base64 so the test is self-contained (no ``tests/`` inside the pinned image).
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from typing import Any

import pytest

from tests._fixtures import binaries

pytestmark = pytest.mark.integration

_ENGINE_ENV = "VIVARIUM_CONTAINER_ENGINE"
_DEFAULT_ENGINE = "podman"
_SRC_MOUNT_ENV = "VIVARIUM_WORKER_SRC_MOUNT"
_RUN_TIMEOUT_SECONDS = 300
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"
_ELF_B64_PLACEHOLDER = "__ELF_B64__"

# --- the in-container driver ---------------------------------------------------------------------
# Decodes the base64 synthetic ARM ELF, writes it to the writable tmpfs, imports it via the AUTO
# loader (no loader hint — the exact F5 path), analyzes, and reports metadata + function count.
_DRIVER = r"""
import base64, json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
BLOB = base64.b64decode("__ELF_B64__")


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "synth_arm32.elf")
    with open(path, "wb") as handle:
        handle.write(BLOB)

    backend = PyGhidraBackend()
    out = {}
    out["import"] = backend.import_binary({"source_ref": path})  # AUTO path — the F5 case
    out["analyze"] = backend.analyze({"timeout_seconds": 120})
    out["metadata"] = backend.program_metadata({})
    return out


try:
    result = {"ok": True, "data": main()}
except Exception as exc:
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


def _build_command(engine: str, image: str, driver: str) -> list[str]:
    """Build the container-run argv that drives the synthetic-ELF import in ``image``.

    Args:
        engine: The container engine binary.
        image: The worker image reference.
        driver: The fully-rendered driver source (ELF already inlined as base64).

    Returns:
        The full argv list.
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
    cmd += ["--entrypoint", "python", image, "-c", driver]
    return cmd


def _parse_marker_json(stdout: str) -> dict[str, Any]:
    """Extract and parse the single marker-prefixed JSON object from ``stdout``."""
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line found in worker stdout:\n{stdout[-2000:]}"
    payload = lines[-1][len(_MARKER) :]
    try:
        parsed: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive: marker present but corrupt
        raise AssertionError(f"marker payload was not valid JSON: {exc}\n{payload!r}") from exc
    return parsed


def test_synthetic_arm32_elf_imports_on_real_worker(worker_image: str) -> None:
    """A readelf-clean synthetic 32-bit ARM ELF must import + analyze via the AUTO loader (F5).

    Builds the fixture, ships it to the worker as base64, and drives import → analyze → metadata.
    Asserts the import succeeded, the architecture is recognized as ARM, and at least one function
    is present — the positive regression gate for the 32-bit ARM container path.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    elf_b64 = base64.b64encode(binaries.synthetic_arm32_elf()).decode("ascii")
    driver = _DRIVER.replace(_ELF_B64_PLACEHOLDER, elf_b64)
    cmd = _build_command(engine, worker_image, driver)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"synthetic-ELF import timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"synthetic ARM ELF failed to import (F5 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    metadata = envelope["data"]["metadata"]
    assert "ELF" in str(metadata.get("format") or ""), f"not recognized as ELF: {metadata!r}"
    assert str(metadata.get("architecture") or "").startswith("ARM"), (
        f"expected an ARM architecture; got {metadata.get('architecture')!r}"
    )
    assert int(metadata.get("function_count") or 0) >= 1, (
        f"expected >=1 recovered function in the synthetic ARM ELF; got {metadata!r}"
    )
