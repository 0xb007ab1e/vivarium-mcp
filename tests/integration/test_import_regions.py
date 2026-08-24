"""Integration: multi-region (scatter-load) raw import on a real worker (ADR-065, v1.9 regions).

Regression + capability gate for the ``session_import`` ``regions`` path: Ghidra opens ONE program
at a shared processor ``LanguageID`` via ``BinaryLoader``, drops the loader's default block, and
creates one initialized memory block per region at its ``base_addr`` from ``path[offset:length]``.
Proven live:

    * write one 32-byte blob; import it as TWO regions at disjoint base addresses
      (``0x1000`` and ``0x400000``); ``memory_map`` then shows exactly the two blocks at those two
      bases (the scatter-load produced N blocks from one image). A regression in
      ``_gh_import_regions`` re-surfaces as ``ok=False`` or the wrong block set.

Why a gated in-container test (not a unit test): the multi-block build (``BinaryLoader`` open +
``Memory.createInitializedBlock`` per region inside one transaction) is the JVM/PyGhidra edge (TB3,
ADR-001) — excluded from server unit coverage and only validatable against a real Ghidra worker.
The server-side validation (confinement, size caps, overlap rejection) is covered by unit tests;
this drives the worker directly with server-resolved region dicts. Gating + fixture posture mirror
``test_import_raw_binary.py``: ``integration``-marked (the default unit run SKIPS it), runs only
when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No real
malware — the input is a tiny synthetic blob written in-container (master §5).

Honored environment (same as ``test_import_raw_binary.py``):
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

#: Shared processor + the two region base addresses the driver applies and the test asserts.
_PROCESSOR = "x86:LE:64:default"
_BASE_A = 0x1000
_BASE_B = 0x400000

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: write one 32-byte blob, import it as two
# regions (server-resolved dicts {source_ref, offset, length, base_addr}) at two disjoint bases,
# then read memory_map to prove the scatter-load produced the two blocks.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
PROCESSOR = os.environ.get("VIVARIUM_DRIVER_PROCESSOR", "x86:LE:64:default")
BASE_A = int(os.environ.get("VIVARIUM_DRIVER_BASE_A", "0x1000"), 0)
BASE_B = int(os.environ.get("VIVARIUM_DRIVER_BASE_B", "0x400000"), 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    # A 32-byte blob (x86-64 `ret` = 0xC3 padding); the bytes are irrelevant to block creation.
    blob = b"\xc3" * 32
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "scatter.bin")
    with open(path, "wb") as handle:
        handle.write(blob)

    backend = PyGhidraBackend()
    out = {}
    out["import"] = backend.import_binary(
        {
            "source_ref": path,
            "processor": PROCESSOR,
            "regions": [
                {"source_ref": path, "offset": 0, "length": 16, "base_addr": BASE_A},
                {"source_ref": path, "offset": 16, "length": 16, "base_addr": BASE_B},
            ],
        }
    )
    out["memory_map"] = backend.memory_map({})
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
    """Build the network-isolated container-run argv driving the scatter-load in ``image``."""
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


def _block_start_int(start: str) -> int:
    """Parse a Ghidra memory-block ``start`` address string (hex, possibly space/name-qualified)."""
    token = start.strip().split()[-1].split(":")[-1]
    return int(token, 16)


def test_import_regions_scatter_load_on_real_worker(worker_image: str) -> None:
    """A two-region scatter-load must produce exactly two blocks at the two requested bases.

    Drives the in-container backend: write one blob, import it as two regions at ``0x1000`` and
    ``0x400000``, then read ``memory_map``. Asserts ``ok`` and that the block set's start addresses
    are exactly the two requested bases (the loader's default whole-file block was dropped and
    one block was created per region). A regression in ``_gh_import_regions`` re-surfaces as
    ``ok=False`` or a mismatched block set.

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
            f"import-regions run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"multi-region import reported failure (ADR-065 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    blocks = envelope["data"]["memory_map"]["blocks"]
    starts = {_block_start_int(b["start"]) for b in blocks}
    assert starts == {_BASE_A, _BASE_B}, (
        f"expected exactly two region blocks at {_BASE_A:#x} and {_BASE_B:#x}; "
        f"got blocks {[b['start'] for b in blocks]!r}"
    )
