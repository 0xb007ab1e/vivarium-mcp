"""Integration: `data_flow_slice` returns a real def-use slice on a live worker (ADR-064).

The HighFunction def-use walk is the JVM/PyGhidra edge (TB3, ADR-001) — `# pragma: no cover` in the
worker and only validatable against a real Ghidra worker. Gating + fixture posture mirror
``test_set_function_signature.py``: ``integration``-marked (the default unit run SKIPS it), runs
only when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No
malware —
the analyzed input is a benign in-image OS utility (master §5).

Honored environment (same as the other gated integration tests):
    * ``VIVARIUM_INTEGRATION`` — truthy enables the suite (see conftest).
    * ``VIVARIUM_WORKER_IMAGE`` — the pinned-by-digest worker image (conftest fixture).
    * ``VIVARIUM_CONTAINER_ENGINE`` — container CLI (default ``podman``).
    * ``VIVARIUM_INTEGRATION_TARGET`` — in-image ELF to analyze (default ``/bin/true``).
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
_TARGET_ENV = "VIVARIUM_INTEGRATION_TARGET"
_DEFAULT_TARGET = "/bin/true"
_SRC_MOUNT_ENV = "VIVARIUM_WORKER_SRC_MOUNT"
_RUN_TIMEOUT_SECONDS = 300
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

# Driver: import -> analyze -> pick the largest function -> get_high_pcode -> take a BACKWARD slice
# from each of the first few ops (union must be non-empty on a real function) + one FORWARD slice.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
TARGET = os.environ.get("VIVARIUM_INTEGRATION_TARGET", "/bin/true")


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    backend.import_binary({"source_ref": TARGET, "expected_sha256": None})
    backend.analyze({"timeout_seconds": 180})

    rows = backend.list_functions({"offset": 0, "limit": 100}).get("functions") or []
    if not rows:
        raise RuntimeError("no functions found")
    target = max(rows, key=lambda r: int(r.get("size") or 0))["address"]

    ops = (backend.get_high_pcode({"function": target, "max_ops": 200}).get("ops") or [])
    if not ops:
        raise RuntimeError("no high p-code for the target function")

    # Backward-slice from each of the first ops; the union of nodes must be non-empty on a real fn.
    backward_nodes = 0
    roles = set()
    for op in ops[:8]:
        sl = backend.data_flow_slice(
            {"function": target, "seed": op["address"], "direction": "backward",
             "max_nodes": 64, "max_depth": 32}
        )
        backward_nodes += len(sl.get("nodes") or [])
        for n in (sl.get("nodes") or []):
            roles.add(n.get("role"))

    forward = backend.data_flow_slice(
        {"function": target, "seed": ops[0]["address"], "direction": "forward",
         "max_nodes": 64, "max_depth": 32}
    )
    return {
        "backward_node_total": backward_nodes,
        "roles": sorted(roles),
        "forward_direction": forward.get("direction"),
        "forward_is_list": isinstance(forward.get("nodes"), list),
    }


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


def _build_command(engine: str, image: str, target: str) -> list[str]:
    """Build the network-isolated container-run argv driving the slice in ``image``."""
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
        f"{_TARGET_ENV}={target}",
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


def test_data_flow_slice_on_real_worker(worker_image: str) -> None:
    """A backward def-use slice over a real function must return non-empty def/boundary nodes.

    Drives the in-container backend: import → analyze → pick the largest function → get its high
    p-code → backward-slice from the first ops (the union must be non-empty; a real function's ops
    have defining ops and/or parameter/constant boundary inputs) → one forward slice. A regression
    in the HighFunction def-use walk surfaces here as ``ok=False`` or an empty union.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    target = os.environ.get(_TARGET_ENV, "").strip() or _DEFAULT_TARGET
    cmd = _build_command(engine, worker_image, target)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"data_flow_slice run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"data_flow_slice reported failure (ADR-064 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert int(data.get("backward_node_total") or 0) >= 1, (
        f"expected >=1 backward def-use node across the function's ops; got {data!r}"
    )
    assert set(data.get("roles") or []) <= {"def", "use", "boundary"}, f"unexpected roles: {data!r}"
    assert data.get("forward_direction") == "forward", (
        f"forward slice did not echo direction: {data!r}"
    )
    assert data.get("forward_is_list") is True, f"forward nodes not a list: {data!r}"
