"""Integration: Intel-HEX firmware import via the named hex loader (ADR-046).

`session_import` with `loader="intel-hex"` must drive Ghidra's `IntelHexLoader` with an allow-listed
`processor` and load the records at the addresses they carry (no `base_addr` needed). This is the
hex-delivered-firmware path — the format many MCU vendors ship before you ever have a raw `.bin`.

Gating + posture mirror `test_import_raw_binary.py`: `integration`-marked, runs only when
`VIVARIUM_INTEGRATION` is truthy with a real worker image + engine. The input is a synthetic, benign
Intel-HEX the driver generates in-container (master §5). `motorola-hex` uses the identical worker
code path (`_open_named_loader`) and is covered by the unit + validation tests.
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
_PROCESSOR = "ARM:LE:32:Cortex"

# In-container driver: build a minimal Intel-HEX carrying a Thumb blob at 0x0, import it via
# loader='intel-hex' + processor, then read metadata + memory map + the first bytes.
_DRIVER = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def _ihex(data, addr=0):
    rec = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, 0x00]) + data
    cks = (-sum(rec)) & 0xFF
    return ":" + (rec + bytes([cks])).hex().upper() + "\n:00000001FF\n"


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    blob = b"\x00\xbf" * 8 + b"\x70\x47"  # eight Thumb NOPs then BX LR
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "fw.hex")
    with open(path, "w") as handle:
        handle.write(_ihex(blob))

    backend = PyGhidraBackend()
    out = {}
    out["import"] = backend.import_binary(
        {"source_ref": path, "loader": "intel-hex", "processor": "ARM:LE:32:Cortex"}
    )
    out["metadata"] = backend.program_metadata({})
    out["memory_map"] = backend.memory_map({})
    out["read_bytes"] = backend.read_bytes({"address": "0x0", "length": 8})
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


def _build_command(engine: str, image: str) -> list[str]:
    """Build the container-run argv that drives the Intel-HEX import in ``image``."""
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
    """Extract and parse the single marker-prefixed JSON object from ``stdout``."""
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line found in worker stdout:\n{stdout[-2000:]}"
    payload = lines[-1][len(_MARKER) :]
    try:
        parsed: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive: marker present but corrupt
        raise AssertionError(f"marker payload was not valid JSON: {exc}\n{payload!r}") from exc
    return parsed


def test_intel_hex_import_on_real_worker(worker_image: str) -> None:
    """An Intel-HEX image must load via ``IntelHexLoader`` at the record addresses (ADR-046).

    Asserts the import succeeded, the architecture is the requested one, a block sits at the record
    address (0x0), and ``read_bytes`` returns the actual loaded bytes.

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
            f"intel-hex import timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"intel-hex import reported failure (ADR-046 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    architecture = str(data.get("metadata", {}).get("architecture") or "")
    assert architecture == _PROCESSOR, (
        f"expected architecture {_PROCESSOR!r} (IntelHexLoader used the hint); got {architecture!r}"
    )
    starts = {str(b.get("start")) for b in (data.get("memory_map", {}).get("blocks") or [])}
    assert any("00000000" in s for s in starts), (
        f"expected a memory block at the record address 0x0; got {sorted(starts)!r}"
    )
    read = data.get("read_bytes", {})
    assert read.get("data") == "00bf00bf00bf00bf", (
        f"read_bytes did not return the loaded Thumb bytes; got {read!r}"
    )
