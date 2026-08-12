"""Integration: self-describing container formats — Mach-O + DEX (ADR-047).

The existing `auto` (opinion) path already detects Mach-O and Android DEX from their headers;
ADR-047 adds explicit `loader="macho"`/`loader="dex"` to *force* the loader. This gate proves BOTH
paths on a real worker (auto-detect and forced) — the capability shipped untested (the F1 docs
wrongly said "auto = ELF/PE only"), and this pins it.

Gating mirrors the other import gates: `integration`-marked, real worker image + engine. The inputs
are tiny synthetic, benign Mach-O / DEX files the driver builds in-container (master §5) — no real
app bytes.
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

# In-container driver: build a minimal ARM64 Mach-O + an empty DEX, then load each via BOTH the auto
# path (no loader hint) and the forced loader, reporting the detected format + architecture.
_DRIVER = r"""
import hashlib, json, os, struct, sys, traceback, zlib

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def macho_arm64():
    code = b"\x1f\x20\x03\xd5" * 4  # ARM64 NOPs
    seg_size = 72
    data_off = 32 + seg_size
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, seg_size, 0, 0)
    seg = struct.pack(
        "<II16sQQQQiiII", 0x19, seg_size, b"__TEXT".ljust(16, b"\0"),
        0x100000000, 0x1000, data_off, len(code), 7, 5, 0, 0,
    )
    return hdr + seg + code


def dex_empty():
    fields = [0x70, 0x70, 0x12345678] + [0] * 17  # file_size, header_size, endian_tag, then zeros
    rest = struct.pack("<20I", *fields)
    sig = hashlib.sha1(rest).digest()  # noqa: S324 — DEX spec header field, not a security digest
    after = sig + rest
    cksum = zlib.adler32(after) & 0xFFFFFFFF
    return b"dex\n035\0" + struct.pack("<I", cksum) + after


def _load(path, loader=None):
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    params = {"source_ref": path}
    if loader:
        params["loader"] = loader
    backend.import_binary(params)
    md = backend.program_metadata({})
    return {"format": md.get("format"), "architecture": md.get("architecture")}


def main():
    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    macho_path = os.path.join(project_dir, "t.macho")
    dex_path = os.path.join(project_dir, "t.dex")
    with open(macho_path, "wb") as f:
        f.write(macho_arm64())
    with open(dex_path, "wb") as f:
        f.write(dex_empty())
    return {
        "macho_auto": _load(macho_path),
        "macho_forced": _load(macho_path, "macho"),
        "dex_auto": _load(dex_path),
        "dex_forced": _load(dex_path, "dex"),
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


def _build_command(engine: str, image: str) -> list[str]:
    """Build the container-run argv that drives the self-describing imports in ``image``."""
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


def test_selfdescribing_macho_and_dex_on_real_worker(worker_image: str) -> None:
    """Mach-O + DEX must load via BOTH the auto path and the forced loader (ADR-047).

    Asserts each of the four loads (macho/dex, each auto + forced) is recognized as the right
    format, with the expected architecture family.

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
            f"self-describing import timed out after {_RUN_TIMEOUT_SECONDS}s "
            f"(engine={engine}, image={worker_image})\n--- stderr tail ---\n{captured[-2000:]}"
        )

    if proc.returncode != 0:
        pytest.fail(
            f"worker run exited {proc.returncode} (engine={engine}, image={worker_image})\n"
            f"--- stderr tail ---\n{proc.stderr[-2000:]}\n"
            f"--- stdout tail ---\n{proc.stdout[-1000:]}"
        )

    env = _parse_marker_json(proc.stdout)
    assert env.get("ok") is True, (
        f"self-describing import failed (ADR-047 regression?): {env.get('error')!r}\n"
        f"{env.get('traceback', '')[-2000:]}"
    )
    data = env["data"]
    for key in ("macho_auto", "macho_forced"):
        assert "Mach-O" in str(data[key]["format"]), f"{key}: not Mach-O: {data[key]!r}"
        assert str(data[key]["architecture"]).startswith("AARCH64"), f"{key}: {data[key]!r}"
    for key in ("dex_auto", "dex_forced"):
        assert "DEX" in str(data[key]["format"]), f"{key}: not DEX: {data[key]!r}"
        assert str(data[key]["architecture"]).startswith("Dalvik"), f"{key}: {data[key]!r}"
