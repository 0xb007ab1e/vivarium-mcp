"""Integration: fat/universal Mach-O slice selection via loader='macho' + processor (ADR-048).

`open_program` always loads a fat binary's default slice; ADR-048 uses the lower-level
`pyghidra.program_loader()` builder to select a specific arch slice by `LanguageID`. This gate
builds a two-slice fat Mach-O (arm64 + x86_64) in-container and imports each slice via `macho` +
`processor`, asserting the *selected* architecture loads (not just the default). It also confirms
the loaded program is usable for a follow-up query (program_metadata) — proving the builder-path
lifecycle keeps the program alive.

Gating mirrors the other import gates. The input is a tiny synthetic, benign fat Mach-O (master §5).
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

_DRIVER = r"""
import json, os, struct, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"


def _macho(cputype, cpusub, code):
    seg_size = 72
    data_off = 32 + seg_size
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, cpusub, 2, 1, seg_size, 0, 0)
    seg = struct.pack(
        "<II16sQQQQiiII", 0x19, seg_size, b"__TEXT".ljust(16, b"\0"),
        0x100000000, 0x1000, data_off, len(code), 7, 5, 0, 0,
    )
    return hdr + seg + code


def _fat():
    a = _macho(0x0100000C, 0, b"\x1f\x20\x03\xd5" * 4)  # arm64
    x = _macho(0x01000007, 3, b"\x90" * 8)              # x86_64
    hsz = 8 + 2 * 20
    oa = (hsz + 0xFFF) & ~0xFFF
    ox = (oa + len(a) + 0xFFF) & ~0xFFF
    fat = (
        struct.pack(">II", 0xCAFEBABE, 2)
        + struct.pack(">iiIII", 0x0100000C, 0, oa, len(a), 12)
        + struct.pack(">iiIII", 0x01000007, 3, ox, len(x), 12)
    )
    b = bytearray(ox + len(x))
    b[: len(fat)] = fat
    b[oa : oa + len(a)] = a
    b[ox : ox + len(x)] = x
    return bytes(b)


def _load(path, processor, projdir):
    # Each load gets its OWN project dir — one import per session/worker is the real flow; two loads
    # into one Ghidra project would collide on the project lock. Point the worker store at projdir.
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    os.makedirs(projdir, exist_ok=True)
    os.environ["VIVARIUM_WORKER_PROJECT_DIR"] = projdir
    backend = PyGhidraBackend()
    backend.import_binary({"source_ref": path, "loader": "macho", "processor": processor})
    md = backend.program_metadata({})  # follow-up query proves the loaded program is usable
    return {"format": md.get("format"), "architecture": md.get("architecture")}


def main():
    base = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(base, "u.fat")
    with open(path, "wb") as f:
        f.write(_fat())
    return {
        "arm64": _load(path, "AARCH64:LE:64:AppleSilicon", os.path.join(base, "a")),
        "x86_64": _load(path, "x86:LE:64:default", os.path.join(base, "b")),
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
    """Build the container-run argv that drives the fat-slice imports in ``image``."""
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


def test_macho_fat_slice_selection_on_real_worker(worker_image: str) -> None:
    """A two-slice fat Mach-O must load the slice named by `processor` (ADR-048).

    Selecting ``AARCH64:...`` loads the arm64 slice; ``x86:LE:64:default`` loads the x86_64 slice —
    proving `program_loader` slice selection (which `open_program` cannot do) and that the loaded
    program survives for a follow-up `program_metadata` query.

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
            f"fat-slice import timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"fat-slice import failed (ADR-048 regression?): {env.get('error')!r}\n"
        f"{env.get('traceback', '')[-2000:]}"
    )
    data = env["data"]
    assert str(data["arm64"]["architecture"]).startswith("AARCH64"), (
        f"arm64 slice: {data['arm64']!r}"
    )
    assert str(data["x86_64"]["architecture"]).startswith("x86"), (
        f"x86_64 slice: {data['x86_64']!r}"
    )
    # The selected slice differs from the default — proves selection actually happened.
    assert data["arm64"]["architecture"] != data["x86_64"]["architecture"]
