"""Integration: lz4-compressed Android ramdisk on a real worker (ADR-088, #414).

Capability gate for `container_region="ramdisk"` with an **lz4** ramdisk (ADR-088): both the
**legacy** lz4 frame (`02 21 4c 18` — the common Android format, decoded via the pure
`core.lz4legacy` framing parser + `lz4.block`) and the **standard** lz4 frame (`04 22 4d 18` — via
`lz4.frame`). It builds two Android boot images whose ramdisk is an lz4 cpio containing an
`init.rc` with a marker string, imports each with `container_region="ramdisk"`, and asserts the
marker is recovered by `list_strings` (slice → lz4-decode → raw cpio load).

`integration`-marked (the default unit run SKIPS it); runs only when `VIVARIUM_INTEGRATION` is
truthy AND a real worker image + engine are available. The worker image must carry the `lz4`
dependency (ADR-088) — so this is validated against a freshly-built worker, not the pre-ADR-088 pin.
No real malware — tiny synthetic boot images built in-container (master §5).

This test is added to the live-regression hard-gate list only at the worker **repin** (the pinned
worker must carry the ADR-088 code + the lz4 dep first — the worker-change-validation-recipe).

Honored environment (same as the other gated integration tests):
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

_RAMDISK_MARKER = "VIVARIUM_LZ4_RAMDISK_MARKER"

_DRIVER = r"""
import json, os, struct, sys, traceback
import lz4.block, lz4.frame

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
PAGE = 2048
RAMDISK_MARKER = "__RAMDISK_MARKER__"


def _cpio_newc(name, data):
    def f(v):
        return b"%08x" % v

    def pad4(b):
        return b + b"\x00" * ((-len(b)) % 4)

    def entry(nm, payload, mode):
        namez = nm.encode() + b"\x00"
        hdr = (b"070701" + f(1) + f(mode) + f(0) + f(0) + f(1) + f(0) + f(len(payload))
               + f(0) + f(0) + f(0) + f(0) + f(len(namez)) + f(0))
        return pad4(hdr + namez) + pad4(payload)

    return entry(name, data, 0o100644) + entry("TRAILER!!!", b"", 0)


def _lz4_legacy(data):
    # Legacy lz4 frame: magic + [u32 compressed_size][block] (one <=8 MiB block here).
    block = lz4.block.compress(data, store_size=False)
    return b"\x02\x21\x4c\x18" + struct.pack("<I", len(block)) + block


def _build_android_boot(kernel, ramdisk, page):
    hdr = struct.pack(
        "<8sIIIIIIIIII16s512s32s1024s",
        b"ANDROID!", len(kernel), 0x10008000, len(ramdisk), 0x11000000, 0, 0, 0x100, page, 0, 0,
        b"itest", b"", b"", b"",
    )

    def pad(b):
        return b + b"\x00" * (((len(b) + page - 1) // page) * page - len(b))

    return pad(hdr) + pad(kernel) + pad(ramdisk)


def _recover_marker(backend, project_dir, name, ramdisk):
    image = _build_android_boot(b"\x90" * 64, ramdisk, PAGE)
    path = os.path.join(project_dir, name)
    with open(path, "wb") as handle:
        handle.write(image)
    backend.import_binary(
        {"source_ref": path, "container": "androidboot", "container_region": "ramdisk",
         "loader": "binary", "processor": "x86:LE:64:default", "base_addr": 0x0, "entry": 0x0}
    )
    backend.analyze({"timeout_seconds": 120})
    strings = backend.list_strings({"offset": 0, "limit": 500}).get("strings") or []
    texts = [str(s.get("value", "")) for s in strings]
    return any(RAMDISK_MARKER in t for t in texts)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    cpio = _cpio_newc("init.rc", ("on boot\n    start " + RAMDISK_MARKER + "\n").encode())

    legacy = _recover_marker(PyGhidraBackend(), project_dir, "boot_legacy.img", _lz4_legacy(cpio))
    standard = _recover_marker(
        PyGhidraBackend(), project_dir, "boot_std.img", lz4.frame.compress(cpio)
    )
    return {"legacy_marker": legacy, "standard_marker": standard}


try:
    result = {"ok": True, "data": main()}
except Exception as exc:  # surface ANY failure as a parseable, fail-closed envelope.
    result = {"ok": False, "error": "{}: {}".format(type(exc).__name__, exc),
              "traceback": traceback.format_exc()}

sys.stdout.write("\n" + MARKER + json.dumps(result) + "\n")
sys.stdout.flush()
os._exit(0)
""".replace("__RAMDISK_MARKER__", _RAMDISK_MARKER)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str) -> list[str]:
    """Build the network-isolated container-run argv driving the in-container driver."""
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


def test_lz4_ramdisk_on_real_worker(worker_image: str) -> None:
    """Both lz4 frame formats surface the ramdisk's content for string triage (ADR-088).

    Builds boot images whose ramdisk is a **legacy** lz4 cpio and a **standard** lz4 cpio, each
    containing an ``init.rc`` with a marker, imports with ``container_region="ramdisk"``, then
    asserts
    the marker is recovered by ``list_strings`` (slice → lz4-decode → raw cpio load). A regression
    re-surfaces as the marker missing or the import failing.

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
            f"lz4 ramdisk run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"lz4 ramdisk reported failure (ADR-088 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert data.get("legacy_marker") is True, (
        f"expected the marker recovered from the LEGACY lz4 ramdisk; got {data!r}"
    )
    assert data.get("standard_marker") is True, (
        f"expected the marker recovered from the STANDARD lz4 ramdisk; got {data!r}"
    )
