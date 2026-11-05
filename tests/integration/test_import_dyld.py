"""Integration: dyld shared-cache component import on a real worker (ADR-086, #369).

Capability gate for ``session_import`` ``loader="dyld"`` (ADR-086): mount a dyld shared cache with
Ghidra's ``DyldCacheFileSystem``, extract one component dylib, and import it as Mach-O. This builds
a deterministic, benign synthetic cache in-container (one tiny ``MH_DYLIB`` component), then
exercises both flows:

* **extract** — import with ``dyld_component`` set → the component loads via
  ``DyldCacheExtractLoader`` (``program_metadata`` format names DYLD; ``memory_map`` shows its
  ``__TEXT`` segment);
* **discovery** — import with ``dyld_component`` omitted → the worker fails closed with a listing
  that names the component path.

This closes the fixture gap ADR-063 deferred dyld on (hermetic, gated-testable). No real system
cache — a synthetic one-dylib cache built in-container (master §5).

``integration``-marked (the default unit run SKIPS it); runs only when ``VIVARIUM_INTEGRATION`` is
truthy AND a real worker image + engine are available.

This test is added to the live-regression hard-gate list only at the worker **repin** (the pinned
worker must carry the ADR-086 code first — the worker-change-validation-recipe).

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

_COMPONENT = "/usr/lib/libviv.dylib"

_DRIVER = r"""
import json, os, struct, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
COMPONENT = "__COMPONENT__"
DYLD_BASE = 0x7FFF00000000


def _minimal_macho_dylib(install_name, vmaddr, fileoff, vmsize):
    # Minimal x86-64 MH_DYLIB: header + __TEXT segment + LC_ID_DYLIB.
    mh_magic_64, cpu_x86_64, cpu_sub, mh_dylib = 0xFEEDFACF, 0x01000007, 3, 0x6
    lc_segment_64, lc_id_dylib = 0x19, 0xD
    namez = install_name.encode() + b"\x00"
    idcmd_size = (24 + len(namez) + 7) // 8 * 8
    idcmd = struct.pack("<IIIIII", lc_id_dylib, idcmd_size, 24, 0, 0x10000, 0x10000) + namez
    idcmd += b"\x00" * (idcmd_size - len(idcmd))
    seg = struct.pack(
        "<II16sQQQQIIII", lc_segment_64, 72, b"__TEXT", vmaddr, vmsize, fileoff, vmsize, 5, 5, 0, 0
    )
    cmds = seg + idcmd
    hdr = struct.pack("<IiiIIIII", mh_magic_64, cpu_x86_64, cpu_sub, mh_dylib, 2, len(cmds), 0, 0)
    return hdr + cmds


def _build_cache(component_path, base_address):
    # One mapping covering the file from offset 0 at base; one image whose address = base + macho
    # file offset (getMacho reads a component at imageAddress - baseAddress, a LINEAR model).
    macho_foff = 0x2000
    magic = b"dyld_v1  x86_64"
    magic += b"\x00" * (16 - len(magic))
    hdr_size = 0x100
    map_off, map_cnt = hdr_size, 1
    img_off, img_cnt = map_off + 32, 1
    path_off = img_off + 32
    path = component_path.encode() + b"\x00"
    file_size = macho_foff + 0x1000
    hdr = bytearray(hdr_size)
    hdr[0:16] = magic
    struct.pack_into("<IIIIQ", hdr, 16, map_off, map_cnt, img_off, img_cnt, base_address)
    mapping = struct.pack("<QQQII", base_address, file_size, 0, 5, 5)
    image_addr = base_address + macho_foff
    image = struct.pack("<QQQII", image_addr, 0, 0, path_off, 0)
    out = bytearray(file_size)
    out[0:hdr_size] = hdr
    out[map_off : map_off + 32] = mapping
    out[img_off : img_off + 32] = image
    out[path_off : path_off + len(path)] = path
    macho = _minimal_macho_dylib(component_path, image_addr, macho_foff, 0x1000)
    out[macho_foff : macho_foff + len(macho)] = macho
    return bytes(out)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    path = os.path.join(project_dir, "dyld_shared_cache_test")
    with open(path, "wb") as handle:
        handle.write(_build_cache(COMPONENT, DYLD_BASE))

    backend = PyGhidraBackend()

    # Discovery: omitting dyld_component fails closed with a listing naming the component.
    disco_err = None
    try:
        backend.import_binary({"source_ref": path, "loader": "dyld"})
    except Exception as exc:
        disco_err = str(exc)

    # Extract: name the component → it loads as Mach-O.
    backend.import_binary({"source_ref": path, "loader": "dyld", "dyld_component": COMPONENT})
    backend.analyze({"timeout_seconds": 120})
    meta = backend.program_metadata({})
    blocks = backend.memory_map({}).get("blocks") or []
    fmt = str(meta.get("format", ""))
    return {
        "disco_lists_component": disco_err is not None and COMPONENT in disco_err,
        "format": fmt,
        # DyldCacheExtractLoader reports "Extracted DYLD Component" — proof the component was
        # materialized THROUGH the cache loader (not a plain-file open, which Ghidra refuses).
        "loaded_via_dyld": "dyld" in fmt.lower(),
        "has_text": any("__TEXT" in str(b.get("name", "")) for b in blocks),
    }


try:
    result = {"ok": True, "data": main()}
except Exception as exc:  # surface ANY failure as a parseable, fail-closed envelope.
    result = {"ok": False, "error": "{}: {}".format(type(exc).__name__, exc),
              "traceback": traceback.format_exc()}

sys.stdout.write("\n" + MARKER + json.dumps(result) + "\n")
sys.stdout.flush()
os._exit(0)
""".replace("__COMPONENT__", _COMPONENT)


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


def test_dyld_component_import_on_real_worker(worker_image: str) -> None:
    """``loader="dyld"`` extracts a component dylib and loads it as Mach-O (ADR-086).

    Builds a synthetic one-component dyld cache, imports the component with ``dyld_component``, and
    asserts it loads via ``DyldCacheExtractLoader`` (``program_metadata`` format + the ``__TEXT``
    segment). Also asserts that omitting ``dyld_component`` fails closed with a listing that names
    the component. A regression re-surfaces as the import failing or the component listing missing.

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
            f"dyld import run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"dyld import reported failure (ADR-086 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert data.get("loaded_via_dyld") is True, (
        "expected the component to load via DyldCacheExtractLoader (format names DYLD); "
        f"got format={data.get('format')!r}"
    )
    assert data.get("has_text") is True, (
        f"expected the component's __TEXT segment in the memory map; got {data!r}"
    )
    assert data.get("disco_lists_component") is True, (
        f"expected omitting dyld_component to fail closed with a listing naming {_COMPONENT!r}; "
        f"got {data!r}"
    )
