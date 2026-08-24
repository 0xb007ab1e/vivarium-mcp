"""Integration: companion debug-map (`debug_ref`) symbol application on a real worker (ADR-071).

Regression + capability gate for the ``session_import`` ``debug_ref``/``debug_format="map"`` path:
Ghidra loads the ELF (auto loader), then the worker's ``_apply_debug`` creates one label per
``(name, address)`` parsed from the companion symbol map. Proven live:

    * write a synthetic ARM ELF whose sole function is at ``0x10054`` plus a one-line ``.map``
      naming that address; import with ``debug_ref``/``debug_format="map"``, analyze, then
      ``list_symbols`` shows the map-supplied name. A regression in ``_apply_debug`` re-surfaces as
      ``ok=False`` or the name never appearing.

Why a gated in-container test (not a unit test): ``_apply_debug`` (Ghidra label creation on a
loaded program) is the JVM/PyGhidra edge (TB3, ADR-001) — excluded from server unit coverage and
only validatable against a real Ghidra worker; the pure ``core.debugmap`` parser and the server
wiring (pair rule, loader='auto', pdb mutual-exclusion) are covered by unit tests. DWARF is
DEFERRED (ADR-071, fixture-blocked); only ``map`` is exercised here. Gating + fixture posture
mirror ``test_import_pdb.py``: ``integration``-marked (the default unit run SKIPS it), runs only
when ``VIVARIUM_INTEGRATION`` is truthy AND a real worker image + engine are available. No real
malware — the inputs are a tiny synthetic ELF + a text map written in-container (master §5).

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
_RUN_TIMEOUT_SECONDS = 360
_MARKER = "VIVARIUM_INTEGRATION_RESULT:"

#: The name the driver puts in the companion map and the test asserts got applied.
_MAP_SYMBOL = "vivarium_dbg_sym"
#: The synthetic ARM ELF's sole code address (its ELF ``e_entry`` / ``.text`` vaddr).
_MAP_ADDRESS = 0x10054

#: The same 239-byte synthetic ARM ELF used by ``test_version_track.py`` (self-contained; the
#: ``tests`` tree is NOT in the worker image). It loads as ``ARM:LE:32`` with ``.text`` at 0x10054.
_ARM_ELF_HEX = (
    "7f454c4601010100000000000000000002002800010000005400010034000000770000000002000534002000010028"
    "000300020001000000000000000000010000000100ef000000ef00000005000000001000"
    "0000bf00bf00bf00bf00bf00bf00bf00bf7047002e74657874002e73687374727461620000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000"
    "0600000054000100540000001200000000000000000000000200000000000000070000000300000000000000000000"
    "00660000001100000000000000000000000100000000000000"
)

# --- the in-container driver ---------------------------------------------------------------------
# Runs as `python -c <DRIVER>` INSIDE the worker image: write the ELF + a one-line symbol map naming
# 0x10054, import with debug_ref/debug_format=map, analyze, then list_symbols and report whether the
# map-supplied name is present.
_DRIVER = (
    r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
ARM_ELF = bytes.fromhex("__ARM_ELF_HEX__")
MAP_SYMBOL = "__MAP_SYMBOL__"
MAP_ADDRESS = int("__MAP_ADDRESS__", 0)


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    elf_path = os.path.join(project_dir, "sym.elf")
    map_path = os.path.join(project_dir, "sym.map")
    with open(elf_path, "wb") as handle:
        handle.write(ARM_ELF)
    with open(map_path, "w") as handle:
        handle.write("{:08x} {}\n".format(MAP_ADDRESS, MAP_SYMBOL))

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": elf_path, "debug_ref": map_path, "debug_format": "map"}
    )
    backend.analyze({"timeout_seconds": 120})

    names = []
    offset = 0
    while True:
        page = backend.list_symbols({"offset": offset, "limit": 200}) or {}
        syms = page.get("symbols") or []
        if not syms:
            break
        names.extend(str(s.get("name")) for s in syms)
        if len(syms) < 200:
            break
        offset += len(syms)
    return {"applied": MAP_SYMBOL in names, "symbol_count": len(names)}


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
    .replace("__MAP_SYMBOL__", _MAP_SYMBOL)
    .replace("__MAP_ADDRESS__", hex(_MAP_ADDRESS))
)


def _engine() -> str:
    """Return the configured container engine binary name (default ``podman``)."""
    return os.environ.get(_ENGINE_ENV, "").strip() or _DEFAULT_ENGINE


def _engine_available(engine: str) -> bool:
    """Return whether the container engine binary is resolvable on ``PATH``."""
    return shutil.which(engine) is not None


def _build_command(engine: str, image: str, driver: str = _DRIVER) -> list[str]:
    """Build the network-isolated container-run argv driving the debug-map import in ``image``."""
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
    """Extract + parse the single marker-prefixed JSON object from ``stdout``."""
    lines = [ln for ln in stdout.splitlines() if ln.startswith(_MARKER)]
    assert lines, f"no {_MARKER!r} line found in worker stdout:\n{stdout[-2000:]}"
    payload = lines[-1][len(_MARKER) :]
    try:
        parsed: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive: marker present but corrupt
        raise AssertionError(f"marker payload was not valid JSON: {exc}\n{payload!r}") from exc
    return parsed


def test_debug_map_symbol_applied_on_real_worker(worker_image: str) -> None:
    """A companion ``.map`` symbol must be applied to the loaded ELF as a resolvable label.

    Drives the in-container backend: write a synthetic ARM ELF + a one-line symbol map naming its
    code address, import with ``debug_ref``/``debug_format="map"``, analyze, then enumerate symbols.
    Asserts ``ok`` and that the map-supplied name is present. A regression in ``_apply_debug``
    re-surfaces as ``ok=False`` or the name never appearing among the program's symbols.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image, _DRIVER)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"debug-map import run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"debug-map import reported failure (ADR-071 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    data = envelope["data"]
    assert data.get("applied") is True, (
        f"map symbol {_MAP_SYMBOL!r} was not applied to the program "
        f"(symbol_count={data.get('symbol_count')!r}): {data!r}"
    )


# --- ADR-071 detached-DWARF apply --------------------------------------------------------------
# A 1016-byte stripped x86-64 ELF carrying a `.gnu_debuglink` -> "dw.debug", plus its 2800-byte
# detached DWARF (accumulate@0x4000f0, scale_and_add@0x400110). The worker stages the .debug next to
# the binary under the debuglink name, and Ghidra's DWARF analyzer applies the names at analysis
# time. Built with:
#   gcc -g -Og -fno-pie -no-pie -nostdlib -nostartfiles -e entry -Wl,-N,--build-id=none \
#       -Wl,-z,noseparate-code -o dw small.c && objcopy --only-keep-debug dw dw.debug &&
#   objcopy --strip-all dw && objcopy --add-gnu-debuglink=dw.debug dw
_DW_STRIPPED_HEX = (
    "7f454c4602010100000000000000000002003e00010000001f014000000000004000000000000000380200000000"
    "0000000000004000380003004000070006000100000007000000f000000000000000f000400000000000f0004000"
    "00000000d400000000000000d400000000000000100000000000000050e57464040000003c010000000000003c01"
    "4000000000003c0140000000000024000000000000002400000000000000040000000000000051e5746406000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000"
    "00000000000000000000b800000000ba00000000eb0d0f1f40004863c803148f83c00139f07cf389d0c38d047f8d"
    "14f50000000029f201d0c355534889fde8c7ffffff89c38b75048b7d00e8daffffff01d85b5dc300011b033b2000"
    "000003000000b4ffffff3c000000d4ffffff50000000e3ffffff640000001400000000000000017a520001781001"
    "1b0c070890010000100000001c00000070ffffff200000000000000010000000300000007cffffff0f0000000000"
    "0000200000004400000077ffffff1c00000000410e108602410e188303580e10410e080000004743433a20284465"
    "6269616e2031342e322e302d3139292031342e322e30000064772e646562756700000000554f52ed002e73687374"
    "72746162002e74657874002e65685f6672616d655f686472002e65685f6672616d65002e636f6d6d656e74002e67"
    "6e755f64656275676c696e6b00000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000b0000000100000007000000"
    "00000000f000400000000000f0000000000000004b00000000000000000000000000000010000000000000000000"
    "000000000000110000000100000002000000000000003c014000000000003c010000000000002400000000000000"
    "0000000000000000040000000000000000000000000000001f000000010000000200000000000000600140000000"
    "00006001000000000000640000000000000000000000000000000800000000000000000000000000000029000000"
    "0100000030000000000000000000000000000000c4010000000000001f0000000000000000000000000000000100"
    "0000000000000100000000000000320000000100000000000000000000000000000000000000e401000000000000"
    "10000000000000000000000000000000040000000000000000000000000000000100000003000000000000000000"
    "00000000000000000000f40100000000000041000000000000000000000000000000010000000000000000000000"
    "00000000"
)
_DW_DEBUG_HEX = (
    "7f454c4602010100000000000000000002003e00010000001f014000000000004000000000000000f00600000000"
    "000000000000400038000300400010000f0001000000070000000000000000000000f000400000000000f0004000"
    "000000000000000000000000d400000000000000100000000000000050e5746404000000f0000000000000003c01"
    "4000000000003c0140000000000000000000000000002400000000000000040000000000000051e5746406000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000"
    "00004743433a202844656269616e2031342e322e302d3139292031342e322e30002c000000020000000000080000"
    "000000f0004000000000004b00000000000000000000000000000000000000000000003901000005000108000000"
    "00060b0000001d0000000008000000f0004000000000004b0000000000000000000000027200000003059c000000"
    "1f014000000000001c00000000000000019c9c00000003760010a3000000120000000c000000036e00169c000000"
    "2900000025000000072901400000000000e10000008e00000004015502760004015403a301540008360140000000"
    "0000a900000000090405696e74000a089c0000000264000000021f9c00000010014000000000000f000000000000"
    "00019ce100000001780002319c000000015501790002379c0000000154000b0000000001011f9c000000f0004000"
    "000000002000000000000000019c017600012fa30000000155016e0001359c00000001540574003c9c0000003b00"
    "0000370000000c0c000000056900489c0000004b0000004700000000000001050003083a21013b0b390b49130218"
    "0000022e013f19030e3a21013b0b390b271949131101120740187a190113000003050003083a21013b2103390b49"
    "130217b74217000004490002187e18000005340003083a21013b2101390b49130217b742170000061101250e130b"
    "031f1b1f11011207101700000748017d017f13011300000848007d017f1300000924000b0b3e0b030800000a0f00"
    "0b0b491300000b2e013f19030e3a0b3b0b390b271949131101120740187a1900000c0b015517000000c000000005"
    "0008002a000000010101fb0e0d00010101010000000100000101011f010800000002011f020f0200000000000000"
    "0000000537000902f0004000000000000105380105400105440105480601053c580540582e055400020403064a05"
    "580002040306010555000204033c055100020403063c054d000204013c055c000204044a056506012e0539062105"
    "3a010542060105463c05449005492e0518062106010519065805200601580530000204012e052f00020402ac0549"
    "2e2e0201000101616363756d756c61746500474e55204331372031342e322e30202d6d74756e653d67656e657269"
    "63202d6d617263683d7838362d3634202d67202d4f67202d666e6f2d706965202d666173796e6368726f6e6f7573"
    "2d756e77696e642d7461626c6573007363616c655f616e645f61646400656e74727900736d616c6c2e63002f746d"
    "702f766669782f647761726666697800530000000500080000000000000000000000042f38015504384a0156044a"
    "4b04a301559f0000000000042f38015404384b04a301549f000200000004000c02309f040c200151000400000004"
    "000c02309f040c1f0150000f0000000500080000000000040005040a1d0000000000000000000000000000000000"
    "0000000000000000010000000400f1ff00000000000000000000000000000000000000000400f1ff000000000000"
    "0000000000000000000009000000000002003c0140000000000000000000000000001c000000120001001f014000"
    "000000001c000000000000002200000012000100f00040000000000020000000000000002d000000120001001001"
    "4000000000000f000000000000003b00000010000300c40140000000000000000000000000004700000010000300"
    "c40140000000000000000000000000004e00000010000300c801400000000000000000000000000000736d616c6c"
    "2e63005f5f474e555f45485f4652414d455f48445200656e74727900616363756d756c617465007363616c655f61"
    "6e645f616464005f5f6273735f7374617274005f6564617461005f656e6400002e73796d746162002e7374727461"
    "62002e7368737472746162002e74657874002e65685f6672616d655f686472002e65685f6672616d65002e636f6d"
    "6d656e74002e64656275675f6172616e676573002e64656275675f696e666f002e64656275675f61626272657600"
    "2e64656275675f6c696e65002e64656275675f737472002e64656275675f6c696e655f737472002e64656275675f"
    "6c6f636c69737473002e64656275675f726e676c6973747300000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "1b000000080000000700000000000000f000400000000000f0000000000000004b00000000000000000000000000"
    "000010000000000000000000000000000000210000000800000002000000000000003c01400000000000f0000000"
    "0000000024000000000000000000000000000000040000000000000000000000000000002f000000080000000200"
    "0000000000006001400000000000f000000000000000640000000000000000000000000000000800000000000000"
    "0000000000000000390000000100000030000000000000000000000000000000e8000000000000001f0000000000"
    "00000000000000000000010000000000000001000000000000004200000001000000000000000000000000000000"
    "00000000070100000000000030000000000000000000000000000000010000000000000000000000000000005100"
    "0000010000000000000000000000000000000000000037010000000000003d010000000000000000000000000000"
    "010000000000000000000000000000005d0000000100000000000000000000000000000000000000740200000000"
    "0000c3000000000000000000000000000000010000000000000000000000000000006b0000000100000000000000"
    "0000000000000000000000003703000000000000c400000000000000000000000000000001000000000000000000"
    "000000000000770000000100000030000000000000000000000000000000fb030000000000007800000000000000"
    "00000000000000000100000000000000010000000000000082000000010000003000000000000000000000000000"
    "000073040000000000001b0000000000000000000000000000000100000000000000010000000000000092000000"
    "01000000000000000000000000000000000000008e04000000000000570000000000000000000000000000000100"
    "0000000000000000000000000000a20000000100000000000000000000000000000000000000e504000000000000"
    "13000000000000000000000000000000010000000000000000000000000000000100000002000000000000000000"
    "00000000000000000000f804000000000000f0000000000000000e00000004000000080000000000000018000000"
    "00000000090000000300000000000000000000000000000000000000e80500000000000053000000000000000000"
    "00000000000001000000000000000000000000000000110000000300000000000000000000000000000000000000"
    "3b06000000000000b200000000000000000000000000000001000000000000000000000000000000"
)

_DRIVER_DWARF = r"""
import json, os, sys, traceback

MARKER = "VIVARIUM_INTEGRATION_RESULT:"
STRIPPED = bytes.fromhex("__DW_STRIPPED_HEX__")
DEBUG = bytes.fromhex("__DW_DEBUG_HEX__")


def main():
    from vivarium.ghidra._jvm_bridge import PyGhidraBackend

    project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")
    bin_path = os.path.join(project_dir, "dw.stripped")
    dbg_path = os.path.join(project_dir, "companion.debug")  # arbitrary name/path (server-confined)
    with open(bin_path, "wb") as h:
        h.write(STRIPPED)
    with open(dbg_path, "wb") as h:
        h.write(DEBUG)

    backend = PyGhidraBackend()
    backend.import_binary(
        {"source_ref": bin_path, "debug_ref": dbg_path, "debug_format": "dwarf"}
    )
    backend.analyze({"timeout_seconds": 120})
    names = []
    offset = 0
    while True:
        page = backend.list_functions({"offset": offset, "limit": 200}) or {}
        rows = page.get("functions") or []
        if not rows:
            break
        names.extend(str(f.get("name")) for f in rows)
        if len(rows) < 200:
            break
        offset += len(rows)
    return {"names": [n for n in names if n in ("accumulate", "scale_and_add")]}


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
""".replace("__DW_STRIPPED_HEX__", _DW_STRIPPED_HEX).replace("__DW_DEBUG_HEX__", _DW_DEBUG_HEX)


def test_debug_dwarf_applied_on_real_worker(worker_image: str) -> None:
    """A detached DWARF (`debug_format="dwarf"`) must recover function names via the analyzer.

    Drives the in-container backend: write a stripped x86-64 ELF (with a `.gnu_debuglink`) + its
    detached `.debug`, import with `debug_ref`/`debug_format="dwarf"`, analyze. The worker stages
    the debug next to the binary under the debuglink name and Ghidra's DWARF analyzer applies it, so
    `accumulate` + `scale_and_add` appear as named functions. A regression in the stage/parse path
    re-surfaces as `ok=False` or the names missing.

    Args:
        worker_image: The pinned worker image reference (conftest fixture; skips if unset).
    """
    engine = _engine()
    if not _engine_available(engine):
        pytest.skip(f"container engine {engine!r} not found on PATH (set {_ENGINE_ENV})")

    cmd = _build_command(engine, worker_image, _DRIVER_DWARF)

    try:
        proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine + image are operator-set.
            cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        captured = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        pytest.fail(
            f"dwarf import run timed out after {_RUN_TIMEOUT_SECONDS}s "
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
        f"dwarf import reported failure (ADR-071 regression?): {envelope.get('error')!r}\n"
        f"{envelope.get('traceback', '')[-2000:]}"
    )
    names = envelope["data"].get("names") or []
    assert "accumulate" in names and "scale_and_add" in names, (
        f"expected DWARF-recovered function names; got {names!r}"
    )
