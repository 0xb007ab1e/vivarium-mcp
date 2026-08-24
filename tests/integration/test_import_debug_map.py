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


def _build_command(engine: str, image: str) -> list[str]:
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

    cmd = _build_command(engine, worker_image)

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
