"""In-worker Boost FID match validation (ADR-043 Inc E — the minimal-analysis DB gate).

Runs INSIDE the worker image (PyGhidra/JVM), NOT under pytest. It answers the one question the
`--minimal-analysis` Boost DB raises: does a DB built with REDUCED analysis (decompiler + DWARF +
reference/data passes disabled, to dodge the mid-analysis "flush() with locks!" on the large C++
object) still MATCH a Boost consumer analyzed NORMALLY (full analysis, as `identify_functions`
does at query time)? FID full-hashes derive from instruction bytes within a function boundary, so
they SHOULD be analysis-depth-independent — this proves it instead of assuming it.

Asymmetry under test: the bundled ``boost.fidbf`` was built minimal; here the consumer at
``/work/input.bin`` is opened with ``analyze=True`` (FULL). A non-empty, Boost-named match set
means the minimal-built DB is sound and B is the real fix.

Method (mirrors ``fid_selfmatch_inworker.py`` but attaches a PRE-BUILT bundled DB instead of
generating one): copy the packed ``.fidbf`` to writable tmpfs (``addUserFidFile`` needs a writable
packed path), attach + activate, open+analyze the consumer, query it against the active DB. Prints
``BOOST-MATCH PASS n=<count>`` + samples and exits 0 on >=1 Boost match; exits 1 otherwise.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

_BIN = os.environ.get("BOOST_CONSUMER", "/work/input.bin")
_SRC_DB = os.environ.get("BOOST_FIDBF", "/opt/vivarium/fid/boost.fidbf")
_DB = "/tmp/ghidra/boost.fidbf"  # noqa: S108 — writable tmpfs scratch (rootfs is read-only)


def main() -> int:
    """Attach the bundled Boost DB, full-analyze the consumer, and assert a non-empty match."""
    import pyghidra

    pyghidra.start(verbose=False)

    from ghidra.feature.fid.db import FidFileManager  # type: ignore[import-not-found]
    from ghidra.feature.fid.service import FidService  # type: ignore[import-not-found]
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import-not-found]
    from java.io import File  # type: ignore[import-not-found]

    # Attach the PRE-BUILT bundled DB. addUserFidFile needs a writable packed path → copy first.
    Path("/tmp/ghidra").mkdir(parents=True, exist_ok=True)  # noqa: S108
    shutil.copyfile(_SRC_DB, _DB)
    mgr = FidFileManager.getInstance()
    svc = FidService()
    monitor = ConsoleTaskMonitor()
    fidfile = mgr.addUserFidFile(File(_DB))
    if fidfile is None:
        print(f"BOOST-MATCH ERROR: addUserFidFile returned None for {_DB}", flush=True)
        return 1
    fidfile.setActive(True)

    # Open + FULL-analyze the consumer (analyze=True) — the asymmetry vs the minimal-built DB.
    with pyghidra.open_program(
        _BIN, project_location="/work/project", project_name="boostmatch", analyze=True
    ) as flat:
        program = flat.getCurrentProgram()
        qs = mgr.openFidQueryService(program.getLanguage(), False)
        threshold = float(svc.getDefaultScoreThreshold())
        rows = []
        for search_result in svc.processProgram(program, qs, threshold, monitor):
            for match in search_result.matches:
                lib = match.getLibraryRecord()
                rows.append(
                    {
                        "address": str(search_result.function.getEntryPoint().toString()),
                        "matched_name": str(match.getFunctionRecord().getName()),
                        "library": str(lib.getLibraryFamilyName()),
                        "score": float(match.getOverallScore()),
                    }
                )

    boost_rows = [r for r in rows if "boost" in str(r["library"]).lower()]
    for r in boost_rows[:25]:
        print(f"  match: {r}", flush=True)
    print(f"total matches={len(rows)} boost-library matches={len(boost_rows)}", flush=True)
    if boost_rows:
        print(f"BOOST-MATCH PASS n={len(boost_rows)}", flush=True)
        return 0
    print("BOOST-MATCH FAIL n=0 (minimal-analysis DB did not match the consumer)", flush=True)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover - JVM edge; surface + fail
        print(f"BOOST-MATCH ERROR: {type(exc).__name__}: {exc}", flush=True)
        sys.exit(1)
