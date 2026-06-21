"""In-worker FID self-match validation (ADR-042 Phase 1 inner-loop + Phase 2 SPIKE-1).

Runs INSIDE the hardened worker image (PyGhidra/JVM), NOT under pytest — the pytest wrapper
``test_identify_functions_selfmatch.py`` invokes it via ``podman run --entrypoint python``. It is
the only hermetic way (no MSVC binary, no shipped DB, no licensing) to exercise two things real
Ghidra is required for:

1. **The ``identify_functions`` inner match loop** — the ``# pragma: no cover`` getters
   (``FidSearchResult.function``/``.matches`` → ``FidMatch.getFunctionRecord().getName()`` /
   ``.getLibraryRecord().get*`` / ``.getOverallScore()``) on a NON-EMPTY result, which the empty
   ELF-vs-MSVC-DB test in ``test_identify_functions_fid.py`` cannot reach.
2. **Phase-2 SPIKE-1** — that a custom ``.fidb`` can be built, attached, and ACTIVATED headlessly
   (``createNewFidDatabase`` → ``addUserFidFile`` → ingest → re-attach → ``setActive``), the
   technical precondition for ELF FID-database coverage.

Method: open+analyze the mounted binary (``/work/input.bin``), ingest its OWN named functions into a
throwaway FID DB, re-attach it (the file caches "no languages" if attached while empty — must
re-add after populating), then query the program against it. A function that is big enough to clear
FID's minimum-hash length self-matches. Prints ``SELF-MATCH PASS n=<count>`` and exits 0 on success;
exits 1 with ``SELF-MATCH FAIL`` otherwise. Fail-soft on JVM errors (printed; exit 1).

No copyleft/licensing concern: the DB is derived from the test's own benign micro-binary.
"""

from __future__ import annotations

import sys

_BIN = "/work/input.bin"
_DB = "/tmp/ghidra/self.fidb"  # noqa: S108 — the worker's writable tmpfs scratch (read-only rootfs)


def main() -> int:
    """Build a self-FID-DB from the mounted binary and assert it self-matches. Return 0 on PASS."""
    import jpype
    import pyghidra

    pyghidra.start(verbose=False)

    from java.io import File  # type: ignore[import-not-found]
    from java.util import ArrayList  # type: ignore[import-not-found]

    with pyghidra.open_program(
        _BIN, project_location="/work/project", project_name="selfmatch", analyze=True
    ) as flat:
        program = flat.getCurrentProgram()
        from ghidra.feature.fid.db import FidFileManager  # type: ignore[import-not-found]
        from ghidra.feature.fid.service import FidService  # type: ignore[import-not-found]
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import-not-found]

        mgr = FidFileManager.getInstance()
        svc = FidService()
        monitor = ConsoleTaskMonitor()
        dbfile = File(_DB)

        # Build an empty DB, attach it, open for update, and ingest the program's named functions.
        mgr.createNewFidDatabase(dbfile)
        fidfile = mgr.addUserFidFile(dbfile)
        fiddb = fidfile.getFidDB(True)

        # Include every function (a JProxy is untyped-decorator-free, unlike @JImplements).
        include_all = jpype.JProxy("java.util.function.Predicate", dict={"test": lambda _t: True})

        domain_files = ArrayList()
        domain_files.add(program.getDomainFile())  # createNewLibraryFromPrograms wants DomainFiles
        result = svc.createNewLibraryFromPrograms(
            fiddb,
            "selflib",
            "1.0",
            "test",
            domain_files,
            include_all,
            program.getLanguageID(),
            ArrayList(),
            ArrayList(),
            monitor,
        )
        print(
            f"ingest: added={result.getTotalAdded()} attempted={result.getTotalAttempted()}",
            flush=True,
        )
        fiddb.saveDatabase("self-ingest", monitor)
        fiddb.close()

        # The FidFile cached "no languages" when attached to the empty DB → canProcessLanguage()
        # would be False and the query service would skip it. Re-attach the now-populated DB so its
        # language registration refreshes, then activate it.
        mgr.removeUserFile(fidfile)
        fidfile = mgr.addUserFidFile(dbfile)
        fidfile.setActive(True)

        # Query the program against the active DBs (the same call identify_functions makes), and
        # shape matches exactly as `_jvm_bridge._gh_identify_functions` does.
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
                        "library": (
                            f"{lib.getLibraryFamilyName()} {lib.getLibraryVersion()} "
                            f"{lib.getLibraryVariant()}"
                        ),
                        "score": float(match.getOverallScore()),
                    }
                )

    for r in rows[:25]:
        print(f"  match: {r}", flush=True)
    if rows:
        print(f"SELF-MATCH PASS n={len(rows)}", flush=True)
        return 0
    print(
        "SELF-MATCH FAIL n=0 (no self-matches — ingest/activation/threshold regression)", flush=True
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover - JVM edge; surface + fail
        print(f"SELF-MATCH ERROR: {type(exc).__name__}: {exc}", flush=True)
        sys.exit(1)
