#!/usr/bin/env python3
"""Build a packed ELF FunctionID database (``.fidbf``) from a library binary (ADR-043 Phase 2).

Runs INSIDE the hardened worker image (PyGhidra/JVM), driven by the gated build stage (the PM /
``Containerfile.worker`` build stage) — NOT under pytest and NOT from the server (ADR-001 isolation;
the server never loads the JVM). It analyzes a reference library binary (built unstripped, WITH
symbols, from pinned-by-digest source) and runs the PROVEN generate+pack recipe (ADR-043 D2,
``tests/integration/fid_selfmatch_inworker.py`` is the reference), then writes BOTH the packed
``.fidbf`` AND a sibling provenance manifest JSON (``std-supplychain`` D4).

Generate+pack recipe (PyGhidra, in-worker):

1. open + analyze the input → ``program``;
2. ``FidFileManager.getInstance().createNewFidDatabase(File(unpacked))`` →
   ``addUserFidFile(File(unpacked))`` → ``getFidDB(True)`` (open for update);
3. ``FidService().createNewLibraryFromPrograms(fidDb, family, version, variant,
   [program.getDomainFile()], <JProxy java.util.function.Predicate→True>, program.getLanguageID(),
   [], [], monitor)`` → ``saveDatabase(comment, monitor)`` → ``close()``;
4. reopen READ-ONLY (``fidFile.getFidDB(False)``, no open transaction) →
   ``PackedDatabase.packDatabase(fidDb.getDBHandle(), name, "FunctionID Database", File(packed),
   monitor)`` → the packed ``.fidbf``.

The packed ``.fidbf`` is the distribution format (the raw ``createNewFidDatabase`` output is NOT).
It holds only non-reversible hashes + symbol names + library metadata, **no library code/source**
(ADR-043 / docs/security/fid-database-licensing.md).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

#: Version of THIS generator script, recorded in the provenance manifest (D4 reproducibility). Bump
#: on any change to the generate+pack recipe so a DB's provenance pins the exact generator version.
GENERATOR_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class LibraryMeta:
    """Library metadata for the generated FID library + provenance manifest (ADR-043 D4).

    Attributes:
        family: FID library family name (e.g. ``zlib``) — appears in ``identify_functions`` matches.
        version: Upstream library version/tag (e.g. ``1.3.1``).
        variant: Build variant tag (e.g. ``x86-64-static``) distinguishing same-version builds.
        license_spdx: The source library's SPDX license id (e.g. ``Zlib``). Gated by the license
            allow-list (ADR-043 D5); recorded in the manifest + SBOM.
        source_digest: Optional ``sha256:...`` digest of the source tarball/commit (provenance).
        compiler: Optional compiler id + version (e.g. ``gcc 13.2.0``) for reproducibility.
        compiler_flags: Optional compiler flags string used to build the reference binary.
        source_name: Optional human source name override (defaults to ``family``).
    """

    family: str
    version: str
    variant: str
    license_spdx: str
    source_digest: str | None = None
    compiler: str | None = None
    compiler_flags: str | None = None
    source_name: str | None = None


def _sha256_file(path: Path) -> str:
    """Return the ``sha256:<hex>`` digest of a file (streaming; bounded memory).

    Args:
        path: The file to digest.

    Returns:
        The digest as ``sha256:<hex>``.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def build_manifest(
    meta: LibraryMeta,
    *,
    fidbf_path: Path,
    ghidra_version: str,
    language_id: str,
    function_count: int,
    now: datetime.datetime | None = None,
) -> dict[str, object]:
    """Build the provenance manifest dict for a generated ``.fidbf`` (pure; D4 / SPIKE-2 §4).

    Records source identity + version + digest, build inputs (compiler/flags/Ghidra/generator), the
    target language, the resulting ``.fidbf`` digest, and the SPDX license — so the DB is a pinned,
    attested, reproducible artifact (``std-supplychain``). Includes the "hashes + names, no code"
    disclaimer on the record (SPIKE-2 §4).

    Args:
        meta: The library metadata.
        fidbf_path: Path to the packed ``.fidbf`` (digested for the manifest).
        ghidra_version: The Ghidra version that generated the DB (pinned image — ADR-003).
        language_id: The Ghidra ``LanguageID`` the DB targets (processor-specific — ADR-043 D7).
        function_count: Number of functions ingested into the library (best-effort provenance).
        now: Injected timestamp (defaults to ``datetime.datetime.now(UTC)``) — for deterministic
            tests (topic-numeric-correctness: injected clock, UTC).

    Returns:
        A JSON-serializable provenance manifest dict.
    """
    when = now or datetime.datetime.now(datetime.UTC)
    return {
        "schema": "vivarium.fid.provenance/1",
        "source": {
            "name": meta.source_name or meta.family,
            "version": meta.version,
            "digest": meta.source_digest,
            "license_spdx": meta.license_spdx,
        },
        "build": {
            "compiler": meta.compiler,
            "compiler_flags": meta.compiler_flags,
            "ghidra_version": ghidra_version,
            "generator_version": GENERATOR_VERSION,
            "built_at": when.isoformat(),
        },
        "library": {
            "family": meta.family,
            "version": meta.version,
            "variant": meta.variant,
            "language_id": language_id,
            "function_count": function_count,
        },
        "artifact": {
            "fidbf": fidbf_path.name,
            "fidbf_digest": _sha256_file(fidbf_path),
        },
        "disclaimer": (
            "This FunctionID database contains only non-reversible function-body hashes, lifted "
            "symbol names, and library metadata. It contains no library code or source "
            "(see docs/security/fid-database-licensing.md)."
        ),
    }


def manifest_path_for(fidbf_path: Path) -> Path:
    """Return the sibling provenance-manifest path for a ``.fidbf`` (``<name>.provenance.json``).

    Args:
        fidbf_path: The packed ``.fidbf`` path.

    Returns:
        The manifest path beside it.
    """
    return fidbf_path.with_suffix(fidbf_path.suffix + ".provenance.json")


def _load_include_symbols(path: Path | None) -> frozenset[str] | None:
    """Load the optional function-name allow-list (one symbol per line); ``None`` → include all.

    A reference binary built by static-linking a library pulls in C-runtime/libc/libgcc functions
    too; ingesting those would mislabel generic CRT code as the library (a false-positive provenance
    claim). The allow-list (e.g. ``nm --defined-only libz.a``) scopes the FID library to exactly the
    library's own functions (ADR-043 D2 — correctness over recall).

    Args:
        path: Path to a newline-delimited symbol allow-list, or ``None`` to include every function.

    Returns:
        A frozenset of accepted function names, or ``None`` when no allow-list is given.
    """
    if path is None:
        return None
    names = frozenset(
        line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    )
    if not names:
        raise ValueError(f"include-symbols file is empty: {path}")
    return names


def _generate_fidbf(
    input_path: Path,
    fidbf_path: Path,
    meta: LibraryMeta,
    include_symbols: frozenset[str] | None = None,
    minimal_analysis: bool = False,
) -> tuple[str, int]:  # pragma: no cover - JVM edge
    """Run the PROVEN generate+pack recipe and write the packed ``.fidbf`` (ADR-043 D2).

    Args:
        input_path: The reference library binary (unstripped, with symbols) to analyze.
        fidbf_path: Output path for the packed ``.fidbf``.
        meta: Library metadata (family/version/variant for the FID library record).
        include_symbols: Optional allow-list of function names to ingest; ``None`` includes every
            function. Scopes the DB to the library's own functions, excluding statically-linked
            CRT/libc/libgcc code (avoids false-positive library identification).
        minimal_analysis: When ``True``, disable the decompiler-driven analyzers before analysis
            (ADR-043 Inc E) — for large C++ objects (Boost) that overflow Ghidra's program-DB
            buffer cache mid-analysis ("Cannot call flush() with locks!"). FID hashes derive from
            disassembly + function boundaries, not decompiler output, so this preserves FID
            validity. Opt-in; the C-lib DBs leave it off and analyze byte-identically.

    Returns:
        ``(language_id, function_count)`` — the target language id and the count of ingested
        functions — for the provenance manifest.
    """
    import jpype  # type: ignore[import-not-found]
    import pyghidra  # type: ignore[import-not-found]

    pyghidra.start(verbose=False)

    from ghidra.feature.fid.db import FidFileManager  # type: ignore[import-not-found]
    from ghidra.feature.fid.service import FidService  # type: ignore[import-not-found]
    from ghidra.framework.store.db import PackedDatabase  # type: ignore[import-not-found]
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import-not-found]
    from java.io import File  # type: ignore[import-not-found]
    from java.lang import Object as JObject  # type: ignore[import-not-found]
    from java.util import ArrayList  # type: ignore[import-not-found]

    unpacked = fidbf_path.with_suffix(".fidb")  # raw createNewFidDatabase output (intermediate)
    monitor = ConsoleTaskMonitor()
    manager = FidFileManager.getInstance()
    service = FidService()

    # New pyghidra API (``open_program`` is deprecated). It fused import→analyze→``project.save``
    # into one call whose internal save threw ``IllegalStateException: Cannot call flush() with
    # locks!`` on large C++ objects (ADR-043 Inc E, Boost) because a post-analysis lock was still
    # held at save time. The replacement SPLITS the steps: load (no auto-analyze), analyze under an
    # explicit transaction that closes before returning (``pyghidra.analyze``), then ``save`` with
    # no lock held. This both fixes the C++ blocker and modernizes off the deprecated call.
    consumer = JObject()
    # ``open_project`` (unlike the old ``open_program``) requires the project's PARENT directory to
    # already exist — ``createProject`` does not mkdir it. Create it ourselves (idempotent).
    genproject_dir = fidbf_path.parent / "_genproject"
    genproject_dir.mkdir(parents=True, exist_ok=True)
    with pyghidra.open_project(str(genproject_dir), "fidgen", create=True) as project:
        results = (
            pyghidra.program_loader()
            .source(File(str(input_path)))
            .project(project)
            .projectFolderPath("/")
            .monitor(monitor)
            .load()
        )
        try:
            program = results.getPrimaryDomainObject(consumer)
            try:
                # ADR-043 Inc E (Boost): a large C++ object overflows Ghidra's program-DB
                # buffer cache DURING analysis; the cache then flushes to disk while the
                # analysis transaction holds a lock → "Cannot call flush() with locks!". The
                # decompiler analyzers churn the DB, but the dominant driver is DWARF import of
                # the -g object's per-template debug types. ``--minimal-analysis`` disables them
                # before analysis so the DB never spills. FID hashes derive from disassembly +
                # function boundaries (NOT decompiler/DWARF output), so FID validity is kept.
                # Opt-in: the C-lib DBs do NOT set it → byte-identical analysis (the #158
                # regression-free guarantee holds).
                if minimal_analysis:
                    from ghidra.app.plugin.core.analysis import (  # type: ignore[import-not-found]
                        AutoAnalysisManager,
                    )
                    from ghidra.program.model.listing import (  # type: ignore[import-not-found]
                        Program,
                    )

                    # Creating the analysis manager REGISTERS every analyzer's options into
                    # ANALYSIS_PROPERTIES. On a freshly-loaded program getOptionNames() is
                    # otherwise EMPTY (names appear only once the manager initializes them) —
                    # so the first attempt silently disabled nothing. pyghidra.analyze reuses
                    # this same per-program manager singleton, so options set here apply to its
                    # run. All under one txn (option registration + setBoolean are DB-backed
                    # writes), closed before ``pyghidra.analyze`` opens its own.
                    to_disable: list[str] = []
                    txid = program.startTransaction("fidgen: minimal-analysis options")
                    try:
                        AutoAnalysisManager.getAnalysisManager(program)
                        analysis_opts = program.getOptions(Program.ANALYSIS_PROPERTIES)
                        existing = sorted(str(n) for n in analysis_opts.getOptionNames())
                        # Diagnostic: surface the REAL analyzer-option names (ADR-035 — a name miss
                        # must be visible, never silent). Safe to log: Ghidra's own option names.
                        print(
                            f"generate_fidb: {len(existing)} analysis options: {existing}",
                            file=sys.stderr,
                        )
                        # Strip to the FID-essential analyzers: KEEP Function Start* /
                        # Disassemble (boundaries), Demangler GNU (C++ names), Function ID,
                        # Non-Returning, Call-Fixup. DISABLE the churners — decompiler passes AND
                        # (the real Boost culprit) DWARF import of every template's debug types
                        # (.o is -g), plus data/reference/string. None feed the FID full-hash
                        # (instruction bytes within a function boundary), so the DB stays valid
                        # but small enough to never spill mid-analysis.
                        to_disable = [
                            n
                            for n in (
                                "Decompiler Parameter ID",
                                "Decompiler Switch Analysis",
                                "Call Convention ID",
                                "Stack",
                                "Variadic Function Signature Override",
                                "Aggressive Instruction Finder",
                                "Shared Return Calls",
                                "DWARF",
                                "Data Reference",
                                "Reference",
                                "x86 Constant Reference Analyzer",
                                "ASCII Strings",
                                "Create Address Tables",
                                "Embedded Media",
                                "Apply Data Archives",
                                "Subroutine References",
                                "GCC Exception Handlers",
                                "ELF Scalar Operand References",
                            )
                            if n in existing
                        ]
                        for name in to_disable:
                            analysis_opts.setBoolean(name, False)
                    finally:
                        program.endTransaction(txid, True)
                    print(
                        f"generate_fidb: minimal-analysis disabled {to_disable}",
                        file=sys.stderr,
                    )
                # ``pyghidra.analyze`` is the supported analysis API (it manages the txn).
                pyghidra.analyze(program)
                # Persist so the program's DomainFile reflects the analysis.
                results.save(monitor)
                language_id = str(program.getLanguageID())

                manager.createNewFidDatabase(File(str(unpacked)))
                fid_file = manager.addUserFidFile(File(str(unpacked)))
                fid_db = fid_file.getFidDB(True)
                if include_symbols is None:
                    function_filter = jpype.JProxy(
                        "java.util.function.Predicate", dict={"test": lambda _t: True}
                    )
                else:
                    # The predicate receives generic.stl.Pair<Function, FidHashQuad>; ``.first`` is
                    # the Function. Fail CLOSED (exclude) on any accessor error so a wrong accessor
                    # yields a loud empty DB rather than silently re-admitting every CRT function.
                    def _accept(pair: object) -> bool:
                        try:
                            return str(pair.first.getName()) in include_symbols  # type: ignore[attr-defined]
                        except Exception:  # JVM-edge accessor; exclude on any failure (fail closed)
                            return False

                    function_filter = jpype.JProxy(
                        "java.util.function.Predicate", dict={"test": _accept}
                    )
                domain_files = ArrayList()
                domain_files.add(program.getDomainFile())
                result = service.createNewLibraryFromPrograms(
                    fid_db,
                    meta.family,
                    meta.version,
                    meta.variant,
                    domain_files,
                    function_filter,
                    program.getLanguageID(),
                    ArrayList(),
                    ArrayList(),
                    monitor,
                )
                function_count = int(result.getTotalAdded())
                fid_db.saveDatabase(f"{meta.family} {meta.version} {meta.variant}", monitor)
                fid_db.close()
            finally:
                program.release(consumer)
        finally:
            results.close()

    # Reopen READ-ONLY (no open transaction) and pack to the distribution `.fidbf`.
    fid_file_ro = manager.addUserFidFile(File(str(unpacked)))
    fid_db_ro = fid_file_ro.getFidDB(False)
    try:
        PackedDatabase.packDatabase(
            fid_db_ro.getDBHandle(),
            fidbf_path.stem,
            "FunctionID Database",
            File(str(fidbf_path)),
            monitor,
        )
    finally:
        fid_db_ro.close()
    return language_id, function_count


def _ghidra_version() -> str:  # pragma: no cover - JVM edge
    """Return the running Ghidra version string (best-effort; falls back to ``unknown``)."""
    try:
        from ghidra.framework import Application  # type: ignore[import-not-found]

        return str(Application.getApplicationVersion())
    except Exception:
        return "unknown"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse the generator CLI arguments (pure; testable).

    Args:
        argv: The argument vector (excluding the program name).

    Returns:
        The parsed namespace.
    """
    parser = argparse.ArgumentParser(
        prog="generate_fidb",
        description="Generate a packed ELF FunctionID database (.fidbf) from a library binary.",
    )
    parser.add_argument("--input", required=True, help="reference library binary (unstripped)")
    parser.add_argument("--output", required=True, help="output packed .fidbf path")
    parser.add_argument("--family", required=True, help="FID library family name (e.g. zlib)")
    parser.add_argument("--version", required=True, help="upstream library version (e.g. 1.3.1)")
    parser.add_argument("--variant", required=True, help="build variant (e.g. x86-64-static)")
    parser.add_argument("--license-spdx", required=True, help="source SPDX license id (e.g. Zlib)")
    parser.add_argument(
        "--include-symbols",
        default=None,
        help="path to a newline-delimited function-name allow-list (scopes the DB to the "
        "library's own functions, e.g. `nm --defined-only libz.a`); omit to include all",
    )
    parser.add_argument("--source-name", default=None, help="human source name (default: family)")
    parser.add_argument("--source-digest", default=None, help="sha256:... of the source tarball")
    parser.add_argument("--compiler", default=None, help="compiler id+version (e.g. 'gcc 13.2.0')")
    # A value starting with '-' must use the =form (argparse else reads it as an option), e.g.
    # --compiler-flags="-O2 -g".
    parser.add_argument(
        "--compiler-flags",
        default=None,
        help="compiler flags used (use =form: --compiler-flags=...)",
    )
    parser.add_argument(
        "--minimal-analysis",
        action="store_true",
        help="disable decompiler-driven analyzers before analysis (ADR-043 Inc E) — for large "
        "C++ objects (Boost) that overflow Ghidra's DB buffer cache mid-analysis; FID hashes do "
        "not need decompiler output. C-lib DBs omit this and analyze identically.",
    )
    return parser.parse_args(argv)


def _meta_from_args(args: argparse.Namespace) -> LibraryMeta:
    """Build :class:`LibraryMeta` from parsed args (pure; testable)."""
    return LibraryMeta(
        family=args.family,
        version=args.version,
        variant=args.variant,
        license_spdx=args.license_spdx,
        source_digest=args.source_digest,
        compiler=args.compiler,
        compiler_flags=args.compiler_flags,
        source_name=args.source_name,
    )


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - JVM-edge orchestration
    """Generate the packed ``.fidbf`` + its provenance manifest. Returns a process exit code.

    Args:
        argv: The argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        ``0`` on success; ``2`` on a usage/IO error.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    meta = _meta_from_args(args)
    input_path = Path(args.input)
    fidbf_path = Path(args.output)
    if not input_path.is_file():
        print(f"generate_fidb: input not found: {input_path}", file=sys.stderr)
        return 2
    fidbf_path.parent.mkdir(parents=True, exist_ok=True)

    include_path = Path(args.include_symbols) if args.include_symbols else None
    if include_path is not None and not include_path.is_file():
        print(f"generate_fidb: include-symbols not found: {include_path}", file=sys.stderr)
        return 2
    include_symbols = _load_include_symbols(include_path)

    language_id, function_count = _generate_fidbf(
        input_path,
        fidbf_path,
        meta,
        include_symbols=include_symbols,
        minimal_analysis=args.minimal_analysis,
    )
    manifest = build_manifest(
        meta,
        fidbf_path=fidbf_path,
        ghidra_version=_ghidra_version(),
        language_id=language_id,
        function_count=function_count,
    )
    manifest_path_for(fidbf_path).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"generate_fidb: wrote {fidbf_path.name} (functions={function_count}, lang={language_id})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
