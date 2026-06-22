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


def _generate_fidbf(
    input_path: Path, fidbf_path: Path, meta: LibraryMeta
) -> tuple[str, int]:  # pragma: no cover - JVM edge
    """Run the PROVEN generate+pack recipe and write the packed ``.fidbf`` (ADR-043 D2).

    Args:
        input_path: The reference library binary (unstripped, with symbols) to analyze.
        fidbf_path: Output path for the packed ``.fidbf``.
        meta: Library metadata (family/version/variant for the FID library record).

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
    from java.util import ArrayList  # type: ignore[import-not-found]

    unpacked = fidbf_path.with_suffix(".fidb")  # raw createNewFidDatabase output (intermediate)
    monitor = ConsoleTaskMonitor()
    manager = FidFileManager.getInstance()
    service = FidService()

    with pyghidra.open_program(
        str(input_path),
        project_location=str(fidbf_path.parent / "_genproject"),
        project_name="fidgen",
        analyze=True,
    ) as flat:
        program = flat.getCurrentProgram()
        language_id = str(program.getLanguageID())

        manager.createNewFidDatabase(File(str(unpacked)))
        fid_file = manager.addUserFidFile(File(str(unpacked)))
        fid_db = fid_file.getFidDB(True)
        include_all = jpype.JProxy("java.util.function.Predicate", dict={"test": lambda _t: True})
        domain_files = ArrayList()
        domain_files.add(program.getDomainFile())
        result = service.createNewLibraryFromPrograms(
            fid_db,
            meta.family,
            meta.version,
            meta.variant,
            domain_files,
            include_all,
            program.getLanguageID(),
            ArrayList(),
            ArrayList(),
            monitor,
        )
        function_count = int(result.getTotalAdded())
        fid_db.saveDatabase(f"{meta.family} {meta.version} {meta.variant}", monitor)
        fid_db.close()

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

    language_id, function_count = _generate_fidbf(input_path, fidbf_path, meta)
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
