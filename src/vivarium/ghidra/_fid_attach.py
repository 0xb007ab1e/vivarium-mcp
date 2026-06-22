"""Worker-startup bundled-FID-DB attach orchestration (ADR-043 Phase 2).

Activates the bundled ELF FunctionID databases at worker init so ``identify_functions`` matches
Linux library code. The ADR-043 O1 spike PROVED the mechanism is **startup-attach**, NOT a data-dir
drop-in: dropping a packed ``.fidbf`` into ``Ghidra/Features/FunctionID/data/`` is silently ignored
(Ghidra registers DBs via an install step, not a directory glob). So at startup the worker, for each
bundled packed ``.fidbf``:

1. copies it to a **writable** path (the tmpfs scratch — the read-only rootfs cannot host it, and
   ``addUserFidFile`` returns ``None`` on a read-only/invalid path);
2. ``FidFileManager.addUserFidFile(File(writableCopy))`` → ``FidFile.setActive(True)``.

This module owns the **pure** part: discovering the bundled ``.fidbf`` set, iterating it, copying to
the writable dir, invoking an INJECTED ``attach_one`` callable (the JVM edge), and the **fail-soft**
contract — a bad/missing/unreadable DB logs a structured warning and is SKIPPED; it never crashes
the worker. No DBs present is a clean no-op (identical to today's behaviour). The JVM-touching
``attach_one`` is supplied by the worker bridge (``# pragma: no cover`` there); here it is injected,
so this orchestration is HERMETICALLY unit-tested with a fake.

Redaction (topic-logging-observability, master §5): logs carry only DB **file names** (our own
build-time artifact names, not binary-derived content), counts, and outcomes — never binary content
or session secrets. The packed ``.fidbf`` holds non-reversible hashes + symbol names + metadata, no
library code (ADR-043 / docs/security/fid-database-licensing.md), but we still log names only.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

#: The packed-FID-database file extension (ADR-043 D2 — ``PackedDatabase.packDatabase`` output).
FIDB_SUFFIX = ".fidbf"

#: Default bundled-FID-DB directory baked into the worker image (ADR-043; overridable via
#: ``VIVARIUM_FID_DB_DIR``). Read-only (it lives on the read-only rootfs); each ``.fidbf`` is copied
#: to the writable tmpfs before ``addUserFidFile`` (which needs a writable path).
DEFAULT_FID_DB_DIR = "/opt/vivarium/fid"

#: A bound on how many bundled DBs we will attempt to attach, so a misconfigured/oversized bundle
#: dir cannot make startup unbounded (CWE-400 — bound startup work). The shipped v1 set is small.
_MAX_FID_DBS = 64

#: Callable contract for the injected JVM edge: given the (writable) packed ``.fidbf`` path, attach
#: it via ``FidFileManager.addUserFidFile`` and ``setActive(True)``. Returns ``True`` on a
#: successful activation, ``False`` when the manager rejected the file (e.g. ``addUserFidFile``
#: returned
#: ``None`` — an invalid/non-writable/corrupt DB). MUST NOT raise for an ordinary bad-DB case; any
#: raise is still caught by the orchestration (fail-soft), but a clean ``False`` is preferred.
AttachOne = Callable[[Path], bool]

#: Callable contract for the injected structured logger: ``log(event, **fields)``. Fields are
#: redaction-safe scalars only (names/counts/outcomes — never binary content).
LogFn = Callable[..., None]


@dataclass(frozen=True, slots=True)
class FidAttachResult:
    """Outcome of the bundled-FID-DB attach pass (all fields redaction-safe).

    Attributes:
        attached: The file names (basenames) of the DBs successfully attached + activated.
        skipped: The file names of DBs that were present but could not be attached (logged, skipped
            — fail-soft). Empty in the happy path.
        scanned: Total ``*.fidbf`` files discovered in the configured dir (``len(attached)+
            len(skipped)``, capped at :data:`_MAX_FID_DBS`).
    """

    attached: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    scanned: int = 0


def discover_fid_dbs(db_dir: str | Path) -> list[Path]:
    """Return the sorted list of bundled packed ``*.fidbf`` files in ``db_dir`` (pure, fail-soft).

    A missing or non-directory path yields an empty list (no DBs bundled ⇒ clean no-op, identical to
    today). Results are sorted for deterministic attach order and bounded to :data:`_MAX_FID_DBS`
    (CWE-400). Only regular files with the :data:`FIDB_SUFFIX` extension are returned;
    subdirectories, symlinks-to-dirs, and other files are ignored.

    Args:
        db_dir: The configured bundled-FID-DB directory.

    Returns:
        A sorted, bounded list of candidate ``.fidbf`` paths (possibly empty).
    """
    root = Path(db_dir)
    if not root.is_dir():
        return []
    candidates = sorted(p for p in root.iterdir() if p.is_file() and p.suffix == FIDB_SUFFIX)
    return candidates[:_MAX_FID_DBS]


def _copy_to_writable(src: Path, writable_dir: Path) -> Path:
    """Copy a bundled ``.fidbf`` into the writable scratch dir; return the writable copy path.

    ``addUserFidFile`` needs a writable, valid packed path (it returns ``None`` otherwise), and the
    bundled dir lives on the read-only rootfs — so each DB is copied to the tmpfs scratch first
    (ADR-043 D3). The destination keeps the source basename.

    Args:
        src: The bundled (read-only) packed ``.fidbf``.
        writable_dir: The writable tmpfs scratch directory.

    Returns:
        The path of the writable copy.
    """
    writable_dir.mkdir(parents=True, exist_ok=True)
    dest = writable_dir / src.name
    shutil.copyfile(src, dest)
    return dest


def attach_bundled_fid_dbs(
    db_dir: str | Path,
    writable_dir: str | Path,
    *,
    attach_one: AttachOne,
    log: LogFn,
    copy: Callable[[Path, Path], Path] = _copy_to_writable,
) -> FidAttachResult:
    """Attach + activate every bundled packed ``.fidbf`` at worker startup (fail-soft; no-op=none).

    For each discovered DB: copy it to ``writable_dir``, then call the injected ``attach_one`` (the
    JVM edge: ``addUserFidFile`` + ``setActive``). Any failure — a copy error, ``attach_one``
    returning ``False`` (manager rejected the file), or ``attach_one`` raising — is logged as a
    structured ``fid_db_skipped`` warning and the DB is SKIPPED; the worker is never crashed
    (fail-soft; master §2 "fail closed" applied as fail-OPEN-but-degraded for an OPTIONAL feature:
    a bad bundled DB must not take down the worker — it just yields fewer matches, identical to the
    no-DB baseline). No DBs present ⇒ a clean no-op (``scanned == 0``).

    Emits one structured ``fid_dbs_attached`` summary log (count + names) at the end. All logged
    fields are redaction-safe: DB file names are our own build-time artifact names (not
    binary-derived) — never binary content or secrets (topic-logging-observability).

    Args:
        db_dir: The configured bundled-FID-DB directory (``VIVARIUM_FID_DB_DIR``).
        writable_dir: The writable tmpfs scratch dir to copy each DB into before attaching.
        attach_one: Injected JVM-edge callable (see :data:`AttachOne`).
        log: Injected structured logger (see :data:`LogFn`).
        copy: Injected copy function (defaults to :func:`_copy_to_writable`); overridable for tests.

    Returns:
        A :class:`FidAttachResult` summarizing the pass (all fields redaction-safe).
    """
    candidates = discover_fid_dbs(db_dir)
    scanned = len(candidates)
    if scanned == 0:
        # No bundled DBs (or no dir) — clean no-op, identical to the pre-Phase-2 baseline.
        return FidAttachResult(scanned=0)

    writable = Path(writable_dir)
    attached: list[str] = []
    skipped: list[str] = []
    for src in candidates:
        name = src.name
        try:
            writable_copy = copy(src, writable)
            ok = attach_one(writable_copy)
        except Exception as exc:
            # Surface the failure class only (no DB content, no traceback to the log payload).
            log("fid_db_skipped", db=name, reason=type(exc).__name__)
            skipped.append(name)
            continue
        if ok:
            attached.append(name)
        else:
            # attach_one returned False → FidFileManager rejected the file (invalid/non-writable/
            # corrupt packed DB). Skip it, keep going (fail-soft).
            log("fid_db_skipped", db=name, reason="rejected")
            skipped.append(name)

    log(
        "fid_dbs_attached", count=len(attached), attached=attached, skipped=skipped, scanned=scanned
    )
    return FidAttachResult(attached=tuple(attached), skipped=tuple(skipped), scanned=scanned)
