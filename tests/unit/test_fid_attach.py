"""Hermetic unit tests for the bundled-FID-DB startup attach orchestration (ADR-043 Phase 2).

Covers the PURE part of the worker-startup attach (``vivarium.ghidra._fid_attach``): discovering the
bundled ``*.fidbf`` set, iterating it, copying to the writable scratch, invoking an INJECTED
``attach_one``, and the FAIL-SOFT contract. The JVM edge (real ``addUserFidFile`` + ``setActive``)
is faked here — these tests never touch Ghidra/the JVM (TB3 boundary; ADR-001).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vivarium.ghidra._fid_attach import (
    DEFAULT_FID_DB_DIR,
    FIDB_SUFFIX,
    FidAttachResult,
    attach_bundled_fid_dbs,
    discover_fid_dbs,
)


def _write_db(directory: Path, name: str) -> Path:
    """Create a stub ``.fidbf`` file with the given name and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(b"stub-packed-db")
    return path


def test_default_dir_constant() -> None:
    """The default bundled-FID-DB dir matches the worker-image path (ADR-043)."""
    assert DEFAULT_FID_DB_DIR == "/opt/vivarium/fid"
    assert FIDB_SUFFIX == ".fidbf"


def test_discover_missing_dir_is_empty(tmp_path: Path) -> None:
    """A missing/non-existent dir yields no candidates (clean no-op baseline)."""
    assert discover_fid_dbs(tmp_path / "does-not-exist") == []


def test_discover_non_directory_is_empty(tmp_path: Path) -> None:
    """A path that exists but is a file (not a dir) yields no candidates (fail-soft)."""
    afile = tmp_path / "afile"
    afile.write_text("x")
    assert discover_fid_dbs(afile) == []


def test_discover_only_fidbf_files_sorted(tmp_path: Path) -> None:
    """Only regular ``*.fidbf`` files are discovered, sorted; other files/dirs are ignored."""
    _write_db(tmp_path, "zlib.fidbf")
    _write_db(tmp_path, "musl.fidbf")
    (tmp_path / "notes.txt").write_text("ignore me")
    (tmp_path / "sources.toml").write_text("ignore me too")
    (tmp_path / "subdir").mkdir()
    found = [p.name for p in discover_fid_dbs(tmp_path)]
    assert found == ["musl.fidbf", "zlib.fidbf"]  # sorted, only .fidbf


def test_discover_is_bounded(tmp_path: Path) -> None:
    """Discovery is bounded (CWE-400) — never returns an unbounded list."""
    from vivarium.ghidra._fid_attach import _MAX_FID_DBS

    for i in range(_MAX_FID_DBS + 10):
        _write_db(tmp_path, f"db{i:03d}.fidbf")
    assert len(discover_fid_dbs(tmp_path)) == _MAX_FID_DBS


def test_attach_no_dbs_is_noop(tmp_path: Path) -> None:
    """No bundled DBs ⇒ a clean no-op: attach_one never called, no log emitted."""
    calls: list[Path] = []
    logs: list[tuple[str, dict[str, object]]] = []

    result = attach_bundled_fid_dbs(
        tmp_path,
        tmp_path / "scratch",
        attach_one=lambda p: calls.append(p) or True,  # type: ignore[func-returns-value]
        log=lambda event, **fields: logs.append((event, fields)),
    )
    assert result == FidAttachResult(scanned=0)
    assert calls == []
    assert logs == []  # no DBs ⇒ no summary log either


def test_attach_happy_path_copies_and_activates(tmp_path: Path) -> None:
    """Each DB is copied to the writable scratch then attached + activated; summary logged."""
    db_dir = tmp_path / "fid"
    scratch = tmp_path / "scratch"
    _write_db(db_dir, "zlib.fidbf")
    _write_db(db_dir, "musl.fidbf")
    attached_paths: list[Path] = []
    logs: list[tuple[str, dict[str, object]]] = []

    def attach_one(p: Path) -> bool:
        # The path handed to the JVM edge MUST be the writable copy, not the read-only source.
        assert p.parent == scratch
        assert p.exists()  # copy happened before attach
        attached_paths.append(p)
        return True

    result = attach_bundled_fid_dbs(
        db_dir,
        scratch,
        attach_one=attach_one,
        log=lambda event, **fields: logs.append((event, fields)),
    )

    assert result.scanned == 2
    assert sorted(result.attached) == ["musl.fidbf", "zlib.fidbf"]
    assert result.skipped == ()
    assert [p.name for p in sorted(attached_paths)] == ["musl.fidbf", "zlib.fidbf"]
    # Exactly one summary log, redaction-safe (names + counts only).
    assert [e for e, _ in logs] == ["fid_dbs_attached"]
    _, fields = logs[0]
    assert fields["count"] == 2
    # Attach order follows the sorted discovery order (deterministic).
    assert fields["attached"] == ["musl.fidbf", "zlib.fidbf"]
    assert fields["skipped"] == []
    assert fields["scanned"] == 2


def test_attach_rejected_db_is_skipped_fail_soft(tmp_path: Path) -> None:
    """A DB ``attach_one`` REJECTS (returns False) is logged + skipped; others still attach."""
    db_dir = tmp_path / "fid"
    _write_db(db_dir, "good.fidbf")
    _write_db(db_dir, "bad.fidbf")
    logs: list[tuple[str, dict[str, object]]] = []

    def attach_one(p: Path) -> bool:
        return p.name != "bad.fidbf"  # the manager rejects the bad one

    result = attach_bundled_fid_dbs(
        db_dir,
        tmp_path / "scratch",
        attach_one=attach_one,
        log=lambda event, **fields: logs.append((event, fields)),
    )

    assert result.attached == ("good.fidbf",)
    assert result.skipped == ("bad.fidbf",)
    assert result.scanned == 2
    # A per-DB skip warning + the summary; the skip names the DB + a redaction-safe reason.
    events = [e for e, _ in logs]
    assert "fid_db_skipped" in events
    skip_fields = next(f for e, f in logs if e == "fid_db_skipped")
    assert skip_fields == {"db": "bad.fidbf", "reason": "rejected"}


def test_attach_raising_db_is_skipped_fail_soft(tmp_path: Path) -> None:
    """A DB whose attach RAISES is caught (fail-soft): logged with the exception class, skipped."""
    db_dir = tmp_path / "fid"
    _write_db(db_dir, "boom.fidbf")
    _write_db(db_dir, "ok.fidbf")
    logs: list[tuple[str, dict[str, object]]] = []

    def attach_one(p: Path) -> bool:
        if p.name == "boom.fidbf":
            raise RuntimeError("jvm exploded")
        return True

    result = attach_bundled_fid_dbs(
        db_dir,
        tmp_path / "scratch",
        attach_one=attach_one,
        log=lambda event, **fields: logs.append((event, fields)),
    )

    assert result.attached == ("ok.fidbf",)
    assert result.skipped == ("boom.fidbf",)
    skip_fields = next(f for e, f in logs if e == "fid_db_skipped")
    # The failure CLASS is surfaced (no traceback / no DB content in the log).
    assert skip_fields == {"db": "boom.fidbf", "reason": "RuntimeError"}


def test_attach_copy_failure_is_skipped_fail_soft(tmp_path: Path) -> None:
    """A copy error is caught (fail-soft): the DB is skipped, the worker is not crashed."""
    db_dir = tmp_path / "fid"
    _write_db(db_dir, "x.fidbf")
    logs: list[tuple[str, dict[str, object]]] = []

    def boom_copy(_src: Path, _dst: Path) -> Path:
        raise OSError("disk full")

    result = attach_bundled_fid_dbs(
        db_dir,
        tmp_path / "scratch",
        attach_one=lambda _p: True,
        log=lambda event, **fields: logs.append((event, fields)),
        copy=boom_copy,
    )

    assert result.attached == ()
    assert result.skipped == ("x.fidbf",)
    skip_fields = next(f for e, f in logs if e == "fid_db_skipped")
    assert skip_fields == {"db": "x.fidbf", "reason": "OSError"}


def test_default_copy_actually_copies(tmp_path: Path) -> None:
    """The default copy writes the source bytes into the writable dir (creating it)."""
    from vivarium.ghidra._fid_attach import _copy_to_writable

    src = _write_db(tmp_path / "fid", "z.fidbf")
    writable = tmp_path / "scratch"  # does not exist yet
    dest = _copy_to_writable(src, writable)
    assert dest == writable / "z.fidbf"
    assert dest.read_bytes() == src.read_bytes()


@pytest.mark.parametrize("scanned", [0, 1, 3])
def test_result_is_immutable(scanned: int) -> None:
    """FidAttachResult is a frozen dataclass (defensive immutability)."""
    result = FidAttachResult(scanned=scanned)
    with pytest.raises((AttributeError, TypeError)):
        result.scanned = 99  # type: ignore[misc]
