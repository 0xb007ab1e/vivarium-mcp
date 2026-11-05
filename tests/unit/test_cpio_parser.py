"""Unit + fuzz tests for the pure cpio ``newc`` parser (ADR-087; #415).

`core.cpio.parse_newc_entries` is a hostile-bytes boundary (ADR-005): it must be total — a validated
list of :class:`CpioEntry` or a :class:`CpioError`, never a crash, hang, over-read, over-allocation,
recursion, or divide-by-zero. The fuzz test is the proof of that fail-closed contract; the unit
tests pin the member arithmetic + type classification against the synthetic fixture.
"""

from __future__ import annotations

import stat

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests._fixtures import binaries
from vivarium.core.cpio import CpioEntry, CpioError, is_cpio_newc, parse_newc_entries

_MAX = 4096


# --- is_cpio_newc probe --------------------------------------------------------------------------


def test_is_cpio_newc_matches_both_magics() -> None:
    """The cheap probe recognises both newc and newc-crc magics, rejects anything else."""
    assert is_cpio_newc(b"070701rest")
    assert is_cpio_newc(b"070702rest")
    assert not is_cpio_newc(b"070703")
    assert not is_cpio_newc(b"\x1f\x8b")  # gzip
    assert not is_cpio_newc(b"")


# --- happy path ----------------------------------------------------------------------------------


def test_parses_files_dirs_symlinks_in_order() -> None:
    """A mixed archive yields the members in order with correct size/type classification."""
    archive = binaries.cpio_newc_archive(
        [
            ("etc", stat.S_IFDIR | 0o755, b""),
            ("etc/init.rc", stat.S_IFREG | 0o644, b"on boot\n    start svc\n"),
            ("bin/sh", stat.S_IFLNK | 0o777, b"busybox"),
        ]
    )
    entries = parse_newc_entries(archive, max_entries=_MAX)

    assert [e.name for e in entries] == ["etc", "etc/init.rc", "bin/sh"]
    etc, initrc, sh = entries
    assert etc.is_dir and not etc.is_symlink and etc.size == 0
    assert not initrc.is_dir and not initrc.is_symlink
    assert initrc.size == len(b"on boot\n    start svc\n")
    assert sh.is_symlink and sh.size == len(b"busybox")
    # data_offset points at the member's data: slicing it back out matches.
    assert (
        archive[initrc.data_offset : initrc.data_offset + initrc.size]
        == b"on boot\n    start svc\n"
    )
    assert archive[sh.data_offset : sh.data_offset + sh.size] == b"busybox"


def test_trailer_terminates_and_is_excluded() -> None:
    """Parsing stops at TRAILER!!! and the sentinel is not reported as a member."""
    archive = binaries.cpio_newc_archive([("a", stat.S_IFREG | 0o644, b"x")])
    entries = parse_newc_entries(archive, max_entries=_MAX)
    assert [e.name for e in entries] == ["a"]
    assert all(e.name != "TRAILER!!!" for e in entries)


def test_empty_archive_is_just_a_trailer() -> None:
    """An archive with only the trailer parses to an empty list (valid, not an error)."""
    archive = binaries.cpio_newc_archive([])
    assert parse_newc_entries(archive, max_entries=_MAX) == []


def test_newc_crc_magic_accepted() -> None:
    """A newc-crc (070702) member header is accepted (checksum field ignored by metadata parse)."""
    archive = bytearray(binaries.cpio_newc_archive([("f", stat.S_IFREG | 0o644, b"hi")]))
    archive[0:6] = b"070702"  # flip the first member's magic to newc-crc
    entries = parse_newc_entries(bytes(archive), max_entries=_MAX)
    assert entries[0].name == "f" and entries[0].size == 2


# --- fail-closed (abuse) -------------------------------------------------------------------------


def test_bad_magic_rejected() -> None:
    """A non-cpio buffer fails closed with CpioError (no over-read)."""
    with pytest.raises(CpioError):
        parse_newc_entries(b"not a cpio at all" * 10, max_entries=_MAX)


def test_missing_trailer_rejected() -> None:
    """An archive with no TRAILER!!! (truncated) fails closed rather than running off the end."""
    full = binaries.cpio_newc_archive([("a", stat.S_IFREG | 0o644, b"data")])
    # Drop the trailer member (last 110+ bytes) → the walk runs out of buffer.
    with pytest.raises(CpioError):
        parse_newc_entries(full[:120], max_entries=_MAX)


def test_oversized_namesize_rejected() -> None:
    """A member claiming a namesize past the buffer fails closed (no over-read/alloc)."""
    archive = bytearray(binaries.cpio_newc_archive([("a", stat.S_IFREG | 0o644, b"d")]))
    archive[94:102] = b"ffffffff"  # namesize = 0xffffffff on member 0
    with pytest.raises(CpioError):
        parse_newc_entries(bytes(archive), max_entries=_MAX)


def test_oversized_filesize_rejected() -> None:
    """A member whose data length overruns the buffer fails closed."""
    archive = bytearray(binaries.cpio_newc_archive([("a", stat.S_IFREG | 0o644, b"d")]))
    archive[54:62] = b"7fffffff"  # filesize huge on member 0
    with pytest.raises(CpioError):
        parse_newc_entries(bytes(archive), max_entries=_MAX)


def test_non_hex_field_rejected() -> None:
    """A corrupt (non-hex) header field fails closed, not with a raw ValueError leak."""
    archive = bytearray(binaries.cpio_newc_archive([("a", stat.S_IFREG | 0o644, b"d")]))
    archive[14:22] = b"zzzzzzzz"  # mode field non-hex
    with pytest.raises(CpioError):
        parse_newc_entries(bytes(archive), max_entries=_MAX)


def test_entry_cap_enforced() -> None:
    """Exceeding max_entries fails closed (CWE-400 resource bound)."""
    archive = binaries.cpio_newc_archive([(f"f{i}", stat.S_IFREG | 0o644, b"x") for i in range(5)])
    with pytest.raises(CpioError, match="max_entries"):
        parse_newc_entries(archive, max_entries=3)


def test_nonpositive_max_entries_rejected() -> None:
    """A non-positive cap is a programmer error surfaced as CpioError, not an infinite loop."""
    with pytest.raises(CpioError):
        parse_newc_entries(binaries.cpio_newc_archive([]), max_entries=0)


# --- fuzz: total on arbitrary bytes (the fail-closed proof) --------------------------------------


@given(st.binary(max_size=4096))
def test_fuzz_arbitrary_bytes_never_crash(data: bytes) -> None:
    """Arbitrary bytes yield a list of CpioEntry or a CpioError — never any other exception/hang."""
    try:
        result = parse_newc_entries(data, max_entries=256)
    except CpioError:
        return
    assert isinstance(result, list)
    assert all(isinstance(e, CpioEntry) for e in result)
    # Every reported member stays within the buffer (no over-read leaked into offsets).
    for e in result:
        assert 0 <= e.data_offset <= len(data)
        assert e.data_offset + e.size <= len(data)


@given(st.lists(st.tuples(st.text(max_size=40), st.integers(0, 0o177777), st.binary(max_size=64))))
def test_fuzz_roundtrip_wellformed_archives(members: list[tuple[str, int, bytes]]) -> None:
    """Any archive the fixture builds parses back to the same member count + names (well-formed)."""
    # Drop names colliding with the sentinel or carrying a NUL (the format can't represent them).
    clean = [
        (name, stat.S_IFREG | (mode & 0o7777), data)
        for name, mode, data in members
        if name and "\x00" not in name and name != "TRAILER!!!"
    ]
    archive = binaries.cpio_newc_archive(clean)
    entries = parse_newc_entries(archive, max_entries=4096)
    assert len(entries) == len(clean)
    assert [e.name for e in entries] == [name for name, _m, _d in clean]
