"""Unit + property/fuzz tests for the pure `.gnu_debuglink` parser (ADR-071 detached DWARF).

The worker's `_stage_dwarf_debug` (filesystem staging) + Ghidra's DWARF analyzer are the
``# pragma: no cover`` worker/JVM edge validated against a real worker; this covers the PURE
``core.debuglink.parse_gnu_debuglink`` boundary — the hostile-ELF-bytes parser. The fuzz test is
the mandate for a parser of untrusted input (``@rules/topic-testing`` / master §4): arbitrary bytes
must never crash or hang — only a filename or ``None``.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from vivarium.core.debuglink import parse_gnu_debuglink

#: A real 1016-byte stripped x86-64 ELF carrying a `.gnu_debuglink` naming "dw.debug" (built with
#: gcc -g -nostdlib ... + objcopy --strip-all --add-gnu-debuglink; see test_import_debug_map).
_STRIPPED_ELF_HEX = (
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


def test_parses_real_debuglink_name() -> None:
    """A real stripped ELF's `.gnu_debuglink` yields the companion filename."""
    assert parse_gnu_debuglink(bytes.fromhex(_STRIPPED_ELF_HEX)) == "dw.debug"


def test_not_an_elf_returns_none() -> None:
    """Non-ELF bytes yield None (not an error)."""
    assert parse_gnu_debuglink(b"MZ not an elf" + b"\x00" * 100) is None
    assert parse_gnu_debuglink(b"") is None


def test_elf_without_debuglink_returns_none() -> None:
    """A well-formed ELF header with no `.gnu_debuglink` section yields None (an ELF's own bytes
    minus the section: mutate the section name so it no longer matches)."""
    raw = bytearray(bytes.fromhex(_STRIPPED_ELF_HEX))
    # blunt: corrupt the section name so the lookup fails; the parser must not crash.
    out = parse_gnu_debuglink(bytes(raw.replace(b".gnu_debuglink", b".gnu_deadlink0")))
    assert out is None


def _elf_with_debuglink_name(name: bytes) -> bytes:
    """Return the real stripped ELF with its `.gnu_debuglink` name overwritten in place.

    ``name`` MUST be <= 8 bytes; it is right-padded with NULs to exactly 8 so every section
    offset/size in the file is preserved (the original name ``dw.debug`` is 8 bytes and unique).
    """
    assert len(name) <= 8
    raw = bytes.fromhex(_STRIPPED_ELF_HEX)
    assert raw.count(b"dw.debug") == 1
    return raw.replace(b"dw.debug", name.ljust(8, b"\x00"))


def test_path_traversal_debuglink_name_rejected() -> None:
    """AA1 (CWE-22): a `.gnu_debuglink` naming a PATH — absolute, ``..``, or a separator — is
    rejected (None), so it can never steer the worker's staging copy destination out of stage_dir.

    A `.gnu_debuglink` value is a bare filename by spec; anything else is hostile/malformed and
    fails closed (indistinguishable from "no debuglink" — the safe branch).
    """
    for hostile in (b"../../x", b"/tmp/xy", b"a/b", b"..", b".", b"..\\x"):
        assert parse_gnu_debuglink(_elf_with_debuglink_name(hostile)) is None, hostile
    # Control: the benign in-place substitution still parses (proves the harness itself is sound).
    assert parse_gnu_debuglink(_elf_with_debuglink_name(b"ok.dbg")) == "ok.dbg"


@given(st.binary(min_size=0, max_size=512))
def test_fuzz_never_crashes(data: bytes) -> None:
    """Hostile fuzz: arbitrary bytes yield either a filename or None — never a crash/hang."""
    out = parse_gnu_debuglink(data)
    assert out is None or (isinstance(out, str) and 0 < len(out) <= 256)


@given(st.binary(min_size=0, max_size=512))
def test_fuzz_returned_name_is_a_bare_basename(data: bytes) -> None:
    """AA1 invariant under fuzz: any name the parser DOES return is a bare basename — never a
    path — so the staging join can't escape (defense the `os.path.join` destination relies on)."""
    out = parse_gnu_debuglink(data)
    if out is not None:
        assert "/" not in out and "\\" not in out and out not in {".", ".."}
