"""Pure parser for the cpio ``newc`` / ``newc-crc`` archive format (ADR-087; #415).

An Android ramdisk (ADR-085) is a (decompressed) cpio *filesystem*. Scope A surfaced its raw bytes
as a flat image for string/byte triage; this module adds the **structured file tree** (Scope B,
#415): it parses the cpio ``newc`` (``070701``) / ``newc-crc`` (``070702``) member headers into a
bounded list of :class:`CpioEntry` records (name, mode, size, and the byte offset of the member's
data within the archive) — it NEVER reads a member's data, never allocates by an untrusted length,
and never touches the JVM or the filesystem, so it is a pure, hermetically fuzzable boundary
(``@rules/topic-architecture-patterns`` functional core).

Every byte here is HOSTILE input (a firmware ramdisk of unknown origin, ADR-005): the parser is
total — it returns a validated list or raises :class:`CpioError`; it must never crash, hang,
over-read, over-allocate, recurse, or divide by zero on arbitrary bytes (verified by the
property/fuzz tests, ``@rules/topic-testing`` adversarial). It is bounded by an explicit entry cap
(CWE-400) and validates every field against the remaining buffer before advancing (CWE-20/-190).
The worker reads the loaded ramdisk program's bytes and calls :func:`parse_newc_entries`; the file
NAMES it returns are binary-derived and wrapped UNTRUSTED by the server (ADR-005).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

#: The two cpio magics accepted: ``newc`` (no checksum) and ``newc-crc`` (checksum field).
_MAGIC_NEWC: Final = b"070701"
_MAGIC_NEWC_CRC: Final = b"070702"

#: Fixed cpio ``newc`` header length: 6-byte ASCII magic + 13 fields of 8 hex each.
_HEADER_LEN: Final = 110

#: The sentinel member name that terminates a cpio archive.
_TRAILER_NAME: Final = "TRAILER!!!"

#: cpio fields + offsets are 4-byte aligned (header+name padded to 4; data padded to 4).
_ALIGN: Final = 4

#: ``st_mode`` file-type mask + the types we label (octal, as in ``<sys/stat.h>``).
_S_IFMT: Final = 0o170000
_S_IFDIR: Final = 0o040000
_S_IFREG: Final = 0o100000
_S_IFLNK: Final = 0o120000

#: Hard cap on a single member name length — a sane ceiling well above any real path (CWE-400).
_MAX_NAME_LEN: Final = 4096


class CpioError(ValueError):
    """Raised when the bytes are not a well-formed, bounded cpio ``newc`` archive.

    A single typed error for every malformation (bad magic, truncation, a field that overruns the
    buffer, a non-hex field, an over-long name, or exceeding the entry cap) — so the worker can
    translate any parse failure to one category-safe ``not-found``/``invalid`` outcome (fail-closed,
    ADR-005): the archive is hostile input and its shape must never leak as an arbitrary exception.
    """


@dataclass(frozen=True)
class CpioEntry:
    """One member of a cpio archive (metadata only — the parser never reads the member's data).

    Attributes:
        name: The member path (binary-derived → wrapped UNTRUSTED by the server).
        mode: The POSIX ``st_mode`` (type bits + permission bits).
        size: The member's data length in bytes.
        data_offset: The byte offset of the member's data within the archive.
        is_dir: Whether the mode marks a directory.
        is_symlink: Whether the mode marks a symlink (its "data" is the link target).
    """

    name: str
    mode: int
    size: int
    data_offset: int
    is_dir: bool
    is_symlink: bool


def _u32_hex(field: bytes) -> int:
    """Parse one 8-char ASCII hex cpio field to an int, or raise :class:`CpioError`.

    Args:
        field: Exactly 8 ASCII hex bytes.

    Returns:
        The field value.

    Raises:
        CpioError: If the field is not 8 ASCII hex digits.
    """
    try:
        return int(field.decode("ascii"), 16)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CpioError("cpio header field is not 8 ASCII hex digits") from exc


def _pad4(value: int) -> int:
    """Round ``value`` up to the next 4-byte boundary (cpio padding)."""
    return (value + _ALIGN - 1) & ~(_ALIGN - 1)


def is_cpio_newc(head: bytes) -> bool:
    """Return whether ``head`` begins with a cpio ``newc`` / ``newc-crc`` magic (cheap probe)."""
    return head[:6] in (_MAGIC_NEWC, _MAGIC_NEWC_CRC)


def parse_newc_entries(data: bytes, *, max_entries: int) -> list[CpioEntry]:
    """Parse a cpio ``newc``/``newc-crc`` archive into a bounded list of member metadata.

    Walks the member headers in order, validating every length against the remaining buffer before
    advancing (no over-read, no over-allocation — the member data is never materialized). Stops at
    the ``TRAILER!!!`` sentinel (not included). Totally defined on arbitrary input: returns a list
    or raises :class:`CpioError`; never hangs, over-reads, recurses, or divides by zero.

    Args:
        data: The full (decompressed) cpio archive bytes — HOSTILE input.
        max_entries: Hard cap on the number of members parsed (CWE-400); exceeding it fails closed.

    Returns:
        The parsed members in archive order (excluding the trailer).

    Raises:
        CpioError: On bad magic, truncation, a field overrunning the buffer, a non-hex field, an
            over-long name, or exceeding ``max_entries``.
    """
    if max_entries <= 0:
        raise CpioError("max_entries must be positive")

    entries: list[CpioEntry] = []
    pos = 0
    total = len(data)

    while True:
        if pos + _HEADER_LEN > total:
            raise CpioError("truncated cpio header (no TRAILER!!! sentinel)")
        magic = data[pos : pos + 6]
        if magic not in (_MAGIC_NEWC, _MAGIC_NEWC_CRC):
            raise CpioError("bad cpio member magic")

        # newc header: magic(6) + ino,mode,uid,gid,nlink,mtime,filesize,devmajor,devminor,
        # rdevmajor,rdevminor,namesize,check — each an 8-char ASCII hex field.
        mode = _u32_hex(data[pos + 14 : pos + 22])
        filesize = _u32_hex(data[pos + 54 : pos + 62])
        namesize = _u32_hex(data[pos + 94 : pos + 102])

        if namesize == 0 or namesize > _MAX_NAME_LEN:
            raise CpioError("cpio namesize is zero or exceeds the cap")

        name_start = pos + _HEADER_LEN
        name_end = name_start + namesize
        if name_end > total:
            raise CpioError("cpio member name overruns the buffer")
        # The name includes a trailing NUL; drop it (and anything after a NUL — defensive).
        raw_name = bytes(data[name_start:name_end])
        name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")

        # Header + name are padded to a 4-byte boundary; the data follows.
        data_start = _pad4(name_end)
        data_end = data_start + filesize
        # data_start may legitimately equal total for a zero-size final member; data_end must fit.
        if data_end > total:
            raise CpioError("cpio member data overruns the buffer")

        if name == _TRAILER_NAME:
            return entries

        if len(entries) >= max_entries:
            raise CpioError("cpio archive exceeds the max_entries cap")

        entries.append(
            CpioEntry(
                name=name,
                mode=mode,
                size=filesize,
                data_offset=data_start,
                is_dir=(mode & _S_IFMT) == _S_IFDIR,
                is_symlink=(mode & _S_IFMT) == _S_IFLNK,
            )
        )

        # Advance past the (4-padded) data to the next header.
        pos = _pad4(data_end)
