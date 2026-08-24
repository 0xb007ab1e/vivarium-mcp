"""Pure parser for an ELF ``.gnu_debuglink`` section (ADR-071 detached-DWARF follow-up).

A stripped ELF that has its debug info split out carries a ``.gnu_debuglink`` section naming the
companion debug file (e.g. ``prog.debug``) plus a CRC. Ghidra's DWARF analyzer resolves that name
against the binary's directory (``SameDirDebugInfoProvider``) at analysis time — so to apply a
detached ``debug_ref`` the worker stages it next to the binary under exactly this name. This module
extracts ONLY that name: a pure, bounded, hermetically-fuzzable parse over HOSTILE ELF bytes
(``@rules/topic-architecture-patterns`` functional core) — no JVM, no filesystem, no allocation by
an untrusted length. It is total on the header window: it returns the name or ``None``, and must
never crash, hang, or over-read on arbitrary bytes (verified by the property/fuzz tests).
"""

from __future__ import annotations

import struct

_ELF_MAGIC = b"\x7fELF"
_DEBUGLINK = b".gnu_debuglink"
#: Sanity ceiling on the section-header count we will walk (a hostile e_shnum is clamped, CWE-400).
_MAX_SECTIONS = 4096
#: Sanity ceiling on a debuglink filename length (basenames are short; reject absurd claims).
_MAX_NAME = 256


def parse_gnu_debuglink(data: bytes) -> str | None:
    """Return the companion debug filename from an ELF's ``.gnu_debuglink`` section, or ``None``.

    Args:
        data: The ELF file bytes (the whole file; only headers + the two small sections are read).

    Returns:
        The NUL-terminated debug filename (e.g. ``"prog.debug"``) if present + well-formed, else
        ``None`` (not an ELF, no such section, or any malformation — fail closed, never raise).
    """
    try:
        return _parse(data)
    except Exception:  # any malformation on hostile bytes → no name (never propagate — fail closed)
        return None


def _parse(data: bytes) -> str | None:  # noqa: C901 - one bounded ELF-header walk; linear + clearer inline
    if len(data) < 64 or data[:4] != _ELF_MAGIC:
        return None
    is64 = data[4] == 2
    little = data[5] == 1
    endian = "<" if little else ">"

    if is64:
        e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
        e_shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
        e_shstrndx = struct.unpack_from(endian + "H", data, 0x3E)[0]
        off_name, off_off, off_size = 0x00, 0x18, 0x20
    else:
        e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        e_shentsize = struct.unpack_from(endian + "H", data, 0x2E)[0]
        e_shnum = struct.unpack_from(endian + "H", data, 0x30)[0]
        e_shstrndx = struct.unpack_from(endian + "H", data, 0x32)[0]
        off_name, off_off, off_size = 0x00, 0x10, 0x14

    if e_shoff == 0 or e_shentsize == 0 or e_shnum == 0 or e_shnum > _MAX_SECTIONS:
        return None
    if e_shstrndx >= e_shnum:
        return None

    def _section(i: int) -> tuple[int, int, int]:
        base = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from(endian + "I", data, base + off_name)[0]
        width = "Q" if is64 else "I"
        sh_off = struct.unpack_from(endian + width, data, base + off_off)[0]
        sh_size = struct.unpack_from(endian + width, data, base + off_size)[0]
        return sh_name, sh_off, sh_size

    # The section-header string table names every section; look each name up there.
    _sn, str_off, str_size = _section(e_shstrndx)
    if str_off + str_size > len(data):
        return None
    shstr = data[str_off : str_off + str_size]

    for i in range(e_shnum):
        sh_name, sh_off, sh_size = _section(i)
        if sh_name >= len(shstr):
            continue
        end = shstr.find(b"\x00", sh_name)
        name = shstr[sh_name : (end if end != -1 else len(shstr))]
        if name != _DEBUGLINK:
            continue
        if sh_size == 0 or sh_off + sh_size > len(data):
            return None
        blob = data[sh_off : sh_off + sh_size]
        nul = blob.find(b"\x00")
        if nul <= 0 or nul > _MAX_NAME:
            return None
        try:
            link = blob[:nul].decode("ascii")
        except UnicodeDecodeError:
            return None
        # A `.gnu_debuglink` value is a bare filename by spec — never a path. Reject any name
        # carrying a path separator or a `.`/`..` component so a hostile binary cannot steer the
        # worker's later `os.path.join(stage_dir, name)` copy destination outside the staging dir
        # (CWE-22 path-traversal write; AA1). Fail closed = treat as "no debuglink".
        if link in {".", ".."} or "/" in link or "\\" in link:
            return None
        return link
    return None
