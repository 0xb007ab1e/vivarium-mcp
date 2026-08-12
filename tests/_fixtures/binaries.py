"""Pure-Python deterministic synthetic binary builders (benign; no payload).

These emit minimal, well-formed magic-and-header byte blobs for the two formats v1 supports
classifying (ELF, PE) plus malformed/oversized variants for abuse and bounds tests. Everything is
constructed with ``struct.pack`` from fixed constants — byte-for-byte reproducible, no randomness,
no clock, no I/O.

IMPORTANT (master §5, PLAN §6): these are NOT real programs and contain NO executable payload.
They exist so tests never need a committed binary sample or any real malware. A real Ghidra worker
(integration suite) may or may not fully analyze such a minimal blob; the unit suite only uses
them as opaque byte inputs to exercise size checks, hashing, and import plumbing through the fake
port.

Reference: ELF64 header layout (Elfxx_Ehdr) and PE/COFF (MS-DOS stub + PE signature + COFF header).
We populate exactly the fields a magic-byte sniffer reads; the rest is zero-padded.
"""

from __future__ import annotations

import struct

# ELF identification constants (e_ident).
_ELF_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_ELFDATA2LSB = 1  # little-endian
_EV_CURRENT = 1
_ELFOSABI_SYSV = 0
_ELFCLASS32 = 1
_ET_REL = 1
_ET_EXEC = 2
_EM_X86_64 = 62
_EM_ARM = 40
_EM_RISCV = 243

# Section/segment constants for the section-bearing 32-bit builders (F5).
_PT_LOAD = 1
_SHT_PROGBITS = 1
_SHT_STRTAB = 3
_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4
_ELF32_BASE_VADDR = 0x10000
_ELF32_EHDR_SIZE = 52
_ELF32_PHDR_SIZE = 32
_ELF32_SHDR_SIZE = 40
#: A benign Thumb blob (eight ``NOP`` then ``BX LR``) used as ``.text`` for the ARM builders.
_THUMB_NOPS_RET = b"\x00\xbf" * 8 + b"\x70\x47"
#: A benign RV32 blob (four ``nop`` then ``ret``).
_RV32_NOPS_RET = b"\x13\x00\x00\x00" * 4 + b"\x67\x80\x00\x00"

# PE constants.
_DOS_MAGIC = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"
_IMAGE_FILE_MACHINE_AMD64 = 0x8664


def build_elf64(*, n_section_pad: int = 64) -> bytes:
    """Build a minimal, deterministic little-endian x86-64 ELF executable header blob.

    Produces a valid 64-byte ``Elf64_Ehdr`` (magic + class/data/version, machine x86-64, type
    EXEC) followed by zero padding so the blob has a small, fixed nonzero body. A format sniffer
    keys off the leading ``\\x7fELF`` magic and the class/data/machine fields, all of which are
    correct here.

    Args:
        n_section_pad: Bytes of zero padding appended after the 64-byte header (deterministic
            filler so size/hash are stable and nonzero). Must be non-negative.

    Returns:
        The synthetic ELF byte blob (length ``64 + n_section_pad``).
    """
    if n_section_pad < 0:
        msg = "n_section_pad must be non-negative"
        raise ValueError(msg)
    e_ident = (
        _ELF_MAGIC
        + bytes([_ELFCLASS64, _ELFDATA2LSB, _EV_CURRENT, _ELFOSABI_SYSV])
        + b"\x00" * 8  # ABI version + padding
    )
    # Elf64_Ehdr after e_ident: type, machine, version, entry, phoff, shoff, flags,
    # ehsize, phentsize, phnum, shentsize, shnum, shstrndx.
    rest = struct.pack(
        "<HHIQQQIHHHHHH",
        _ET_EXEC,  # e_type
        _EM_X86_64,  # e_machine
        _EV_CURRENT,  # e_version
        0x00401000,  # e_entry
        0,  # e_phoff
        0,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        0,  # e_phentsize
        0,  # e_phnum
        0,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )
    header = e_ident + rest
    assert len(header) == 64  # invariant on the fixed 64-byte Elf64_Ehdr layout
    return header + b"\x00" * n_section_pad


def build_pe32(*, n_body_pad: int = 64) -> bytes:
    """Build a minimal, deterministic PE (MS-DOS stub + PE signature + COFF header) blob.

    Produces a 64-byte MS-DOS header whose ``e_lfanew`` points just past it to the ``PE\\x00\\x00``
    signature, followed by a minimal COFF file header declaring machine AMD64. A format sniffer
    keys off ``MZ`` then the ``PE\\x00\\x00`` signature at ``e_lfanew``, both correct here.

    Args:
        n_body_pad: Bytes of zero padding appended after the COFF header. Non-negative.

    Returns:
        The synthetic PE byte blob.
    """
    if n_body_pad < 0:
        msg = "n_body_pad must be non-negative"
        raise ValueError(msg)
    e_lfanew = 64
    dos_header = (
        _DOS_MAGIC + b"\x00" * (e_lfanew - len(_DOS_MAGIC) - 4) + struct.pack("<I", e_lfanew)
    )
    assert len(dos_header) == e_lfanew  # e_lfanew lands exactly at the PE signature
    # COFF IMAGE_FILE_HEADER: machine, num_sections, timestamp, ptr_symtab, num_syms,
    # opt_header_size, characteristics.
    coff = struct.pack(
        "<HHIIIHH",
        _IMAGE_FILE_MACHINE_AMD64,
        0,  # num sections
        0,  # timestamp (fixed → deterministic)
        0,  # ptr to symbol table
        0,  # num symbols
        0,  # size of optional header
        0x0002,  # IMAGE_FILE_EXECUTABLE_IMAGE
    )
    return dos_header + _PE_SIGNATURE + coff + b"\x00" * n_body_pad


def build_elf32_exec(machine: int, code: bytes, *, e_flags: int = 0) -> bytes:
    """Build a section-bearing, PT_LOAD-bearing little-endian 32-bit ELF **executable** (F5).

    Unlike :func:`build_elf64` (a header-only sniffer blob), this emits a *complete, readelf-clean*
    ``Elf32`` executable: a 52-byte ``Elf32_Ehdr``, one ``PT_LOAD`` program header mapping the whole
    file at :data:`_ELF32_BASE_VADDR`, a ``.text`` (``PROGBITS``, ``AX``) section holding ``code``,
    a ``.shstrtab``, and the three section headers (null/.text/.shstrtab). It is the synthetic
    analogue of the v1.8 F5 firmware-ELF case — a Ghidra worker can actually load + analyze it.

    Args:
        machine: The ``e_machine`` value (e.g. :data:`_EM_ARM`, :data:`_EM_RISCV`).
        code: The raw ``.text`` bytes (benign machine code; no payload).
        e_flags: The ``e_flags`` word (e.g. ARM EABI ``0x05000200``); ``0`` if irrelevant.

    Returns:
        The synthetic 32-bit ELF executable byte blob.
    """
    shstr = b"\x00.text\x00.shstrtab\x00"
    text_name_off, shstr_name_off = 1, 7
    phoff = _ELF32_EHDR_SIZE
    text_off = phoff + _ELF32_PHDR_SIZE  # one program header
    text_vaddr = _ELF32_BASE_VADDR + text_off
    shstr_off = text_off + len(code)
    shoff = shstr_off + len(shstr)
    filesz = shoff + _ELF32_SHDR_SIZE * 3  # whole file is mapped by the single PT_LOAD

    e_ident = (
        _ELF_MAGIC + bytes([_ELFCLASS32, _ELFDATA2LSB, _EV_CURRENT, _ELFOSABI_SYSV]) + b"\x00" * 8
    )
    ehdr = e_ident + struct.pack(
        "<HHIIIIIHHHHHH",
        _ET_EXEC,
        machine,
        _EV_CURRENT,
        text_vaddr,
        phoff,
        shoff,
        e_flags,
        _ELF32_EHDR_SIZE,
        _ELF32_PHDR_SIZE,
        1,
        _ELF32_SHDR_SIZE,
        3,
        2,
    )
    assert len(ehdr) == _ELF32_EHDR_SIZE
    phdr = struct.pack(
        "<IIIIIIII",
        _PT_LOAD,
        0,
        _ELF32_BASE_VADDR,
        _ELF32_BASE_VADDR,
        filesz,
        filesz,
        0x5,
        0x1000,  # RX
    )

    def _shdr(name: int, typ: int, flags: int, addr: int, off: int, size: int, align: int) -> bytes:
        return struct.pack("<IIIIIIIIII", name, typ, flags, addr, off, size, 0, 0, align, 0)

    blob = bytearray(filesz)
    blob[0 : len(ehdr)] = ehdr
    blob[phoff : phoff + len(phdr)] = phdr
    blob[text_off : text_off + len(code)] = code
    blob[shstr_off : shstr_off + len(shstr)] = shstr
    blob[shoff : shoff + _ELF32_SHDR_SIZE] = _shdr(0, 0, 0, 0, 0, 0, 0)
    blob[shoff + _ELF32_SHDR_SIZE : shoff + 2 * _ELF32_SHDR_SIZE] = _shdr(
        text_name_off,
        _SHT_PROGBITS,
        _SHF_ALLOC | _SHF_EXECINSTR,
        text_vaddr,
        text_off,
        len(code),
        2,
    )
    blob[shoff + 2 * _ELF32_SHDR_SIZE : shoff + 3 * _ELF32_SHDR_SIZE] = _shdr(
        shstr_name_off, _SHT_STRTAB, 0, 0, shstr_off, len(shstr), 1
    )
    return bytes(blob)


def synthetic_arm32_elf() -> bytes:
    """Return a readelf-clean 32-bit little-endian ARM (Cortex, EABI5) executable (F5 fixture)."""
    return build_elf32_exec(_EM_ARM, _THUMB_NOPS_RET, e_flags=0x05000200)


def synthetic_riscv32_elf() -> bytes:
    """Return a readelf-clean 32-bit little-endian RISC-V executable (F5 fixture)."""
    return build_elf32_exec(_EM_RISCV, _RV32_NOPS_RET)


def malformed_elf() -> bytes:
    """Build a deliberately malformed ELF: correct magic, garbage/truncated header.

    Has the ``\\x7fELF`` magic (so a sniffer starts parsing) but a truncated, internally invalid
    header — drives the ``ANALYSIS_FAILED`` / parser-robustness abuse path (WS4) without any real
    malware.

    Returns:
        A malformed ELF byte blob.
    """
    return _ELF_MAGIC + bytes([_ELFCLASS64, _ELFDATA2LSB]) + b"\xff" * 6  # truncated e_ident only


def truncated_pe() -> bytes:
    """Build a deliberately malformed PE: ``MZ`` magic with a dangling ``e_lfanew``.

    The DOS magic is present but ``e_lfanew`` points past the end of the blob, so there is no PE
    signature to find — a parser must reject it (abuse / fail-closed path).

    Returns:
        A truncated/malformed PE byte blob.
    """
    return _DOS_MAGIC + b"\x00" * 58 + struct.pack("<I", 0x7FFFFFFF)  # e_lfanew way out of range


def oversized_blob(size_bytes: int) -> bytes:
    """Build a deterministic blob of exactly ``size_bytes`` zero bytes for size-cap abuse tests.

    Used to drive ``check_binary_size`` / ``LIMIT_EXCEEDED`` boundary tests (just over a cap)
    without allocating gigabytes — callers pass a small ``size_bytes`` and a small test limit.

    Args:
        size_bytes: Exact length of the returned blob. Non-negative.

    Returns:
        ``size_bytes`` zero bytes.
    """
    if size_bytes < 0:
        msg = "size_bytes must be non-negative"
        raise ValueError(msg)
    return b"\x00" * size_bytes


def zeros(n: int) -> bytes:
    """Return ``n`` zero bytes (a format-less blob — neither ELF nor PE; a sniffer rejects it)."""
    if n < 0:
        msg = "n must be non-negative"
        raise ValueError(msg)
    return b"\x00" * n


# Pre-built constants for tests that want a ready malformed sample without calling a builder.
MALFORMED_ELF = malformed_elf()
"""A deliberately malformed ELF blob (correct magic, truncated header)."""

TRUNCATED_PE = truncated_pe()
"""A deliberately malformed PE blob (MZ magic, out-of-range e_lfanew)."""
