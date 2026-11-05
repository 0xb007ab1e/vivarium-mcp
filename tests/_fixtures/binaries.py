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


# --- Android boot image (ADR-070 `androidboot` container; fixture for #380) ----------------------

#: Android boot image magic (`boot_img_hdr`).
ANDROID_BOOT_MAGIC = b"ANDROID!"

#: Default page size used to lay out a synthetic boot image (a common real value).
_ANDROID_DEFAULT_PAGE = 2048


def _page_round_up(size: int, page: int) -> int:
    """Round ``size`` up to the next multiple of ``page`` (the boot-image region alignment)."""
    return ((size + page - 1) // page) * page


def synthetic_android_boot_image(
    *,
    page_size: int = _ANDROID_DEFAULT_PAGE,
    kernel: bytes | None = None,
    ramdisk: bytes | None = None,
    second: bytes = b"",
) -> bytes:
    """Build a deterministic, benign Android boot image (`boot_img_hdr` v0).

    Byte-for-byte reproducible (fixed constants, no randomness/clock/I/O). Lays out a standard
    `ANDROID!` header (page 0) followed by the **page-aligned kernel, ramdisk, and optional second**
    regions — exactly the structure the deferred `androidboot` loader must parse to surface
    the kernel and (the #380 gap) the **ramdisk** region. Not a real program: the kernel/ramdisk
    payloads are small marker blobs (the default ramdisk is a real gzip stream, since Android
    ramdisks are a compressed cpio — so the ramdisk-decompress follow-on is exercisable too).

    Header layout (LE): ``magic[8]``, ten ``u32`` (kernel_size, kernel_addr, ramdisk_size,
    ramdisk_addr, second_size, second_addr, tags_addr, page_size, header_version, os_version),
    ``name[16]``, ``cmdline[512]``, ``id[32]`` (zeroed — a fixture needs no real SHA1), and
    ``extra_cmdline[1024]`` = 1632 bytes, then zero-padded to ``page_size``.

    Args:
        page_size: Region alignment (must be > 0); regions start on page boundaries.
        kernel: Kernel region bytes (default: a benign marker blob).
        ramdisk: Ramdisk region bytes (default: a gzip-compressed benign marker, ``mtime=0`` for
            reproducibility).
        second: Optional second-stage region bytes (default: none).

    Returns:
        The complete boot-image bytes.
    """
    import gzip

    if page_size <= 0:
        msg = "page_size must be positive"
        raise ValueError(msg)
    if kernel is None:
        kernel = b"KERNEL--synthetic-benign-payload\n"
    if ramdisk is None:
        ramdisk = gzip.compress(b"RAMDISK--synthetic-benign-cpio\n", mtime=0)

    header = struct.pack(
        "<8sIIIIIIIIII16s512s32s1024s",
        ANDROID_BOOT_MAGIC,
        len(kernel),
        0x10008000,  # kernel_addr (conventional; inert in a fixture)
        len(ramdisk),
        0x11000000,  # ramdisk_addr
        len(second),
        0x10F00000,  # second_addr
        0x10000100,  # tags_addr
        page_size,
        0,  # header_version (v0)
        0,  # os_version
        b"vivarium-fixture",  # name[16] (exactly 16 bytes)
        b"console=ttyS0",  # cmdline (zero-padded to 512 by struct)
        b"",  # id[32] (zeroed — no real SHA1 needed)
        b"",  # extra_cmdline (zero-padded to 1024)
    )

    def _region(payload: bytes) -> bytes:
        return payload + b"\x00" * (_page_round_up(len(payload), page_size) - len(payload))

    blob = bytearray()
    blob += _region(header)  # header occupies page 0 (1632 B rounded up to page_size)
    blob += _region(kernel)
    blob += _region(ramdisk)
    if second:
        blob += _region(second)
    return bytes(blob)


# --- synthetic dyld_shared_cache (ADR-086, #369) -------------------------------------------------
#: Default cache base address (the address that maps to file offset 0). Ghidra's
#: `SplitDyldCache.getMacho` reads a component at `imageAddress - baseAddress` (a LINEAR model), so
#: the single mapping must cover from file offset 0 at this base.
_DYLD_DEFAULT_BASE = 0x7FFF00000000


def _minimal_macho_dylib(install_name: bytes, *, vmaddr: int, fileoff: int, vmsize: int) -> bytes:
    """Build a minimal x86-64 ``MH_DYLIB`` Mach-O (header + ``__TEXT`` segment + ``LC_ID_DYLIB``).

    Deterministic + side-effect-free. Used only as a dyld-cache component; ``vmaddr``/``fileoff``
    are the component's address + cache file offset so Ghidra's cache reader resolves it.
    """
    import struct

    mh_magic_64, cpu_x86_64, cpu_sub, mh_dylib = 0xFEEDFACF, 0x01000007, 3, 0x6
    lc_segment_64, lc_id_dylib = 0x19, 0xD
    namez = install_name + b"\x00"
    idcmd_size = (24 + len(namez) + 7) // 8 * 8
    idcmd = struct.pack("<IIIIII", lc_id_dylib, idcmd_size, 24, 0, 0x10000, 0x10000) + namez
    idcmd += b"\x00" * (idcmd_size - len(idcmd))
    seg = struct.pack(
        "<II16sQQQQIIII", lc_segment_64, 72, b"__TEXT", vmaddr, vmsize, fileoff, vmsize, 5, 5, 0, 0
    )
    cmds = seg + idcmd
    hdr = struct.pack("<IiiIIIII", mh_magic_64, cpu_x86_64, cpu_sub, mh_dylib, 2, len(cmds), 0, 0)
    return hdr + cmds


def synthetic_dyld_shared_cache(
    *,
    arch: bytes = b"x86_64",
    component_path: bytes = b"/usr/lib/libviv.dylib",
    base_address: int = _DYLD_DEFAULT_BASE,
) -> bytes:
    """Build a deterministic, benign, hermetic ``dyld_shared_cache`` with one component dylib.

    Byte-for-byte reproducible (fixed constants, no randomness/clock/I/O). Lays out a minimal, SELF-
    CONSISTENT cache that Ghidra's ``DyldCacheFileSystem`` mounts and extracts the component from
    (verified live against the pinned worker, ADR-086): a ``dyld_v1  <arch>`` header, one
    ``dyld_cache_mapping_info`` covering the whole file from offset 0 at ``base_address`` (Ghidra's
    ``SplitDyldCache.getMacho`` reads a component at ``imageAddress - baseAddress`` — a LINEAR
    model, so the mapping fileOffset is 0 and the image address = base + the Mach-O file offset),
    one ``dyld_cache_image_info`` → the embedded ``MH_DYLIB`` Mach-O, and the component path string.
    Not a real system cache: one tiny synthetic dylib — it proves the loader wiring, the hermetic
    fixture path ADR-063 was blocked on (master §5: tests build their own deterministic inputs).

    Args:
        arch: The cache architecture token in the magic (e.g. ``b"x86_64"``, ``b"arm64"``).
        component_path: The in-cache path of the single component dylib.
        base_address: The cache base address (maps to file offset 0).

    Returns:
        The synthetic ``dyld_shared_cache`` bytes.
    """
    import struct

    macho_foff = 0x2000  # the embedded Mach-O's FILE offset ⇒ image address = base + macho_foff
    magic = b"dyld_v1  " + arch
    magic += b"\x00" * (16 - len(magic))
    if len(magic) != 16:
        raise ValueError("dyld arch token too long for the 16-byte magic")
    hdr_size = 0x100
    map_off, map_cnt = hdr_size, 1
    img_off, img_cnt = map_off + 32, 1
    path_off = img_off + 32
    path = component_path + b"\x00"
    file_size = macho_foff + 0x1000

    hdr = bytearray(hdr_size)
    hdr[0:16] = magic
    # magic[16] | mappingOffset u32 | mappingCount u32 | imagesOffsetOld u32 | imagesCountOld u32 |
    # dyldBaseAddress u64 — the only fields Ghidra needs for a single-image mount.
    struct.pack_into("<IIIIQ", hdr, 16, map_off, map_cnt, img_off, img_cnt, base_address)
    mapping = struct.pack(
        "<QQQII", base_address, file_size, 0, 5, 5
    )  # addr,size,fileOff=0,prot r-x
    image_addr = base_address + macho_foff
    image = struct.pack(
        "<QQQII", image_addr, 0, 0, path_off, 0
    )  # address,modTime,inode,pathOff,pad

    out = bytearray(file_size)
    out[0:hdr_size] = hdr
    out[map_off : map_off + 32] = mapping
    out[img_off : img_off + 32] = image
    out[path_off : path_off + len(path)] = path
    macho = _minimal_macho_dylib(
        component_path, vmaddr=image_addr, fileoff=macho_foff, vmsize=0x1000
    )
    out[macho_foff : macho_foff + len(macho)] = macho
    return bytes(out)


# --- synthetic cpio newc archive (ADR-087, #415) -------------------------------------------------
def cpio_newc_archive(entries: list[tuple[str, int, bytes]]) -> bytes:
    """Build a deterministic cpio ``newc`` (``070701``) archive + the ``TRAILER!!!`` sentinel.

    Byte-for-byte reproducible (fixed ino/mtime, no clock/randomness). Mirrors the kernel's
    `gen_init_cpio` layout: a 110-byte ASCII header per member, the NUL-terminated name padded to a
    4-byte boundary, then the data padded to a 4-byte boundary. Used to exercise the pure
    :func:`vivarium.core.cpio.parse_newc_entries`.

    Args:
        entries: ``(name, mode, data)`` per member (``mode`` carries the file-type bits).

    Returns:
        The cpio ``newc`` archive bytes.
    """

    def _f(value: int) -> bytes:
        return b"%08x" % value

    def _pad4(buf: bytes) -> bytes:
        return buf + b"\x00" * ((-len(buf)) % 4)

    def _member(name: str, mode: int, data: bytes) -> bytes:
        namez = name.encode() + b"\x00"
        header = (
            b"070701"
            + _f(1)  # ino
            + _f(mode)
            + _f(0)  # uid
            + _f(0)  # gid
            + _f(1)  # nlink
            + _f(0)  # mtime
            + _f(len(data))  # filesize
            + _f(0)  # devmajor
            + _f(0)  # devminor
            + _f(0)  # rdevmajor
            + _f(0)  # rdevminor
            + _f(len(namez))  # namesize
            + _f(0)  # check
        )
        return _pad4(header + namez) + _pad4(data)

    out = b"".join(_member(name, mode, data) for name, mode, data in entries)
    return out + _member("TRAILER!!!", 0, b"")
