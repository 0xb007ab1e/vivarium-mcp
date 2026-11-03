"""Pure parser for the Android boot image (`boot_img_hdr`) header (ADR-070; #380).

An Android boot image wraps a **kernel** (and a ramdisk + optional second stage) behind a fixed
`ANDROID!` header with page-aligned regions. This module parses ONLY the header fields the unwrap
path needs and computes the page-aligned region windows — it never reads a region's bytes, never
allocates by an untrusted length, and never touches the JVM or the filesystem, so it is a pure,
hermetically fuzzable boundary (`@rules/topic-architecture-patterns` functional core). The worker
(`_decompress_container` → `_unwrap_androidboot`) calls :func:`parse_android_boot_header`, then
slices the **kernel** region under the same size caps as the other ADR-070 containers.

Every byte here is HOSTILE input (a firmware image of unknown origin, ADR-005): the parser is total
on the header window — it returns a validated :class:`AndroidBootHeader` or raises
:class:`ValueError`; it must never crash, hang, over-read, or divide by zero on arbitrary bytes
(verified by the property/fuzz tests). Scope note: this surfaces the **kernel** region (the loadable
image to import/analyze). The **ramdisk** is a (compressed) cpio *filesystem* — not loadable code —
surfacing its contents needs a separate filesystem-extract capability — out of scope for a container
loader (#380 follow-up); the header fields + offsets are parsed here so that work can reuse them.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

#: The Android boot image magic, at offset 0.
ANDROID_BOOT_MAGIC: Final = b"ANDROID!"

#: Bytes of the fixed header prefix this parser reads (magic + the eight u32 size/addr/page fields).
#: The full `boot_img_hdr` is larger, but every field we need lives in the first 40 bytes.
_HEADER_PREFIX_SIZE: Final = 40

#: Page-size sanity bounds. Android requires a power-of-two page size; real images use 2048/4096.
#: A zero/garbage value would break the page-alignment arithmetic (div-by-zero / absurd offsets), so
#: it is rejected here before any slice (CWE-20 / CWE-400 / CWE-369).
_MIN_PAGE_SIZE: Final = 256
_MAX_PAGE_SIZE: Final = 1 << 20  # 1 MiB — far above any real boot-image page size


@dataclass(frozen=True)
class AndroidBootHeader:
    """A validated Android boot-image header — the fields + page-aligned windows the unwrap needs.

    Offsets are absolute byte positions into the image, computed from the page-aligned layout
    (header = page 0; kernel = page 1; ramdisk after the page-aligned kernel). All values are
    range-checked against the caller's cap before they leave this module.

    Attributes:
        page_size: The image page size (validated power-of-two within sane bounds).
        kernel_offset: Absolute byte offset of the kernel region (``page_size``).
        kernel_size: Kernel byte count (``> 0``, ``<= max_region_size``).
        ramdisk_offset: Absolute byte offset of the ramdisk region (page-aligned after the kernel).
        ramdisk_size: Ramdisk byte count (``>= 0``, ``<= max_region_size``); ``0`` ⇒ no ramdisk.
    """

    page_size: int
    kernel_offset: int
    kernel_size: int
    ramdisk_offset: int
    ramdisk_size: int


def _page_up(size: int, page: int) -> int:
    """Round ``size`` up to a whole number of ``page``-sized pages (the boot-image alignment)."""
    return ((size + page - 1) // page) * page


def parse_android_boot_header(data: bytes, *, max_region_size: int) -> AndroidBootHeader:
    """Parse + validate an Android boot image header from the leading bytes of a firmware image.

    Args:
        data: The image bytes; only the fixed header prefix is read.
        max_region_size: Absolute ceiling each region's declared size must not exceed — a hostile
            header claiming a huge kernel/ramdisk is rejected here, before any slice/allocation
            (CWE-400 / CWE-190). The caller passes the operator's decompressed-output cap.

    Returns:
        The validated :class:`AndroidBootHeader` with page-aligned region windows.

    Raises:
        ValueError: If the header is short, the magic is wrong, the page size is not a sane
            power-of-two, the kernel size is non-positive or over the cap, or a region size is
            negative / over the cap.
    """
    if len(data) < _HEADER_PREFIX_SIZE:
        raise ValueError("not an Android boot image: shorter than the header prefix")
    magic = data[:8]
    if magic != ANDROID_BOOT_MAGIC:
        raise ValueError("not an Android boot image: bad magic")

    # Little-endian u32 fields after the 8-byte magic: kernel_size, kernel_addr, ramdisk_size,
    # ramdisk_addr, second_size, second_addr, tags_addr, page_size.
    (
        kernel_size,
        _kernel_addr,
        ramdisk_size,
        _ramdisk_addr,
        _second_size,
        _second_addr,
        _tags_addr,
        page_size,
    ) = struct.unpack_from("<IIIIIIII", data, 8)

    if not (_MIN_PAGE_SIZE <= page_size <= _MAX_PAGE_SIZE) or (page_size & (page_size - 1)) != 0:
        raise ValueError("Android boot image: page_size is not a sane power-of-two")
    if not (0 < kernel_size <= max_region_size):
        raise ValueError("Android boot image: kernel_size is zero or over the cap")
    if ramdisk_size > max_region_size:
        raise ValueError("Android boot image: ramdisk_size is over the cap")

    kernel_offset = page_size  # header occupies page 0; kernel starts at page 1
    ramdisk_offset = page_size + _page_up(kernel_size, page_size)
    return AndroidBootHeader(
        page_size=page_size,
        kernel_offset=kernel_offset,
        kernel_size=kernel_size,
        ramdisk_offset=ramdisk_offset,
        ramdisk_size=ramdisk_size,
    )
