"""Validate the synthetic Android boot-image fixture (`androidboot` — ADR-070; #380).

The `androidboot` container loader is deferred (the schema's container allow-list is
`gzip`/`xz`/`lzma`/`uimage`; `androidboot` fails closed today). This fixture is the prerequisite for
implementing it (kernel + the #380 ramdisk region): a deterministic, benign `ANDROID!` boot image
whose header + page-aligned regions parse back exactly. These tests parse the fixture independently
(no worker) to prove it is well-formed and that the **ramdisk region is locatable and extractable**
— the structural contract the loader will rely on.
"""

from __future__ import annotations

import gzip
import struct

import pytest

from tests._fixtures import binaries

_PAGE = 2048
_HDR = "<8sIIIIIIIIII16s512s32s1024s"


def _parse(image: bytes) -> dict[str, int]:
    """Parse the integer boot_img_hdr v0 fields this fixture populates (sizes + page_size)."""
    fields = struct.unpack_from(_HDR, image, 0)
    return {
        "kernel_size": fields[1],
        "ramdisk_size": fields[3],
        "second_size": fields[5],
        "page_size": fields[8],
        "header_version": fields[9],
    }


def _round_up(size: int, page: int) -> int:
    return ((size + page - 1) // page) * page


def _region(image: bytes, offset: int, size: int) -> bytes:
    return image[offset : offset + size]


def test_magic_and_header_fields() -> None:
    """The image starts with the ANDROID! magic and a v0 header carrying the real region sizes."""
    kernel = b"KERN" * 10
    ramdisk = b"RDSK" * 7
    img = binaries.synthetic_android_boot_image(kernel=kernel, ramdisk=ramdisk, page_size=_PAGE)
    assert struct.unpack_from(_HDR, img, 0)[0] == binaries.ANDROID_BOOT_MAGIC
    h = _parse(img)
    assert h["kernel_size"] == len(kernel) and h["ramdisk_size"] == len(ramdisk)
    assert h["page_size"] == _PAGE and h["header_version"] == 0
    assert h["second_size"] == 0


def test_regions_page_aligned_and_extractable() -> None:
    """Kernel and ramdisk sit at page-aligned offsets and extract back byte-for-byte."""
    kernel = b"KERNEL-bytes-xyz"
    ramdisk = b"RAMDISK-bytes-abc"
    img = binaries.synthetic_android_boot_image(kernel=kernel, ramdisk=ramdisk, page_size=_PAGE)
    h = _parse(img)
    # Header occupies page 0; kernel starts at page 1; ramdisk after the page-aligned kernel.
    kernel_off = _PAGE
    ramdisk_off = _PAGE + _round_up(h["kernel_size"], _PAGE)
    assert kernel_off % _PAGE == 0 and ramdisk_off % _PAGE == 0
    assert _region(img, kernel_off, h["kernel_size"]) == kernel
    # The #380 target: the ramdisk region is locatable from the header and extracts exactly.
    assert _region(img, ramdisk_off, h["ramdisk_size"]) == ramdisk


def test_default_ramdisk_is_a_real_gzip_stream() -> None:
    """The default ramdisk is a reproducible gzip cpio-stand-in → the decompress follow-on works."""
    img = binaries.synthetic_android_boot_image()
    h = _parse(img)
    ramdisk_off = _PAGE + _round_up(h["kernel_size"], _PAGE)
    ramdisk = _region(img, ramdisk_off, h["ramdisk_size"])
    assert gzip.decompress(ramdisk) == b"RAMDISK--synthetic-benign-cpio\n"


def test_total_length_is_page_multiple_and_deterministic() -> None:
    """The image is a whole number of pages and byte-for-byte reproducible (no clock/randomness)."""
    a = binaries.synthetic_android_boot_image()
    b = binaries.synthetic_android_boot_image()
    assert a == b  # deterministic (gzip mtime=0, fixed constants)
    assert len(a) % _PAGE == 0


def test_second_region_appended_when_present() -> None:
    """An optional second-stage region is laid out page-aligned after the ramdisk."""
    second = b"SECOND-stage"
    img = binaries.synthetic_android_boot_image(second=second, page_size=_PAGE)
    h = _parse(img)
    assert h["second_size"] == len(second)
    second_off = _PAGE + _round_up(h["kernel_size"], _PAGE) + _round_up(h["ramdisk_size"], _PAGE)
    assert _region(img, second_off, h["second_size"]) == second


def test_bad_page_size_rejected() -> None:
    """A non-positive page size fails closed (no divide-by-zero / degenerate layout)."""
    with pytest.raises(ValueError, match="page_size"):
        binaries.synthetic_android_boot_image(page_size=0)
