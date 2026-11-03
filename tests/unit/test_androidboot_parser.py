"""Unit + fuzz tests for the pure Android boot-image header parser (ADR-070; #380).

`core.androidboot.parse_android_boot_header` is a hostile-bytes boundary (ADR-005): it must be
total on the header window — a validated :class:`AndroidBootHeader` or a :class:`ValueError`, never
a crash, hang, over-read, or divide-by-zero. The fuzz test is the proof of that contract; the unit
tests pin the page-aligned region arithmetic against the synthetic fixture (#383).
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests._fixtures import binaries
from vivarium.core.androidboot import (
    ANDROID_BOOT_MAGIC,
    AndroidBootHeader,
    parse_android_boot_header,
)

_CAP = 1 << 30  # 1 GiB region cap for the tests


def test_parses_the_synthetic_fixture() -> None:
    """The #383 fixture parses to the correct page-aligned kernel + ramdisk windows."""
    kernel = b"KERNEL-payload" * 4
    ramdisk = b"RD" * 11
    img = binaries.synthetic_android_boot_image(kernel=kernel, ramdisk=ramdisk, page_size=2048)
    h = parse_android_boot_header(img, max_region_size=_CAP)
    assert h.page_size == 2048
    assert h.kernel_offset == 2048 and h.kernel_size == len(kernel)
    # Ramdisk starts after the page-aligned kernel (one page for a sub-page kernel).
    assert h.ramdisk_offset == 2048 + 2048 and h.ramdisk_size == len(ramdisk)
    # The computed windows extract the exact payloads from the image.
    assert img[h.kernel_offset : h.kernel_offset + h.kernel_size] == kernel
    assert img[h.ramdisk_offset : h.ramdisk_offset + h.ramdisk_size] == ramdisk


def test_bad_magic_rejected() -> None:
    img = bytearray(binaries.synthetic_android_boot_image())
    img[:8] = b"NOTANDR!"
    with pytest.raises(ValueError, match="magic"):
        parse_android_boot_header(bytes(img), max_region_size=_CAP)


def test_short_header_rejected() -> None:
    with pytest.raises(ValueError, match="shorter"):
        parse_android_boot_header(ANDROID_BOOT_MAGIC + b"\x00" * 8, max_region_size=_CAP)


@pytest.mark.parametrize("page_size", [0, 1, 100, 3000, (1 << 20) + 1, 2048 + 1])
def test_bad_page_size_rejected(page_size: int) -> None:
    """A zero / non-power-of-two / out-of-range page size fails closed (no div-by-zero / absurd)."""
    hdr = struct.pack("<8sIIIIIIII", ANDROID_BOOT_MAGIC, 16, 0, 0, 0, 0, 0, 0, page_size)
    with pytest.raises(ValueError, match="page_size"):
        parse_android_boot_header(hdr, max_region_size=_CAP)


def test_zero_kernel_rejected() -> None:
    hdr = struct.pack("<8sIIIIIIII", ANDROID_BOOT_MAGIC, 0, 0, 0, 0, 0, 0, 0, 2048)
    with pytest.raises(ValueError, match="kernel_size"):
        parse_android_boot_header(hdr, max_region_size=_CAP)


def test_oversized_region_rejected() -> None:
    """A header claiming a kernel / ramdisk over the cap is rejected before any slice (CWE-400)."""
    big = struct.pack("<8sIIIIIIII", ANDROID_BOOT_MAGIC, 999, 0, 0, 0, 0, 0, 0, 2048)
    with pytest.raises(ValueError, match="kernel_size"):
        parse_android_boot_header(big, max_region_size=100)
    big_rd = struct.pack("<8sIIIIIIII", ANDROID_BOOT_MAGIC, 16, 0, 999, 0, 0, 0, 0, 2048)
    with pytest.raises(ValueError, match="ramdisk_size"):
        parse_android_boot_header(big_rd, max_region_size=100)


def test_zero_ramdisk_is_valid() -> None:
    """A ramdisk_size of 0 (no ramdisk) is allowed; kernel still surfaces."""
    hdr = struct.pack("<8sIIIIIIII", ANDROID_BOOT_MAGIC, 16, 0, 0, 0, 0, 0, 0, 2048)
    h = parse_android_boot_header(hdr, max_region_size=_CAP)
    assert h.kernel_size == 16 and h.ramdisk_size == 0


@given(st.binary(max_size=4096))
def test_parser_is_total_on_arbitrary_bytes(data: bytes) -> None:
    """Arbitrary bytes: either a validated header or a ValueError — never another exception/hang."""
    try:
        h = parse_android_boot_header(data, max_region_size=_CAP)
    except ValueError:
        return
    # A successful parse: sane, in-cap, page-aligned, non-over-reading-by-construction fields.
    assert isinstance(h, AndroidBootHeader)
    assert 0 < h.kernel_size <= _CAP and 0 <= h.ramdisk_size <= _CAP
    assert h.page_size >= 256 and (h.page_size & (h.page_size - 1)) == 0
    assert h.kernel_offset == h.page_size
    assert h.ramdisk_offset >= h.kernel_offset + h.kernel_size
    assert h.ramdisk_offset % h.page_size == 0
