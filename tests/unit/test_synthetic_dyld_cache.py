"""Validate the synthetic ``dyld_shared_cache`` fixture (ADR-086; #369).

The `dyld` loader extracts one component dylib from a shared cache and imports it as Mach-O. ADR-063
deferred dyld support as *fixture*-blocked (no hermetic way to make a mountable cache); this fixture
is the unblocker: a deterministic, benign `dyld_v1` cache whose header + single mapping + single
image + embedded ``MH_DYLIB`` are self-consistent with Ghidra's ``SplitDyldCache.getMacho`` linear
``imageAddress - baseAddress`` model. These tests parse the fixture independently (no worker) to
prove it is well-formed — the structural contract the loader relies on. The gated live-regression
integration test proves Ghidra actually mounts + extracts it.
"""

from __future__ import annotations

import struct

import pytest

from tests._fixtures import binaries

_MH_MAGIC_64 = 0xFEEDFACF
_MH_DYLIB = 0x6


def _parse_header(cache: bytes) -> dict[str, int]:
    """Parse the dyld cache header fields the fixture populates (offsets/counts + base address)."""
    map_off, map_cnt, img_off, img_cnt, base = struct.unpack_from("<IIIIQ", cache, 16)
    return {
        "map_off": map_off,
        "map_cnt": map_cnt,
        "img_off": img_off,
        "img_cnt": img_cnt,
        "base": base,
    }


def test_magic_and_single_mapping_single_image() -> None:
    """The cache starts with the ``dyld_v1  <arch>`` magic + declares exactly one mapping/image."""
    cache = binaries.synthetic_dyld_shared_cache()
    assert cache[:9] == b"dyld_v1  "
    assert cache[9:16].rstrip(b"\x00") == b"x86_64"
    h = _parse_header(cache)
    assert h["map_cnt"] == 1 and h["img_cnt"] == 1
    assert h["base"] == binaries._DYLD_DEFAULT_BASE


def test_mapping_covers_file_from_offset_zero_at_base() -> None:
    """The single mapping starts at ``base`` with file offset 0 (the linear ``getMacho`` model)."""
    cache = binaries.synthetic_dyld_shared_cache()
    h = _parse_header(cache)
    addr, size, file_off, _max_prot, _init_prot = struct.unpack_from("<QQQII", cache, h["map_off"])
    assert addr == h["base"]
    assert file_off == 0  # base ⇒ file offset 0, so imageAddress - base is the component's offset
    assert size == len(cache)


def test_image_address_resolves_to_embedded_macho() -> None:
    """The image address, minus the base, lands on a real ``MH_DYLIB`` Mach-O in the cache bytes."""
    cache = binaries.synthetic_dyld_shared_cache()
    h = _parse_header(cache)
    image_addr, _mod, _inode, path_off, _pad = struct.unpack_from("<QQQII", cache, h["img_off"])
    # getMacho reads the component at imageAddress - baseAddress (linear): assert a Mach-O is there.
    macho_off = image_addr - h["base"]
    magic, _cpu, _sub, filetype = struct.unpack_from("<IiiI", cache, macho_off)
    assert magic == _MH_MAGIC_64
    assert filetype == _MH_DYLIB
    # The image's path field points at the component path string.
    path_end = cache.index(b"\x00", path_off)
    assert cache[path_off:path_end] == b"/usr/lib/libviv.dylib"


def test_component_path_and_arch_are_parameterizable() -> None:
    """A custom component path + arch token are placed verbatim (self-consistent)."""
    cache = binaries.synthetic_dyld_shared_cache(
        arch=b"arm64", component_path=b"/usr/lib/libcustom.dylib"
    )
    assert cache[9:16].rstrip(b"\x00") == b"arm64"
    h = _parse_header(cache)
    _addr, _mod, _inode, path_off, _pad = struct.unpack_from("<QQQII", cache, h["img_off"])
    path_end = cache.index(b"\x00", path_off)
    assert cache[path_off:path_end] == b"/usr/lib/libcustom.dylib"


def test_slid_cache_is_base_relative() -> None:
    """A non-default ("slid") base still resolves (ADR-089 #419): imageAddr - base == macho offset.

    `getMacho` reads a component at ``imageAddress - cacheBaseAddress``, so the extraction is
    base-relative — a cache loaded at a slid base must still land on the embedded Mach-O, proving
    the fixture + the offset model are slide-correct (not hardcoded to the default base).
    """
    slid_base = 0x180000000  # a different ("slid") base than the default
    cache = binaries.synthetic_dyld_shared_cache(base_address=slid_base)
    h = _parse_header(cache)
    assert h["base"] == slid_base
    image_addr, _mod, _inode, _path_off, _pad = struct.unpack_from("<QQQII", cache, h["img_off"])
    macho_off = image_addr - h["base"]
    magic, _cpu, _sub, filetype = struct.unpack_from("<IiiI", cache, macho_off)
    assert magic == _MH_MAGIC_64 and filetype == _MH_DYLIB  # the slide did not break the offset


def test_deterministic_and_benign() -> None:
    """Byte-for-byte reproducible (fixed constants, no clock/randomness) — hermetic fixture."""
    a = binaries.synthetic_dyld_shared_cache()
    b = binaries.synthetic_dyld_shared_cache()
    assert a == b


def test_arch_token_too_long_rejected() -> None:
    """An arch token that overflows the 16-byte magic fails closed (no silent truncation)."""
    with pytest.raises(ValueError, match="arch token too long"):
        binaries.synthetic_dyld_shared_cache(arch=b"this_is_way_too_long_for_the_magic")
