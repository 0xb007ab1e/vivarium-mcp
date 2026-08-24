"""Unit + property/fuzz tests for the pure uImage header parser (ADR-070 container follow-up).

The worker's ``_unwrap_uimage`` (filesystem streaming + nested decompress) is a
``# pragma: no cover`` worker edge validated against a real worker; these cover the PURE
``core.uimage.parse_uimage_header`` boundary — the hostile-bytes parser. The fuzz test is the
mandate for a parser of untrusted input (``@rules/topic-testing`` / master §4): random bytes must
never crash or hang — only a validated header or a ``ValueError``.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vivarium.core.uimage import (
    UIMAGE_HEADER_SIZE,
    UIMAGE_MAGIC,
    parse_uimage_header,
)

_CAP = 512 * 1024 * 1024


def _header(magic: int = UIMAGE_MAGIC, size: int = 100, comp: int = 0, pad: int = 0) -> bytes:
    """Build a 64-byte uImage header (+ ``pad`` trailing bytes) with the given fields."""
    b = bytearray(UIMAGE_HEADER_SIZE + pad)
    struct.pack_into(">I", b, 0, magic & 0xFFFFFFFF)
    struct.pack_into(">I", b, 12, size & 0xFFFFFFFF)
    b[31] = comp & 0xFF
    return bytes(b)


@pytest.mark.parametrize(("code", "name"), [(0, "none"), (1, "gzip"), (3, "lzma")])
def test_parses_supported_compression(code: int, name: str) -> None:
    """A well-formed header with a supported ih_comp yields the parsed size + comp name."""
    h = parse_uimage_header(_header(size=4096, comp=code), max_payload_size=_CAP)
    assert h.payload_size == 4096
    assert h.comp == name


def test_short_input_rejected() -> None:
    """Fewer than 64 bytes is not a uImage."""
    with pytest.raises(ValueError, match="64-byte header"):
        parse_uimage_header(b"\x27\x05\x19\x56" + b"\x00" * 10, max_payload_size=_CAP)


def test_bad_magic_rejected() -> None:
    """A wrong magic fails closed (arbitrary blob is not a uImage)."""
    with pytest.raises(ValueError, match="bad magic"):
        parse_uimage_header(_header(magic=0xDEADBEEF), max_payload_size=_CAP)


def test_non_positive_size_rejected() -> None:
    """A zero declared payload size is rejected (empty/degenerate)."""
    with pytest.raises(ValueError, match="non-positive"):
        parse_uimage_header(_header(size=0), max_payload_size=_CAP)


def test_oversized_declared_payload_rejected() -> None:
    """A header claiming a payload over the cap is rejected BEFORE any slice (CWE-400/CWE-190)."""
    with pytest.raises(ValueError, match="larger than the allowed cap"):
        parse_uimage_header(_header(size=_CAP + 1), max_payload_size=_CAP)


@pytest.mark.parametrize("comp", [2, 4, 5, 255])
def test_unsupported_compression_rejected(comp: int) -> None:
    """bzip2/lzo/lz4/unknown ih_comp codes are rejected (no stdlib streaming decompressor here)."""
    with pytest.raises(ValueError, match="unsupported"):
        parse_uimage_header(_header(comp=comp), max_payload_size=_CAP)


@given(st.binary(min_size=0, max_size=256))
def test_fuzz_never_crashes_on_arbitrary_bytes(data: bytes) -> None:
    """Hostile fuzz: arbitrary bytes yield either a valid header or a ValueError — never a crash."""
    try:
        h = parse_uimage_header(data, max_payload_size=_CAP)
    except ValueError:
        return
    # If it parsed, the invariants the worker relies on must hold.
    assert 0 < h.payload_size <= _CAP
    assert h.comp in {"none", "gzip", "lzma"}
