"""Unit + fuzz tests for the pure legacy-lz4 frame framing parser (ADR-088; #414).

`core.lz4legacy.parse_legacy_frame` is a hostile-bytes boundary (ADR-005): it must be total — a
validated list of ``(offset, size)`` block spans or a :class:`Lz4LegacyError`, never a crash, hang,
over-read, over-allocation, recursion, or divide-by-zero. It validates the FRAMING only (it never
decompresses — the worker's ``lz4.block`` does that), so it needs no ``lz4`` dependency. The fuzz
test is the proof of the fail-closed contract; the unit tests pin the span arithmetic against the
synthetic framing fixture.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests._fixtures import binaries
from vivarium.core.lz4legacy import (
    LEGACY_MAGIC,
    Lz4LegacyError,
    is_legacy_lz4,
    parse_legacy_frame,
)

_MAX = 4096


def test_is_legacy_lz4_probe() -> None:
    """The cheap probe matches the legacy magic, rejects the standard frame + anything else."""
    assert is_legacy_lz4(LEGACY_MAGIC + b"rest")
    assert not is_legacy_lz4(b"\x04\x22\x4d\x18")  # standard lz4 frame
    assert not is_legacy_lz4(b"\x1f\x8b")  # gzip
    assert not is_legacy_lz4(b"")


def test_parses_block_spans_in_order() -> None:
    """A multi-block frame yields the (offset, size) spans pointing at each block's bytes."""
    blocks = [b"AAAA", b"BBBBBB", b"C"]
    frame = binaries.lz4_legacy_frame(blocks)
    spans = parse_legacy_frame(frame, max_blocks=_MAX)
    assert len(spans) == 3
    assert [frame[off : off + size] for off, size in spans] == blocks


def test_single_block_frame() -> None:
    """A one-block frame parses to a single span."""
    frame = binaries.lz4_legacy_frame([b"only-block"])
    spans = parse_legacy_frame(frame, max_blocks=_MAX)
    assert len(spans) == 1
    off, size = spans[0]
    assert frame[off : off + size] == b"only-block"


def test_stops_at_concatenated_next_frame_magic() -> None:
    """A u32 equal to the legacy magic marks a concatenated next frame → parsing stops there."""
    frame = binaries.lz4_legacy_frame([b"AAAA"]) + LEGACY_MAGIC + b"ignored-second-frame"
    spans = parse_legacy_frame(frame, max_blocks=_MAX)
    assert len(spans) == 1  # only the first frame's block; the second magic halts the walk


def test_bad_magic_rejected() -> None:
    """A buffer without the legacy magic fails closed."""
    with pytest.raises(Lz4LegacyError):
        parse_legacy_frame(b"\x04\x22\x4d\x18" + b"\x04\x00\x00\x00AAAA", max_blocks=_MAX)


def test_oversized_block_rejected() -> None:
    """A block-size record that overruns the buffer fails closed (no over-read)."""
    bad = LEGACY_MAGIC + struct.pack("<I", 0x7FFFFFFF) + b"short"
    with pytest.raises(Lz4LegacyError):
        parse_legacy_frame(bad, max_blocks=_MAX)


def test_zero_block_size_rejected() -> None:
    """A zero-length block record fails closed (would otherwise loop with no progress)."""
    bad = LEGACY_MAGIC + struct.pack("<I", 0)
    with pytest.raises(Lz4LegacyError):
        parse_legacy_frame(bad, max_blocks=_MAX)


def test_no_blocks_rejected() -> None:
    """A bare magic with no block records fails closed (nothing to decode)."""
    with pytest.raises(Lz4LegacyError):
        parse_legacy_frame(LEGACY_MAGIC, max_blocks=_MAX)


def test_block_cap_enforced() -> None:
    """Exceeding max_blocks fails closed (CWE-400 resource bound)."""
    frame = binaries.lz4_legacy_frame([b"x"] * 10)
    with pytest.raises(Lz4LegacyError, match="max_blocks"):
        parse_legacy_frame(frame, max_blocks=5)


def test_nonpositive_max_blocks_rejected() -> None:
    """A non-positive cap is surfaced as Lz4LegacyError, not an infinite loop."""
    with pytest.raises(Lz4LegacyError):
        parse_legacy_frame(binaries.lz4_legacy_frame([b"x"]), max_blocks=0)


@given(st.binary(max_size=4096))
def test_fuzz_arbitrary_bytes_never_crash(data: bytes) -> None:
    """Arbitrary bytes yield spans within the buffer or an Lz4LegacyError — never anything else."""
    try:
        spans = parse_legacy_frame(data, max_blocks=256)
    except Lz4LegacyError:
        return
    assert isinstance(spans, list) and spans
    for off, size in spans:
        assert 0 <= off <= len(data)
        assert off + size <= len(data)


@given(st.lists(st.binary(min_size=1, max_size=64), min_size=1, max_size=32))
def test_fuzz_roundtrip_wellformed_frames(blocks: list[bytes]) -> None:
    """Any frame the fixture builds parses back to the same block payloads (well-formed)."""
    # A block whose first 4 bytes equal the magic would halt the walk early; drop those.
    clean = [b for b in blocks if b[:4] != LEGACY_MAGIC]
    if not clean:
        return
    frame = binaries.lz4_legacy_frame(clean)
    spans = parse_legacy_frame(frame, max_blocks=4096)
    assert [frame[off : off + size] for off, size in spans] == clean
