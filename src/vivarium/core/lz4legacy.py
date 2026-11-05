"""Pure parser for the **legacy** lz4 frame format's block framing (ADR-088; #414).

Android/kernel ramdisks are frequently lz4-compressed in the **legacy** frame format (magic
``02 21 4c 18``), which ``python-lz4``'s ``lz4.frame`` API does NOT decode. The legacy frame is a
magic followed by repeated ``[u32 little-endian compressed_block_size][block]`` records, each block
decompressing to at most 8 MiB. This module parses ONLY that framing — it validates the magic and
walks the block-size records, returning the bounded list of ``(offset, size)`` block spans; it NEVER
decompresses a block (the worker's `lz4.block` call does that), never allocates by untrusted length,
and never touches the JVM or the filesystem, so it is a pure, hermetically fuzzable boundary that
needs **no** ``lz4`` import (``@rules/topic-architecture-patterns`` functional core).

Every byte here is HOSTILE input (a firmware ramdisk of unknown origin, ADR-005): the parser is
total — a validated list or a typed :class:`Lz4LegacyError`; it must never crash, hang, over-read,
over-allocate, recurse, or divide by zero on arbitrary bytes (verified by the property/fuzz tests).
It is bounded by an explicit block cap (CWE-400) and validates every ``u32`` size against the
remaining buffer before advancing (CWE-20/-190).
"""

from __future__ import annotations

from typing import Final

#: Legacy lz4 frame magic (little-endian ``0x184C2102``) — distinct from the standard frame
#: (``0x184D2204`` / ``04 22 4d 18``), which ``lz4.frame`` handles.
LEGACY_MAGIC: Final = b"\x02\x21\x4c\x18"

#: Legacy frame fixed maximum *uncompressed* block size (8 MiB) — the cap passed to the per-block
#: ``lz4.block.decompress`` and the ceiling the worker trusts for one block's output.
MAX_BLOCK_OUTPUT: Final = 8 * 1024 * 1024

#: The legacy-magic value as an int, to detect a concatenated next frame (stop, don't misparse it
#: as a block size).
_MAGIC_AS_SIZE: Final = int.from_bytes(LEGACY_MAGIC, "little")


class Lz4LegacyError(ValueError):
    """Raised when the bytes are not a well-formed, bounded legacy lz4 frame.

    A single typed error for every malformation (bad magic, a truncated/oversized block-size record,
    a block overrunning the buffer, or exceeding the block cap) — so the worker can translate any
    framing failure to one category-safe fail-closed outcome (ADR-005): the stream is hostile input
    and its shape must never leak as an arbitrary exception.
    """


def is_legacy_lz4(head: bytes) -> bool:
    """Return whether ``head`` begins with the legacy lz4 frame magic (cheap probe)."""
    return head[:4] == LEGACY_MAGIC


def parse_legacy_frame(data: bytes, *, max_blocks: int) -> list[tuple[int, int]]:
    """Parse a legacy lz4 frame's block framing into bounded ``(offset, size)`` compressed spans.

    Validates the magic, then walks the ``[u32 size][block]`` records, checking every size against
    the remaining buffer before advancing. Stops at EOF or at a record whose ``u32`` equals the
    legacy magic (a concatenated next frame — not treated as a block). The block bytes are NOT
    decompressed here (the worker calls ``lz4.block`` on each returned span). Totally defined on
    arbitrary input: returns a list or raises :class:`Lz4LegacyError`; never hangs, over-reads,
    recurses, or divides by zero.

    Args:
        data: The full legacy lz4 frame bytes — HOSTILE input.
        max_blocks: Hard cap on the number of block records parsed (CWE-400); exceeding it fails
            closed.

    Returns:
        The compressed block spans ``(offset, size)`` in frame order (at least one).

    Raises:
        Lz4LegacyError: On bad magic, a truncated/oversized/zero block-size record, a block
            overrunning the buffer, no blocks, or exceeding ``max_blocks``.
    """
    if max_blocks <= 0:
        raise Lz4LegacyError("max_blocks must be positive")
    if data[:4] != LEGACY_MAGIC:
        raise Lz4LegacyError("not a legacy lz4 frame (bad magic)")

    total = len(data)
    blocks: list[tuple[int, int]] = []
    pos = 4

    while pos + 4 <= total:
        size = int.from_bytes(data[pos : pos + 4], "little")
        if size == _MAGIC_AS_SIZE:
            break  # a concatenated next frame begins here — stop (single-frame ramdisk).
        pos += 4
        if size == 0 or pos + size > total:
            raise Lz4LegacyError("legacy lz4 block size is zero or overruns the buffer")
        blocks.append((pos, size))
        pos += size
        if len(blocks) > max_blocks:
            raise Lz4LegacyError("legacy lz4 frame exceeds the max_blocks cap")

    if not blocks:
        raise Lz4LegacyError("legacy lz4 frame has no blocks")
    return blocks
