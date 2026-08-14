"""Pure (JVM-free) reassembly of stack-string byte slots into recovered strings (ADR-068).

Part of the functional core (ADR-001): the worker walks a function's RAW p-code (dead-code
elimination is what hides these in the decompiler's HighFunction, so the *unoptimized* raw
p-code is used) and produces a ``{stack_offset: byte}`` map of constant stores to stack slots. This
module turns that map into recovered strings — grouping contiguous slots, splitting on NUL, and
keeping only runs that meet a length floor and a printable-ratio filter. Deterministic + testable.

Heuristic (ADR-068 D4): non-constant / non-adjacent / gapped stores simply terminate a run rather
than being guessed. Recovered text is binary-derived and MUST be wrapped untrusted by the adapter
(ADR-005).
"""

from __future__ import annotations


def printable_ratio(data: bytes) -> float:
    """Return the fraction of ``data`` that is printable ASCII (0.0 for empty)."""
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte < 127)
    return printable / len(data)


def reassemble_stack_strings(
    slots: dict[int, int], *, min_length: int, min_printable_ratio: float
) -> list[str]:
    """Reassemble contiguous constant-store stack slots into recovered strings.

    Deterministic + side-effect-free. Slots are grouped into maximal runs of consecutive offsets;
    each run is split on NUL terminators, and each segment is kept when it meets ``min_length`` and
    ``min_printable_ratio``. Returns the recovered texts in ascending stack-offset order.

    Args:
        slots: ``{stack_offset: byte_value}`` — one entry per byte of a constant store to a stack
            slot (from the worker's raw-p-code walk).
        min_length: Minimum recovered-string length to keep (noise floor; already server-clamped).
        min_printable_ratio: Minimum fraction of printable-ASCII bytes for a segment to qualify.

    Returns:
        The recovered strings (Latin-1 decoded — every byte maps), ascending by offset.
    """
    if not slots:
        return []
    out: list[str] = []
    offsets = sorted(slots)
    run: list[int] = []
    previous: int | None = None

    def _flush() -> None:
        if not run:
            return
        for segment in bytes(run).split(b"\x00"):
            if len(segment) >= min_length and printable_ratio(segment) >= min_printable_ratio:
                out.append(segment.decode("latin1"))

    for offset in offsets:
        if previous is not None and offset != previous + 1:
            _flush()
            run = []
        run.append(slots[offset])
        previous = offset
    _flush()
    return out
