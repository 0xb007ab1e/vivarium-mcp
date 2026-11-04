"""Unit + property tests for the pure multi-stage decode core (ADR-081, #379).

Hermetic (no JVM): exercises `vivarium.core.multidecode` — the buffer selection + stage-chain
assembly that widen ADR-068's single-pass `xor_decode` to chained local decoders. The JVM edge
(detect + emulate) is validated separately by the gated live-regression integration test.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from vivarium.core.multidecode import (
    assemble_stage_chain,
    best_decoded_run,
    leading_printable_run,
    select_decode_ops,
)

# --- leading_printable_run -----------------------------------------------------------------------


def test_leading_run_empty() -> None:
    """Empty input yields an empty run."""
    assert leading_printable_run(b"") == b""


def test_leading_run_all_printable() -> None:
    """A fully printable buffer is returned whole."""
    assert leading_printable_run(b"Hello!") == b"Hello!"


def test_leading_run_stops_at_nul() -> None:
    """The run stops at the first NUL (C-string terminator)."""
    assert leading_printable_run(b"Hi\x00junk") == b"Hi"


def test_leading_run_stops_at_nonprintable() -> None:
    """The run stops at the first non-printable byte."""
    assert leading_printable_run(b"ab\x01cd") == b"ab"


def test_leading_run_nonprintable_first() -> None:
    """A non-printable first byte yields an empty run."""
    assert leading_printable_run(b"\xffabc") == b""


# --- best_decoded_run ----------------------------------------------------------------------------


def test_best_run_empty_buffers() -> None:
    """No buffers → no recovery."""
    assert best_decoded_run([], min_length=4) is None


def test_best_run_picks_changed_printable() -> None:
    """A buffer whose decode became printable AND changed is recovered."""
    out = best_decoded_run([(0x1000, b"\x01\x02\x03\x04\x05\x06", b"Hello!")], min_length=4)
    assert out == (0x1000, b"Hello!")


def test_best_run_rejects_unchanged() -> None:
    """A buffer already plaintext (after == before) is NOT a decode — rejected (fail closed)."""
    assert best_decoded_run([(0x1000, b"Hello!", b"Hello!")], min_length=4) is None


def test_best_run_rejects_short() -> None:
    """A run below min_length is rejected."""
    assert best_decoded_run([(0x1000, b"\x00\x00\x00", b"Hi")], min_length=4) is None


def test_best_run_rejects_nonprintable() -> None:
    """A buffer that decoded to non-printable bytes yields nothing."""
    assert best_decoded_run([(0x1000, b"aaaa", b"\x01\x02\x03\x04")], min_length=4) is None


def test_best_run_multistage_picks_final_not_minimum() -> None:
    """The KEY #379 case: the final plaintext is in a non-minimum write buffer.

    The single-pass impl read `min(write_targets)` (the intermediate scratch, still garbage); the
    multi-buffer readback reads every buffer and picks the one that became printable — here the
    HIGHER address, which the old code would have missed.
    """
    intermediate = (0x1000, b"\x01\x02\x03\x04\x05\x06", b"\x11\x22\x33\x44\x55\x66")  # scratch
    final = (0x2000, b"\x00\x00\x00\x00\x00\x00", b"Hello!")  # final plaintext, higher addr
    out = best_decoded_run([intermediate, final], min_length=4)
    assert out == (0x2000, b"Hello!")


def test_best_run_longest_wins_then_lowest_base() -> None:
    """Among qualifying buffers the longest run wins; equal length breaks on the lowest base."""
    short = (0x3000, b"\x00\x00\x00\x00", b"Hey!")
    long = (0x4000, b"\x00\x00\x00\x00\x00\x00", b"Longer")
    assert best_decoded_run([short, long], min_length=4) == (0x4000, b"Longer")
    tie_hi = (0x5000, b"\x00\x00\x00\x00", b"AAAA")
    tie_lo = (0x1000, b"\x00\x00\x00\x00", b"BBBB")
    assert best_decoded_run([tie_hi, tie_lo], min_length=4) == (0x1000, b"BBBB")


# --- assemble_stage_chain ------------------------------------------------------------------------


def test_stage_chain_single() -> None:
    """A single-stage decoder yields a one-entry chain (backward-compatible)."""
    stages, truncated = assemble_stage_chain([("xor", 0x41)], max_stages=8)
    assert stages == [{"op": "xor", "key": "0x41"}]
    assert truncated is False


def test_stage_chain_preserves_order_and_ops() -> None:
    """The chain preserves instruction order and mixed ops (xor then add)."""
    stages, truncated = assemble_stage_chain([("xor", 0x41), ("add", 0x10)], max_stages=8)
    assert stages == [{"op": "xor", "key": "0x41"}, {"op": "add", "key": "0x10"}]
    assert truncated is False


def test_stage_chain_caps_and_flags_truncated() -> None:
    """The chain is capped at max_stages with a truthful truncated flag (DoS bound)."""
    ops = [("xor", i) for i in range(10)]
    stages, truncated = assemble_stage_chain(ops, max_stages=3)
    assert len(stages) == 3
    assert truncated is True
    assert [s["key"] for s in stages] == ["0x0", "0x1", "0x2"]


def test_stage_chain_key_masked_to_byte() -> None:
    """Keys are normalised to a single byte (0..0xff)."""
    stages, _ = assemble_stage_chain([("xor", 0x1041)], max_stages=8)
    assert stages == [{"op": "xor", "key": "0x41"}]


# --- select_decode_ops (ADD-const filter, #401) --------------------------------------------------


def test_select_keeps_all_xor() -> None:
    """XOR ops are always kept regardless of whether they feed a store (permissive, low FP)."""
    ops = [("xor", "AL", 0x41), ("xor", "AL", 0x13)]
    assert select_decode_ops(ops, set()) == [("xor", 0x41), ("xor", 0x13)]


def test_select_keeps_add_only_when_value_feeding() -> None:
    """An ADD is kept only when its output varnode is a STORE value (the genuine decode op)."""
    # ("add","AL",..) feeds a stored value (AL in store_value_keys) → kept;
    # ("add","RDX",..) is an address displacement (not a stored value) → dropped.
    ops = [("add", "AL", 0x10), ("add", "RDX", 0x08)]
    assert select_decode_ops(ops, {"AL"}) == [("add", 0x10)]


def test_select_drops_loop_counter_add() -> None:
    """A loop-counter ADD (inc ecx: output ECX, never a stored value) is dropped."""
    ops = [("add", "ECX", 0x01)]
    assert select_decode_ops(ops, {"AL"}) == []


def test_select_preserves_order_mixed() -> None:
    """Mixed XOR + value-feeding ADD stay in instruction order (xor then add)."""
    ops = [("xor", "AL", 0x41), ("add", "RDX", 0x08), ("add", "AL", 0x80)]
    assert select_decode_ops(ops, {"AL"}) == [("xor", 0x41), ("add", 0x80)]


# --- properties (fuzz) ---------------------------------------------------------------------------


@settings(max_examples=300)
@given(st.binary(max_size=64))
def test_prop_leading_run_is_printable_prefix(data: bytes) -> None:
    """leading_printable_run never raises and returns an all-printable prefix of the input."""
    run = leading_printable_run(data)
    assert data.startswith(run)
    assert all(0x20 <= b <= 0x7E for b in run)
    # Maximal: the byte right after the run (if any) is non-printable.
    if len(run) < len(data):
        assert not (0x20 <= data[len(run)] <= 0x7E)


@settings(max_examples=300)
@given(
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=0xFFFF),
            st.binary(max_size=32),
            st.binary(max_size=32),
        ),
        max_size=16,
    ),
    st.integers(min_value=1, max_value=16),
)
def test_prop_best_run_is_sound(buffers: list[tuple[int, bytes, bytes]], min_length: int) -> None:
    """best_decoded_run never raises; any result is printable, changed, and meets min_length."""
    out = best_decoded_run(buffers, min_length=min_length)
    if out is None:
        return
    _base, run = out
    assert len(run) >= min_length
    assert all(0x20 <= b <= 0x7E for b in run)
    # Some input buffer produced exactly this run as a CHANGED decode (sound, base-collision safe).
    assert any(
        leading_printable_run(after) == run and run != before[: len(run)]
        for _, before, after in buffers
    )
