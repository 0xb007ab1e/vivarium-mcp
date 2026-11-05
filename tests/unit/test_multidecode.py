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
    expand_value_feeders,
    extract_changed_strings,
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


# --- expand_value_feeders (COPY/SUBPIECE reach, #401 copy-chain fix) ------------------------------


def test_expand_no_edges_is_identity() -> None:
    """With no COPY/SUBPIECE edges the set is unchanged."""
    assert expand_value_feeders({"AL"}, {}) == {"AL"}


def test_expand_one_copy_level() -> None:
    """A stored AL copied from a unique temp pulls the unique into the value-feeder set."""
    # AL = COPY(u1); STORE ..., AL  → u1 is effectively value-feeding.
    assert expand_value_feeders({"AL"}, {"AL": ["u1"]}) == {"AL", "u1"}


def test_expand_multi_level_chain() -> None:
    """A multi-link COPY/SUBPIECE chain is fully walked (bounded)."""
    edges = {"AL": ["u1"], "u1": ["u2"]}
    assert expand_value_feeders({"AL"}, edges) == {"AL", "u1", "u2"}


def test_expand_add_output_becomes_selectable() -> None:
    """The #401 copy-chain case end-to-end: add output (unique) is kept after expansion."""
    # add al,k lands in u1; AL = COPY(u1); STORE AL. The add candidate's out is u1.
    feeders = expand_value_feeders({"AL"}, {"AL": ["u1"]})
    ops = [("add", "u1", 0x10), ("add", "ECX", 0x01)]  # decode add (via copy) + loop counter
    assert select_decode_ops(ops, feeders) == [("add", 0x10)]  # counter still filtered


def test_expand_cycle_safe() -> None:
    """A cyclic edge set terminates (does not hang) and resolves the reachable nodes."""
    edges = {"a": ["b"], "b": ["a"]}
    assert expand_value_feeders({"a"}, edges) == {"a", "b"}


def test_expand_depth_bound() -> None:
    """The backward walk stops at max_depth (deep chains are bounded, DoS guard)."""
    edges = {"n0": ["n1"], "n1": ["n2"], "n2": ["n3"]}
    out = expand_value_feeders({"n0"}, edges, max_depth=2)
    assert "n1" in out and "n2" in out and "n3" not in out


# --- extract_changed_strings (unpack output scan, ADR-084, #399) ---------------------------------


def test_extract_finds_unpacked_string() -> None:
    """A printable run the unpacker wrote (changed vs before) is extracted with its offset."""
    before = bytes(8)
    after = b"\x00\x00Hello!\x00" + b"\x00" * 0
    # after = 00 00 'Hello!' 00  → the run "Hello!" at offset 2, changed vs the zero before.
    out = extract_changed_strings(before + b"\x00", after, min_length=4, max_results=16)
    assert out == [(2, "Hello!")]


def test_extract_ignores_preexisting_plaintext() -> None:
    """A run identical to the before-bytes (already plaintext) is NOT reported."""
    before = b"Hello!\x00\x00"
    after = b"Hello!\x00\x00"
    assert extract_changed_strings(before, after, min_length=4, max_results=16) == []


def test_extract_respects_min_length() -> None:
    """Runs shorter than min_length are skipped."""
    out = extract_changed_strings(bytes(8), b"\x00Hi\x00ABCDE\x00", min_length=4, max_results=16)
    assert out == [(4, "ABCDE")]


def test_extract_caps_results() -> None:
    """The result list is bounded by max_results."""
    after = b"AAAA\x00BBBB\x00CCCC\x00DDDD"
    out = extract_changed_strings(bytes(len(after)), after, min_length=4, max_results=2)
    assert len(out) == 2
    assert out[0] == (0, "AAAA") and out[1] == (5, "BBBB")


def test_extract_multiple_changed_runs() -> None:
    """Several changed printable runs are each reported in offset order."""
    after = b"\x00Hi there\x00\x01bye now!"
    out = extract_changed_strings(bytes(len(after)), after, min_length=4, max_results=16)
    assert out == [(1, "Hi there"), (11, "bye now!")]


# --- properties (fuzz) ---------------------------------------------------------------------------


@settings(max_examples=300)
@given(st.binary(max_size=64), st.binary(max_size=64), st.integers(min_value=1, max_value=8))
def test_prop_extract_changed_is_sound(before: bytes, after: bytes, min_length: int) -> None:
    """extract_changed_strings never raises; every result is printable, long enough, and changed."""
    out = extract_changed_strings(before, after, min_length=min_length, max_results=32)
    assert len(out) <= 32
    for off, text in out:
        raw = text.encode("latin1")
        assert len(raw) >= min_length
        assert all(0x20 <= b <= 0x7E for b in raw)
        assert after[off : off + len(raw)] == raw
        assert raw != before[off : off + len(raw)]


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
