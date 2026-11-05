"""Unit tests for ADR-068 `deobfuscate_strings` (stack_string) — pure core + schema/builder.

The worker's raw-p-code stack-store walk is a `# pragma: no cover` JVM edge validated against a real
worker (recovered "Hello!" from a crafted x86-64 stack-string); these cover the pure
`core.stackstring` reassembly + the server contract (schema validation, `_build_deobfuscate_strings`
untrusted-wrapping).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vivarium.core.envelope import Untrusted
from vivarium.core.stackstring import printable_ratio, reassemble_stack_strings
from vivarium.ghidra.rpc_client import _build_deobfuscate_strings
from vivarium.tools import schemas as s

# --- pure core -----------------------------------------------------------------------------------


def _slots(start: int, data: bytes) -> dict[int, int]:
    return {start + i: b for i, b in enumerate(data)}


def test_reassembles_contiguous_run() -> None:
    """A contiguous run of constant stack slots reassembles into the string."""
    out = reassemble_stack_strings(_slots(-8, b"Hello!"), min_length=4, min_printable_ratio=0.8)
    assert out == ["Hello!"]


def test_splits_on_nul_and_applies_min_length() -> None:
    """NUL terminates a segment; segments below min_length are dropped."""
    out = reassemble_stack_strings(
        _slots(-16, b"path\x00X\x00value123"), min_length=4, min_printable_ratio=0.8
    )
    assert out == ["path", "value123"]  # the single "X" is below min_length


def test_gap_breaks_a_run() -> None:
    """A non-adjacent slot terminates a run rather than being guessed (ADR-068 D4)."""
    slots = {**_slots(-8, b"abcd"), **_slots(-2, b"efgh")}  # gap between -5 and -2
    out = reassemble_stack_strings(slots, min_length=4, min_printable_ratio=0.8)
    assert out == ["abcd", "efgh"]


def test_printable_filter_drops_binary_run() -> None:
    """A mostly-non-printable run is filtered out."""
    out = reassemble_stack_strings(
        _slots(-8, bytes([1, 2, 3, 4, 5, 6])), min_length=4, min_printable_ratio=0.8
    )
    assert out == []


def test_empty_slots() -> None:
    """No slots -> no strings."""
    assert reassemble_stack_strings({}, min_length=4, min_printable_ratio=0.8) == []


def test_printable_ratio() -> None:
    """printable_ratio counts printable-ASCII bytes; empty is 0.0."""
    assert printable_ratio(b"") == 0.0
    assert printable_ratio(b"abcd") == 1.0
    assert printable_ratio(bytes([0, 0, ord("a"), ord("b")])) == 0.5


# --- schema --------------------------------------------------------------------------------------


def test_defaults_bounded() -> None:
    """Absent function/techniques default to a bounded whole-program stack_string scan."""
    m = s.DeobfuscateStringsIn(session_id="s")
    assert m.function is None
    assert m.min_length == 4 and m.max_results == 256 and m.max_bytes == 256


def test_technique_enum_closed() -> None:
    """techniques is a closed set — stack_string + xor_decode accepted, anything else rejected."""
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", techniques=["rot13"])  # type: ignore[list-item]
    m = s.DeobfuscateStringsIn(session_id="s", techniques=["stack_string", "xor_decode"])
    assert m.techniques == ["stack_string", "xor_decode"]


def test_stream_decode_technique_accepted() -> None:
    """ADR-083: `stream_decode` is an accepted (opt-in) technique."""
    m = s.DeobfuscateStringsIn(session_id="s", function="0x1000", techniques=["stream_decode"])
    assert m.techniques == ["stream_decode"]


def test_caps_bounded() -> None:
    """min_length/max_results/max_bytes are >= 1."""
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", max_results=0)
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", max_bytes=0)


def test_max_stages_bounded() -> None:
    """ADR-081: max_stages defaults to 8 and is clamped to [1, 64]."""
    assert s.DeobfuscateStringsIn(session_id="s").max_stages == 8
    assert s.DeobfuscateStringsIn(session_id="s", max_stages=1).max_stages == 1
    assert s.DeobfuscateStringsIn(session_id="s", max_stages=64).max_stages == 64
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", max_stages=0)
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", max_stages=65)


def test_interprocedural_bounds() -> None:
    """ADR-082: max_call_depth defaults to 2 ([0,8]) and max_callees to 16 ([1,256])."""
    m = s.DeobfuscateStringsIn(session_id="s")
    assert m.max_call_depth == 2 and m.max_callees == 16
    assert s.DeobfuscateStringsIn(session_id="s", max_call_depth=0).max_call_depth == 0  # entry
    assert s.DeobfuscateStringsIn(session_id="s", max_call_depth=8).max_call_depth == 8
    assert s.DeobfuscateStringsIn(session_id="s", max_callees=256).max_callees == 256
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", max_call_depth=9)
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", max_call_depth=-1)
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", max_callees=0)
    with pytest.raises(ValidationError):
        s.DeobfuscateStringsIn(session_id="s", max_callees=257)


# --- result builder ------------------------------------------------------------------------------


def test_builder_wraps_text_untrusted() -> None:
    """`_build_deobfuscate_strings` wraps each recovered text UNTRUSTED; address/length safe."""
    out = _build_deobfuscate_strings(
        {
            "strings": [
                {
                    "address": "0x00401000",
                    "technique": "stack_string",
                    "text": "Hello!",
                    "length": 6,
                }
            ],
            "truncated": True,
        }
    )
    assert out.truncated is True
    assert len(out.strings) == 1
    rec = out.strings[0]
    assert rec.address == "0x00401000" and rec.technique == "stack_string" and rec.length == 6
    assert isinstance(rec.text, Untrusted)
    # stack_string carries no xor metadata (back-compat: absent keys map to None).
    assert rec.encoding is None and rec.decode_key is None


def test_builder_xor_decode_wraps_key_and_keeps_encoding() -> None:
    """`xor_decode` results carry a safe `encoding` + an UNTRUSTED `decode_key`."""
    out = _build_deobfuscate_strings(
        {
            "strings": [
                {
                    "address": "0x00401000",
                    "technique": "xor_decode",
                    "text": "Hello!",
                    "length": 6,
                    "encoding": "xor",
                    "decode_key": "0x41",
                }
            ],
            "truncated": False,
        }
    )
    rec = out.strings[0]
    assert rec.technique == "xor_decode" and rec.encoding == "xor"
    assert isinstance(rec.text, Untrusted)
    assert isinstance(rec.decode_key, Untrusted) and rec.decode_key.value == "0x41"
    # No stages key in the result → stages is None (backward-compatible).
    assert rec.stages is None


def test_builder_stream_decode_no_key() -> None:
    """ADR-083: a `stream_decode` result carries `encoding="stream"`, no key, no stages."""
    out = _build_deobfuscate_strings(
        {
            "strings": [
                {
                    "address": "0x00401000",
                    "technique": "stream_decode",
                    "text": "Hello!",
                    "length": 6,
                    "encoding": "stream",
                    "decode_key": None,
                    "stages": None,
                }
            ],
            "truncated": False,
        }
    )
    rec = out.strings[0]
    assert rec.technique == "stream_decode" and rec.encoding == "stream"
    assert isinstance(rec.text, Untrusted)
    assert rec.decode_key is None and rec.stages is None


def test_builder_multistage_wraps_each_stage_key_untrusted() -> None:
    """ADR-081: a chained xor_decode carries an ordered `stages` chain; each key is UNTRUSTED."""
    out = _build_deobfuscate_strings(
        {
            "strings": [
                {
                    "address": "0x00401000",
                    "technique": "xor_decode",
                    "text": "Hello!",
                    "length": 6,
                    "encoding": "xor",
                    "decode_key": "0x41",
                    "stages": [{"op": "xor", "key": "0x41"}, {"op": "xor", "key": "0x13"}],
                }
            ],
            "truncated": False,
        }
    )
    rec = out.strings[0]
    assert rec.stages is not None and len(rec.stages) == 2
    assert [st.op for st in rec.stages] == ["xor", "xor"]
    assert all(isinstance(st.key, Untrusted) for st in rec.stages)
    assert [st.key.value for st in rec.stages] == ["0x41", "0x13"]


def test_builder_tolerates_empty() -> None:
    """No recovered strings yields an empty list, not an error."""
    out = _build_deobfuscate_strings({"strings": [], "truncated": False})
    assert out.strings == [] and out.truncated is False
