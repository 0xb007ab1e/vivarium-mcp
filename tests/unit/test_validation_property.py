"""Property/fuzz tests for the untrusted-input parsers in ``core.validation`` (gap round-3 P14).

Complements the example-based tests in ``test_validation.py`` with generated-input INVARIANTS over
the two client-facing string parsers that turn hostile text into trusted values (the CWE-190 /
CWE-20 boundary — validated server-side before any worker sees them):

  * :func:`parse_address` — accept ⟹ a non-negative int in ``[0, 2**64-1]``; every valid hex form
    round-trips; anything else raises a ``VALIDATION`` :class:`GhidraMcpError` — never another
    exception, never an out-of-range or negative result (integer-overflow guard, CWE-190).
  * :func:`validate_name` — accept ⟹ the value returned UNCHANGED, ``1..MAX_NAME_LEN`` chars, with
    NO C0/C1/DEL control char and no Unicode line/paragraph separator; anything else raises
    (stored-injection / log-corruption defense, CWE-20).

The load-bearing safety property for each is **total + fail-closed**: over arbitrary text the
parser either returns a value meeting the invariant or raises the single permitted ``VALIDATION``
taxonomy — a stray ``ValueError``/``OverflowError``/etc. escaping the parser fails the test.
Hermetic + deterministic: pure functions, no I/O.

(The annotation-document validator is deliberately NOT fuzzed here: it runs behind pydantic
construction + the per-entry ``validate_entry`` allow-lists — both already example-tested — so a
document-level structural fuzz would mostly exercise pydantic, not our validator.)
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")  # skip cleanly if the property-test extra is absent
from hypothesis import example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from vivarium.core.errors import ErrorType, GhidraMcpError  # noqa: E402
from vivarium.core.validation import (  # noqa: E402
    MAX_NAME_LEN,
    parse_address,
    validate_name,
)

_MAX_ADDR = (1 << 64) - 1

#: Unicode line / paragraph separators that ``validate_name`` rejects. Built with ``chr`` so the
#: source carries no raw ambiguous character (and can't be mistaken for an ordinary space, allowed).
_LINE_SEP = chr(0x2028)
_PARA_SEP = chr(0x2029)


def _is_control_or_separator(ch: str) -> bool:
    """Mirror ``validate_name``'s reject set: C0/DEL/C1 control chars + U+2028/U+2029 separators."""
    code = ord(ch)
    return code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F or ch in (_LINE_SEP, _PARA_SEP)


# --- parse_address (CWE-190) --------------------------------------------------------------------
@settings(max_examples=400)
@given(st.text())
@example("")  # empty
@example("0x")  # prefix, no digits
@example("  0x10  ")  # surrounding whitespace (stripped → valid)
@example("0xGG")  # non-hex letters
@example("-1")  # sign rejected (no int() leniency)
@example("0x1_000")  # underscore rejected
@example("0x" + "f" * 17)  # over the 16-hex-digit cap
def test_parse_address_is_total_and_bounded(text: str) -> None:
    """Arbitrary text → a non-negative ``<= 2**64-1`` int, or raise VALIDATION — nothing else."""
    try:
        result = parse_address(text)
    except GhidraMcpError as exc:
        assert exc.envelope.type is ErrorType.VALIDATION  # the ONLY permitted failure taxonomy
    else:
        assert isinstance(result, int)
        assert 0 <= result <= _MAX_ADDR  # never negative, never past the 64-bit ceiling (CWE-190)


@settings(max_examples=400)
@given(st.integers(min_value=0, max_value=_MAX_ADDR))
def test_parse_address_round_trips_every_valid_form(n: int) -> None:
    """Every in-range address parses back to itself from its bare / 0x / uppercase hex forms."""
    assert parse_address(f"{n:x}") == n
    assert parse_address(f"0x{n:x}") == n
    assert parse_address(f"0X{n:X}") == n


# --- validate_name (CWE-20 / stored injection) --------------------------------------------------
_PRINTABLE = st.characters(min_codepoint=0x21, max_codepoint=0x7E)
_CONTROL_OR_SEP = st.sampled_from(
    ["\x00", "\x1f", "\x7f", "\x80", "\x9f", _LINE_SEP, _PARA_SEP, "\n", "\t", "\r"]
)


@settings(max_examples=400)
@given(st.text())
def test_validate_name_is_total_and_returns_unchanged(text: str) -> None:
    """Arbitrary text → the value UNCHANGED (meeting the invariant), or raise VALIDATION."""
    try:
        result = validate_name(text)
    except GhidraMcpError as exc:
        assert exc.envelope.type is ErrorType.VALIDATION
    else:
        assert result == text  # accepted names are returned verbatim (no silent mutation)
        assert 1 <= len(result) <= MAX_NAME_LEN
        assert not any(_is_control_or_separator(ch) for ch in result)


@settings(max_examples=300)
@given(
    st.text(alphabet=_PRINTABLE, max_size=20),
    _CONTROL_OR_SEP,
    st.text(alphabet=_PRINTABLE, max_size=20),
)
def test_validate_name_rejects_any_control_or_separator(pre: str, bad: str, post: str) -> None:
    """A name containing ANY control/DEL/C1 char or Unicode line/para separator is rejected."""
    with pytest.raises(GhidraMcpError) as ei:
        validate_name(pre + bad + post)
    assert ei.value.envelope.type is ErrorType.VALIDATION
