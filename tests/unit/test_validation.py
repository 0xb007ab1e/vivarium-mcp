"""Unit tests for boundary validation (trust boundary 1) — critical path (target 100%).

Covers positive (allow-list) parses plus the negative/abuse inputs the validators must reject:
bad hex, oversized names, control characters, overflowing/zero ranges, malformed byte patterns.
Each rejection MUST be a fail-closed :class:`GhidraMcpError` of the right type, and detail strings
MUST NOT echo the rejected (untrusted) value.
"""

from __future__ import annotations

import pytest

from vivarium.core import validation as v
from vivarium.core.errors import ErrorType, GhidraMcpError

pytestmark = pytest.mark.critical


# --- parse_address -------------------------------------------------------------------
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0x0", 0),
        ("0x401000", 0x401000),
        ("00401000", 0x401000),
        ("0X401000", 0x401000),
        ("deadBEEF", 0xDEADBEEF),
        ("  0x10  ", 0x10),  # surrounding whitespace tolerated
        ("ffffffffffffffff", (1 << 64) - 1),  # max 64-bit
    ],
)
def test_parse_address_accepts_valid_hex(value: str, expected: int) -> None:
    assert v.parse_address(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "0x",
        "0X",
        "GG",
        "0xZZ",
        "0x10;rm -rf",
        "0x 10",  # internal whitespace not allowed
        "+0x10",
        "-1",
        "0x1_000",  # python int underscores must be rejected (allow-list)
        "1.0",
        "0x" + "f" * 17,  # too many hex digits (>64 bit)
        "f" * 17,
    ],
)
def test_parse_address_rejects_invalid(value: str) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.parse_address(value)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    # Safe detail: never echoes the rejected value.
    assert value.strip() not in exc.value.envelope.detail or value.strip() == ""


def test_parse_address_rejects_non_string() -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.parse_address(0x10)  # type: ignore[arg-type]
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_name -------------------------------------------------------------------
@pytest.mark.parametrize("value", ["main", "FUN_00401000", "operator==", "a" * v.MAX_NAME_LEN])
def test_validate_name_accepts_valid(value: str) -> None:
    assert v.validate_name(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * (v.MAX_NAME_LEN + 1),
        "bad\nname",
        "bad\tname",
        "nul\x00byte",
        "esc\x1bseq",
        "del\x7f",
        "c1\x85control",
        "line\u2028sep",  # U+2028 LINE SEPARATOR (escape form keeps the source unambiguous)
        "para\u2029sep",  # U+2029 PARAGRAPH SEPARATOR
    ],
)
def test_validate_name_rejects_invalid(value: str) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_name(value)
    assert exc.value.envelope.type is ErrorType.VALIDATION


def test_validate_name_rejects_non_string() -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_name(123)  # type: ignore[arg-type]
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_byte_range -------------------------------------------------------------
@pytest.mark.parametrize(
    ("offset", "length"),
    [
        (0, 1),
        (0, v.MAX_READ_BYTES),
        (0x1000, 256),
        ((1 << 64) - 1, 1),  # last byte exactly at the ceiling
    ],
)
def test_validate_byte_range_accepts_valid(offset: int, length: int) -> None:
    assert v.validate_byte_range(offset, length) == (offset, length)


@pytest.mark.parametrize(
    ("offset", "length", "etype"),
    [
        (-1, 16, ErrorType.VALIDATION),
        (0, 0, ErrorType.VALIDATION),
        (0, -5, ErrorType.VALIDATION),
        (0, v.MAX_READ_BYTES + 1, ErrorType.LIMIT_EXCEEDED),
        ((1 << 64), 1, ErrorType.VALIDATION),  # offset out of range
        ((1 << 64) - 1, 2, ErrorType.VALIDATION),  # end overflows the address space
    ],
)
def test_validate_byte_range_rejects_invalid(offset: int, length: int, etype: ErrorType) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_byte_range(offset, length)
    assert exc.value.envelope.type is etype


@pytest.mark.parametrize(("offset", "length"), [(True, 16), (0, False), (1.0, 16), (0, "16")])
def test_validate_byte_range_rejects_non_integers(offset: object, length: object) -> None:
    # bool is an int subclass; floats/strings must also be rejected (fail closed).
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_byte_range(offset, length)  # type: ignore[arg-type]
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_query ------------------------------------------------------------------
@pytest.mark.parametrize("value", ["x", "AaBb 09", "a" * v.MAX_QUERY_LEN])
def test_validate_query_accepts_valid(value: str) -> None:
    assert v.validate_query(value) == value


@pytest.mark.parametrize("value", ["", "a" * (v.MAX_QUERY_LEN + 1), "bad\nq", "z\x00"])
def test_validate_query_rejects_invalid(value: str) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_query(value)
    assert exc.value.envelope.type is ErrorType.VALIDATION


def test_validate_query_rejects_non_string() -> None:
    with pytest.raises(GhidraMcpError):
        v.validate_query(5)  # type: ignore[arg-type]


# --- validate_byte_pattern -----------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    ["de", "dead", "deadbeef", "de ad be ef", "??", "de??ff", "DE AD"],
)
def test_validate_byte_pattern_accepts_valid(value: str) -> None:
    assert v.validate_byte_pattern(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "d",  # odd length (half a byte)
        "abc",  # odd length
        "zz",  # non-hex byte
        "de?f",  # single wildcard char is not a whole wildcard byte
        "g0",
        "a" * (v.MAX_QUERY_LEN + 1),
    ],
)
def test_validate_byte_pattern_rejects_invalid(value: str) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_byte_pattern(value)
    assert exc.value.envelope.type is ErrorType.VALIDATION


def test_validate_byte_pattern_rejects_non_string() -> None:
    with pytest.raises(GhidraMcpError):
        v.validate_byte_pattern(b"de")  # type: ignore[arg-type]


def test_error_details_are_safe_and_bounded() -> None:
    """Rejection details must be safe summaries (non-empty, bounded, no echoed payload)."""
    payload = "0xZZ; DROP TABLE users; --"
    with pytest.raises(GhidraMcpError) as exc:
        v.parse_address(payload)
    detail = exc.value.envelope.detail
    assert 0 < len(detail) <= 2048
    assert "DROP TABLE" not in detail
