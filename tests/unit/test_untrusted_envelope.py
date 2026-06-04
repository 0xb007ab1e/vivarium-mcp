"""Contract tests for the untrusted-data envelope (ADR-005, FROZEN — WS0).

Lock the wrapper shape that marks ALL binary-derived content as hostile-origin. Critical path
(envelope) → 100% target. The ``wrap()`` normalization is a WS4 stub; we assert it is reserved.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ghidra_mcp.core.envelope import DataOrigin, Untrusted, wrap


@pytest.mark.critical
def test_origin_slugs_are_stable() -> None:
    assert DataOrigin.BINARY == "binary-derived"
    assert DataOrigin.GHIDRA == "ghidra-generated"


@pytest.mark.critical
def test_wraps_text_with_defaults() -> None:
    u: Untrusted[str] = Untrusted(value="mov eax, 1", origin=DataOrigin.BINARY)
    assert u.value == "mov eax, 1"
    assert u.origin == DataOrigin.BINARY
    assert u.truncated is False
    assert u.encoding is None
    assert u.notes == []


@pytest.mark.critical
def test_wraps_structured_payloads_generically() -> None:
    # The envelope is generic over payload shape (str, list, etc.).
    u: Untrusted[list[str]] = Untrusted(
        value=["a", "b"], origin=DataOrigin.GHIDRA, truncated=True, notes=["clipped"]
    )
    assert u.value == ["a", "b"]
    assert u.truncated is True
    assert u.notes == ["clipped"]


@pytest.mark.critical
def test_envelope_is_frozen_and_forbids_extra() -> None:
    u: Untrusted[str] = Untrusted(value="x", origin=DataOrigin.BINARY)
    with pytest.raises(ValidationError):
        u.value = "y"  # type: ignore[misc]  # frozen
    with pytest.raises(ValidationError):
        Untrusted(value="x", origin=DataOrigin.BINARY, trusted=True)  # type: ignore[call-arg]


@pytest.mark.critical
def test_notes_are_bounded() -> None:
    with pytest.raises(ValidationError):
        Untrusted(value="x", origin=DataOrigin.BINARY, notes=[str(i) for i in range(17)])


@pytest.mark.critical
def test_wrap_helper_is_reserved_for_ws4() -> None:
    # The normalization chokepoint is intentionally a stub until WS4 hardens it.
    with pytest.raises(NotImplementedError):
        wrap("anything")
