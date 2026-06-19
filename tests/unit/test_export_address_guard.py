"""Unit tests for the address-keyable guard behind ``session_export_annotations`` (ADR-024 F2).

Regression coverage for **F2 PR-2 of ADR-024**: ``session_export_annotations`` failed with an
opaque ``internal worker error`` on a real, renamed program because step 4 of the export
(``rename_symbol`` enumeration) called ``str(symbol.getAddress())`` on USER_DEFINED symbols whose
``getAddress()`` returns a null Java reference (namespace/class/library/global/external symbols).

The JVM enumeration loop itself is ``# pragma: no cover - JVM edge`` (validated only in the gated
real-worker integration suite), but the *decision* was extracted into the pure, duck-typed
predicate :func:`vivarium.ghidra._jvm_bridge._is_address_keyable` so the guard logic is testable
hermetically with fakes — no JVM, no real worker (ADR-001). These tests pin every branch of that
predicate: ``None``, a null-like memory-less address, a register/stack/external (non-memory)
address, a concrete memory address, and a malformed/foreign object (fails closed, never crashes).
"""

from __future__ import annotations

from vivarium.ghidra._jvm_bridge import _is_address_keyable


class _FakeAddress:
    """Duck-typed stand-in for a Ghidra ``Address`` exposing only ``isMemoryAddress()``."""

    def __init__(self, *, memory: bool) -> None:
        self._memory = memory

    def isMemoryAddress(self) -> bool:  # noqa: N802 — mirrors the Java API name exactly.
        """Return whether this fake address is a concrete memory address."""
        return self._memory


class _ExplodingAddress:
    """A foreign/malformed object whose ``isMemoryAddress()`` raises (must fail closed)."""

    def isMemoryAddress(self) -> bool:  # noqa: N802 — mirrors the Java API name exactly.
        """Raise to model a malformed/foreign Address reference."""
        raise RuntimeError("not a real Address")


def test_none_is_not_keyable() -> None:
    """A null ``getAddress()`` (Python ``None``) is not keyable — the exact F2 crash input."""
    assert _is_address_keyable(None) is False


def test_memory_address_is_keyable() -> None:
    """A concrete memory address (the valid ``rename_symbol`` target) is keyable."""
    assert _is_address_keyable(_FakeAddress(memory=True)) is True


def test_non_memory_address_is_not_keyable() -> None:
    """A non-memory address (register/stack/external slot) is not a rename_symbol target."""
    assert _is_address_keyable(_FakeAddress(memory=False)) is False


def test_malformed_address_fails_closed() -> None:
    """A malformed/foreign object answers 'not keyable' rather than crashing the export."""
    assert _is_address_keyable(_ExplodingAddress()) is False
