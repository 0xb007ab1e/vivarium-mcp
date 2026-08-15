"""Unit tests for ADR-066 `emulate` call-convenience — schema field + result builder.

The worker's scratch-stack + sentinel-return setup is a `# pragma: no cover` JVM edge validated
against a real worker (a crafted `int add(int,int)` returned 0xc via `call=true`); these test the
server contract: the additive `call` field and `_build_emulate`'s `return_value` untrusted-wrap.
"""

from __future__ import annotations

from vivarium.core.envelope import Untrusted
from vivarium.ghidra.rpc_client import _build_emulate
from vivarium.tools import schemas as s

# --- schema --------------------------------------------------------------------------------------


def test_call_defaults_false() -> None:
    """`call` is additive/opt-in — absent, it is False (byte-for-byte the pre-ADR-066 emulate)."""
    m = s.EmulateIn(session_id="s", start="0x1000")
    assert m.call is False


def test_call_can_be_set() -> None:
    """`call=True` engages the call convenience."""
    m = s.EmulateIn(session_id="s", start="0x1000", call=True)
    assert m.call is True


# --- result builder ------------------------------------------------------------------------------


def test_builder_wraps_return_value_untrusted() -> None:
    """`_build_emulate` wraps a present return_value UNTRUSTED (emulation output)."""
    out = _build_emulate(
        {
            "steps_executed": 3,
            "stop_reason": "stop-address",
            "registers": [],
            "memory": [],
            "return_value": "c",
        }
    )
    assert out.return_value is not None
    assert isinstance(out.return_value, Untrusted)
    assert out.return_value.value == "c"


def test_builder_return_value_none_when_absent() -> None:
    """A non-call emulation (no return_value) yields return_value=None, not a bare Untrusted."""
    out = _build_emulate(
        {"steps_executed": 5, "stop_reason": "max-steps", "registers": [], "memory": []}
    )
    assert out.return_value is None


def test_builder_unexpected_stop_reason_fails_closed() -> None:
    """An unexpected worker stop_reason is coerced to 'fault' (fail closed) — regression guard."""
    out = _build_emulate(
        {"steps_executed": 1, "stop_reason": "bogus", "registers": [], "memory": []}
    )
    assert out.stop_reason == "fault"
