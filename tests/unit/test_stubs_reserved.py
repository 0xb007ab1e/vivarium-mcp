"""Frozen-constant guards + anti-stub-regression checks (reconciled at WS1-WS5 integration).

History: in WS0 this file asserted every WS1-WS5 stub raised ``NotImplementedError`` to lock the
interface before the build fan-out. At integration (2026-06-03) WS1/WS2/WS4 implemented those
stubs, so the transitional ``*_stubs_reserved`` guards were retired by the PM (this file is the
batch-atomicity-owned coordination artifact, edited only here — not by a feature workstream).

What remains here:
- The **frozen module-level constants** that are part of the contract (validation bounds, limit
  defaults) — these must never drift.
- Light **anti-regression** checks that the three 100%-critical pure functions
  (``core.validation``, ``security.limits``, ``core.envelope.wrap``) were NOT reverted to a stub.

Real behavior/coverage now lives in the per-module suites authored by the owning workstreams:
``test_validation.py`` (WS1), ``test_tools_registry.py``/``test_server_app.py``/
``test_config_logging.py`` (WS1), ``test_sessions_manager.py``/``test_rpc_adapter.py`` (WS2),
``test_limits.py``/``test_envelope_wrap.py`` (WS4), and ``tests/security/**`` (WS4 abuse paths).

Still genuinely stubbed (integration-only, intentionally not unit-guarded): the ``_gh_*``
PyGhidra bindings inside ``vivarium.ghidra._jvm_bridge`` — they require the pinned Ghidra/JDK
worker image (a GATED supply-chain action) to validate and are exercised only by the real-worker
integration suite (``tests/integration/**``, WS5 Wave-2). ``_jvm_bridge`` is ``omit``-ed from
server-side coverage by design.
"""

from __future__ import annotations

import pytest

from vivarium.core import validation as v


def _did_not_revert_to_stub(fn: object, *args: object, **kwargs: object) -> None:
    """Call ``fn`` and fail ONLY if it still raises ``NotImplementedError`` (i.e. is a stub).

    Any other exception (e.g. ``ValidationError`` on a deliberately-iffy argument) is acceptable
    here — this guard's sole job is to prove the implementation did not regress to the reserved
    stub. Real input/behavior assertions live in the owning workstream's per-module test file.

    Args:
        fn: The callable under test.
        *args: Positional arguments to pass.
        **kwargs: Keyword arguments to pass.
    """
    try:
        fn(*args, **kwargs)  # type: ignore[operator]
    except NotImplementedError as exc:  # pragma: no cover - only hit on a real regression
        raise AssertionError(
            f"{getattr(fn, '__name__', fn)!r} reverted to a NotImplementedError stub"
        ) from exc
    except Exception:  # noqa: S110 - any non-NotImplementedError means "implemented"; intentionally ignored
        pass


def test_validation_constants_frozen() -> None:
    """The validation boundary constants are part of the frozen contract and must not drift."""
    assert v.MAX_NAME_LEN == 1024
    assert v.MAX_QUERY_LEN == 4096
    assert v.MAX_READ_BYTES == 1_048_576
    assert v.MAX_RESULT_COUNT == 10_000


def test_limits_defaults_and_clamps_present() -> None:
    """The security-limit defaults are frozen; the dataclass is constructible with safe defaults."""
    from vivarium.security import limits as lim

    assert lim.DEFAULT_MAX_BINARY_BYTES == 128 * 1024 * 1024
    assert lim.HARD_MAX_BINARY_BYTES == 1024 * 1024 * 1024
    defaults = lim.Limits()
    assert defaults.max_sessions == lim.DEFAULT_MAX_SESSIONS


@pytest.mark.critical
def test_validation_implemented_not_stub() -> None:
    """Critical-path: ``core.validation`` helpers are implemented (not reverted to stubs)."""
    _did_not_revert_to_stub(v.parse_address, "0x1000")
    _did_not_revert_to_stub(v.validate_name, "main")
    _did_not_revert_to_stub(v.validate_byte_range, 0, 16)


@pytest.mark.critical
def test_limits_implemented_not_stub() -> None:
    """Critical-path: ``security.limits`` enforcement is implemented (not reverted to stubs)."""
    from vivarium.security import limits as lim

    _did_not_revert_to_stub(lim.resolve_limits, {"max_sessions": 2})
    _did_not_revert_to_stub(lim.check_binary_size, 10, lim.Limits())


@pytest.mark.critical
def test_envelope_wrap_implemented_not_stub() -> None:
    """Critical-path (TB4): the untrusted-data ``wrap`` chokepoint is implemented (not a stub)."""
    from vivarium.core.envelope import wrap

    _did_not_revert_to_stub(wrap, "x")
