"""Unit tests for the SessionManager on-evict callback wiring (ADR-040 streaming-job lifetime).

A streaming job lives only inside its session's lifetime (ADR-040 §6 / ADR-002): the manager fires
an injected ``on_evict(session_id)`` callback on EVERY eviction path (close, TTL, idle, shutdown,
lazy-expiry-on-authorize) so the streaming-job manager can discard the session's jobs + buffers.
The callback runs AFTER the lock is released (lock-ordering safety) and is best-effort (a callback
exception never aborts the eviction). Hermetic: injected :class:`FrozenClock`, no real worker.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tests.conftest import FrozenClock
from vivarium.core.errors import GhidraMcpError
from vivarium.sessions.manager import SessionManager


def _manager(clock: FrozenClock, on_evict: Callable[[str], None] | None) -> SessionManager:
    return SessionManager(
        ttl_s=100,
        idle_s=50,
        clock=clock.monotonic,
        wall_clock=clock.time,
        on_evict=on_evict,
    )


@pytest.mark.critical
def test_on_evict_fires_on_explicit_close() -> None:
    clock = FrozenClock()
    seen: list[str] = []
    mgr = _manager(clock, seen.append)
    info = mgr.create()
    mgr.evict(info.session_id, reason="close")
    assert seen == [info.session_id]


@pytest.mark.critical
def test_on_evict_fires_on_ttl_reap() -> None:
    clock = FrozenClock()
    seen: list[str] = []
    mgr = _manager(clock, seen.append)
    info = mgr.create()
    clock.advance(101)  # past TTL
    assert mgr.reap_expired() == 1
    assert seen == [info.session_id]


@pytest.mark.critical
def test_on_evict_fires_on_idle_reap() -> None:
    clock = FrozenClock()
    seen: list[str] = []
    mgr = _manager(clock, seen.append)
    info = mgr.create()
    clock.advance(51)  # past idle, within TTL
    assert mgr.reap_expired() == 1
    assert seen == [info.session_id]


@pytest.mark.critical
def test_on_evict_fires_on_lazy_expiry_during_authorize() -> None:
    clock = FrozenClock()
    seen: list[str] = []
    mgr = _manager(clock, seen.append)
    info = mgr.create()
    clock.advance(101)  # past TTL
    # The next authorize lazily evicts the expired session AND fires the callback after the lock.
    with pytest.raises(GhidraMcpError):
        mgr.authorize(info.session_id)
    assert seen == [info.session_id]


@pytest.mark.critical
def test_on_evict_fires_for_every_session_on_shutdown() -> None:
    clock = FrozenClock()
    seen: list[str] = []
    mgr = _manager(clock, seen.append)
    ids = {mgr.create().session_id for _ in range(3)}
    mgr.shutdown()
    assert set(seen) == ids


def test_on_evict_callback_exception_does_not_abort_eviction() -> None:
    clock = FrozenClock()

    def boom(_sid: str) -> None:
        raise RuntimeError("callback failed")

    mgr = _manager(clock, boom)
    info = mgr.create()
    # The eviction itself must still succeed (verified-wipe True) despite the callback fault.
    assert mgr.evict(info.session_id, reason="close") is True


def test_no_callback_when_on_evict_is_none() -> None:
    # The default (no callback) path must not break and must not collect anything.
    clock = FrozenClock()
    mgr = SessionManager(clock=clock.monotonic, wall_clock=clock.time)
    info = mgr.create()
    assert mgr.evict(info.session_id, reason="close") is True


@pytest.mark.critical
def test_set_evict_callback_binds_and_fires_on_eviction() -> None:
    # The public composition seam (used by build_app) binds the hook without a private-attr poke;
    # the bound callback fires on eviction exactly like a constructor-injected one.
    clock = FrozenClock()
    seen: list[str] = []
    mgr = SessionManager(clock=clock.monotonic, wall_clock=clock.time)  # no on_evict at ctor
    mgr.set_evict_callback(seen.append)
    info = mgr.create()
    mgr.evict(info.session_id, reason="close")
    assert seen == [info.session_id]


@pytest.mark.critical
def test_set_evict_callback_is_call_once_and_fails_closed_on_rebind() -> None:
    # Rebinding must raise (fail closed): a silent second binding would drop the first callback's
    # sessions on eviction. Holds whether the first binding came from __init__ or the seam itself.
    clock = FrozenClock()
    first: list[str] = []
    mgr = _manager(clock, first.append)  # first binding via __init__
    with pytest.raises(RuntimeError, match="already bound"):
        mgr.set_evict_callback(lambda _sid: None)
    # A second set_evict_callback after a first one also raises.
    mgr2 = SessionManager(clock=clock.monotonic, wall_clock=clock.time)
    mgr2.set_evict_callback(first.append)
    with pytest.raises(RuntimeError, match="already bound"):
        mgr2.set_evict_callback(lambda _sid: None)
    # The original binding still fires — the rejected rebind did not disturb it.
    info = mgr.create()
    mgr.evict(info.session_id, reason="close")
    assert first == [info.session_id]
