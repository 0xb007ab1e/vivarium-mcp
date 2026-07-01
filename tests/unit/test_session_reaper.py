"""Unit tests for the background session reaper (gap N5).

The reaper periodically calls ``SessionManager.reap_expired`` so an abandoned session's worker +
store don't linger until shutdown. These tests use a fake reapable + ``Event`` signalling (no
manual sleeps) and assert: it sweeps periodically, survives a reap exception (a failing sweep must
not kill the daemon), stop/start are idempotent, and a non-positive interval is rejected.
"""

from __future__ import annotations

import threading

import pytest

from vivarium.sessions.reaper import PeriodicReaper


class _CountingManager:
    """A fake reapable that counts ``reap_expired`` calls and signals progress via Events."""

    def __init__(self, *, raise_first: bool = False, evicted: int = 0) -> None:
        """Set up the counter; ``raise_first`` makes the first sweep raise (to test survival)."""
        self.calls = 0
        self._raise_first = raise_first
        self._evicted = evicted
        self.first = threading.Event()
        self.twice = threading.Event()

    def reap_expired(self) -> int:
        """Record a sweep, fire the progress Events, optionally raise on the first call."""
        self.calls += 1
        self.first.set()
        if self.calls >= 2:
            self.twice.set()
        if self._raise_first and self.calls == 1:
            raise RuntimeError("simulated reap failure")
        return self._evicted


def test_rejects_non_positive_interval() -> None:
    """A non-positive interval is rejected (a zero/negative sweep period is a misconfig)."""
    with pytest.raises(ValueError, match="positive"):
        PeriodicReaper(_CountingManager(), interval_s=0)


def test_sweeps_periodically_then_stops_cleanly() -> None:
    """The daemon calls reap_expired on its interval; stop() joins and is idempotent."""
    mgr = _CountingManager()
    reaper = PeriodicReaper(mgr, interval_s=0.005)
    reaper.start()
    try:
        assert mgr.first.wait(2), "reaper never called reap_expired"
    finally:
        reaper.stop()
    assert mgr.calls >= 1
    reaper.stop()  # idempotent — a second stop is a no-op


def test_survives_a_reap_exception() -> None:
    """A sweep that raises is logged and swallowed — the daemon keeps sweeping (does not die)."""
    mgr = _CountingManager(raise_first=True)
    reaper = PeriodicReaper(mgr, interval_s=0.005)
    reaper.start()
    try:
        # If the exception killed the daemon, the second sweep never happens and this times out.
        assert mgr.twice.wait(2), "reaper died after a reap exception"
    finally:
        reaper.stop()


def test_logs_when_a_sweep_evicts_sessions() -> None:
    """A sweep that evicts >0 sessions exercises the audit-log branch (then stops cleanly)."""
    mgr = _CountingManager(evicted=2)
    reaper = PeriodicReaper(mgr, interval_s=0.005)
    reaper.start()
    try:
        assert mgr.first.wait(2), "reaper never swept"
    finally:
        reaper.stop()
    assert mgr.calls >= 1


def test_start_is_idempotent() -> None:
    """A second start() does not spawn a second thread."""
    reaper = PeriodicReaper(_CountingManager(), interval_s=3600)  # long → won't fire in-test
    reaper.start()
    thread = reaper._thread
    reaper.start()  # no-op
    assert reaper._thread is thread
    reaper.stop()


def test_concurrent_start_spawns_exactly_one_thread() -> None:
    """A start() stampede spawns ONE sweeper thread — the lifecycle lock serializes the check.

    Without the lock, concurrent callers could each pass the ``_thread is None`` check and spawn
    their own thread; the lock guarantees exactly one is created.
    """
    reaper = PeriodicReaper(_CountingManager(), interval_s=3600)  # long → threads just wait
    barrier = threading.Barrier(8)

    def _start() -> None:
        barrier.wait()  # release all at once to maximise the race on the idempotency check
        reaper.start()

    threads = [threading.Thread(target=_start) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(2)
    live = [th for th in threading.enumerate() if th.name == "vivarium-session-reaper"]
    assert len(live) == 1  # exactly one sweeper despite 8 concurrent start() calls
    reaper.stop()
    assert reaper._thread is None
