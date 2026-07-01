"""Unit tests for the operational metrics registry + instrumentation (gap N3a).

Covers :mod:`vivarium.metrics` (operational observability — NOT ``vivarium.core.metrics``, the
code-analysis metric cores tested in ``test_metrics.py``): the registry counters + snapshot, the
periodic-emission daemon (event-driven, no sleeps), and that the three instrument sites actually
record — RED at the tool error-boundary, auth allow/deny at the HTTP authentication middleware, and
session create/evict + the active-count gauge at the manager. Hermetic + deterministic (master §4).
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

from vivarium import metrics
from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.metrics import (
    AUTH_ALLOW,
    AUTH_DENY,
    OUTCOME_OK,
    Metrics,
    PeriodicMetricsLogger,
)
from vivarium.server import app as srv
from vivarium.server.auth import BearerAuthenticator, NullAuthenticator
from vivarium.server.http_middleware import AuthenticationMiddleware
from vivarium.sessions.manager import SessionManager

_TOKEN = "token-of-sufficient-length-xx"  # noqa: S105  # test fixture, not a real secret


# --- registry ------------------------------------------------------------------------------------
def test_record_tool_call_accumulates_count_and_duration() -> None:
    """Tool calls accumulate per (tool, outcome) count + a per-tool duration sum/count."""
    m = Metrics()
    m.record_tool_call("decompile_function", OUTCOME_OK, 0.5)
    m.record_tool_call("decompile_function", OUTCOME_OK, 1.5)
    m.record_tool_call("decompile_function", "validation-error", 0.1)
    snap = m.snapshot()
    assert snap["tool_calls"]["decompile_function/ok"] == 2
    assert snap["tool_calls"]["decompile_function/validation-error"] == 1
    assert snap["tool_duration_seconds"]["decompile_function"] == {"sum": 2.1, "count": 3}


def test_negative_duration_is_clamped_to_zero() -> None:
    """A negative duration (monotonic-clock skew) is clamped, never decrementing the sum."""
    m = Metrics()
    m.record_tool_call("t", OUTCOME_OK, -5.0)
    assert m.snapshot()["tool_duration_seconds"]["t"]["sum"] == 0.0


def test_lifecycle_and_auth_counters() -> None:
    """Session create/evict and auth allow/deny accumulate under their labels."""
    m = Metrics()
    m.record_session_created()
    m.record_session_created()
    m.record_session_evicted("ttl")
    m.record_session_evicted("ttl")
    m.record_session_evicted("close")
    m.record_auth_decision("bearer", AUTH_ALLOW)
    m.record_auth_decision("bearer", AUTH_DENY)
    snap = m.snapshot()
    assert snap["sessions_created"] == 2
    assert snap["sessions_evicted"] == {"close": 1, "ttl": 2}
    assert snap["auth_decisions"] == {"bearer/allow": 1, "bearer/deny": 1}


def test_snapshot_keys_are_sorted_and_reset_clears() -> None:
    """Snapshot keys are deterministically ordered; reset() zeroes everything."""
    m = Metrics()
    for reason in ("zeta", "alpha", "mid"):
        m.record_session_evicted(reason)
    assert list(m.snapshot()["sessions_evicted"]) == ["alpha", "mid", "zeta"]
    m.reset()
    snap = m.snapshot()
    assert snap["sessions_created"] == 0 and snap["sessions_evicted"] == {}
    assert snap["tool_calls"] == {} and snap["auth_decisions"] == {}


def test_log_snapshot_emits_structured_line_with_active_gauge(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """log_snapshot emits one ``metrics.snapshot`` record carrying the snapshot + active gauge."""
    m = Metrics()
    m.record_session_created()
    with caplog.at_level("INFO", logger="vivarium.metrics"):
        m.log_snapshot(active_sessions=3)
    rec = next(r for r in caplog.records if r.msg == "metrics.snapshot")
    payload = rec.metrics  # type: ignore[attr-defined]
    assert payload["sessions_created"] == 1 and payload["sessions_active"] == 3


def test_module_functions_delegate_to_default_registry() -> None:
    """The thin module functions record onto the process-default registry."""
    metrics.metrics().reset()
    metrics.record_tool_call("get_symbol", OUTCOME_OK, 0.01)
    metrics.record_session_created()
    metrics.record_session_evicted("idle")
    metrics.record_auth_decision("none", AUTH_ALLOW)
    snap = metrics.metrics().snapshot()
    assert snap["tool_calls"]["get_symbol/ok"] == 1
    assert snap["sessions_created"] == 1
    assert snap["sessions_evicted"]["idle"] == 1
    assert snap["auth_decisions"]["none/allow"] == 1
    metrics.metrics().reset()


# --- periodic emission daemon --------------------------------------------------------------------
class _SignallingRegistry:
    """A fake registry whose log_snapshot fires Events (no sleeps); optionally raises once."""

    def __init__(self, *, raise_first: bool = False) -> None:
        self.calls = 0
        self._raise_first = raise_first
        self.first = threading.Event()
        self.twice = threading.Event()
        self.active_seen: list[int | None] = []

    def log_snapshot(self, *, active_sessions: int | None = None) -> None:
        self.calls += 1
        self.active_seen.append(active_sessions)
        self.first.set()
        if self.calls >= 2:
            self.twice.set()
        if self._raise_first and self.calls == 1:
            raise RuntimeError("simulated emit failure")


def test_logger_rejects_non_positive_interval() -> None:
    """A non-positive interval is a misconfig — rejected."""
    with pytest.raises(ValueError, match="positive"):
        PeriodicMetricsLogger(Metrics(), interval_s=0)


def test_logger_emits_periodically_then_a_final_snapshot_on_stop() -> None:
    """The daemon emits on its interval, threads the active gauge, and emits once more on stop."""
    reg = _SignallingRegistry()
    logger = PeriodicMetricsLogger(reg, interval_s=0.005, active_sessions=lambda: 7)  # type: ignore[arg-type]
    logger.start()
    try:
        assert reg.first.wait(2), "logger never emitted"
    finally:
        logger.stop()
    assert reg.calls >= 2  # at least one interval emit + the final stop emit
    assert reg.active_seen[-1] == 7  # the active-gauge callback is threaded through
    logger.stop()  # idempotent


def test_logger_survives_an_emit_exception() -> None:
    """An emit that raises is logged + swallowed — the daemon keeps emitting (does not die)."""
    reg = _SignallingRegistry(raise_first=True)
    logger = PeriodicMetricsLogger(reg, interval_s=0.005)  # type: ignore[arg-type]
    logger.start()
    try:
        assert reg.twice.wait(2), "logger died after an emit exception"
    finally:
        logger.stop()


def test_logger_start_is_idempotent() -> None:
    """A second start() does not spawn a second thread."""
    logger = PeriodicMetricsLogger(Metrics(), interval_s=3600)  # long → won't fire in-test
    logger.start()
    thread = logger._thread
    logger.start()
    assert logger._thread is thread
    logger.stop()


def test_logger_concurrent_start_spawns_exactly_one_thread() -> None:
    """A start() stampede spawns ONE snapshot thread — the lifecycle lock serializes the check.

    Without the lock, concurrent callers could each pass the ``_thread is None`` check and spawn
    their own thread; the lock guarantees exactly one is created.
    """
    logger = PeriodicMetricsLogger(Metrics(), interval_s=3600)  # long → threads just wait
    barrier = threading.Barrier(8)

    def _start() -> None:
        barrier.wait()  # release all at once to maximise the race on the idempotency check
        logger.start()

    threads = [threading.Thread(target=_start) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(2)
    live = [th for th in threading.enumerate() if th.name == "vivarium-metrics-logger"]
    assert len(live) == 1  # exactly one snapshot thread despite 8 concurrent start() calls
    logger.stop()
    assert logger._thread is None


def test_never_started_logger_stop_is_silent() -> None:
    """Stopping a logger that was never started emits nothing (no spurious snapshot)."""
    reg = _SignallingRegistry()
    PeriodicMetricsLogger(reg, interval_s=3600).stop()  # type: ignore[arg-type]
    assert reg.calls == 0


def test_stop_skips_final_emit_when_join_times_out() -> None:
    """If the daemon is mid-emit and the bounded join times out, stop() does NOT emit again (P6).

    Guards the race: a timed-out join means the daemon thread is still running ``_emit()``; stop()
    must not fire a second concurrent emit. Deterministic via a blocking fake (Events, no sleeps).
    """
    started = threading.Event()
    release = threading.Event()
    calls: list[int] = []

    class _BlockingRegistry:
        def log_snapshot(self, *, active_sessions: int | None = None) -> None:
            calls.append(1)
            started.set()
            release.wait(5)  # hold the daemon inside its emit until released

    logger = PeriodicMetricsLogger(_BlockingRegistry(), interval_s=0.005)  # type: ignore[arg-type]
    logger.start()
    try:
        assert started.wait(2), "daemon never entered its emit"
        logger.stop(timeout_s=0.05)  # join times out — the daemon is still blocked in log_snapshot
        assert len(calls) == 1, "stop() raced a second concurrent emit instead of skipping it"
    finally:
        release.set()  # let the daemon finish its emit + exit cleanly


# --- instrument site: RED at the tool error-boundary ---------------------------------------------
def test_error_boundary_records_red_for_success_and_failure() -> None:
    """The tool boundary records OUTCOME_OK on success and the error-type slug on failure."""
    metrics.metrics().reset()

    def ok(**_kw: object) -> str:
        return "result"

    def boom(**_kw: object) -> object:
        raise GhidraMcpError(
            ErrorEnvelope(type=ErrorType.SESSION_INVALID, title="x", detail="nope", status=404)
        )

    srv._with_error_boundary("get_function", ok)(session_id="s")
    out = srv._with_error_boundary("get_function", boom)(session_id="s")
    assert isinstance(out, ErrorEnvelope) and out.type is ErrorType.SESSION_INVALID
    snap = metrics.metrics().snapshot()
    assert snap["tool_calls"]["get_function/ok"] == 1
    assert snap["tool_calls"]["get_function/session-invalid"] == 1
    assert snap["tool_duration_seconds"]["get_function"]["count"] == 2
    metrics.metrics().reset()


# --- instrument site: auth allow/deny at the HTTP authentication middleware ---
async def _ok_inner(scope: Any, receive: Any, send: Any) -> None:
    """A trivial inner ASGI app that returns 200 (the authorized path)."""
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _drive(mw: Any) -> int | None:
    """Drive one credential-less POST through ``mw`` (typed Any, per test_http_middleware)."""
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "headers": [], "client": ("1.2.3.4", 5)}
    asyncio.run(mw(scope, receive, send))
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    return start["status"] if start else None


def test_auth_middleware_records_allow_and_deny() -> None:
    """The authentication middleware records an allow on success and a deny on 401, by mode."""
    metrics.metrics().reset()
    ok_mw = AuthenticationMiddleware(_ok_inner, authenticator=NullAuthenticator(), mode="none")
    assert _drive(ok_mw) == 200
    deny_mw = AuthenticationMiddleware(
        _ok_inner,
        authenticator=BearerAuthenticator(expected_token=_TOKEN),
        mode="bearer",
    )
    assert _drive(deny_mw) == 401  # no Authorization header → deny
    snap = metrics.metrics().snapshot()
    assert snap["auth_decisions"]["none/allow"] == 1
    assert snap["auth_decisions"]["bearer/deny"] == 1
    metrics.metrics().reset()


# --- instrument site: lifecycle + active-count gauge at the session manager ---
def test_session_manager_records_lifecycle_and_active_count() -> None:
    """create() bumps sessions_created + active_count; evict() bumps sessions_evicted."""
    metrics.metrics().reset()
    sm = SessionManager()  # no port → create/evict run without a worker
    info = sm.create()
    assert sm.active_count() == 1
    sm.evict(info.session_id, reason="close")
    assert sm.active_count() == 0
    snap = metrics.metrics().snapshot()
    assert snap["sessions_created"] == 1
    assert snap["sessions_evicted"]["close"] == 1
    metrics.metrics().reset()
