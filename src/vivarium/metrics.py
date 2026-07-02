"""In-process metrics registry + periodic structured-log emission (gap N3a).

The server had structured logs but no aggregated SLIs (topic-logging-observability /
topic-reliability: RED — Rate, Errors, Duration). This adds a tiny, dependency-free, thread-safe
in-process counter registry and emits a single ``metrics.snapshot`` structured-log line on a fixed
interval (and on shutdown). **No new dependency and no ``/metrics`` scrape endpoint** (operator
decision) — the existing redacting logger is the transport.

What is metered:
  * **RED (per tool):** call count by ``(tool, outcome)`` + a duration sum/count per tool, recorded
    at the single tool error-boundary chokepoint so BOTH transports (stdio + HTTP) are covered.
  * **Lifecycle:** sessions created / evicted (by reason).
  * **Auth decisions:** allow / deny by auth mode (HTTP authentication chokepoint).

Redaction (master §5): every label is closed-vocabulary — a Tier-1 tool name, an outcome slug
(``ok`` / an :class:`~vivarium.core.errors.ErrorType` value), a session-evict reason, or an auth
mode/decision. No binary-derived content, session id, or principal id is ever recorded, so the
snapshot is safe to log.

Registry access is a **module-level default** (in-process counters are inherently process-global,
like a Prometheus default registry) exposed through thin module functions so each instrument site is
a one-liner; the registry is still a plain, resettable object for hermetic tests.

Note: distinct from :mod:`vivarium.core.metrics`, which holds the pure *code-analysis* metric cores
(cyclomatic complexity, call-graph metrics — ADR-008). This module is *operational* observability.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from vivarium.logging import get_logger

_log = get_logger(__name__)

#: Outcome slug for a tool call that returned normally (vs. an ErrorType value on failure).
OUTCOME_OK = "ok"

#: Auth-decision slugs (closed vocabulary).
AUTH_ALLOW = "allow"
AUTH_DENY = "deny"


class Metrics:
    """Thread-safe in-process counters for RED + lifecycle + auth SLIs (no I/O on the hot path)."""

    __slots__ = (
        "_auth",
        "_lock",
        "_sessions_created",
        "_sessions_evicted",
        "_tool_calls",
        "_tool_dur_count",
        "_tool_dur_sum",
    )

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._lock = threading.Lock()
        self._tool_calls: dict[tuple[str, str], int] = {}
        self._tool_dur_sum: dict[str, float] = {}
        self._tool_dur_count: dict[str, int] = {}
        self._sessions_created = 0
        self._sessions_evicted: dict[str, int] = {}
        self._auth: dict[tuple[str, str], int] = {}

    def record_tool_call(self, tool: str, outcome: str, duration_s: float) -> None:
        """Record one tool invocation: count by ``(tool, outcome)`` + duration sum/count (RED).

        Args:
            tool: The Tier-1 tool name (closed vocabulary — safe).
            outcome: :data:`OUTCOME_OK` or an :class:`ErrorType` value slug.
            duration_s: Wall-clock duration; negatives clamp to 0 (a monotonic-clock skew guard).
        """
        with self._lock:
            self._tool_calls[(tool, outcome)] = self._tool_calls.get((tool, outcome), 0) + 1
            self._tool_dur_sum[tool] = self._tool_dur_sum.get(tool, 0.0) + max(0.0, duration_s)
            self._tool_dur_count[tool] = self._tool_dur_count.get(tool, 0) + 1

    def record_session_created(self) -> None:
        """Increment the sessions-created counter (lifecycle)."""
        with self._lock:
            self._sessions_created += 1

    def record_session_evicted(self, reason: str) -> None:
        """Increment the sessions-evicted counter for ``reason`` (closed-vocabulary label)."""
        with self._lock:
            self._sessions_evicted[reason] = self._sessions_evicted.get(reason, 0) + 1

    def record_auth_decision(self, mode: str, decision: str) -> None:
        """Record an auth allow/deny by mode (HTTP authentication chokepoint).

        Args:
            mode: The auth mode (``none``/``bearer``/``mtls``/``oauth``/``mtls-proxy``) — safe.
            decision: :data:`AUTH_ALLOW` or :data:`AUTH_DENY`.
        """
        with self._lock:
            self._auth[(mode, decision)] = self._auth.get((mode, decision), 0) + 1

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe, deterministically-ordered snapshot of all counters.

        Returns:
            A nested dict: ``tool_calls`` (``"tool/outcome" -> count``), ``tool_duration_seconds``
            (``tool -> {sum, count}``), ``sessions_created``, ``sessions_evicted`` (``reason ->
            count``), and ``auth_decisions`` (``"mode/decision" -> count``). All keys sorted.
        """
        with self._lock:
            return {
                "tool_calls": {
                    f"{tool}/{outcome}": n
                    for (tool, outcome), n in sorted(self._tool_calls.items())
                },
                "tool_duration_seconds": {
                    tool: {
                        "sum": round(self._tool_dur_sum[tool], 6),
                        "count": self._tool_dur_count[tool],
                    }
                    for tool in sorted(self._tool_dur_sum)
                },
                "sessions_created": self._sessions_created,
                "sessions_evicted": dict(sorted(self._sessions_evicted.items())),
                "auth_decisions": {
                    f"{mode}/{decision}": n for (mode, decision), n in sorted(self._auth.items())
                },
            }

    def log_snapshot(self, *, active_sessions: int | None = None) -> None:
        """Emit the snapshot as one ``metrics.snapshot`` structured-log line (redaction-safe).

        Args:
            active_sessions: Optional current live-session gauge (the registry holds only counters;
                the manager owns the live count, so it is passed in at emit time).
        """
        snap = self.snapshot()
        if active_sessions is not None:
            snap["sessions_active"] = active_sessions
        _log.info("metrics.snapshot", extra={"metrics": snap})

    def reset(self) -> None:
        """Clear all counters (test hygiene — never called in production)."""
        with self._lock:
            self._tool_calls.clear()
            self._tool_dur_sum.clear()
            self._tool_dur_count.clear()
            self._sessions_created = 0
            self._sessions_evicted.clear()
            self._auth.clear()


# Module-level default registry (in-process counters are process-global). Instrument sites call the
# thin module functions below so each is a one-liner; tests use `metrics()` + `reset()`.
_DEFAULT = Metrics()


def metrics() -> Metrics:
    """Return the process-default :class:`Metrics` registry."""
    return _DEFAULT


def record_tool_call(tool: str, outcome: str, duration_s: float) -> None:
    """Record a tool invocation on the default registry (see :meth:`Metrics.record_tool_call`)."""
    _DEFAULT.record_tool_call(tool, outcome, duration_s)


def record_session_created() -> None:
    """Record a session creation on the default registry."""
    _DEFAULT.record_session_created()


def record_session_evicted(reason: str) -> None:
    """Record a session eviction (by reason) on the default registry."""
    _DEFAULT.record_session_evicted(reason)


def record_auth_decision(mode: str, decision: str) -> None:
    """Record an auth allow/deny (by mode) on the default registry."""
    _DEFAULT.record_auth_decision(mode, decision)


class PeriodicMetricsLogger:
    """Daemon thread that emits a metrics snapshot every ``interval_s`` until stopped.

    The registry only accumulates; this is the emission mechanism (the "logs-only" transport — no
    scrape endpoint). Mirrors :class:`~vivarium.sessions.reaper.PeriodicReaper`: an interruptible
    ``Event`` stop (graceful shutdown does not wait out the interval) and a snapshot failure is
    logged + swallowed so a bad emit never kills the daemon.
    """

    def __init__(
        self,
        registry: Metrics,
        *,
        interval_s: float,
        active_sessions: Callable[[], int] | None = None,
    ) -> None:
        """Initialize the logger (does not start it).

        Args:
            registry: The metrics registry to snapshot.
            interval_s: Seconds between snapshots. Must be positive.
            active_sessions: Optional callable returning the current live-session count (the
                registry holds only counters; the manager owns the live gauge).
        """
        if interval_s <= 0:
            raise ValueError("metrics interval_s must be positive")
        self._registry = registry
        self._interval_s = interval_s
        self._active_sessions = active_sessions
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        #: Serializes the start()/stop() lifecycle transitions so concurrent callers can't both
        #: pass the idempotency check (double-start) or both swap out `_thread` (double-join). The
        #: join + final emit run OUTSIDE this lock so a slow join can't block a concurrent
        #: transition.
        self._lock = threading.Lock()

    def start(self) -> None:
        """Spawn the daemon snapshot thread (idempotent — a second call is a no-op)."""
        with self._lock:
            if self._thread is not None:
                return
            # Reset the stop signal so a start() AFTER a prior stop() actually emits. stop() SETS
            # the Event and never clears it, and _run loops on `while not self._stop.wait(...)`, so
            # without this a restarted daemon's first wait() returns True immediately → the thread
            # exits without ever emitting a snapshot (silent no-op logger). Cleared here (under the
            # lock, only on a real (re)start), not in stop() (R3/round-5).
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name="vivarium-metrics-logger", daemon=True
            )
            self._thread.start()

    def stop(self, *, timeout_s: float = 5.0) -> None:
        """Signal the daemon to exit, join it, then emit a final snapshot (idempotent).

        The final snapshot is emitted ONLY once the daemon thread has actually exited (the bounded
        join completed). If the join TIMES OUT (a slow emit still in flight) we skip it rather than
        run a second ``_emit()`` concurrently with the daemon's still-running one. That concurrency
        is benign (``snapshot()`` is lock-guarded, counters are read-only) but the "emit, signal,
        join"
        contract was subtly unsound on a slow emit; this makes it strict. A never-started logger
        (thread is ``None``) stays silent.
        """
        self._stop.set()
        with self._lock:
            thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout_s)
            # Final snapshot captures the last interval's activity — but only if the daemon truly
            # exited; a timed-out join means it is still emitting, so we must not race it.
            if not thread.is_alive():
                self._emit()

    def _emit(self) -> None:
        """Emit one snapshot, swallowing+logging any failure (an emit must never propagate)."""
        try:
            active = self._active_sessions() if self._active_sessions is not None else None
            self._registry.log_snapshot(active_sessions=active)
        except Exception:
            _log.exception("metrics.snapshot.error")

    def _run(self) -> None:
        """Snapshot loop: wait the interval (interruptibly) then emit; exit when ``stop`` is set."""
        while not self._stop.wait(self._interval_s):
            self._emit()
