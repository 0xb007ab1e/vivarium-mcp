"""Background periodic session reaper (gap N5 / ADR-025).

:meth:`SessionManager.reap_expired` is lock-safe and in-flight-exempt, but nothing called it on a
schedule — eviction was purely **lazy** (a session is only evicted on its *next* call). So an
**abandoned** session (the common case when an MCP client disconnects — stdio host crash, HTTP
client drop) never gets another call: its TTL/idle never fires, and its hardened worker keeps the
hostile binary resident with the per-session store **unwiped** until ``shutdown()``. That is a
resource leak + a confidentiality window (master §5).

This daemon sweeps expired sessions on a fixed interval, closing that window. It is deliberately
tiny: the manager already owns all the locking, in-flight exemption, and the verified store-wipe
(ADR-025 D4) — the reaper just calls it. Stop is interruptible (an ``Event``), so graceful shutdown
does not wait out the interval.
"""

from __future__ import annotations

import logging
import threading
from typing import Protocol

_log = logging.getLogger(__name__)


class _Reapable(Protocol):
    """The narrow slice of the session manager the reaper needs (interface segregation)."""

    def reap_expired(self) -> int:
        """Evict every session past its TTL/idle (in-flight-exempt); return the count evicted."""
        ...


class PeriodicReaper:
    """Daemon thread calling :meth:`_Reapable.reap_expired` every ``interval_s`` until stopped."""

    def __init__(self, manager: _Reapable, *, interval_s: float) -> None:
        """Initialize the reaper (does not start it).

        Args:
            manager: The session manager (only its ``reap_expired`` is used).
            interval_s: Seconds between sweeps. Must be positive.
        """
        if interval_s <= 0:
            raise ValueError("reaper interval_s must be positive")
        self._manager = manager
        self._interval_s = interval_s
        #: The CURRENT run's stop signal (``None`` when not running). Each start() creates a FRESH
        #: Event owned by exactly that thread — NOT one shared Event that is cleared/reset across
        #: runs (round-6 V8). A shared, cleared Event had a race: a restart's ``clear()`` could wipe
        #: a still-running prior thread's exit signal (or a concurrent stop() could set the just-
        #: started thread's). A per-run Event has no shared mutable signal → no such race, while
        #: still giving R3 its property (a restart resumes: the new thread's Event starts unset).
        self._stop: threading.Event | None = None
        self._thread: threading.Thread | None = None
        #: Serializes the start()/stop() lifecycle transitions so concurrent callers can't both
        #: pass the idempotency check (double-start) or both swap out `_thread` (double-join). The
        #: join itself runs OUTSIDE this lock so a slow join can't block a concurrent transition.
        self._lock = threading.Lock()

    def start(self) -> None:
        """Spawn the daemon sweeper thread (idempotent — a second call is a no-op)."""
        with self._lock:
            if self._thread is not None:
                return
            # A FRESH Event per run (see `_stop` note): the new thread loops on ITS OWN signal, so a
            # later start() or a concurrent stop() cannot clear/set the wrong thread's Event. A
            # restart naturally resumes (the new Event starts unset → the first wait() blocks the
            # interval, not returns-true-immediately — the R3 property, without a shared clear()).
            stop = threading.Event()
            self._stop = stop
            self._thread = threading.Thread(
                target=self._run, args=(stop,), name="vivarium-session-reaper", daemon=True
            )
            self._thread.start()

    def stop(self, *, timeout_s: float = 5.0) -> None:
        """Signal the sweeper to exit and join it (idempotent; bounded by ``timeout_s``)."""
        with self._lock:
            thread, self._thread = self._thread, None
            stop, self._stop = self._stop, None
        # Set THIS run's own Event (captured under the lock) — never a shared one a concurrent
        # start() may have replaced — then join outside the lock (a slow join can't block a
        # transition). Idempotent: a second stop() finds both None and no-ops.
        if stop is not None:
            stop.set()
        if thread is not None:
            thread.join(timeout_s)

    def _run(self, stop: threading.Event) -> None:
        """Sweep loop: wait the interval (interruptibly), then reap; exit when ``stop`` is set."""
        # `stop` is THIS thread's own Event (passed at spawn). wait() returns True the moment stop()
        # fires (→ exit now, no interval wait), or False on timeout (→ time to sweep). A reap
        # exception must NEVER kill the daemon — that would silently halt all future sweeps — so it
        # is logged and the loop continues.
        while not stop.wait(self._interval_s):
            try:
                evicted = self._manager.reap_expired()
                if evicted:
                    _log.info("session.reaper.swept", extra={"evicted": evicted})
            except Exception:
                _log.exception("session.reaper.error")
