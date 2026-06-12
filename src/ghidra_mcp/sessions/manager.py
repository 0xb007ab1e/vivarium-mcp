"""Session manager — create / authorize / evict per-binary sessions (WS2; critical path).

Responsibilities (PLAN §2, ADR-002):

- Create sessions with an opaque, high-entropy id (unguessable — BOLA defense).
- Enforce a concurrency cap (worker-pool size) with backpressure above it (DoS — F7).
- Track TTL (absolute) and idle timeouts; evict on expiry.
- On eviction (TTL/idle/close/poison): **kill the session's worker** and **verified-wipe** the
  per-session project store; emit an audit log line. Eviction is idempotent.
- Authorize every tool call against a live session; unknown/foreign ids fail closed with a
  ``SESSION_INVALID`` envelope WITHOUT revealing whether another session exists.

The manager owns worker lifetimes (one worker per session); it depends on the Ghidra adapter
``port`` for spawning/killing workers and never touches the JVM itself (ADR-001). It is the single
owner of the session table; all mutating operations are serialized under a re-entrant lock so a
periodic reaper and request threads cannot corrupt the table (topic-concurrency).
"""

from __future__ import annotations

import contextlib
import secrets
import shutil
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ghidra_mcp.core.errors import ErrorType
from ghidra_mcp.ghidra import _errors
from ghidra_mcp.logging import get_logger
from ghidra_mcp.tools.schemas import SessionInfo

_LOG = get_logger(__name__)

#: Number of random bytes in a session id (256 bits — unguessable, BOLA defense). Rendered as
#: URL-safe base64 (~43 chars), well under the 64-char schema bound and safe as a path component.
_SESSION_ID_BYTES = 32

# Conservative built-in lifecycle defaults (overridable at construction from validated config).
_DEFAULT_TTL_S = 3600
_DEFAULT_IDLE_S = 900
_DEFAULT_MAX_SESSIONS = 4

#: Lifecycle states surfaced via :class:`SessionInfo` (tool-catalog.md / schemas.SessionInfo).
STATE_OPEN = "open"
STATE_READY = "ready"
STATE_EVICTED = "evicted"


class WorkerHandle(Protocol):
    """Opaque handle to a running Ghidra worker bound to one session (port).

    The concrete implementation lives in :mod:`ghidra_mcp.ghidra`; the manager treats it
    abstractly (dependency inversion — depend on the port, not the adapter).
    """

    def kill(self) -> None:
        """Forcibly terminate the worker process/container (on timeout or eviction)."""
        ...


class WorkerPort(Protocol):
    """Minimal worker-lifecycle surface the manager needs from the Ghidra adapter (port).

    A subset of :class:`ghidra_mcp.ghidra.port.GhidraPort`; depending on the narrow interface keeps
    the manager decoupled from the full tool surface (interface segregation).
    """

    def start_worker(self, session_id: str) -> None:
        """Spawn the session's worker (no binary yet)."""
        ...

    def kill_worker(self, session_id: str) -> None:
        """Forcibly terminate the session's worker. Idempotent."""
        ...


@dataclass(slots=True)
class _Session:
    """Server-side bookkeeping for one live session (no binary-derived content).

    Attributes:
        session_id: Opaque CSPRNG id.
        state: Lifecycle state string.
        created_at: Wall-clock epoch seconds at creation (for ``SessionInfo``; not used for TTL).
        created_mono: Monotonic timestamp at creation (TTL math — immune to clock jumps).
        last_used_mono: Monotonic timestamp of the last authorize (idle math).
        ttl_s: Absolute lifetime in seconds.
        idle_s: Idle timeout in seconds.
        binary_sha256: Server-computed digest once a binary is imported, else ``None``.
        store_path: Per-session project-store path to verified-wipe on eviction, or ``None`` if no
            store was provisioned.
        worker_started: Whether a worker was spawned (so eviction only kills a real worker).
        writes_enabled: Whether write consent was granted for this session (default-deny —
            ADR-012 §3). Mutation tools fail closed unless this is ``True``.
        allow_structural: Whether the (deferred) structural write set is additionally permitted.
            Only meaningful while ``writes_enabled`` is ``True``; reset on revoke.
    """

    session_id: str
    state: str
    created_at: int
    created_mono: float
    last_used_mono: float
    ttl_s: int
    idle_s: int
    binary_sha256: str | None = None
    store_path: str | None = None
    worker_started: bool = False
    writes_enabled: bool = False
    allow_structural: bool = False
    notes: list[str] = field(default_factory=list)


class SessionManager:
    """Owns the set of live sessions and their one-per-session workers (WS2).

    Constructed once at startup (composition root). Collaborators are injected (dependency
    inversion); all default to safe values so a bare ``SessionManager()`` is constructible (used by
    interface guards), but a worker ``port`` must be supplied for real worker lifecycle.
    """

    def __init__(
        self,
        *,
        port: WorkerPort | None = None,
        store_root: str | None = None,
        ttl_s: int = _DEFAULT_TTL_S,
        idle_s: int = _DEFAULT_IDLE_S,
        max_sessions: int = _DEFAULT_MAX_SESSIONS,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        """Initialize the session manager with injected collaborators.

        Args:
            port: Worker-lifecycle port (spawn/kill). ``None`` disables worker management (the
                manager still tracks sessions; kill becomes a no-op) — used by tests/guards.
            store_root: Root directory under which per-session project stores live. ``None`` means
                no on-disk store is provisioned (wipe is vacuously verified).
            ttl_s: Absolute session lifetime before TTL eviction.
            idle_s: Idle timeout before idle eviction.
            max_sessions: Concurrency cap; ``create`` applies backpressure above it.
            clock: Monotonic clock injection (for deterministic tests — topic-numeric-correctness).
            wall_clock: Wall-clock epoch-seconds injection (for ``SessionInfo`` timestamps).
        """
        self._port = port
        self._store_root = store_root
        self._ttl_s = ttl_s
        self._idle_s = idle_s
        self._max_sessions = max_sessions
        self._clock = clock
        self._wall_clock = wall_clock
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.RLock()

    def create(self, *, label: str | None = None) -> SessionInfo:
        """Open a new session with an opaque id; spawn nothing until import.

        Args:
            label: Optional audit label (untrusted; never used as a path or logged verbatim).

        Returns:
            The new session's :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``LIMIT_EXCEEDED`` if the concurrency cap is reached (backpressure).
        """
        with self._lock:
            if len(self._sessions) >= self._max_sessions:
                # Backpressure: refuse new work above the worker-pool cap (DoS — F7).
                _LOG.warning(
                    "session.create.rejected",
                    extra={"event": "session_cap_reached", "active": len(self._sessions)},
                )
                raise _errors.make_error(
                    ErrorType.LIMIT_EXCEEDED,
                    "session capacity reached; retry later",
                )
            session_id = secrets.token_urlsafe(_SESSION_ID_BYTES)
            now_mono = self._clock()
            now_wall = self._wall_clock()
            sess = _Session(
                session_id=session_id,
                state=STATE_OPEN,
                created_at=now_wall,
                created_mono=now_mono,
                last_used_mono=now_mono,
                ttl_s=self._ttl_s,
                idle_s=self._idle_s,
                store_path=self._store_path_for(session_id),
            )
            self._sessions[session_id] = sess
            _LOG.info(
                "session.create",
                extra={"event": "session_created", "session_id": session_id},
            )
            return self._to_info(sess)

    def authorize(self, session_id: str) -> SessionInfo:
        """Look up and authorize a live session by id, refreshing its idle clock.

        BOLA chokepoint: an unknown, expired, or evicted id all yield the SAME ``SESSION_INVALID``
        error — the response never reveals whether another session exists (error-envelope.md).
        Constant-time-ish lookup is not required (the id space is 256-bit random), but the *error*
        is identical across all failure modes.

        Args:
            session_id: The opaque id supplied by the client.

        Returns:
            The authorized :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted ids (BOLA-safe).
        """
        with self._lock:
            return self._to_info(self._get_live_locked(session_id))

    def _get_live_locked(self, session_id: str) -> _Session:
        """Look up a live session by id (caller holds ``_lock``); refresh its idle clock.

        Shared BOLA chokepoint for :meth:`authorize` and the write-consent methods so the
        unknown/expired/evicted handling is identical across them (all yield ``SESSION_INVALID``).

        Args:
            session_id: The opaque id supplied by the client.

        Returns:
            The live internal :class:`_Session`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted ids (BOLA-safe).
        """
        sess = self._sessions.get(session_id)
        if sess is None or sess.state == STATE_EVICTED:
            raise _errors.session_invalid()
        now = self._clock()
        if self._is_expired(sess, now):
            # Lazily evict an expired session, then fail closed with the same BOLA-safe error.
            self._evict_locked(session_id, reason="expired-on-authorize")
            raise _errors.session_invalid()
        sess.last_used_mono = now
        return sess

    def enable_writes(self, session_id: str, *, allow_structural: bool = False) -> SessionInfo:
        """Grant WRITE CONSENT to a session — the human-in-the-loop mutation gate (ADR-012 §3).

        Default-deny: sessions are read-only until this is called. The grant is per-session,
        revocable (:meth:`disable_writes` / implicit on evict), and audited.

        Args:
            session_id: The opaque session id.
            allow_structural: Additionally opt into the (deferred) structural write set.

        Returns:
            The session's updated :class:`SessionInfo` (reporting the consent state).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted ids (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id)
            sess.writes_enabled = True
            sess.allow_structural = allow_structural
            _LOG.info(
                "session.writes_enabled",
                extra={
                    "event": "session_writes_enabled",
                    "session_id": session_id,
                    "allow_structural": allow_structural,
                },
            )
            return self._to_info(sess)

    def disable_writes(self, session_id: str) -> SessionInfo:
        """Revoke write consent for a session (return it to read-only).

        Args:
            session_id: The opaque session id.

        Returns:
            The session's updated :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted ids (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id)
            sess.writes_enabled = False
            sess.allow_structural = False
            _LOG.info(
                "session.writes_disabled",
                extra={"event": "session_writes_disabled", "session_id": session_id},
            )
            return self._to_info(sess)

    def require_write_consent(self, session_id: str, *, structural: bool = False) -> SessionInfo:
        """Authorize the session AND require write consent; fail closed otherwise (ADR-012 §3).

        The mutation-tool gate chokepoint: every write handler calls this before delegating to the
        port. A session without consent (the default) is rejected with a ``VALIDATION`` envelope —
        no destructive action runs without the explicit, prior :meth:`enable_writes` grant (LLM08).

        Args:
            session_id: The opaque session id.
            structural: When ``True``, also require the (deferred) structural-write opt-in.

        Returns:
            The authorized :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) for a bad id, or ``VALIDATION`` when the
                session has not been granted (structural) write consent.
        """
        with self._lock:
            sess = self._get_live_locked(session_id)
            if not sess.writes_enabled:
                raise _errors.make_error(
                    ErrorType.VALIDATION,
                    "session is read-only; write consent not granted",
                )
            if structural and not sess.allow_structural:
                raise _errors.make_error(
                    ErrorType.VALIDATION,
                    "structural writes not permitted for this session",
                )
            return self._to_info(sess)

    def ensure_worker(self, session_id: str) -> None:
        """Idempotently spawn the session's worker (manager owns worker lifetime — ADR-002).

        Called on first import: the session exists (created with no worker — "spawn nothing until
        import") and now needs its one-per-session hardened worker. Spawning here (not at
        ``create``) keeps a bare session cheap and bounds resource use to sessions that actually
        import (DoS — F7). Marks ``worker_started`` so eviction kills the real worker and the
        per-session store is wiped (the symmetric counterpart to ``evict`` → ``kill_worker``).

        Idempotent: a second call is a no-op (a worker already runs). No-ops when no port is wired
        (test/guard construction). Re-validates the session under the lock (fails closed if it was
        evicted between authorize and here — a race).

        Args:
            session_id: The opaque id of a live session.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` if the session is unknown/evicted (BOLA-safe).
        """
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None or sess.state == STATE_EVICTED:
                raise _errors.session_invalid()
            if sess.worker_started or self._port is None:
                return
            # Spawn BEFORE flipping the flag: if the launcher raises, the session has no worker and
            # eviction won't try to kill a non-existent one (fail closed — the import then surfaces
            # worker-unavailable from the adapter).
            self._port.start_worker(session_id)
            sess.worker_started = True
            _LOG.info(
                "session.worker_started",
                extra={"event": "worker_started", "session_id": session_id},
            )

    def evict(self, session_id: str, *, reason: str) -> bool:
        """Evict a session: kill its worker and verified-wipe its store. Idempotent.

        Args:
            session_id: The session to evict.
            reason: Audit reason (e.g. ``"ttl"``, ``"idle"``, ``"close"``, ``"poison"``,
                ``"timeout"``).

        Returns:
            ``True`` if the per-session store was verified-wiped (or there was none); ``False``
            indicates a cleanup failure that MUST be alerted on (a wipe failure is a
            confidentiality incident).
        """
        with self._lock:
            return self._evict_locked(session_id, reason=reason)

    def reap_expired(self) -> int:
        """Evict all sessions past their TTL or idle timeout (called by a periodic sweeper).

        Returns:
            Number of sessions evicted.
        """
        with self._lock:
            now = self._clock()
            expired = [
                sid
                for sid, sess in self._sessions.items()
                if sess.state != STATE_EVICTED and self._is_expired(sess, now)
            ]
            for sid in expired:
                reason = "ttl" if self._ttl_expired(self._sessions[sid], now) else "idle"
                self._evict_locked(sid, reason=reason)
            return len(expired)

    def shutdown(self) -> None:
        """Evict all sessions on graceful server shutdown (drain → kill workers → wipe stores).

        Each eviction is independent; a failure on one does not abort the rest (best-effort drain —
        topic-resource-management). Wipe failures are logged for alerting.
        """
        with self._lock:
            for sid in list(self._sessions.keys()):
                if self._sessions[sid].state != STATE_EVICTED:
                    self._evict_locked(sid, reason="shutdown")
            self._sessions.clear()

    # --- internals (caller holds the lock) --------------------------------------------------
    def _evict_locked(self, session_id: str, *, reason: str) -> bool:
        """Kill the worker then verified-wipe the store. Idempotent. Caller holds ``_lock``.

        Args:
            session_id: The session to evict.
            reason: Audit reason.

        Returns:
            ``True`` if the store was verified absent afterward; ``False`` on a wipe failure.
        """
        sess = self._sessions.get(session_id)
        if sess is None:
            # Already gone / never existed: idempotent success (nothing to leak).
            return True

        # 1) Kill the worker FIRST so no process can still touch the store during the wipe.
        if sess.worker_started and self._port is not None:
            try:
                self._port.kill_worker(session_id)
            except Exception:
                _LOG.error(
                    "session.evict.kill_failed",
                    extra={"event": "worker_kill_failed", "session_id": session_id},
                )

        # 2) Verified wipe of the per-session store (confidentiality — ADR-002).
        wiped = self._wipe_store(sess.store_path)

        # 3) Mark evicted and drop from the table (idempotent: re-evict is a no-op success).
        sess.state = STATE_EVICTED
        self._sessions.pop(session_id, None)

        _LOG.info(
            "session.evict",
            extra={
                "event": "session_evicted",
                "session_id": session_id,
                "reason": reason,
                "store_wiped": wiped,
            },
        )
        if not wiped:
            # A wipe failure is a confidentiality incident — alert (surfaced as store_wiped=False).
            _LOG.error(
                "session.evict.store_wipe_failed",
                extra={
                    "event": "store_wipe_failed",
                    "session_id": session_id,
                    "reason": reason,
                },
            )
        return wiped

    @staticmethod
    def _wipe_store(store_path: str | None) -> bool:
        """Remove a per-session store directory and VERIFY it no longer exists.

        Args:
            store_path: The store path, or ``None`` if no store was provisioned.

        Returns:
            ``True`` if the path is confirmed absent afterward (or there was none); ``False`` if it
            still exists after the attempt (cleanup failure → confidentiality incident).
        """
        if store_path is None:
            return True
        # Fall through to the existence check — verification, not the attempt, decides success.
        with contextlib.suppress(OSError):
            shutil.rmtree(store_path, ignore_errors=True)
        # Verified wipe: the contract is that the store path no longer exists (ADR-002).
        return not Path(store_path).exists()

    def _store_path_for(self, session_id: str) -> str | None:
        """Compute the per-session store path under the store root, if one is configured.

        Args:
            session_id: The opaque, CSPRNG session id (safe, non-traversing path component).

        Returns:
            The store path, or ``None`` if no store root is configured.
        """
        if self._store_root is None:
            return None
        # session_id is URL-safe base64 of CSPRNG bytes: no separators, no traversal sequences.
        return str(Path(self._store_root) / session_id)

    def _is_expired(self, sess: _Session, now: float) -> bool:
        """Whether a session has hit either its absolute TTL or its idle timeout.

        Args:
            sess: The session.
            now: Current monotonic time.

        Returns:
            ``True`` if TTL or idle has elapsed.
        """
        return self._ttl_expired(sess, now) or (now - sess.last_used_mono) >= sess.idle_s

    @staticmethod
    def _ttl_expired(sess: _Session, now: float) -> bool:
        """Whether a session has hit its absolute TTL.

        Args:
            sess: The session.
            now: Current monotonic time.

        Returns:
            ``True`` if the absolute lifetime has elapsed.
        """
        return (now - sess.created_mono) >= sess.ttl_s

    def _to_info(self, sess: _Session) -> SessionInfo:
        """Project internal session state to the public :class:`SessionInfo` (no binary content).

        Args:
            sess: The session.

        Returns:
            The public session info.
        """
        return SessionInfo(
            session_id=sess.session_id,
            state=sess.state,
            created_at=sess.created_at,
            expires_at=sess.created_at + sess.ttl_s,
            binary_sha256=sess.binary_sha256,
            writes_enabled=sess.writes_enabled,
            allow_structural=sess.allow_structural,
        )
