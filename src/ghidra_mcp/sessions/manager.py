"""Session manager — create / authorize / evict per-binary sessions (WS2; critical path).

Responsibilities (PLAN §2, ADR-002):

- Create sessions with an opaque, high-entropy id (unguessable — BOLA defense).
- Enforce a concurrency cap (worker-pool size) with backpressure above it (DoS — F7).
- Track TTL (absolute) and idle timeouts; evict on expiry.
- On eviction (TTL/idle/close/poison): **kill the session's worker** and **verified-wipe** the
  per-session project store; emit an audit log line. Eviction is idempotent.
- Authorize every tool call against a live session AND against the **calling principal** (ADR-017):
  a session is owned by the principal that created it; a caller that is not the owner is denied with
  the SAME ``SESSION_INVALID`` envelope as unknown/expired/evicted — no oracle distinguishes "exists
  but not yours" from "does not exist" (BOLA / ``std-owasp-api`` API1; ADR-017 D2).
- Bound the number of concurrent sessions globally (``max_sessions``) AND per owner
  (``max_sessions_per_owner``) so one principal cannot starve others (noisy-neighbor —
  topic-multi-tenancy; ADR-017 STRIDE-D).

The manager owns worker lifetimes (one worker per session); it depends on the Ghidra adapter
``port`` for spawning/killing workers and never touches the JVM itself (ADR-001). It is the single
owner of the session table; all mutating operations are serialized under a re-entrant lock so a
periodic reaper and request threads cannot corrupt the table (topic-concurrency).

Ownership is the single, load-bearing per-principal authZ control (ADR-017): the owner check lives
in the shared :meth:`SessionManager._get_live_locked` chokepoint so every session-scoped entry point
(authorize, write-consent, ensure_worker, tool-initiated evict) enforces it uniformly and a new
session-scoped path cannot forget it (complete mediation, ``std-zero-trust``). The owner id is set
once at ``create`` from the **server-derived** principal and is immutable; the server never trusts a
client-supplied owner/principal.
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
#: Default per-owner session cap (ADR-017 STRIDE-D). Bounds one principal's share of the global
#: table so a single noisy principal cannot starve others (topic-multi-tenancy). ``None`` disables
#: the per-owner cap (the global ``max_sessions`` still applies). Defaults to the global cap so the
#: single-principal (stdio/``local``) case is unaffected.
_DEFAULT_MAX_SESSIONS_PER_OWNER: int | None = None

#: The implicit local-operator principal id used when no network authentication is in play (stdio,
#: ADR-006/ADR-017). Mirrors :class:`ghidra_mcp.server.auth.NullAuthenticator`'s principal id; kept
#: here as a plain literal so the manager has no import dependency on the auth/server layer.
_LOCAL_PRINCIPAL_ID = "local"

#: Upper bound on the number of distinct targets the change-log will retain per session (ADR-027).
#: Mirrors the worker's ``_MAX_RESULT_COUNT`` export cap so a session can never log more targets
#: than the export read-out can return. Over the cap the *write* still succeeds, but a new target
#: is dropped from the log so export fails closed at the worker's limit (``limit-exceeded``) rather
#: than the log growing unbounded (DoS — CWE-400). Re-touching an already-logged target is free.
_MAX_CHANGE_LOG_TARGETS = 10_000

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
        owner: The creating principal's id (ADR-017). Immutable, set once at ``create`` from the
            server-derived principal — never client-supplied. The single per-principal authZ key:
            a caller whose id != ``owner`` is denied the SAME ``SESSION_INVALID`` as an unknown id.
        state: Lifecycle state string.
        created_at: Wall-clock epoch seconds at creation (for ``SessionInfo``; not used for TTL).
        created_mono: Monotonic timestamp at creation (TTL math — immune to clock jumps).
        last_used_mono: Monotonic timestamp of the last authorize (idle math).
        in_flight: Count of currently-executing calls against this session (ADR-025 / F4). A
            session with ``in_flight > 0`` has a call actively running (e.g. a long ``analyze``) and
            is treated as **non-idle** so a legitimate long single operation cannot idle-evict
            itself. Bounded in-flight by the existing per-call timeout-kill (rpc_client.py) — the
            real in-flight DoS control — not by the idle clock. A non-negative counter (not a bool)
            so re-entrant/overlapping calls on one session are tracked correctly.
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
    owner: str
    state: str
    created_at: int
    created_mono: float
    last_used_mono: float
    ttl_s: int
    idle_s: int
    in_flight: int = 0
    binary_sha256: str | None = None
    store_path: str | None = None
    worker_started: bool = False
    writes_enabled: bool = False
    allow_structural: bool = False
    notes: list[str] = field(default_factory=list)
    #: Session-scoped change-log of comment write TARGETS (ADR-027 D2). Identity keys ONLY —
    #: ``(address, comment_type)`` pairs — NEVER the comment text/value (ADR-002/master §5). It is a
    #: set; a clear (``set_comment`` with ``text is None``) removes the key, so an authored-then-
    #: cleared comment is correctly absent from export. In-memory, wiped with the session on evict.
    comment_targets: set[tuple[str, str]] = field(default_factory=set)
    #: Session-scoped change-log of composite write TARGETS (ADR-027 D1 option 2). Composite NAMES
    #: ONLY (server/worker-validated identity, not binary-derived field values). Export reads only
    #: the named composites in this set instead of blind-enumerating program-local types (which
    #: also include Ghidra auto-analysis structs). In-memory, wiped with the session on evict.
    composite_targets: set[str] = field(default_factory=set)


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
        max_sessions_per_owner: int | None = _DEFAULT_MAX_SESSIONS_PER_OWNER,
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
            max_sessions: Global concurrency cap; ``create`` applies backpressure above it.
            max_sessions_per_owner: Per-principal session cap (ADR-017 STRIDE-D); ``create`` refuses
                a principal already holding this many live sessions (noisy-neighbor isolation —
                topic-multi-tenancy). ``None`` disables the per-owner cap (only the global cap
                applies) — the single-principal default.
            clock: Monotonic clock injection (for deterministic tests — topic-numeric-correctness).
            wall_clock: Wall-clock epoch-seconds injection (for ``SessionInfo`` timestamps).
        """
        self._port = port
        self._store_root = store_root
        self._ttl_s = ttl_s
        self._idle_s = idle_s
        self._max_sessions = max_sessions
        self._max_sessions_per_owner = max_sessions_per_owner
        self._clock = clock
        self._wall_clock = wall_clock
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.RLock()

    def create(self, *, owner: str = _LOCAL_PRINCIPAL_ID, label: str | None = None) -> SessionInfo:
        """Open a new session with an opaque id, owned by ``owner``; spawn nothing until import.

        Args:
            owner: The creating principal's id (ADR-017). **Server-derived** — the registry/shell
                always passes the authenticated principal's id (``ctx.caller_id``), never a
                client-supplied value. Recorded immutably as the session's owner; only this
                principal may subsequently authorize the session. Defaults to the implicit local
                operator for the single-principal stdio path (consistent with ``caller`` on the
                authorize family).
            label: Optional audit label (untrusted; never used as a path or logged verbatim).

        Returns:
            The new session's :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``LIMIT_EXCEEDED`` if the global concurrency cap OR the per-owner cap is
                reached (backpressure / noisy-neighbor isolation).
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
            # Per-owner cap (ADR-017 STRIDE-D): one principal cannot consume more than its share of
            # the global table and starve others (noisy-neighbor — topic-multi-tenancy). The audit
            # line records the owner id (an authenticated principal id, not a secret), not a token.
            if self._max_sessions_per_owner is not None:
                owned = sum(1 for s in self._sessions.values() if s.owner == owner)
                if owned >= self._max_sessions_per_owner:
                    _LOG.warning(
                        "session.create.rejected",
                        extra={
                            "event": "owner_session_cap_reached",
                            "principal_id": owner,
                            "owned": owned,
                        },
                    )
                    raise _errors.make_error(
                        ErrorType.LIMIT_EXCEEDED,
                        "per-principal session capacity reached; retry later",
                    )
            session_id = secrets.token_urlsafe(_SESSION_ID_BYTES)
            now_mono = self._clock()
            now_wall = self._wall_clock()
            sess = _Session(
                session_id=session_id,
                owner=owner,
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
                extra={
                    "event": "session_created",
                    "session_id": session_id,
                    "principal_id": owner,
                },
            )
            return self._to_info(sess)

    def authorize(self, session_id: str, *, caller: str = _LOCAL_PRINCIPAL_ID) -> SessionInfo:
        """Look up and authorize a live session by id for ``caller``, refreshing its idle clock.

        BOLA chokepoint: an unknown, expired, evicted, **or foreign-owned** id all yield the SAME
        ``SESSION_INVALID`` error — the response never reveals whether another session exists or
        belongs to a different principal (error-envelope.md; ADR-017 D2). Constant-time-ish lookup
        is not required (the id space is 256-bit random), but the *error* is identical across all
        failure modes.

        Args:
            session_id: The opaque id supplied by the client.
            caller: The authenticated, **server-derived** calling-principal id (ADR-017). Defaults
                to the implicit local operator for the single-principal stdio path.

        Returns:
            The authorized :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted/foreign ids (BOLA-safe).
        """
        with self._lock:
            return self._to_info(self._get_live_locked(session_id, caller=caller))

    def begin_call(self, session_id: str) -> None:
        """Mark a session in-flight for the duration of a tool call (ADR-025 / F4); refresh idle.

        Called by the dispatch chokepoint as a session-scoped tool call begins, paired with
        :meth:`end_call` in a ``finally``. Increments the session's in-flight counter and refreshes
        ``last_used_mono`` so a long-running single operation (e.g. an 18-26 min ``analyze``) cannot
        idle-evict itself: while in-flight the idle branch of :meth:`_is_expired` exempts it (F4).

        This is a **best-effort marker**, not an authorization step: it is keyed only by
        ``session_id`` (no owner/expiry check) and is a silent no-op for an unknown or already-
        evicted id. Authorization stays the sole responsibility of :meth:`authorize` /
        :meth:`_get_live_locked`, which the handler invokes itself — so marking in-flight never
        grants access (a foreign caller is still denied the BOLA-safe ``SESSION_INVALID``) and never
        resurrects an evicted session. Idempotent-safe under overlapping calls via the counter.

        Lock-safe: all mutation happens under ``_lock``; no I/O is performed while holding it.

        Args:
            session_id: The opaque id of the session the call targets.
        """
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None or sess.state == STATE_EVICTED:
                # Unknown/evicted: nothing to mark. The handler's authorize fails closed regardless.
                return
            sess.in_flight += 1
            sess.last_used_mono = self._clock()

    def end_call(self, session_id: str) -> None:
        """Clear a session's in-flight mark when a tool call ends (ADR-025 / F4); refresh idle.

        The ``finally`` counterpart of :meth:`begin_call`. Decrements the in-flight counter (never
        below zero — fail safe against an unmatched/spurious ``end_call``) and refreshes
        ``last_used_mono`` again so the idle clock restarts **after** the long call completes, not
        at its start: an abandoned session then idle-evicts from when its last call finished, while
        a session whose call just ended is fresh.

        A silent no-op for an unknown/evicted id (e.g. the session was evicted mid-call by the
        timeout-kill path). Lock-safe: mutation under ``_lock``, no I/O held.

        Args:
            session_id: The opaque id of the session the finished call targeted.
        """
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None or sess.state == STATE_EVICTED:
                return
            # Clamp at zero: an unmatched end_call must never drive the counter negative (which
            # would leave a phantom-negative in-flight that under-counts a real concurrent call).
            sess.in_flight = max(0, sess.in_flight - 1)
            sess.last_used_mono = self._clock()

    def _get_live_locked(self, session_id: str, *, caller: str) -> _Session:
        """Look up a live, caller-owned session by id (caller holds ``_lock``); refresh idle clock.

        Shared BOLA + **ownership** chokepoint for :meth:`authorize`, the write-consent methods,
        :meth:`ensure_worker`, and tool-initiated :meth:`evict` so the unknown/expired/evicted/
        foreign handling is identical and unbypassable across them (complete mediation; ADR-017). A
        session whose ``owner`` is not ``caller`` is denied with the SAME ``SESSION_INVALID`` as a
        nonexistent id — no oracle distinguishes "exists but not yours" from "does not exist" (D2).

        Args:
            session_id: The opaque id supplied by the client.
            caller: The authenticated, server-derived calling-principal id.

        Returns:
            The live, caller-owned internal :class:`_Session`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted/foreign ids (BOLA-safe).
        """
        sess = self._sessions.get(session_id)
        if sess is None or sess.state == STATE_EVICTED:
            raise _errors.session_invalid()
        if sess.owner != caller:
            # Cross-principal access (BOLA / ADR-017 D2): deny with the SAME SESSION_INVALID as an
            # unknown id — never confirm the session exists. Record the real cause server-side only.
            _LOG.warning(
                "session.authorize.denied",
                extra={
                    "event": "session_owner_mismatch",
                    "session_id": session_id,
                    "principal_id": caller,
                },
            )
            raise _errors.session_invalid()
        now = self._clock()
        if self._is_expired(sess, now):
            # Lazily evict an expired session, then fail closed with the same BOLA-safe error.
            self._evict_locked(session_id, reason="expired-on-authorize")
            raise _errors.session_invalid()
        sess.last_used_mono = now
        return sess

    def enable_writes(
        self,
        session_id: str,
        *,
        allow_structural: bool = False,
        caller: str = _LOCAL_PRINCIPAL_ID,
    ) -> SessionInfo:
        """Grant WRITE CONSENT to a caller-owned session — the human-in-the-loop gate (ADR-012 §3).

        Default-deny: sessions are read-only until this is called. The grant is per-session,
        revocable (:meth:`disable_writes` / implicit on evict), and audited. Owner-scoped (ADR-017):
        only the session's owner may grant consent; a foreign id is BOLA-safe ``SESSION_INVALID``.

        Args:
            session_id: The opaque session id.
            allow_structural: Additionally opt into the (deferred) structural write set.
            caller: The authenticated, server-derived calling-principal id.

        Returns:
            The session's updated :class:`SessionInfo` (reporting the consent state).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted/foreign ids (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            sess.writes_enabled = True
            sess.allow_structural = allow_structural
            _LOG.info(
                "session.writes_enabled",
                extra={
                    "event": "session_writes_enabled",
                    "session_id": session_id,
                    "principal_id": caller,
                    "allow_structural": allow_structural,
                },
            )
            return self._to_info(sess)

    def disable_writes(self, session_id: str, *, caller: str = _LOCAL_PRINCIPAL_ID) -> SessionInfo:
        """Revoke write consent for a caller-owned session (return it to read-only).

        Args:
            session_id: The opaque session id.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            The session's updated :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted/foreign ids (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            sess.writes_enabled = False
            sess.allow_structural = False
            _LOG.info(
                "session.writes_disabled",
                extra={
                    "event": "session_writes_disabled",
                    "session_id": session_id,
                    "principal_id": caller,
                },
            )
            return self._to_info(sess)

    def require_write_consent(
        self,
        session_id: str,
        *,
        structural: bool = False,
        caller: str = _LOCAL_PRINCIPAL_ID,
    ) -> SessionInfo:
        """Authorize the session AND require write consent; fail closed otherwise (ADR-012 §3).

        The mutation-tool gate chokepoint: every write handler calls this before delegating to the
        port. A session without consent (the default) is rejected with a ``FORBIDDEN`` envelope
        (ADR-036) — no destructive action runs without the explicit, prior :meth:`enable_writes`
        grant (LLM08). A foreign caller is rejected earlier at the owner check with the BOLA-safe
        ``SESSION_INVALID`` (never 403 — that would be an existence oracle).

        Args:
            session_id: The opaque session id.
            structural: When ``True``, also require the (deferred) structural-write opt-in.
            caller: The authenticated, server-derived calling-principal id (ADR-017). A foreign
                caller is rejected at the owner check before any consent state is consulted (a write
                on another principal's session is BOLA-safe ``SESSION_INVALID``, no oracle).

        Returns:
            The authorized :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) for a bad/foreign id, or ``FORBIDDEN``
                (ADR-036) when the owned session has not been granted (structural) write consent.
        """
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            if not sess.writes_enabled:
                # FORBIDDEN (ADR-036): authenticated + owns the session (the owner check in
                # _get_live_locked already passed), but write consent was never granted — a
                # permission denial, not a malformed request. Distinct from the BOLA-safe
                # SESSION_INVALID a foreign caller gets at the owner check above.
                raise _errors.make_error(
                    ErrorType.FORBIDDEN,
                    "session is read-only; write consent not granted",
                )
            if structural and not sess.allow_structural:
                raise _errors.make_error(
                    ErrorType.FORBIDDEN,
                    "structural writes not permitted for this session",
                )
            return self._to_info(sess)

    def ensure_worker(self, session_id: str, *, caller: str = _LOCAL_PRINCIPAL_ID) -> None:
        """Idempotently spawn a caller-owned session's worker (manager owns lifetime — ADR-002).

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
            caller: The authenticated, server-derived calling-principal id (ADR-017). A foreign
                caller cannot spawn another principal's worker — denied at the shared owner check
                with the BOLA-safe ``SESSION_INVALID`` (no principal gains another's worker).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` if unknown/evicted/foreign (BOLA-safe).
        """
        with self._lock:
            # Owner-gate via the shared chokepoint before spawning (complete mediation — ADR-017): a
            # foreign caller never reaches start_worker.
            sess = self._get_live_locked(session_id, caller=caller)
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

    def record_binary_hash(
        self, session_id: str, sha256: str, *, caller: str = _LOCAL_PRINCIPAL_ID
    ) -> None:
        """Persist the worker-computed program hash on a caller-owned session (ADR-018 binding).

        Called from the import handler after the worker reports the digest of the bytes it actually
        opened (ADR-001: the SERVER never parses the binary — the hash is the worker's computed
        digest, overlaid here). It is the session's authoritative program identity, used to verify
        an imported annotation document's ``binary.sha256`` binding (TB8): a document minted for a
        different binary is rejected because its hash will not match this. Owner-scoped via the
        shared chokepoint (a foreign caller cannot stamp another principal's session — ADR-017).

        Idempotent for a stable binary (re-import of the same bytes records the same hash). Set once
        per imported binary; never client-supplied.

        Args:
            session_id: The opaque id of a live, caller-owned session.
            sha256: The worker-computed hex SHA-256 of the imported binary.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` if unknown/expired/evicted/foreign (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            sess.binary_sha256 = sha256

    # --- session-scoped change-log (ADR-027 D2/D4; comments + composites export selection) -------
    def record_comment_target(
        self,
        session_id: str,
        *,
        address: str,
        comment_type: str,
        cleared: bool,
        caller: str = _LOCAL_PRINCIPAL_ID,
    ) -> None:
        """Record (or, on a clear, drop) one comment write TARGET in the change-log (ADR-027 D2).

        Called from the ``set_comment`` write chokepoint AFTER the worker reports ``applied=True``.
        Stores the **identity key only** — the ``(address, comment_type)`` pair — never the comment
        text (ADR-002/master §5: no binary-derived value in the log; the value is re-read live at
        export). A clear (``set_comment`` with ``text is None``) **removes** the key so an authored-
        then-cleared comment is correctly absent from export. Owner-scoped via the shared chokepoint
        (a foreign caller cannot mutate another principal's log — ADR-017). Mutates under ``_lock``;
        holds no I/O (topic-concurrency).

        Idempotent for a stable target (re-setting the same slot is a free set re-add). Over the
        per-session cap a NEW set-target is dropped (the write itself already succeeded) so the log
        stays bounded and export fails closed at the worker's ``limit-exceeded``; an already-logged
        target and any clear are always honored regardless of the cap.

        Args:
            session_id: The opaque id of a live, caller-owned session.
            address: The server-validated target address (closed-vocabulary identity, not a value).
            comment_type: The closed comment-slot label (``"EOL"``/``"PRE"``/.../``"REPEATABLE"``).
            cleared: ``True`` when the write cleared the slot (``text is None``) — drops the key.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` if unknown/expired/evicted/foreign (BOLA-safe).
        """
        key = (address, comment_type)
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            if cleared:
                sess.comment_targets.discard(key)
                return
            if key in sess.comment_targets:
                return  # already logged — free re-add, never counts against the cap
            if len(sess.comment_targets) >= _MAX_CHANGE_LOG_TARGETS:
                return  # bounded: write succeeded, but the log is full → export fails closed
            sess.comment_targets.add(key)

    def record_composite_target(
        self, session_id: str, *, name: str, caller: str = _LOCAL_PRINCIPAL_ID
    ) -> None:
        """Record one composite write TARGET (its NAME) in the change-log (ADR-027 D1 option 2).

        Called from the ``define_struct``/``define_union``/``define_types`` write chokepoint AFTER
        the worker reports ``applied=True``. Stores the composite **name only** — a server/worker-
        validated identity, not a binary-derived field value (ADR-002/master §5). Export looks up
        ONLY these named composites instead of blind-enumerating program-local types (which also
        include Ghidra auto-analysis structs — the F7 leak). Owner-scoped via the shared chokepoint;
        mutates under ``_lock`` with no I/O held (topic-concurrency).

        Idempotent (re-adding the same name is free). Over the per-session cap a NEW name is
        dropped (the write itself succeeded) so the log stays bounded and export fails closed at the
        worker's ``limit-exceeded``.

        Args:
            session_id: The opaque id of a live, caller-owned session.
            name: The server-validated composite name (identity, not a binary-derived value).
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` if unknown/expired/evicted/foreign (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            if name in sess.composite_targets:
                return  # already logged — free re-add
            if len(sess.composite_targets) >= _MAX_CHANGE_LOG_TARGETS:
                return  # bounded: write succeeded, but the log is full → export fails closed
            sess.composite_targets.add(name)

    def is_composite_target(
        self, session_id: str, *, name: str, caller: str = _LOCAL_PRINCIPAL_ID
    ) -> bool:
        """Return whether ``name`` is a composite THIS session authored (ADR-031 D2 authority).

        The server-side gate for ``delete_type``: only a composite recorded in this session's
        change-log (created via ``define_struct``/``define_union``/``define_types``) may be deleted.
        Owner-scoped — a foreign/expired session id is the BOLA-safe ``SESSION_INVALID``.

        Args:
            session_id: The opaque id of a live, caller-owned session.
            name: The server-validated composite name to check.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            ``True`` iff this session created a composite of that name.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` if unknown/expired/evicted/foreign (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            return name in sess.composite_targets

    def forget_composite_target(
        self, session_id: str, *, name: str, caller: str = _LOCAL_PRINCIPAL_ID
    ) -> None:
        """Drop a composite NAME from the change-log after it was deleted (ADR-031 D4).

        Called from the ``delete_type`` chokepoint AFTER the worker reports the type removed, so a
        later export never references a deleted type and the name is free to re-create (creation's
        collision check now passes). Idempotent (dropping an absent name is free). Owner-scoped;
        mutates under ``_lock`` with no I/O held (topic-concurrency).

        Args:
            session_id: The opaque id of a live, caller-owned session.
            name: The server-validated composite name to forget.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` if unknown/expired/evicted/foreign (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            sess.composite_targets.discard(name)

    def export_targets(
        self, session_id: str, *, caller: str = _LOCAL_PRINCIPAL_ID
    ) -> tuple[list[tuple[str, str]], list[str]]:
        """Read back the change-log's comment + composite targets for export (ADR-027 D4).

        The export handler calls this (owner-scoped) and hands the result to the port/worker as the
        server-supplied ``targets`` so the worker reads ONLY this session's authored comments and
        composites (steps 1 + 5) instead of blind-enumerating (steps 2-4 stay source-type-driven).
        Returns sorted **copies** (snapshots, not the live sets) so the caller cannot mutate session
        state and the ordering is deterministic (topic-testing: hermetic). Identity keys only — no
        binary-derived value ever crosses this boundary.

        Args:
            session_id: The opaque id of a live, caller-owned session.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            ``(comment_targets, composite_targets)`` — a sorted list of ``(address, comment_type)``
            pairs and a sorted list of composite names (both possibly empty).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` if unknown/expired/evicted/foreign (BOLA-safe).
        """
        with self._lock:
            sess = self._get_live_locked(session_id, caller=caller)
            return sorted(sess.comment_targets), sorted(sess.composite_targets)

    def evict(self, session_id: str, *, reason: str, caller: str | None = None) -> bool:
        """Evict a session: kill its worker and verified-wipe its store. Idempotent.

        Args:
            session_id: The session to evict.
            reason: Audit reason (e.g. ``"ttl"``, ``"idle"``, ``"close"``, ``"poison"``,
                ``"timeout"``).
            caller: When set, the authenticated calling-principal id for a **tool-initiated** evict
                (``session_close``): the session is owner-checked via the shared chokepoint first,
                so one principal cannot close another's session — a foreign id raises the BOLA-safe
                ``SESSION_INVALID`` (ADR-017). ``None`` is the internal/system path (reaper,
                shutdown, lazy expiry) which is not principal-scoped and skips the check.

        Returns:
            ``True`` if the per-session store was verified-wiped (or there was none); ``False``
            indicates a cleanup failure that MUST be alerted on (a wipe failure is a
            confidentiality incident).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` when ``caller`` is set and is not the owner (or the
                id is unknown/expired/evicted) — BOLA-safe, no oracle.
        """
        with self._lock:
            if caller is not None:
                # Tool-initiated close: prove ownership through the shared chokepoint BEFORE the
                # eviction so a foreign caller cannot tear down another's session (ADR-017).
                self._get_live_locked(session_id, caller=caller)
            return self._evict_locked(session_id, reason=reason)

    def reap_expired(self) -> int:
        """Evict all sessions past their TTL or idle timeout (called by a periodic sweeper).

        In-flight sessions (``in_flight > 0``) are **skipped** (ADR-025 / F4): a session with a call
        actively executing is never torn out from under it by the reaper — not for idle (it is
        non-idle by definition) and not for TTL (a legitimate long single operation must run to
        completion, bounded by the per-call timeout-kill in ``rpc_client.py``). The absolute TTL is
        still enforced for such a session at its **next** call boundary (:meth:`_get_live_locked`),
        so TTL caps standing lifetime without killing an in-progress operation.

        Returns:
            Number of sessions evicted.
        """
        with self._lock:
            now = self._clock()
            expired = [
                sid
                for sid, sess in self._sessions.items()
                if sess.state != STATE_EVICTED
                and sess.in_flight == 0
                and self._is_expired(sess, now)
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
        """Whether a session has hit its absolute TTL, or its idle timeout while NOT in-flight.

        Idle exemption (ADR-025 / F4): a session with a call actively executing
        (``in_flight > 0``) is **never idle-expired** — a long single operation (e.g. an
        18-26 min ``analyze``) refreshes nothing mid-call, so without this the next call's
        authorize would lazily idle-evict it (``expired-on-authorize``) and abort the workflow.
        The in-flight call is instead bounded by the per-call timeout-kill in ``rpc_client.py``
        (the real in-flight DoS control), not by the idle clock.

        The **absolute TTL** still applies regardless of in-flight: it is re-checked at every call
        boundary (via :meth:`_get_live_locked`), so a session that has exceeded ``ttl_s`` cannot
        accept NEW work even if a prior long call kept it alive. (The periodic reaper additionally
        declines to tear an in-flight session out mid-call for TTL — see :meth:`reap_expired` — so
        TTL caps standing lifetime without killing a legitimate long operation.)

        Args:
            sess: The session.
            now: Current monotonic time.

        Returns:
            ``True`` if TTL has elapsed, or (only when not in-flight) idle has elapsed.
        """
        if self._ttl_expired(sess, now):
            return True
        if sess.in_flight > 0:
            # In-flight: exempt from idle eviction (F4). TTL was already checked above.
            return False
        return (now - sess.last_used_mono) >= sess.idle_s

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
