"""Session manager — create / authorize / evict per-binary sessions (stub, WS2; critical path).

Responsibilities (PLAN §2, ADR-002):

- Create sessions with an opaque, high-entropy id (unguessable — BOLA defense).
- Enforce a concurrency cap (worker-pool size) with backpressure above it (DoS — F7).
- Track TTL (absolute) and idle timeouts; evict on expiry.
- On eviction (TTL/idle/close/poison): **kill the session's worker** and **verified-wipe** the
  per-session project store; emit an audit log line. Eviction is idempotent.
- Authorize every tool call against a live session; unknown/foreign ids fail closed with a
  ``SESSION_INVALID`` envelope WITHOUT revealing whether another session exists.

The manager owns worker lifetimes (one worker per session); it depends on the Ghidra adapter
``port`` for spawning/killing workers and never touches the JVM itself (ADR-001).

WS0 ships the interface; WS2 implements it; WS4 adds poisoning detection/rotation; WS5 drives
isolation/eviction to 100% coverage.
"""

from __future__ import annotations

from typing import Protocol

from ghidra_mcp.tools.schemas import SessionInfo


class WorkerHandle(Protocol):
    """Opaque handle to a running Ghidra worker bound to one session (port).

    The concrete implementation lives in :mod:`ghidra_mcp.ghidra`; the manager treats it
    abstractly (dependency inversion — depend on the port, not the adapter).
    """

    def kill(self) -> None:
        """Forcibly terminate the worker process/container (on timeout or eviction)."""
        ...


class SessionManager:
    """Owns the set of live sessions and their one-per-session workers (stub, WS2).

    Thread/async-safety: all mutating operations must be serialized (single owner of the session
    table — topic-concurrency). The manager is constructed once at startup (composition root).
    """

    def create(self, *, label: str | None = None) -> SessionInfo:
        """Open a new session with an opaque id; spawn nothing until import.

        Args:
            label: Optional audit label (untrusted; never used as a path).

        Returns:
            The new session's :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``LIMIT_EXCEEDED`` if the concurrency cap is reached (backpressure).

        Note:
            STUB (WS2). Id MUST be generated with ``secrets`` (CSPRNG), not ``random``.
        """
        raise NotImplementedError("WS2: implement session creation with CSPRNG id + cap")

    def authorize(self, session_id: str) -> SessionInfo:
        """Look up and authorize a live session by id, refreshing its idle clock.

        Args:
            session_id: The opaque id supplied by the client.

        Returns:
            The authorized :class:`SessionInfo`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` for unknown/expired/evicted ids (BOLA-safe — same
                response regardless of whether other sessions exist).

        Note:
            STUB (WS2). This is the BOLA chokepoint; covered by abuse tests in WS4/WS5.
        """
        raise NotImplementedError("WS2: implement session authorization + idle refresh")

    def evict(self, session_id: str, *, reason: str) -> bool:
        """Evict a session: kill its worker and verified-wipe its store. Idempotent.

        Args:
            session_id: The session to evict.
            reason: Audit reason (e.g. ``"ttl"``, ``"idle"``, ``"close"``, ``"poison"``,
                ``"timeout"``).

        Returns:
            ``True`` if the per-session store was verified-wiped; ``False`` indicates a cleanup
            failure that MUST be alerted on (a wipe failure is a confidentiality incident).

        Note:
            STUB (WS2). Must kill before wipe; verify the store path no longer exists.
        """
        raise NotImplementedError("WS2: implement kill-worker + verified store wipe")

    def reap_expired(self) -> int:
        """Evict all sessions past their TTL or idle timeout (called by a periodic sweeper).

        Returns:
            Number of sessions evicted.

        Note:
            STUB (WS2).
        """
        raise NotImplementedError("WS2: implement periodic TTL/idle reaping")

    def shutdown(self) -> None:
        """Evict all sessions on graceful server shutdown (drain → kill workers → wipe stores).

        Note:
            STUB (WS2). Bound by a shutdown timeout (topic-resource-management).
        """
        raise NotImplementedError("WS2: implement graceful shutdown of all sessions")
