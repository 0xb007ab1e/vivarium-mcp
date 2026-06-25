"""Integration: kill-on-timeout and verified-wipe-on-evict against a real worker (WS5 scaffold).

Covers the two confidentiality/DoS-critical worker behaviors (ADR-002, rpc-protocol §6):

- a per-analysis (or per-tool) wall-clock timeout **kills** the worker (no graceful wait for a
  hung/hostile JVM), surfaces a ``TIMEOUT`` envelope, and marks the session for eviction;
- eviction (timeout / idle / TTL / close / poison) **verified-wipes** the per-session project
  store — the store path no longer exists after eviction (a wipe failure is an incident).

Marked ``integration``; skipped without a real worker. Synthetic fixtures only (master §5).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_analysis_timeout_kills_worker(worker_image: str) -> None:
    """A deliberately tiny analysis timeout forces a worker kill and a ``TIMEOUT`` envelope.

    Asserts (once wired): the worker process/container is gone after the deadline, and the client
    receives a ``TIMEOUT`` error (no hung JVM, no partial result leaked).
    """
    pytest.skip(
        "Covered live (G4 Phase 1) by tests/e2e/test_abuse_containment_oss.py::"
        "test_decompile_bomb_bounded_kills_worker; this finer in-process variant is deferred."
    )


def test_eviction_verified_wipes_session_store(worker_image: str) -> None:
    """Closing/evicting a session verified-wipes its store: the store path is gone afterward.

    Asserts (once wired): ``session_close`` returns ``store_wiped=True`` and the per-session store
    directory (and RPC socket) no longer exist on disk (ADR-002 verified wipe).
    """
    pytest.skip(
        "Covered live (G4 Phase 1) by tests/e2e/test_abuse_containment_oss.py::"
        "test_cross_session_store_isolation_and_verified_wipe; finer in-process variant deferred."
    )


def test_eviction_is_idempotent(worker_image: str) -> None:
    """Evicting an already-evicted session is a safe no-op reporting a wiped store (idempotent)."""
    pytest.skip("WS5 Wave-2: double-evict and assert idempotent verified-wipe semantics (WS2)")
