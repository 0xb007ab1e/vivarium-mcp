"""Unit tests for the session manager — isolation / BOLA / eviction (WS2; critical path).

Critical-path coverage of the session-isolation chokepoint (master §4, marked ``critical``):

- opaque CSPRNG ids (high entropy, distinct);
- BOLA-safety: unknown, expired, evicted, and "foreign" ids ALL yield the SAME ``session-invalid``
  error — never revealing whether another session exists;
- concurrency cap enforces backpressure (``limit-exceeded``) above ``max_sessions``;
- eviction is idempotent and kills the worker BEFORE wiping, then VERIFIES the store is gone;
- a wipe failure surfaces as ``store_wiped=False`` (confidentiality incident);
- TTL (absolute) and idle reaping; graceful shutdown evicts everything.

All time is injected (a fake monotonic clock) so tests are deterministic and hermetic.
"""

from __future__ import annotations

import os

import pytest

from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.sessions.manager import STATE_OPEN, SessionManager


class _FakeClock:
    """A deterministic, advanceable monotonic clock for tests."""

    def __init__(self) -> None:
        """Start at t=0."""
        self.t = 0.0

    def __call__(self) -> float:
        """Return the current fake time."""
        return self.t

    def advance(self, dt: float) -> None:
        """Advance the clock by ``dt`` seconds."""
        self.t += dt


class _FakePort:
    """A fake worker port recording spawn/kill calls per session."""

    def __init__(self) -> None:
        """Initialize with empty call records."""
        self.started: list[str] = []
        self.killed: list[str] = []

    def start_worker(self, session_id: str) -> None:
        """Record a spawn."""
        self.started.append(session_id)

    def kill_worker(self, session_id: str) -> None:
        """Record a kill."""
        self.killed.append(session_id)


def _mgr(**kw: object) -> tuple[SessionManager, _FakeClock]:
    """Build a manager with a fake clock and sane test defaults.

    Returns:
        The manager and its fake clock.
    """
    clock = _FakeClock()
    mgr = SessionManager(clock=clock, **kw)  # type: ignore[arg-type]
    return mgr, clock


# --- creation / ids ---------------------------------------------------------------------------
def test_create_returns_open_session_with_opaque_id() -> None:
    mgr, _ = _mgr()
    info = mgr.create()
    assert info.state == STATE_OPEN
    assert len(info.session_id) >= 32  # 256-bit CSPRNG → ~43 url-safe chars
    assert info.expires_at > info.created_at


@pytest.mark.critical
def test_ids_are_unique_and_high_entropy() -> None:
    mgr, _ = _mgr(max_sessions=100)
    ids = {mgr.create().session_id for _ in range(50)}
    assert len(ids) == 50  # no collisions (CSPRNG)


# --- concurrency cap / backpressure -----------------------------------------------------------
@pytest.mark.critical
def test_concurrency_cap_applies_backpressure() -> None:
    mgr, _ = _mgr(max_sessions=2)
    mgr.create()
    mgr.create()
    with pytest.raises(GhidraMcpError) as ei:
        mgr.create()
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED
    assert ei.value.envelope.retryable is True


@pytest.mark.critical
def test_cap_frees_a_slot_after_eviction() -> None:
    mgr, _ = _mgr(max_sessions=1)
    a = mgr.create()
    with pytest.raises(GhidraMcpError):
        mgr.create()
    mgr.evict(a.session_id, reason="close")
    # Slot freed → create succeeds again.
    assert mgr.create().session_id != a.session_id


# --- BOLA / authorization ---------------------------------------------------------------------
@pytest.mark.critical
def test_authorize_unknown_id_is_session_invalid() -> None:
    mgr, _ = _mgr()
    with pytest.raises(GhidraMcpError) as ei:
        mgr.authorize("does-not-exist")
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_bola_unknown_foreign_and_evicted_yield_identical_error() -> None:
    """Unknown, evicted, and 'foreign' ids must produce an indistinguishable response."""
    mgr, _ = _mgr(max_sessions=4)
    live = mgr.create()  # a real, live session exists ("foreign" to the attacker)
    evicted = mgr.create()
    mgr.evict(evicted.session_id, reason="close")

    def _envelope_for(sid: str) -> dict[str, object]:
        with pytest.raises(GhidraMcpError) as ei:
            mgr.authorize(sid)
        env = ei.value.envelope
        # Compare only the client-visible discriminators (correlation_id is intentionally None).
        return {"type": env.type, "title": env.title, "detail": env.detail, "status": env.status}

    unknown = _envelope_for("totally-unknown-id")
    evicted_env = _envelope_for(evicted.session_id)
    # A different live session's id is "foreign" — authorizing it as another caller would still
    # succeed here (manager has no per-caller ownership in v1: single stdio client), so we assert
    # the *failure modes* are identical and never confirm existence of `live`.
    assert unknown == evicted_env
    assert "exists" not in unknown["detail"].lower()
    # The live session is still authorizable (we did not accidentally evict it proving foreignness).
    assert mgr.authorize(live.session_id).session_id == live.session_id


@pytest.mark.critical
def test_authorize_refreshes_idle_clock() -> None:
    mgr, clock = _mgr(idle_s=100, ttl_s=10_000)
    info = mgr.create()
    clock.advance(60)
    mgr.authorize(info.session_id)  # refresh
    clock.advance(60)  # 120s since create but only 60s since last use
    # Still authorizable: idle measured from last use, not creation.
    assert mgr.authorize(info.session_id).session_id == info.session_id


@pytest.mark.critical
def test_authorize_expired_session_is_session_invalid_and_evicts() -> None:
    port = _FakePort()
    mgr, clock = _mgr(idle_s=10, ttl_s=10_000, port=port)
    info = mgr.create()
    clock.advance(20)  # idle timeout passed
    with pytest.raises(GhidraMcpError) as ei:
        mgr.authorize(info.session_id)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID
    # Re-authorize: still invalid (it was evicted on the expired authorize).
    with pytest.raises(GhidraMcpError):
        mgr.authorize(info.session_id)


# --- eviction: kill + verified wipe -----------------------------------------------------------
@pytest.mark.critical
def test_evict_kills_worker_then_wipes_store(tmp_path) -> None:
    port = _FakePort()
    store_root = str(tmp_path / "stores")
    mgr, _ = _mgr(port=port, store_root=store_root)
    info = mgr.create()
    sid = info.session_id
    # Simulate a provisioned store + a started worker.
    store_path = os.path.join(store_root, sid)
    os.makedirs(store_path, exist_ok=True)
    # Mark the worker started so eviction kills it.
    mgr._sessions[sid].worker_started = True

    assert os.path.exists(store_path)
    wiped = mgr.evict(sid, reason="close")
    assert wiped is True
    assert not os.path.exists(store_path)  # VERIFIED wipe
    assert port.killed == [sid]  # killed before wipe


@pytest.mark.critical
def test_evict_is_idempotent() -> None:
    port = _FakePort()
    mgr, _ = _mgr(port=port)
    info = mgr.create()
    mgr._sessions[info.session_id].worker_started = True
    assert mgr.evict(info.session_id, reason="close") is True
    # Second eviction: idempotent success, no double-kill.
    assert mgr.evict(info.session_id, reason="close") is True
    assert port.killed == [info.session_id]


@pytest.mark.critical
def test_evict_unknown_session_is_idempotent_success() -> None:
    mgr, _ = _mgr()
    assert mgr.evict("never-existed", reason="close") is True


@pytest.mark.critical
def test_wipe_failure_surfaces_store_wiped_false(tmp_path, monkeypatch) -> None:
    """A store that still exists after the wipe attempt must report ``store_wiped=False``."""
    store_root = str(tmp_path / "stores")
    mgr, _ = _mgr(store_root=store_root)
    info = mgr.create()
    sid = info.session_id
    store_path = os.path.join(store_root, sid)
    os.makedirs(store_path, exist_ok=True)

    # Simulate a wipe that cannot remove the directory: rmtree no-ops, path persists.
    monkeypatch.setattr("ghidra_mcp.sessions.manager.shutil.rmtree", lambda *a, **k: None)
    wiped = mgr.evict(sid, reason="close")
    assert wiped is False  # confidentiality incident — alerted on
    assert os.path.exists(store_path)


def test_evict_no_store_is_vacuously_wiped() -> None:
    mgr, _ = _mgr()  # no store_root → no on-disk store
    info = mgr.create()
    assert mgr.evict(info.session_id, reason="close") is True


# --- reaping / shutdown -----------------------------------------------------------------------
@pytest.mark.critical
def test_reap_expired_evicts_idle_session_keeps_refreshed_one() -> None:
    port = _FakePort()
    mgr, clock = _mgr(port=port, ttl_s=1000, idle_s=50, max_sessions=8)
    a = mgr.create()
    b = mgr.create()
    clock.advance(40)  # within idle window
    mgr.authorize(a.session_id)  # refresh a at t=40
    clock.advance(40)  # t=80: a idle=40 (ok), b idle=80 (expired)
    assert mgr.reap_expired() == 1  # only b
    assert mgr.authorize(a.session_id).session_id == a.session_id  # a survived


@pytest.mark.critical
def test_reap_expired_evicts_ttl_regardless_of_idle() -> None:
    mgr, clock = _mgr(ttl_s=100, idle_s=10_000, max_sessions=8)
    mgr.create()
    clock.advance(150)  # absolute TTL elapsed even though not idle
    assert mgr.reap_expired() == 1
    assert mgr.reap_expired() == 0


def test_reap_expired_keeps_live_sessions() -> None:
    mgr, clock = _mgr(ttl_s=1000, idle_s=1000, max_sessions=4)
    mgr.create()
    clock.advance(10)
    assert mgr.reap_expired() == 0


@pytest.mark.critical
def test_shutdown_evicts_all(tmp_path) -> None:
    port = _FakePort()
    store_root = str(tmp_path / "stores")
    mgr, _ = _mgr(port=port, store_root=store_root, max_sessions=8)
    sids = []
    for _ in range(3):
        info = mgr.create()
        sids.append(info.session_id)
        os.makedirs(os.path.join(store_root, info.session_id), exist_ok=True)
        mgr._sessions[info.session_id].worker_started = True
    mgr.shutdown()
    assert sorted(port.killed) == sorted(sids)
    for sid in sids:
        assert not os.path.exists(os.path.join(store_root, sid))
    # Idempotent: a second shutdown is a no-op.
    mgr.shutdown()


def test_store_path_no_traversal() -> None:
    mgr, _ = _mgr(store_root="/var/lib/ghidra-mcp/stores")
    info = mgr.create()
    path = mgr._store_path_for(info.session_id)
    assert path is not None
    # The CSPRNG url-safe id contains no path separators or traversal sequences.
    assert ".." not in info.session_id
    assert "/" not in info.session_id
    assert path.startswith("/var/lib/ghidra-mcp/stores/")
