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

from pathlib import Path

import pytest

from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.sessions.manager import STATE_EVICTED, STATE_OPEN, SessionManager


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
    assert "exists" not in str(unknown["detail"]).lower()
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


# --- worker spawn (ensure_worker) -------------------------------------------------------------
@pytest.mark.critical
def test_ensure_worker_spawns_once_and_is_idempotent() -> None:
    port = _FakePort()
    mgr, _ = _mgr(port=port)
    info = mgr.create()
    assert port.started == []  # create spawns nothing (spawn-on-first-import)
    mgr.ensure_worker(info.session_id)
    mgr.ensure_worker(info.session_id)  # idempotent: second call is a no-op
    assert port.started == [info.session_id]
    assert mgr._sessions[info.session_id].worker_started is True


@pytest.mark.critical
def test_ensure_worker_no_port_is_noop() -> None:
    mgr, _ = _mgr()  # no port wired (guard/test construction)
    info = mgr.create()
    mgr.ensure_worker(info.session_id)  # must not raise
    assert mgr._sessions[info.session_id].worker_started is False


@pytest.mark.critical
def test_ensure_worker_unknown_session_is_session_invalid() -> None:
    port = _FakePort()
    mgr, _ = _mgr(port=port)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.ensure_worker("nonexistent-session-id")
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID
    assert port.started == []  # fail closed: no spawn for an unknown session


@pytest.mark.critical
def test_ensure_worker_started_worker_is_killed_on_eviction(tmp_path: Path) -> None:
    """The worker_started flag set by ensure_worker drives the eviction kill (containment)."""
    port = _FakePort()
    mgr, _ = _mgr(port=port, store_root=str(tmp_path))
    info = mgr.create()
    mgr.ensure_worker(info.session_id)
    mgr.evict(info.session_id, reason="close")
    assert port.killed == [info.session_id]


# --- eviction: kill + verified wipe -----------------------------------------------------------
@pytest.mark.critical
def test_evict_kills_worker_then_wipes_store(tmp_path: Path) -> None:
    port = _FakePort()
    store_root = str(tmp_path / "stores")
    mgr, _ = _mgr(port=port, store_root=store_root)
    info = mgr.create()
    sid = info.session_id
    # Simulate a provisioned store + a started worker.
    store_path = Path(store_root) / sid
    store_path.mkdir(parents=True, exist_ok=True)
    # Mark the worker started so eviction kills it.
    mgr._sessions[sid].worker_started = True

    assert store_path.exists()
    wiped = mgr.evict(sid, reason="close")
    assert wiped is True
    assert not store_path.exists()  # VERIFIED wipe
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
def test_wipe_failure_surfaces_store_wiped_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A store that still exists after the wipe attempt must report ``store_wiped=False``."""
    store_root = str(tmp_path / "stores")
    mgr, _ = _mgr(store_root=store_root)
    info = mgr.create()
    sid = info.session_id
    store_path = Path(store_root) / sid
    store_path.mkdir(parents=True, exist_ok=True)

    # Simulate a wipe that cannot remove the directory: rmtree no-ops, path persists.
    monkeypatch.setattr("ghidra_mcp.sessions.manager.shutil.rmtree", lambda *a, **k: None)
    wiped = mgr.evict(sid, reason="close")
    assert wiped is False  # confidentiality incident — alerted on
    assert store_path.exists()


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
    mgr.create()  # session "b": never refreshed → will idle-expire
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
def test_shutdown_evicts_all(tmp_path: Path) -> None:
    port = _FakePort()
    store_root = str(tmp_path / "stores")
    mgr, _ = _mgr(port=port, store_root=store_root, max_sessions=8)
    sids = []
    for _ in range(3):
        info = mgr.create()
        sids.append(info.session_id)
        (Path(store_root) / info.session_id).mkdir(parents=True, exist_ok=True)
        mgr._sessions[info.session_id].worker_started = True
    mgr.shutdown()
    assert sorted(port.killed) == sorted(sids)
    for sid in sids:
        assert not (Path(store_root) / sid).exists()
    # Idempotent: a second shutdown is a no-op.
    mgr.shutdown()


@pytest.mark.critical
def test_evict_survives_worker_kill_failure_and_still_wipes(tmp_path: Path) -> None:
    """A worker-kill that raises must NOT abort eviction: the store is still verified-wiped.

    Covers the kill-failure branch in ``_evict_locked`` (best-effort kill, logged) — a launcher /
    runtime hiccup during teardown cannot leave the confidential store behind.
    """

    class _ExplodingPort:
        def start_worker(self, session_id: str) -> None:  # pragma: no cover - unused here
            raise AssertionError("not used")

        def kill_worker(self, session_id: str) -> None:
            raise RuntimeError("runtime refused to SIGKILL")

    store_root = str(tmp_path / "stores")
    mgr = SessionManager(port=_ExplodingPort(), store_root=store_root, clock=_FakeClock())
    info = mgr.create()
    sid = info.session_id
    store_path = Path(store_root) / sid
    store_path.mkdir(parents=True, exist_ok=True)
    mgr._sessions[sid].worker_started = True

    # Kill raises internally but eviction proceeds and the store is verified gone.
    assert mgr.evict(sid, reason="poison") is True
    assert not store_path.exists()


@pytest.mark.critical
def test_shutdown_skips_already_evicted_session_in_table() -> None:
    """``shutdown`` must skip a session already marked EVICTED still present in the table.

    Covers the false branch of the state guard in the shutdown loop (idempotency / no double-kill
    of an already-torn-down session).
    """
    port = _FakePort()
    mgr, _ = _mgr(port=port, max_sessions=4)
    live = mgr.create()
    stale = mgr.create()
    mgr._sessions[live.session_id].worker_started = True
    # Force a session into EVICTED state WITHOUT removing it from the table, so the shutdown loop
    # encounters it and must skip (the guard's False branch).
    mgr._sessions[stale.session_id].state = STATE_EVICTED
    mgr.shutdown()
    # Only the live session was (re-)evicted/killed; the pre-evicted one was skipped, not killed.
    assert port.killed == [live.session_id]


def test_store_path_no_traversal() -> None:
    mgr, _ = _mgr(store_root="/var/lib/ghidra-mcp/stores")
    info = mgr.create()
    path = mgr._store_path_for(info.session_id)
    assert path is not None
    # The CSPRNG url-safe id contains no path separators or traversal sequences.
    assert ".." not in info.session_id
    assert "/" not in info.session_id
    assert path.startswith("/var/lib/ghidra-mcp/stores/")


# ==============================================================================================
# Per-principal ownership (ADR-017) — the load-bearing BOLA control across EVERY session-scoped
# entry point. The owner check lives in the shared ``_get_live_locked`` chokepoint, so a foreign
# caller is denied the SAME ``SESSION_INVALID`` as an unknown id (D2, no oracle). All hermetic
# (distinct synthetic principal ids; injected clock). Marked ``critical`` — authZ-critical path.
# ==============================================================================================
_A = "principal-A"
_B = "principal-B"


def _invalid_envelope_fields(
    mgr: SessionManager, fn: object, *args: object, **kw: object
) -> dict[str, object]:
    """Call ``fn`` expecting ``SESSION_INVALID`` and return its client-visible envelope fields."""
    with pytest.raises(GhidraMcpError) as ei:
        fn(*args, **kw)  # type: ignore[operator]
    env = ei.value.envelope
    return {"type": env.type, "title": env.title, "detail": env.detail, "status": env.status}


@pytest.mark.critical
def test_create_records_owner_and_owner_can_authorize() -> None:
    mgr, _ = _mgr(max_sessions=8)
    info = mgr.create(owner=_A)
    # The owner authorizes successfully; the SessionInfo never leaks the owner (server-internal).
    assert mgr.authorize(info.session_id, caller=_A).session_id == info.session_id
    assert not hasattr(info, "owner")


@pytest.mark.critical
def test_foreign_caller_authorize_is_session_invalid_no_oracle() -> None:
    """Principal B presenting A's live session id is denied the SAME SESSION_INVALID as unknown."""
    mgr, _ = _mgr(max_sessions=8)
    a = mgr.create(owner=_A)

    foreign = _invalid_envelope_fields(mgr, mgr.authorize, a.session_id, caller=_B)
    unknown = _invalid_envelope_fields(mgr, mgr.authorize, "totally-unknown-id", caller=_B)
    # Byte-identical: B cannot tell "exists but A's" from "does not exist" (D2 / no oracle).
    assert foreign == unknown
    assert foreign["type"] is ErrorType.SESSION_INVALID
    assert "exists" not in str(foreign["detail"]).lower()
    assert "owned" not in str(foreign["detail"]).lower()
    # The session is untouched: A can still use it (the denied authorize did not evict it).
    assert mgr.authorize(a.session_id, caller=_A).session_id == a.session_id


@pytest.mark.critical
def test_foreign_caller_denied_across_every_session_scoped_entry_point() -> None:
    """B cannot read, enable/disable writes, require consent, spawn, OR close A's session.

    Every entry point routes through the one owner-checked chokepoint, so all yield the IDENTICAL
    BOLA-safe ``SESSION_INVALID`` — complete mediation (ADR-017).
    """
    port = _FakePort()
    mgr, _ = _mgr(port=port, max_sessions=8)
    a = mgr.create(owner=_A)
    sid = a.session_id

    baseline = _invalid_envelope_fields(mgr, mgr.authorize, sid, caller=_B)
    # read / status
    assert _invalid_envelope_fields(mgr, mgr.authorize, sid, caller=_B) == baseline
    # enable writes
    assert _invalid_envelope_fields(mgr, mgr.enable_writes, sid, caller=_B) == baseline
    # disable writes
    assert _invalid_envelope_fields(mgr, mgr.disable_writes, sid, caller=_B) == baseline
    # require write consent (write op)
    assert _invalid_envelope_fields(mgr, mgr.require_write_consent, sid, caller=_B) == baseline
    # ensure_worker (spawn) — and prove no worker was spawned for the foreign caller
    assert _invalid_envelope_fields(mgr, mgr.ensure_worker, sid, caller=_B) == baseline
    assert port.started == []
    # tool-initiated close (evict with caller)
    assert _invalid_envelope_fields(mgr, mgr.evict, sid, reason="close", caller=_B) == baseline
    # The underlying op never ran: A's session is still live and was not evicted/killed.
    assert mgr.authorize(sid, caller=_A).session_id == sid
    assert port.killed == []


@pytest.mark.critical
def test_foreign_caller_cannot_enable_writes_on_owned_session() -> None:
    """B granting consent on A's session must NOT enable writes on it (deny before state change)."""
    mgr, _ = _mgr(max_sessions=8)
    a = mgr.create(owner=_A)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.enable_writes(a.session_id, caller=_B)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID
    # A's session is still read-only — B's denied grant did not flip the consent flag.
    assert mgr.authorize(a.session_id, caller=_A).writes_enabled is False


@pytest.mark.critical
def test_owner_can_close_but_foreign_cannot() -> None:
    port = _FakePort()
    mgr, _ = _mgr(port=port, max_sessions=8)
    a = mgr.create(owner=_A)
    mgr.ensure_worker(a.session_id, caller=_A)
    # B's close is denied (no kill); A's close succeeds (kills the worker).
    with pytest.raises(GhidraMcpError):
        mgr.evict(a.session_id, reason="close", caller=_B)
    assert port.killed == []
    assert mgr.evict(a.session_id, reason="close", caller=_A) is True
    assert port.killed == [a.session_id]


@pytest.mark.critical
def test_internal_evict_without_caller_skips_owner_check() -> None:
    """The reaper/shutdown path (``caller=None``) is not principal-scoped — it evicts regardless."""
    port = _FakePort()
    mgr, _ = _mgr(port=port, max_sessions=8)
    a = mgr.create(owner=_A)
    mgr.ensure_worker(a.session_id, caller=_A)
    # No caller → system path, no owner check (used by reap/shutdown/lazy-expiry).
    assert mgr.evict(a.session_id, reason="ttl") is True
    assert port.killed == [a.session_id]


@pytest.mark.critical
def test_two_principals_each_own_only_their_sessions() -> None:
    mgr, _ = _mgr(max_sessions=8)
    a = mgr.create(owner=_A)
    b = mgr.create(owner=_B)
    # Each can use its own; neither can use the other's (cross checks both directions).
    assert mgr.authorize(a.session_id, caller=_A).session_id == a.session_id
    assert mgr.authorize(b.session_id, caller=_B).session_id == b.session_id
    with pytest.raises(GhidraMcpError):
        mgr.authorize(b.session_id, caller=_A)
    with pytest.raises(GhidraMcpError):
        mgr.authorize(a.session_id, caller=_B)


# --- per-owner session cap (ADR-017 STRIDE-D / noisy-neighbor) --------------------------------
@pytest.mark.critical
def test_per_owner_cap_limits_one_principal_without_blocking_others() -> None:
    """One principal cannot exceed its per-owner cap, yet another principal can still create."""
    mgr, _ = _mgr(max_sessions=8, max_sessions_per_owner=2)
    mgr.create(owner=_A)
    mgr.create(owner=_A)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.create(owner=_A)  # A is at its per-owner cap
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED
    assert ei.value.envelope.retryable is True
    # B is unaffected (no noisy-neighbor starvation) — the global cap (8) is not yet reached.
    assert mgr.create(owner=_B).session_id is not None


@pytest.mark.critical
def test_per_owner_cap_frees_a_slot_after_eviction() -> None:
    mgr, _ = _mgr(max_sessions=8, max_sessions_per_owner=1)
    a = mgr.create(owner=_A)
    with pytest.raises(GhidraMcpError):
        mgr.create(owner=_A)
    mgr.evict(a.session_id, reason="close", caller=_A)
    # Slot freed → A can create again.
    assert mgr.create(owner=_A).session_id != a.session_id


@pytest.mark.critical
def test_per_owner_cap_none_disables_per_owner_limit() -> None:
    """``max_sessions_per_owner=None`` (default) applies only the global cap (single-principal)."""
    mgr, _ = _mgr(max_sessions=3, max_sessions_per_owner=None)
    for _ in range(3):
        mgr.create(owner=_A)  # all three under one owner are fine (no per-owner cap)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.create(owner=_A)  # only the GLOBAL cap stops the 4th
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED


@pytest.mark.critical
def test_global_cap_takes_precedence_over_per_owner_cap() -> None:
    """The global cap is checked first: it fires even when the per-owner cap would allow more."""
    mgr, _ = _mgr(max_sessions=1, max_sessions_per_owner=5)
    mgr.create(owner=_A)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.create(owner=_B)  # global cap (1) reached even though B owns nothing yet
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED


def test_default_owner_is_local_operator() -> None:
    """``create()`` without an explicit owner records the implicit local operator (stdio path)."""
    mgr, _ = _mgr()
    info = mgr.create()  # no owner → "local"
    # The local operator can authorize it; a different principal cannot.
    assert mgr.authorize(info.session_id, caller="local").session_id == info.session_id
    with pytest.raises(GhidraMcpError):
        mgr.authorize(info.session_id, caller="someone-else")


# ==============================================================================================
# record_binary_hash (ADR-018 TB8) — the security-load-bearing program-identity binding source.
# It stamps the worker-computed digest onto the session; the import handler later compares an
# annotation document's binary.sha256 against it (a doc minted for a different binary is rejected).
# Owner-scoped via the shared _get_live_locked chokepoint (BOLA-safe). Exercises the REAL method.
# ==============================================================================================
_HASH_A = "a" * 64
_HASH_B = "b" * 64


@pytest.mark.critical
def test_record_binary_hash_reflects_worker_digest_on_session() -> None:
    # abuse case 71/73 support — the recorded digest is the authoritative program identity the
    # import hash-binding check reads. Before recording it is None; after, it is the worker digest.
    mgr, _ = _mgr(max_sessions=8)
    info = mgr.create(owner=_A)
    assert info.binary_sha256 is None  # no binary imported yet
    mgr.record_binary_hash(info.session_id, _HASH_A, caller=_A)
    assert mgr.authorize(info.session_id, caller=_A).binary_sha256 == _HASH_A


@pytest.mark.critical
def test_record_binary_hash_is_idempotent_for_same_bytes() -> None:
    # Re-importing the same bytes records the same hash (stable identity; set-once-per-binary).
    mgr, _ = _mgr(max_sessions=8)
    info = mgr.create(owner=_A)
    mgr.record_binary_hash(info.session_id, _HASH_A, caller=_A)
    mgr.record_binary_hash(info.session_id, _HASH_A, caller=_A)
    assert mgr.authorize(info.session_id, caller=_A).binary_sha256 == _HASH_A


@pytest.mark.critical
def test_record_binary_hash_foreign_caller_is_session_invalid_and_no_stamp() -> None:
    # BOLA: a foreign caller cannot stamp another principal's session — denied the SAME
    # SESSION_INVALID as an unknown id (owner check before any state change). A's hash is untouched.
    mgr, _ = _mgr(max_sessions=8)
    info = mgr.create(owner=_A)
    foreign = _invalid_envelope_fields(
        mgr, mgr.record_binary_hash, info.session_id, _HASH_B, caller=_B
    )
    unknown = _invalid_envelope_fields(
        mgr, mgr.record_binary_hash, "totally-unknown-id", _HASH_B, caller=_B
    )
    assert foreign == unknown
    assert foreign["type"] is ErrorType.SESSION_INVALID
    # B's stamp never landed: A's session still has no recorded hash.
    assert mgr.authorize(info.session_id, caller=_A).binary_sha256 is None


@pytest.mark.critical
def test_record_binary_hash_unknown_session_is_session_invalid() -> None:
    # An unknown id fails closed with SESSION_INVALID (BOLA-safe; no oracle).
    mgr, _ = _mgr(max_sessions=8)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.record_binary_hash("no-such-session", _HASH_A, caller=_A)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_record_binary_hash_evicted_session_is_session_invalid() -> None:
    # An evicted id is indistinguishable from unknown (BOLA-safe) and the stamp cannot land.
    mgr, _ = _mgr(max_sessions=8)
    info = mgr.create(owner=_A)
    mgr.evict(info.session_id, reason="close")
    with pytest.raises(GhidraMcpError) as ei:
        mgr.record_binary_hash(info.session_id, _HASH_A, caller=_A)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID
