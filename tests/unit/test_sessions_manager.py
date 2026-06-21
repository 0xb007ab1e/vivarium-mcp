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

from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.sessions.manager import STATE_EVICTED, STATE_OPEN, SessionManager


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
    monkeypatch.setattr("vivarium.sessions.manager.shutil.rmtree", lambda *a, **k: None)
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
    mgr, _ = _mgr(store_root="/var/lib/vivarium/stores")
    info = mgr.create()
    path = mgr._store_path_for(info.session_id)
    assert path is not None
    # The CSPRNG url-safe id contains no path separators or traversal sequences.
    assert ".." not in info.session_id
    assert "/" not in info.session_id
    assert path.startswith("/var/lib/vivarium/stores/")


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


# ==============================================================================================
# record_analysis_profile (ADR-029 B) — echoes the effective analyzer preset on SessionInfo.
# Owner-scoped via the same BOLA chokepoint. Exercises the REAL SessionManager.
# ==============================================================================================
@pytest.mark.critical
def test_record_analysis_profile_is_echoed_on_session_info() -> None:
    # Before any analyze the profile is None; after recording it is surfaced on SessionInfo.
    mgr, _ = _mgr(max_sessions=8)
    info = mgr.create(owner=_A)
    assert mgr.authorize(info.session_id, caller=_A).analysis_profile is None
    mgr.record_analysis_profile(info.session_id, "deep", caller=_A)
    assert mgr.authorize(info.session_id, caller=_A).analysis_profile == "deep"


@pytest.mark.critical
def test_record_analysis_profile_foreign_caller_is_session_invalid_and_no_stamp() -> None:
    # BOLA: a foreign caller cannot stamp another principal's profile (denied SESSION_INVALID).
    mgr, _ = _mgr(max_sessions=8)
    info = mgr.create(owner=_A)
    fields = _invalid_envelope_fields(
        mgr, mgr.record_analysis_profile, info.session_id, "light", caller=_B
    )
    assert fields["type"] is ErrorType.SESSION_INVALID
    assert mgr.authorize(info.session_id, caller=_A).analysis_profile is None  # never stamped


# =====================================================================================
# Session-scoped change-log (ADR-027 D2/D4) — comment + composite export-target tracking.
# Critical-path: the change-log is the load-bearing provenance signal for the F7 fix, lives on the
# session, and is wiped with it on evict. Identity keys ONLY — never a binary-derived value.
# =====================================================================================
_ADDR_1 = "0x401000"
_ADDR_2 = "0x402000"
# An auto-comment / value-ish (binary-derived) string that must NEVER reach the change-log, which
# stores identity keys only (ADR-002/master §5). Used to assert no value leaks into the log.
_VALUE_LIKE = "WARNING: do not call this; decompiled secret material"


@pytest.mark.critical
def test_record_comment_target_then_read_back() -> None:
    # A recorded comment target round-trips through export_targets (identity key only).
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    mgr.record_comment_target(
        info.session_id, address=_ADDR_1, comment_type="PLATE", cleared=False, caller=_A
    )
    comments, composites = mgr.export_targets(info.session_id, caller=_A)
    assert comments == [(_ADDR_1, "PLATE")]
    assert composites == []


@pytest.mark.critical
def test_record_composite_target_then_read_back() -> None:
    # A recorded composite NAME round-trips through export_targets.
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    mgr.record_composite_target(info.session_id, name="my_struct", caller=_A)
    comments, composites = mgr.export_targets(info.session_id, caller=_A)
    assert comments == []
    assert composites == ["my_struct"]


@pytest.mark.critical
def test_change_log_records_are_identity_keys_only_no_values() -> None:
    # The log NEVER stores a comment text / field value — only (address, type) + name (ADR-002/§5).
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    # The handler records identity keys; a value-ish string is NOT part of the recording API and
    # must never reach the log. Record a target whose address is benign and assert no value leaks.
    mgr.record_comment_target(
        info.session_id, address=_ADDR_1, comment_type="EOL", cleared=False, caller=_A
    )
    mgr.record_composite_target(info.session_id, name="cfg_t", caller=_A)
    sess = mgr._sessions[info.session_id]  # introspect the raw log (test-only)
    # The log holds ONLY identity keys; no stored element contains the binary-ish/secret value.
    for addr, ctype in sess.comment_targets:
        assert _VALUE_LIKE not in addr
        assert _VALUE_LIKE not in ctype
    assert sess.comment_targets == {(_ADDR_1, "EOL")}
    assert sess.composite_targets == {"cfg_t"}
    assert all(_VALUE_LIKE not in name for name in sess.composite_targets)


@pytest.mark.critical
def test_comment_clear_removes_the_logged_target() -> None:
    # set_comment(text=None) is a CLEAR — it drops the key so export does NOT emit it (ADR-027 D2).
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    mgr.record_comment_target(
        info.session_id, address=_ADDR_1, comment_type="PRE", cleared=False, caller=_A
    )
    assert mgr.export_targets(info.session_id, caller=_A)[0] == [(_ADDR_1, "PRE")]
    # Now clear the same slot — the target is removed (authored-then-cleared ⇒ absent from export).
    mgr.record_comment_target(
        info.session_id, address=_ADDR_1, comment_type="PRE", cleared=True, caller=_A
    )
    assert mgr.export_targets(info.session_id, caller=_A)[0] == []


@pytest.mark.critical
def test_clearing_an_unlogged_target_is_a_safe_noop() -> None:
    # Clearing a never-set slot must not raise and leaves the log empty (discard is idempotent).
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    mgr.record_comment_target(
        info.session_id, address=_ADDR_2, comment_type="POST", cleared=True, caller=_A
    )
    assert mgr.export_targets(info.session_id, caller=_A) == ([], [])


@pytest.mark.critical
def test_change_log_records_are_deduplicated() -> None:
    # Re-touching the same target is a free re-add (a set, not a list) — no duplicate export entry.
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    for _ in range(3):
        mgr.record_comment_target(
            info.session_id, address=_ADDR_1, comment_type="EOL", cleared=False, caller=_A
        )
        mgr.record_composite_target(info.session_id, name="dup_t", caller=_A)
    comments, composites = mgr.export_targets(info.session_id, caller=_A)
    assert comments == [(_ADDR_1, "EOL")]
    assert composites == ["dup_t"]


@pytest.mark.critical
def test_export_targets_returns_sorted_snapshot_not_live_set() -> None:
    # The read-back is a sorted COPY; mutating it cannot corrupt session state (hermetic).
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    mgr.record_composite_target(info.session_id, name="zeta", caller=_A)
    mgr.record_composite_target(info.session_id, name="alpha", caller=_A)
    _, composites = mgr.export_targets(info.session_id, caller=_A)
    assert composites == ["alpha", "zeta"]  # deterministic order
    composites.append("INJECTED")  # mutate the returned list
    # The session's real log is unaffected by mutating the returned snapshot.
    assert mgr._sessions[info.session_id].composite_targets == {"alpha", "zeta"}


@pytest.mark.critical
def test_change_log_is_wiped_when_session_is_evicted() -> None:
    # The log is session-lifetime state — eviction drops the session record entirely (ADR-002).
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    mgr.record_comment_target(
        info.session_id, address=_ADDR_1, comment_type="EOL", cleared=False, caller=_A
    )
    mgr.record_composite_target(info.session_id, name="t", caller=_A)
    assert info.session_id in mgr._sessions
    mgr.evict(info.session_id, reason="close")
    # The whole session record (with its change-log sets) is gone — no durable confidential state.
    assert info.session_id not in mgr._sessions
    # And a read-back now fails closed (BOLA-safe) — the log no longer exists.
    with pytest.raises(GhidraMcpError):
        mgr.export_targets(info.session_id, caller=_A)


# --- in-flight liveness during long calls (ADR-025 / F4) --------------------------------------
# A long-running call (e.g. an 18-26 min ``analyze``) must not idle-evict its OWN session. The
# mechanism: begin_call marks the session in-flight + refreshes the idle clock; _is_expired exempts
# an in-flight session from idle eviction; end_call clears the mark + refreshes again so the idle
# clock restarts AFTER the call. The absolute TTL is re-applied at the next call boundary. All time
# is injected (no real sleeps). Marked ``critical`` — manager.py is a critical-path module.
@pytest.mark.critical
def test_in_flight_session_is_not_idle_evicted_on_authorize() -> None:
    # F4 regression: a session whose call is actively executing survives a clock advance well past
    # the idle window — the NEXT authorize must SUCCEED, not lazily idle-evict it.
    mgr, clock = _mgr(idle_s=900, ttl_s=10_000, max_sessions=8)
    info = mgr.create()
    sid = info.session_id
    mgr.begin_call(sid)  # the long analyze starts
    clock.advance(1_500)  # 25 min elapse mid-analyze — past the 900s idle window
    # A concurrent/next authorize against the in-flight session does NOT evict it.
    assert mgr.authorize(sid).session_id == sid
    mgr.end_call(sid)  # analyze completes


@pytest.mark.critical
def test_in_flight_session_is_not_idle_reaped() -> None:
    # The periodic reaper must also skip an in-flight session (never tear a running call out).
    port = _FakePort()
    mgr, clock = _mgr(port=port, idle_s=900, ttl_s=10_000, max_sessions=8)
    sid = mgr.create().session_id
    mgr.begin_call(sid)
    clock.advance(1_500)  # past idle
    assert mgr.reap_expired() == 0  # not reaped while in-flight
    assert mgr.authorize(sid).session_id == sid
    assert port.killed == []
    mgr.end_call(sid)


@pytest.mark.critical
def test_abandoned_idle_session_is_evicted_with_wipe(tmp_path: Path) -> None:
    # The counterpart (ADR-002 preserved): a genuinely abandoned (NOT in-flight) idle session still
    # evicts with the verified store-wipe and worker-kill. Eviction reason is unchanged ("idle").
    port = _FakePort()
    store_root = str(tmp_path / "stores")
    mgr, clock = _mgr(port=port, store_root=store_root, idle_s=900, ttl_s=10_000, max_sessions=8)
    sid = mgr.create().session_id
    store_path = Path(store_root) / sid
    store_path.mkdir(parents=True, exist_ok=True)
    mgr._sessions[sid].worker_started = True
    clock.advance(1_500)  # past idle, never in-flight
    assert mgr.reap_expired() == 1
    assert not store_path.exists()  # VERIFIED wipe preserved
    assert port.killed == [sid]


@pytest.mark.critical
def test_abandoned_idle_session_lazily_evicts_on_authorize() -> None:
    # Without a begin_call refresh, the existing lazy authorize path still idle-evicts an abandoned
    # session (BOLA-safe SESSION_INVALID) — in-flight exemption does not weaken the default path.
    port = _FakePort()
    mgr, clock = _mgr(port=port, idle_s=900, ttl_s=10_000, max_sessions=8)
    sid = mgr.create().session_id
    clock.advance(1_500)  # past idle, never marked in-flight
    with pytest.raises(GhidraMcpError) as ei:
        mgr.authorize(sid)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID
    assert sid not in mgr._sessions  # evicted


@pytest.mark.critical
def test_ttl_reapplied_at_next_boundary_after_in_flight_finishes() -> None:
    # TTL still caps standing lifetime: an in-flight call finishes, then the NEXT call on a session
    # that has exceeded its absolute TTL is rejected (evicted on authorize) — begin_call refreshes
    # only the idle clock (last_used_mono), never created_mono, so TTL fires.
    port = _FakePort()
    mgr, clock = _mgr(port=port, idle_s=900, ttl_s=1_000, max_sessions=8)
    sid = mgr.create().session_id
    mgr.begin_call(sid)
    clock.advance(1_500)  # exceeds TTL during the long call — but in-flight is not torn out
    assert mgr.reap_expired() == 0  # reaper leaves the in-flight session alone
    mgr.end_call(sid)  # the long call completes
    # The next call boundary re-applies the absolute TTL: NEW work is refused.
    mgr.begin_call(sid)  # marker first (mirrors dispatch order), refreshes idle only
    with pytest.raises(GhidraMcpError) as ei:
        mgr.authorize(sid)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID
    mgr.end_call(sid)  # no-op on the now-evicted session
    assert sid not in mgr._sessions


@pytest.mark.critical
def test_end_call_refreshes_idle_clock_so_window_restarts_after_call() -> None:
    # end_call refreshes last_used_mono: the idle window restarts when the call FINISHES, not at its
    # start. A short post-call idle then keeps the session alive; a long one idle-evicts it.
    mgr, clock = _mgr(idle_s=100, ttl_s=10_000, max_sessions=8)
    sid = mgr.create().session_id
    mgr.begin_call(sid)
    clock.advance(500)  # long call, far past idle (exempt while in-flight)
    mgr.end_call(sid)  # refresh at t=500 → idle clock restarts here
    clock.advance(50)  # only 50s since the call ended (< 100 idle)
    assert mgr.authorize(sid).session_id == sid  # survives
    clock.advance(120)  # now 170s since the call ended (> 100 idle), not in-flight
    with pytest.raises(GhidraMcpError) as ei:
        mgr.authorize(sid)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_change_log_is_owner_scoped_record_and_read() -> None:
    # A foreign caller can neither record into nor read another principal's log (ADR-017; BOLA).
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    for op in (
        lambda: mgr.record_comment_target(
            info.session_id, address=_ADDR_1, comment_type="EOL", cleared=False, caller=_B
        ),
        lambda: mgr.record_composite_target(info.session_id, name="t", caller=_B),
        lambda: mgr.export_targets(info.session_id, caller=_B),
    ):
        with pytest.raises(GhidraMcpError) as ei:
            op()
        assert ei.value.envelope.type is ErrorType.SESSION_INVALID
    # The owner's log is untouched by the foreign attempts.
    assert mgr.export_targets(info.session_id, caller=_A) == ([], [])


@pytest.mark.critical
def test_change_log_is_bounded_per_session() -> None:
    # Over the per-session cap a NEW target is dropped so the log can't grow unbounded (CWE-400).
    from vivarium.sessions.manager import _MAX_CHANGE_LOG_TARGETS

    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    sess = mgr._sessions[info.session_id]
    # Pre-fill the composite log to the cap directly (avoid N record calls), then attempt one more.
    sess.composite_targets = {f"t{i}" for i in range(_MAX_CHANGE_LOG_TARGETS)}
    mgr.record_composite_target(info.session_id, name="overflow", caller=_A)
    assert "overflow" not in sess.composite_targets
    assert len(sess.composite_targets) == _MAX_CHANGE_LOG_TARGETS
    # An already-logged name is still a free re-add at the cap (idempotent).
    mgr.record_composite_target(info.session_id, name="t0", caller=_A)
    assert len(sess.composite_targets) == _MAX_CHANGE_LOG_TARGETS
    # The same bound applies to NEW comment targets.
    sess.comment_targets = {(f"0x{i:x}", "EOL") for i in range(_MAX_CHANGE_LOG_TARGETS)}
    mgr.record_comment_target(
        info.session_id, address="0xdead", comment_type="EOL", cleared=False, caller=_A
    )
    assert ("0xdead", "EOL") not in sess.comment_targets
    # A clear at the cap is always honored (it shrinks the log, never grows it).
    a_key = next(iter(sess.comment_targets))
    mgr.record_comment_target(
        info.session_id, address=a_key[0], comment_type=a_key[1], cleared=True, caller=_A
    )
    assert a_key not in sess.comment_targets


@pytest.mark.critical
def test_change_log_unknown_session_is_session_invalid() -> None:
    # Every change-log method fails closed with SESSION_INVALID on an unknown id (no oracle).
    mgr, _ = _mgr(max_sessions=4)
    for op in (
        lambda: mgr.record_comment_target(
            "no-such", address=_ADDR_1, comment_type="EOL", cleared=False, caller=_A
        ),
        lambda: mgr.record_composite_target("no-such", name="t", caller=_A),
        lambda: mgr.export_targets("no-such", caller=_A),
    ):
        with pytest.raises(GhidraMcpError) as ei:
            op()
        assert ei.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_a_fresh_session_has_an_empty_change_log() -> None:
    # Default-empty: a session that performed no comment/composite writes exports no such targets.
    mgr, _ = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    assert mgr.export_targets(info.session_id, caller=_A) == ([], [])


def test_overlapping_calls_tracked_by_counter_not_a_bool() -> None:
    # Two concurrent calls on one session: in-flight is a COUNTER, so the first end_call does not
    # prematurely clear the in-flight mark while a second call is still running.
    mgr, clock = _mgr(idle_s=100, ttl_s=10_000, max_sessions=8)
    sid = mgr.create().session_id
    mgr.begin_call(sid)  # call 1 starts
    mgr.begin_call(sid)  # call 2 starts (overlap)
    mgr.end_call(sid)  # call 1 ends — call 2 still in-flight
    clock.advance(500)  # past idle, but call 2 keeps it non-idle
    assert mgr.authorize(sid).session_id == sid
    mgr.end_call(sid)  # call 2 ends


@pytest.mark.critical
def test_begin_and_end_call_on_unknown_or_evicted_session_are_noops() -> None:
    # Best-effort markers: an unknown or already-evicted id is a silent no-op (the handler's
    # authorize fails closed regardless — begin/end_call never raise and never resurrect a session).
    mgr, _ = _mgr(max_sessions=8)
    mgr.begin_call("never-existed")  # no raise
    mgr.end_call("never-existed")  # no raise
    sid = mgr.create().session_id
    mgr.evict(sid, reason="close")
    mgr.begin_call(sid)  # evicted → no-op, no resurrection
    mgr.end_call(sid)
    assert sid not in mgr._sessions


@pytest.mark.critical
def test_end_call_does_not_drive_counter_negative() -> None:
    # An unmatched/spurious end_call clamps at zero — it must not leave a phantom-negative in-flight
    # that would under-count a later real concurrent call (fail safe).
    mgr, clock = _mgr(idle_s=100, ttl_s=10_000, max_sessions=8)
    sid = mgr.create().session_id
    mgr.end_call(sid)  # spurious (no matching begin_call) → counter clamped at 0
    assert mgr._sessions[sid].in_flight == 0
    # A subsequent real call still correctly marks the session in-flight.
    mgr.begin_call(sid)
    clock.advance(500)  # past idle
    assert mgr.authorize(sid).session_id == sid
    mgr.end_call(sid)
