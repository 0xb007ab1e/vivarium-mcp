"""Unit tests for the session-scoped WRITE-CONSENT gate (ADR-012 §3) — critical path (100%).

The default-deny write-consent gate is the genuinely new agency control (LLM08): a session is
read-only until ``enable_writes`` is called; the mutation handlers call ``require_write_consent``
as the chokepoint before any write reaches the worker. Covered here against a real
:class:`SessionManager` with a fake worker port (no JVM, no I/O — ADR-001):

- default-deny: ``require_write_consent`` raises ``FORBIDDEN`` (ADR-036) on a fresh session;
- after ``enable_writes`` it passes; ``allow_structural`` gates the (deferred) structural set;
- ``disable_writes`` returns the session to read-only (and clears ``allow_structural``);
- ``SessionInfo`` reports ``writes_enabled`` / ``allow_structural``;
- BOLA: all three consent methods on an unknown/evicted id raise the SAME ``SESSION_INVALID``
  envelope (no oracle that the session exists).

Time is injected (a fake monotonic clock) so tests are deterministic and hermetic.
"""

from __future__ import annotations

import pytest

from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.sessions.manager import SessionManager

pytestmark = pytest.mark.critical


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
    """A fake worker port recording spawn/kill calls per session (mirrors the manager tests)."""

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
    """Build a manager with a fake clock + port and generous default lifetimes.

    Lifetimes default to large values so consent tests don't accidentally expire; a test may
    override ``ttl_s``/``idle_s`` to exercise the expired-session path.

    Returns:
        The manager and its fake clock.
    """
    clock = _FakeClock()
    params: dict[str, object] = {"ttl_s": 10_000, "idle_s": 10_000}
    params.update(kw)
    mgr = SessionManager(port=_FakePort(), clock=clock, **params)  # type: ignore[arg-type]
    return mgr, clock


# --- default-deny ---------------------------------------------------------------------------
def test_fresh_session_is_read_only_by_default() -> None:
    mgr, _ = _mgr()
    info = mgr.create()
    # Default-deny: write consent is not granted at creation.
    assert info.writes_enabled is False
    assert info.allow_structural is False
    with pytest.raises(GhidraMcpError) as exc:
        mgr.require_write_consent(info.session_id)
    # ADR-036: an owned session lacking write consent is a permission denial → FORBIDDEN (403).
    assert exc.value.envelope.type is ErrorType.FORBIDDEN
    assert "read-only" in exc.value.envelope.detail


# --- enable / annotation writes -------------------------------------------------------------
def test_enable_writes_grants_consent_for_annotation_writes() -> None:
    mgr, _ = _mgr()
    sid = mgr.create().session_id
    granted = mgr.enable_writes(sid)
    assert granted.writes_enabled is True
    assert granted.allow_structural is False
    # The annotation gate now passes (no structural opt-in needed).
    ok = mgr.require_write_consent(sid)
    assert ok.writes_enabled is True


# --- structural gate ------------------------------------------------------------------------
def test_structural_write_requires_allow_structural_opt_in() -> None:
    mgr, _ = _mgr()
    sid = mgr.create().session_id
    mgr.enable_writes(sid)  # annotation consent only (allow_structural defaults False)
    # Annotation consent is NOT enough for a structural write.
    with pytest.raises(GhidraMcpError) as exc:
        mgr.require_write_consent(sid, structural=True)
    # ADR-036: structural write without the opt-in is a permission denial → FORBIDDEN (403).
    assert exc.value.envelope.type is ErrorType.FORBIDDEN
    assert "structural" in exc.value.envelope.detail


def test_allow_structural_opt_in_permits_structural_write() -> None:
    mgr, _ = _mgr()
    sid = mgr.create().session_id
    info = mgr.enable_writes(sid, allow_structural=True)
    assert info.allow_structural is True
    # Both the annotation and structural gates pass.
    assert mgr.require_write_consent(sid).writes_enabled is True
    assert mgr.require_write_consent(sid, structural=True).allow_structural is True


# --- revoke ---------------------------------------------------------------------------------
def test_disable_writes_returns_to_read_only() -> None:
    mgr, _ = _mgr()
    sid = mgr.create().session_id
    mgr.enable_writes(sid, allow_structural=True)
    revoked = mgr.disable_writes(sid)
    assert revoked.writes_enabled is False
    assert revoked.allow_structural is False  # structural opt-in is cleared on revoke
    with pytest.raises(GhidraMcpError) as exc:
        mgr.require_write_consent(sid)
    # ADR-036: consent revoked → back to read-only → permission denial → FORBIDDEN (403).
    assert exc.value.envelope.type is ErrorType.FORBIDDEN


def test_enable_then_revoke_then_reenable_roundtrip() -> None:
    mgr, _ = _mgr()
    sid = mgr.create().session_id
    mgr.enable_writes(sid)
    mgr.disable_writes(sid)
    # A re-enable after revoke restores annotation consent (consent is re-grantable).
    assert mgr.enable_writes(sid).writes_enabled is True
    assert mgr.require_write_consent(sid).writes_enabled is True


# --- SessionInfo reporting ------------------------------------------------------------------
def test_session_info_reports_consent_state() -> None:
    mgr, _ = _mgr()
    sid = mgr.create().session_id
    # authorize() projects the same state via _to_info — consent fields visible to status tools.
    assert mgr.authorize(sid).writes_enabled is False
    mgr.enable_writes(sid, allow_structural=True)
    after = mgr.authorize(sid)
    assert after.writes_enabled is True
    assert after.allow_structural is True


# --- BOLA: consent methods on a bad id are indistinguishable from any other invalid id ------
@pytest.mark.parametrize("method", ["enable_writes", "disable_writes", "require_write_consent"])
def test_consent_methods_on_unknown_id_are_session_invalid(method: str) -> None:
    mgr, _ = _mgr()
    op = getattr(mgr, method)
    with pytest.raises(GhidraMcpError) as exc:
        op("totally-unknown-id")
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.parametrize("method", ["enable_writes", "disable_writes", "require_write_consent"])
def test_consent_methods_on_evicted_id_are_session_invalid(method: str) -> None:
    mgr, _ = _mgr()
    sid = mgr.create().session_id
    mgr.evict(sid, reason="close")
    op = getattr(mgr, method)
    with pytest.raises(GhidraMcpError) as exc:
        op(sid)
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID


def test_consent_bola_no_oracle_across_invalid_id_kinds() -> None:
    """Unknown vs evicted ids yield a byte-identical SESSION_INVALID — no existence oracle."""
    mgr, _ = _mgr()
    evicted = mgr.create().session_id
    mgr.evict(evicted, reason="close")

    def _env(sid: str) -> dict[str, object]:
        with pytest.raises(GhidraMcpError) as exc:
            mgr.require_write_consent(sid)
        env = exc.value.envelope
        return {"type": env.type, "title": env.title, "detail": env.detail, "status": env.status}

    assert _env("never-existed") == _env(evicted)


def test_require_write_consent_evicts_expired_session_bola_safe() -> None:
    """An expired session fails the consent gate with SESSION_INVALID (lazy-evicted, BOLA-safe)."""
    mgr, clock = _mgr(idle_s=10)
    sid = mgr.create().session_id
    mgr.enable_writes(sid)  # consent granted, but the session will idle-expire
    clock.advance(20)
    with pytest.raises(GhidraMcpError) as exc:
        mgr.require_write_consent(sid)
    # Expiry beats consent: the live-session check fails first → SESSION_INVALID, not FORBIDDEN.
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.parametrize("structural", [False, True])
def test_foreign_caller_write_is_session_invalid_not_forbidden(structural: bool) -> None:
    """ADR-036 D3 invariant: a non-owner's write attempt is SESSION_INVALID, never FORBIDDEN.

    The owner check (_get_live_locked) fires BEFORE the consent/capability check, so a foreign
    caller is denied the BOLA-safe SESSION_INVALID — a 403 here would confirm the session exists
    (an existence oracle). FORBIDDEN may only ever surface AFTER ownership is established.

    Parametrized over both the annotation and structural gates: the owner grants FULL consent
    (incl. ``allow_structural``) first, so if the owner check did NOT fire first, the consent gate
    would PASS and nothing would raise — the test only sees an error because ownership is checked
    first. This guards against a future refactor that splits the owner check per write-branch.
    """
    mgr, _ = _mgr()
    sid = mgr.create(owner="alice").session_id
    # Owner grants full consent, so a 403 leak would reveal "exists + consented" (worse).
    mgr.enable_writes(sid, caller="alice", allow_structural=True)
    with pytest.raises(GhidraMcpError) as exc:
        mgr.require_write_consent(sid, caller="bob", structural=structural)
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID
