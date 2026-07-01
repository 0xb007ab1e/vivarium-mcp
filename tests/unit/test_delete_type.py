"""Unit tests for the ADR-031 ``delete_type`` tool — gated deletion of session-authored composites.

Covers the four layers of the additive ``delete_type`` capability (TB7-internal structural write,
no new boundary). No JVM/worker is touched (ADR-001); the ``_gh_delete_type`` JVM edge is
``# pragma: no cover`` and live-verified separately (ADR-031 D5). All synthetic + hermetic.

- **A. Schema** — ``DeleteTypeIn`` accepts a valid payload and rejects empty/over-long/extra-field
  ones (``extra="forbid"``); ``DeleteTypeResult`` round-trips and is frozen.
- **B. SessionManager (REAL manager)** — the new ``is_composite_target`` /
  ``forget_composite_target`` pair: the record→is→forget→is round-trip, idempotent forget, and BOLA
  raises (``SESSION_INVALID`` on a foreign/unknown id) — the 100%-critical-path branches (§4).
- **C. Handler (via ``build_handlers``)** — the structural gate, the load-bearing session-authored
  change-log check (NOT_FOUND with NO port call), the happy path (port called + name forgotten on
  ``deleted=True``), validation-before-change-log on an attacker name, and the ``deleted=False``
  path (name NOT forgotten).
- **D. rpc_client adapter** — ``delete_type`` forwards method ``"delete_type"`` with
  ``{"name": ...}`` and builds a ``DeleteTypeResult`` from a worker reply.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from pydantic import ValidationError

from vivarium.config import Config
from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.ghidra.port import GhidraPort
from vivarium.ghidra.rpc_client import RpcGhidraAdapter, _build_delete_type_result
from vivarium.security.limits import Limits
from vivarium.sessions.manager import SessionManager
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

_VALID_SID = "sid1"
# A session-authored composite name (a valid write-name identity) — a module constant so no test
# repeats a bare ``name`` literal that could trip a per-arg lint rule (consistent across cases).
_AUTHORED = "Packet"


# =====================================================================================
# A. Schema — DeleteTypeIn / DeleteTypeResult
# =====================================================================================
def test_delete_type_in_accepts_valid_payload() -> None:
    """A well-formed ``{session_id, name}`` constructs and round-trips its fields."""
    args = s.DeleteTypeIn(session_id=_VALID_SID, name=_AUTHORED)
    assert args.session_id == _VALID_SID
    assert args.name == _AUTHORED


def test_delete_type_in_rejects_empty_name() -> None:
    """An empty ``name`` violates ``min_length=1``."""
    with pytest.raises(ValidationError):
        s.DeleteTypeIn(session_id=_VALID_SID, name="")


def test_delete_type_in_rejects_overlong_name() -> None:
    """A ``name`` past ``_MAX_NAME`` is rejected at the boundary (CWE-20 bound)."""
    with pytest.raises(ValidationError):
        s.DeleteTypeIn(session_id=_VALID_SID, name="a" * (s._MAX_NAME + 1))


def test_delete_type_in_forbids_extra_fields() -> None:
    """``extra="forbid"`` rejects an unexpected field (no silent mass-assignment)."""
    with pytest.raises(ValidationError):
        s.DeleteTypeIn(session_id=_VALID_SID, name=_AUTHORED, unexpected="x")  # type: ignore[call-arg]


def test_delete_type_result_round_trips() -> None:
    """The result carries the SAFE server/worker scalars verbatim."""
    out = s.DeleteTypeResult(name=_AUTHORED, deleted=True, dependents_reverted=3)
    assert out.name == _AUTHORED
    assert out.deleted is True
    assert out.dependents_reverted == 3


def test_delete_type_result_is_frozen() -> None:
    """The result is immutable (frozen ``_Out``) — no post-construction mutation."""
    out = s.DeleteTypeResult(name=_AUTHORED, deleted=False, dependents_reverted=0)
    with pytest.raises(ValidationError):
        out.deleted = True


# =====================================================================================
# B. SessionManager — is_composite_target / forget_composite_target (REAL manager, critical path)
# =====================================================================================
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


def _mgr(**kw: object) -> SessionManager:
    """Build a real manager with a fake clock and sane test defaults."""
    return SessionManager(clock=_FakeClock(), **kw)  # type: ignore[arg-type]


_A = "principal-A"
_B = "principal-B"


def _invalid_envelope_type(
    mgr: SessionManager, fn: object, *args: object, **kw: object
) -> ErrorType:
    """Call ``fn`` expecting a ``GhidraMcpError`` and return its envelope ``type``."""
    with pytest.raises(GhidraMcpError) as ei:
        fn(*args, **kw)  # type: ignore[operator]
    return ei.value.envelope.type


@pytest.mark.critical
def test_is_composite_target_full_round_trip() -> None:
    """False before record, True after ``record_composite_target``, False after ``forget``."""
    mgr = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    sid = info.session_id
    # Before any record: not a target.
    assert mgr.is_composite_target(sid, name=_AUTHORED, caller=_A) is False
    # After recording (the create-side counterpart): it is a target.
    mgr.record_composite_target(sid, name=_AUTHORED, caller=_A)
    assert mgr.is_composite_target(sid, name=_AUTHORED, caller=_A) is True
    # After forgetting (the delete-side upkeep): no longer a target.
    mgr.forget_composite_target(sid, name=_AUTHORED, caller=_A)
    assert mgr.is_composite_target(sid, name=_AUTHORED, caller=_A) is False


@pytest.mark.critical
def test_forget_composite_target_is_idempotent() -> None:
    """Forgetting an absent name is a safe no-op (still not a target, no raise)."""
    mgr = _mgr(max_sessions=4)
    info = mgr.create(owner=_A)
    sid = info.session_id
    # Never recorded → forget must not raise and the name stays absent.
    mgr.forget_composite_target(sid, name=_AUTHORED, caller=_A)
    assert mgr.is_composite_target(sid, name=_AUTHORED, caller=_A) is False
    # Record then forget twice — the second forget is still a no-op.
    mgr.record_composite_target(sid, name=_AUTHORED, caller=_A)
    mgr.forget_composite_target(sid, name=_AUTHORED, caller=_A)
    mgr.forget_composite_target(sid, name=_AUTHORED, caller=_A)
    assert mgr.is_composite_target(sid, name=_AUTHORED, caller=_A) is False


@pytest.mark.critical
def test_is_composite_target_foreign_caller_is_session_invalid() -> None:
    """BOLA: principal B querying A's session id is denied the BOLA-safe ``SESSION_INVALID``."""
    mgr = _mgr(max_sessions=4)
    a = mgr.create(owner=_A)
    mgr.record_composite_target(a.session_id, name=_AUTHORED, caller=_A)
    err = _invalid_envelope_type(
        mgr, mgr.is_composite_target, a.session_id, name=_AUTHORED, caller=_B
    )
    assert err is ErrorType.SESSION_INVALID
    # A's log is untouched by the foreign probe (the check raised before any read leaked).
    assert mgr.is_composite_target(a.session_id, name=_AUTHORED, caller=_A) is True


@pytest.mark.critical
def test_is_composite_target_unknown_session_is_session_invalid() -> None:
    """An unknown id fails closed with ``SESSION_INVALID`` (no oracle)."""
    mgr = _mgr(max_sessions=4)
    err = _invalid_envelope_type(mgr, mgr.is_composite_target, "no-such", name=_AUTHORED, caller=_A)
    assert err is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_forget_composite_target_foreign_caller_is_session_invalid() -> None:
    """BOLA: principal B cannot forget on A's session — and A's target survives the attempt."""
    mgr = _mgr(max_sessions=4)
    a = mgr.create(owner=_A)
    mgr.record_composite_target(a.session_id, name=_AUTHORED, caller=_A)
    err = _invalid_envelope_type(
        mgr, mgr.forget_composite_target, a.session_id, name=_AUTHORED, caller=_B
    )
    assert err is ErrorType.SESSION_INVALID
    # The foreign forget never landed: A's composite is still recorded.
    assert mgr.is_composite_target(a.session_id, name=_AUTHORED, caller=_A) is True


@pytest.mark.critical
def test_forget_composite_target_unknown_session_is_session_invalid() -> None:
    """An unknown id fails closed with ``SESSION_INVALID`` (no oracle)."""
    mgr = _mgr(max_sessions=4)
    err = _invalid_envelope_type(
        mgr, mgr.forget_composite_target, "no-such", name=_AUTHORED, caller=_A
    )
    assert err is ErrorType.SESSION_INVALID


# =====================================================================================
# C. Handler — _handle_delete_type via build_handlers (fakes; no JVM/worker — ADR-001)
# =====================================================================================
class _FakeSessions:
    """Consent + change-log fake extended for ADR-031 (BOLA-safe on bad ids)."""

    def __init__(self) -> None:
        """Start with one read-only session and an empty change-log."""
        self._writes = {_VALID_SID: False}
        self._structural = {_VALID_SID: False}
        self._composites: set[str] = set()
        self.consent_checks: list[tuple[str, bool]] = []
        self.is_target_calls: list[str] = []
        self.forgotten: list[str] = []

    def _live(self, sid: str) -> None:
        if sid not in self._writes:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.SESSION_INVALID,
                    title="Session not found",
                    detail="the session is unknown, expired, or no longer valid",
                    status=404,
                )
            )

    def begin_call(self, session_id: str, *, caller: str | None = None) -> None:
        """In-flight marker (ADR-025 / F4) — no-op for these dispatch tests."""

    def end_call(self, session_id: str, *, caller: str | None = None) -> None:
        """In-flight clear (ADR-025 / F4) — no-op for these dispatch tests."""

    def enable_writes(
        self, session_id: str, *, allow_structural: bool = False, caller: str = "local"
    ) -> s.SessionInfo:
        """Grant write (and optionally structural) consent on a live session."""
        self._live(session_id)
        self._writes[session_id] = True
        self._structural[session_id] = allow_structural
        return s.SessionInfo(
            session_id=session_id,
            state="ready",
            created_at=0,
            expires_at=10,
            writes_enabled=True,
            allow_structural=allow_structural,
        )

    def require_write_consent(
        self, session_id: str, *, structural: bool = False, caller: str = "local"
    ) -> s.SessionInfo:
        """Default-deny structural-write gate (mirrors the real manager's semantics)."""
        self._live(session_id)
        self.consent_checks.append((session_id, structural))
        if not self._writes[session_id]:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.VALIDATION,
                    title="Invalid arguments",
                    detail="session is read-only; write consent not granted",
                    status=400,
                )
            )
        if structural and not self._structural[session_id]:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.VALIDATION,
                    title="Invalid arguments",
                    detail="structural writes not permitted for this session",
                    status=400,
                )
            )
        return s.SessionInfo(
            session_id=session_id,
            state="ready",
            created_at=0,
            expires_at=10,
            writes_enabled=True,
            allow_structural=self._structural[session_id],
        )

    def record_composite_target(self, session_id: str, *, name: str, caller: str = "local") -> None:
        """Record a composite write target in the change-log (ADR-027)."""
        self._live(session_id)
        self._composites.add(name)

    def is_composite_target(self, session_id: str, *, name: str, caller: str = "local") -> bool:
        """Return whether ``name`` is in this session's change-log (ADR-031 D2 authority)."""
        self._live(session_id)
        self.is_target_calls.append(name)
        return name in self._composites

    def forget_composite_target(self, session_id: str, *, name: str, caller: str = "local") -> None:
        """Drop a deleted composite name from the change-log (ADR-031 D4)."""
        self._live(session_id)
        self.forgotten.append(name)
        self._composites.discard(name)


class _FakePort:
    """Records ``delete_type`` calls; returns a configurable result."""

    def __init__(self, *, deleted: bool = True, dependents_reverted: int = 0) -> None:
        """Configure the canned ``deleted`` / ``dependents_reverted`` reply."""
        self.calls: list[tuple[str, str]] = []
        self._deleted = deleted
        self._dependents = dependents_reverted

    def delete_type(self, sid: str, a: s.DeleteTypeIn) -> s.DeleteTypeResult:
        """Record the call and return the canned typed result."""
        self.calls.append((sid, a.name))
        return s.DeleteTypeResult(
            name=a.name, deleted=self._deleted, dependents_reverted=self._dependents
        )


def _ctx(port: _FakePort | None = None) -> reg.ToolContext:
    """Build a ToolContext wired to the ADR-031 fakes (no JVM/worker)."""
    config = Config(
        log_level="INFO",
        log_format="json",
        session_ttl_s=3600,
        session_idle_s=900,
        limits=Limits(),
        worker_image="x",
        worker_runtime="runsc",
        worker_uid=65532,
        worker_gid=65532,
        rpc_socket_dir="/run/x",
        import_root="/work/imports",
    )
    return reg.ToolContext(
        config=config,
        sessions=cast(SessionManager, _FakeSessions()),
        port=cast(GhidraPort, port if port is not None else _FakePort()),
    )


def _sessions(ctx: reg.ToolContext) -> _FakeSessions:
    return cast(_FakeSessions, ctx.sessions)


def _port(ctx: reg.ToolContext) -> _FakePort:
    return cast(_FakePort, ctx.port)


@pytest.mark.critical
def test_delete_type_without_allow_structural_is_denied() -> None:
    """No structural consent → denied (VALIDATION); the port is never reached (fail closed)."""
    ctx = _ctx()
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=False)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["delete_type"](session_id=_VALID_SID, name=_AUTHORED)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_delete_type_not_session_authored_is_not_found_no_port_call() -> None:
    """The load-bearing gate: a name absent from the change-log → NOT_FOUND, NO worker call."""
    ctx = _ctx()
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    # The name was never recorded as a session-authored composite (e.g. a Ghidra-recovered struct).
    with pytest.raises(GhidraMcpError) as exc:
        handlers["delete_type"](session_id=_VALID_SID, name=_AUTHORED)
    assert exc.value.envelope.type is ErrorType.NOT_FOUND
    assert _port(ctx).calls == []  # no data-poisoning of a non-authored type
    assert _sessions(ctx).is_target_calls == [_AUTHORED]  # the authority check DID run
    assert _sessions(ctx).forgotten == []  # nothing forgotten on the reject path


@pytest.mark.critical
def test_delete_type_happy_path_calls_port_and_forgets() -> None:
    """Consent + recorded name → port.delete_type called; ``deleted=True`` drops the name."""
    ctx = _ctx()
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    _sessions(ctx).record_composite_target(_VALID_SID, name=_AUTHORED)  # this session authored it
    out = handlers["delete_type"](session_id=_VALID_SID, name=_AUTHORED)
    assert isinstance(out, s.DeleteTypeResult)
    assert out.name == _AUTHORED and out.deleted is True
    assert _port(ctx).calls == [(_VALID_SID, _AUTHORED)]  # the worker delete ran
    assert _sessions(ctx).forgotten == [_AUTHORED]  # change-log upkeep on success (ADR-031 D4)
    assert (_VALID_SID, True) in _sessions(ctx).consent_checks


@pytest.mark.critical
def test_delete_type_bad_name_rejected_before_change_log_check() -> None:
    """An attacker-style name is rejected (VALIDATION) BEFORE the change-log is consulted."""
    ctx = _ctx()
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    # A path-separator name passes the schema (length/charset) but fails validate_write_name's
    # identifier allow-list — which runs before is_composite_target (ADR-031 D4 ordering).
    with pytest.raises(GhidraMcpError) as exc:
        handlers["delete_type"](session_id=_VALID_SID, name="../evil")
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _sessions(ctx).is_target_calls == []  # change-log NOT consulted on a bad name
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_delete_type_deleted_false_does_not_forget() -> None:
    """If the worker reports ``deleted=False`` the handler must NOT forget the name."""
    ctx = _ctx(_FakePort(deleted=False))
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    _sessions(ctx).record_composite_target(_VALID_SID, name=_AUTHORED)
    out = handlers["delete_type"](session_id=_VALID_SID, name=_AUTHORED)
    assert out.deleted is False
    assert _port(ctx).calls == [(_VALID_SID, _AUTHORED)]  # the worker WAS asked
    assert _sessions(ctx).forgotten == []  # but the name is retained (no spurious upkeep)


def test_delete_type_on_unknown_session_is_session_invalid() -> None:
    """BOLA: an unknown/foreign session id yields ``SESSION_INVALID`` with no worker call."""
    ctx = _ctx()
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["delete_type"](session_id="foreign", name=_AUTHORED)
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID
    assert _port(ctx).calls == []


# =====================================================================================
# D. rpc_client adapter — delete_type forwarding + result building
# =====================================================================================
def _adapter_with_stubbed_call(
    captured: dict[str, Any], canned: dict[str, Any]
) -> RpcGhidraAdapter:
    """An adapter whose ``_tool_call`` is stubbed to capture args + return a canned result."""
    adapter = RpcGhidraAdapter.__new__(RpcGhidraAdapter)

    def _fake_tool_call(sid: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        captured["sid"] = sid
        captured["method"] = method
        captured["params"] = params
        return canned

    adapter._tool_call = _fake_tool_call  # type: ignore[method-assign]  # instance-level test stub
    return adapter


@pytest.mark.critical
def test_adapter_delete_type_forwards_method_and_params() -> None:
    """The adapter sends method ``"delete_type"`` with ONLY ``{"name": ...}`` and a typed result."""
    captured: dict[str, Any] = {}
    canned = {"name": _AUTHORED, "deleted": True, "dependents_reverted": 2}
    adapter = _adapter_with_stubbed_call(captured, canned)
    out = adapter.delete_type("sidX", s.DeleteTypeIn(session_id="sidX", name=_AUTHORED))
    assert captured["sid"] == "sidX"
    assert captured["method"] == "delete_type"
    assert captured["params"] == {"name": _AUTHORED}  # name only — no session/extra smuggled
    assert isinstance(out, s.DeleteTypeResult)
    assert out.name == _AUTHORED and out.deleted is True and out.dependents_reverted == 2


def test_build_delete_type_result_fields_are_safe() -> None:
    """The result builder coerces the worker reply's scalars into the typed SAFE result."""
    out = _build_delete_type_result({"name": _AUTHORED, "deleted": False, "dependents_reverted": 0})
    assert out.name == _AUTHORED
    assert out.deleted is False
    assert out.dependents_reverted == 0
