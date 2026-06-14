"""Unit tests for the mutation/write tool handlers (ADR-012) — critical-path gate (100%).

The write handlers are the new agency chokepoint (LLM08): each must
``require_write_consent`` → validate the attacker-influenced inputs → delegate to the port →
audit. These tests drive the six handlers via the registry's synthesized flat-kwargs callables
(``build_handlers``) with local fakes for the session manager + :class:`GhidraPort` (no JVM, no
real worker — ADR-001). Assertions:

- write-without-consent is denied with ``VALIDATION`` and the port is NEVER called (fail closed);
- ``session_enable_writes`` / ``session_disable_writes`` report the consent state;
- a consented rename delegates to the port and returns the typed result;
- an injection-steered ``new_name`` is rejected by ``validate_write_name`` BEFORE the port;
- ``set_comment`` passes the worker the NORMALIZED text (model_copy), and ``text=None`` clears;
- ``session_undo`` requires consent then calls ``port.undo``;
- BOLA: enabling writes on an unknown id yields ``SESSION_INVALID`` (no oracle).
"""

from __future__ import annotations

from typing import cast

import pytest

from ghidra_mcp.config import Config
from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from ghidra_mcp.ghidra.port import GhidraPort
from ghidra_mcp.security.limits import Limits
from ghidra_mcp.sessions.manager import SessionManager
from ghidra_mcp.tools import registry as reg
from ghidra_mcp.tools import schemas as s

_VALID_SID = "sid1"


def _u(text: str, origin: DataOrigin = DataOrigin.BINARY) -> Untrusted[str]:
    return Untrusted(value=text, origin=origin)


class FakeSessionManager:
    """Fake session manager implementing the write-consent surface the handlers call.

    Models the default-deny gate: a session has no consent until ``enable_writes``;
    ``require_write_consent`` raises ``VALIDATION`` without it. An unknown id raises the BOLA-safe
    ``SESSION_INVALID`` from every method (no oracle). Records calls so tests can assert ordering.
    """

    def __init__(self) -> None:
        """Seed the single valid session in the read-only (default-deny) state."""
        self._writes: dict[str, bool] = {_VALID_SID: False}
        self._structural: dict[str, bool] = {_VALID_SID: False}
        self.consent_checks: list[str] = []

    def _info(self, sid: str) -> s.SessionInfo:
        return s.SessionInfo(
            session_id=sid,
            state="ready",
            created_at=0,
            expires_at=10,
            writes_enabled=self._writes[sid],
            allow_structural=self._structural[sid],
        )

    def _require_live(self, sid: str) -> None:
        if sid not in self._writes:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.SESSION_INVALID,
                    title="Session not found",
                    detail="the session is unknown, expired, or no longer valid",
                    status=404,
                )
            )

    def enable_writes(
        self, session_id: str, *, allow_structural: bool = False, caller: str = "local"
    ) -> s.SessionInfo:
        """Grant write consent (BOLA-safe on a bad id)."""
        self._require_live(session_id)
        self._writes[session_id] = True
        self._structural[session_id] = allow_structural
        return self._info(session_id)

    def disable_writes(self, session_id: str, *, caller: str = "local") -> s.SessionInfo:
        """Revoke write consent."""
        self._require_live(session_id)
        self._writes[session_id] = False
        self._structural[session_id] = False
        return self._info(session_id)

    def require_write_consent(
        self, session_id: str, *, structural: bool = False, caller: str = "local"
    ) -> s.SessionInfo:
        """Authorize + require consent; fail closed with ``VALIDATION`` when not granted."""
        self._require_live(session_id)
        self.consent_checks.append(session_id)
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
        return self._info(session_id)


class FakePort:
    """In-test :class:`GhidraPort` recording write calls and returning minimal valid results."""

    def __init__(self) -> None:
        """Initialize with an empty call log."""
        self.calls: list[tuple[str, str]] = []
        self.set_comment_text: str | None = "UNSET"  # sentinel to detect whether it was set

    def rename_function(self, sid: str, a: s.RenameFunctionIn) -> s.RenameResult:
        self.calls.append(("rename_function", sid))
        return s.RenameResult(
            address="0x401000", old_name=_u("FUN_00401000"), new_name=a.new_name, applied=True
        )

    def rename_symbol(self, sid: str, a: s.RenameSymbolIn) -> s.RenameSymbolResult:
        self.calls.append(("rename_symbol", sid))
        return s.RenameSymbolResult(
            address="0x402000",
            old_name=_u("DAT_00402000"),
            new_name=a.new_name,
            applied=True,
            kind="LABEL",
        )

    def set_comment(self, sid: str, a: s.SetCommentIn) -> s.SetCommentResult:
        self.calls.append(("set_comment", sid))
        self.set_comment_text = a.text  # capture exactly what the worker would receive
        return s.SetCommentResult(address="0x403000", comment_type=a.comment_type, applied=True)

    def undo(self, sid: str, a: s.SessionUndoIn) -> s.SessionUndoOut:
        self.calls.append(("undo", sid))
        return s.SessionUndoOut(session_id=sid, undone=True)


def _ctx() -> reg.ToolContext:
    """Build a tool context with the write-aware fakes."""
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
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, FakePort()),
    )


@pytest.fixture
def ctx() -> reg.ToolContext:
    """Provide a fresh write-aware tool context per test."""
    return _ctx()


def _port(ctx: reg.ToolContext) -> FakePort:
    return cast(FakePort, ctx.port)


def _sessions(ctx: reg.ToolContext) -> FakeSessionManager:
    return cast(FakeSessionManager, ctx.sessions)


# --- write-without-consent is the default-deny gate ----------------------------------------
@pytest.mark.critical
@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        (
            "rename_function",
            {"session_id": _VALID_SID, "function": "FUN_00401000", "new_name": "decrypt"},
        ),
        (
            "rename_symbol",
            {"session_id": _VALID_SID, "identifier": "DAT_00402000", "new_name": "g_key"},
        ),
        (
            "set_comment",
            {
                "session_id": _VALID_SID,
                "address": "0x403000",
                "comment_type": "EOL",
                "text": "note",
            },
        ),
        ("session_undo", {"session_id": _VALID_SID}),
    ],
)
def test_write_without_consent_is_denied_and_port_untouched(
    ctx: reg.ToolContext, tool: str, kwargs: dict[str, object]
) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers[tool](**kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    # Fail closed: no write reached the worker.
    assert _port(ctx).calls == []


# --- enable / disable lifecycle tools -------------------------------------------------------
@pytest.mark.critical
def test_session_enable_writes_reports_state(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    out = handlers["session_enable_writes"](session_id=_VALID_SID)
    assert isinstance(out, s.SessionWriteStateOut)
    assert out.writes_enabled is True
    assert out.allow_structural is False
    assert out.session_id == _VALID_SID


@pytest.mark.critical
def test_session_enable_writes_allow_structural_flag(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    out = handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    assert out.writes_enabled is True
    assert out.allow_structural is True


def test_session_disable_writes_reports_read_only(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    out = handlers["session_disable_writes"](session_id=_VALID_SID)
    assert isinstance(out, s.SessionWriteStateOut)
    assert out.writes_enabled is False
    assert out.allow_structural is False


# --- happy-path writes after consent --------------------------------------------------------
@pytest.mark.critical
def test_rename_function_after_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    out = handlers["rename_function"](
        session_id=_VALID_SID, function="FUN_00401000", new_name="decrypt_payload"
    )
    assert isinstance(out, s.RenameResult)
    assert out.new_name == "decrypt_payload"  # the validated name we set (bare/safe)
    assert isinstance(out.old_name, Untrusted)  # prior name is binary-derived → untrusted
    assert out.old_name.origin is DataOrigin.BINARY
    assert out.applied is True
    assert ("rename_function", _VALID_SID) in _port(ctx).calls
    # Consent was checked before the port was reached.
    assert _sessions(ctx).consent_checks == [_VALID_SID]


@pytest.mark.critical
def test_rename_symbol_after_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    out = handlers["rename_symbol"](
        session_id=_VALID_SID, identifier="DAT_00402000", new_name="g_key"
    )
    assert isinstance(out, s.RenameSymbolResult)
    assert out.new_name == "g_key"
    assert out.kind == "LABEL"  # closed-vocabulary, bare
    assert out.old_name.origin is DataOrigin.BINARY
    assert ("rename_symbol", _VALID_SID) in _port(ctx).calls


# --- injection-steered names are rejected BEFORE the port ----------------------------------
@pytest.mark.critical
@pytest.mark.parametrize(
    "malicious", ["<b>evil</b>", "../escape", "zero​width", "rtl‮name", "ctrl\x01"]
)
def test_rename_function_rejects_injection_name_before_port(
    ctx: reg.ToolContext, malicious: str
) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)  # consent granted
    with pytest.raises(GhidraMcpError) as exc:
        handlers["rename_function"](
            session_id=_VALID_SID, function="FUN_00401000", new_name=malicious
        )
    assert exc.value.envelope.type is ErrorType.VALIDATION
    # The validation runs AFTER consent but BEFORE the worker — nothing was written.
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_rename_symbol_rejects_injection_name_before_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["rename_symbol"](
            session_id=_VALID_SID, identifier="DAT_00402000", new_name="bad name"
        )
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


# --- set_comment: normalized on the way in; None clears ------------------------------------
@pytest.mark.critical
def test_set_comment_passes_normalized_text_to_worker(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    # A planted bidi/zero-width injection payload in the comment text.
    handlers["set_comment"](
        session_id=_VALID_SID,
        address="0x403000",
        comment_type="PRE",
        text="note‮ rules‌ here",
    )
    received = _port(ctx).set_comment_text
    assert received is not None
    # The worker receives the NORMALIZED value (inert tokens), not the raw camouflage.
    assert "‮" not in received
    assert "‌" not in received
    assert "<U+202E>" in received
    assert "<U+200C>" in received
    assert ("set_comment", _VALID_SID) in _port(ctx).calls


@pytest.mark.critical
def test_set_comment_none_clears_without_normalization(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    out = handlers["set_comment"](session_id=_VALID_SID, address="0x403000", comment_type="EOL")
    assert isinstance(out, s.SetCommentResult)
    # text=None clears the comment — the worker receives None (no validate_comment_text call).
    assert _port(ctx).set_comment_text is None
    assert out.applied is True


def test_set_comment_validates_address_before_worker(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["set_comment"](
            session_id=_VALID_SID, address="NOTHEX", comment_type="EOL", text="x"
        )
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


def test_set_comment_over_length_text_is_limit_exceeded(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    # The pydantic field bound (_MAX_COMMENT) rejects an over-length text at model construction,
    # surfacing as a VALIDATION error before the handler body runs.
    with pytest.raises((GhidraMcpError, Exception)):
        handlers["set_comment"](
            session_id=_VALID_SID,
            address="0x403000",
            comment_type="EOL",
            text="a" * (s._MAX_COMMENT + 1),
        )
    assert _port(ctx).calls == []


# --- session_undo: requires consent then delegates -----------------------------------------
@pytest.mark.critical
def test_session_undo_after_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID)
    out = handlers["session_undo"](session_id=_VALID_SID)
    assert isinstance(out, s.SessionUndoOut)
    assert out.undone is True
    assert ("undo", _VALID_SID) in _port(ctx).calls


# --- BOLA on the grant ----------------------------------------------------------------------
@pytest.mark.critical
def test_enable_writes_on_unknown_session_is_session_invalid(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_enable_writes"](session_id="someone-elses-id")
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_write_on_unknown_session_is_session_invalid_before_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["rename_function"](session_id="someone-elses-id", function="f", new_name="x")
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID
    assert _port(ctx).calls == []
