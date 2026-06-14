"""Unit tests for the ADR-015 Phase C composite-creation tools — critical-path gate.

Covers ``define_struct`` / ``define_union``: they reuse the ADR-013/014 structural gate
(``require_write_consent(structural=True)``) and add the composite validators
(``validate_composite`` / ``validate_field_spec``). Drives the two handlers via ``build_handlers``
with fakes (no JVM/worker — ADR-001), plus the adapter methods + result builders. Security
assertions (TB7 structural Phase C, abuse-cases 41-54):

- a composite create WITHOUT the ``allow_structural`` opt-in is denied with VALIDATION, port
  untouched (the structural gate is real, not just plain write-consent);
- with the opt-in, a consented call delegates to the port and returns the typed result (all fields
  server/worker-controlled — no Untrusted echo, ADR-015 §7);
- a by-value self-embed / injection member name / duplicate name is rejected BEFORE the port;
- BOLA: a composite create on an unknown session id yields SESSION_INVALID, no port call.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ghidra_mcp.config import Config
from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from ghidra_mcp.ghidra.port import GhidraPort
from ghidra_mcp.ghidra.rpc_client import (
    RpcGhidraAdapter,
    _build_define_struct_result,
    _build_define_union_result,
    _field_spec_params,
)
from ghidra_mcp.security.limits import Limits
from ghidra_mcp.sessions.manager import SessionManager
from ghidra_mcp.tools import registry as reg
from ghidra_mcp.tools import schemas as s

_VALID_SID = "sid1"


def _ref(**kw: object) -> s.TypeRef:
    base = kw.pop("base", "int")
    return s.TypeRef(base=base, **kw)  # type: ignore[arg-type]


# --- handler harness (mirrors test_structural_type_mutation's fakes) ---------------------------
class _FakeSessions:
    """Default-deny consent fake with the structural opt-in (BOLA-safe on bad ids)."""

    def __init__(self) -> None:
        self._writes = {_VALID_SID: False}
        self._structural = {_VALID_SID: False}
        self.consent_checks: list[tuple[str, bool]] = []

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

    def enable_writes(
        self, session_id: str, *, allow_structural: bool = False, caller: str = "local"
    ) -> s.SessionInfo:
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


class _FakePort:
    """Records the composite-create calls; returns a minimal valid result."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def define_struct(self, sid: str, a: s.DefineStructIn) -> s.DefineStructResult:
        self.calls.append(("define_struct", sid))
        return s.DefineStructResult(
            name=a.name, kind="struct", size=12, field_count=len(a.fields), applied=True
        )

    def define_union(self, sid: str, a: s.DefineUnionIn) -> s.DefineUnionResult:
        self.calls.append(("define_union", sid))
        return s.DefineUnionResult(
            name=a.name, kind="union", size=8, field_count=len(a.fields), applied=True
        )


def _ctx() -> reg.ToolContext:
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
        port=cast(GhidraPort, _FakePort()),
    )


@pytest.fixture
def ctx() -> reg.ToolContext:
    return _ctx()


def _port(ctx: reg.ToolContext) -> _FakePort:
    return cast(_FakePort, ctx.port)


def _struct_kwargs() -> dict[str, object]:
    return {
        "name": "Packet",
        "fields": [s.FieldSpec(name="id", type=_ref()), s.FieldSpec(name="len", type=_ref())],
        "packed": False,
    }


def _union_kwargs() -> dict[str, object]:
    return {
        "name": "Variant",
        "fields": [
            s.FieldSpec(name="i", type=_ref()),
            s.FieldSpec(name="f", type=_ref(base="float")),
        ],
    }


# --- the structural gate (allow_structural) — the new agency control ----------------------------
@pytest.mark.critical
@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        ("define_struct", _struct_kwargs()),
        ("define_union", _union_kwargs()),
    ],
)
def test_composite_create_without_allow_structural_is_denied(
    ctx: reg.ToolContext, tool: str, kwargs: dict[str, object]
) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=False)
    with pytest.raises(GhidraMcpError) as exc:
        handlers[tool](session_id=_VALID_SID, **kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []  # fail closed — no write reached the worker


@pytest.mark.critical
def test_define_struct_with_structural_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    out = handlers["define_struct"](session_id=_VALID_SID, **_struct_kwargs())
    assert isinstance(out, s.DefineStructResult)
    assert out.name == "Packet" and out.kind == "struct"
    assert out.field_count == 2 and out.applied is True
    assert ("define_struct", _VALID_SID) in _port(ctx).calls
    assert (_VALID_SID, True) in cast(_FakeSessions, ctx.sessions).consent_checks


@pytest.mark.critical
def test_define_union_with_structural_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    out = handlers["define_union"](session_id=_VALID_SID, **_union_kwargs())
    assert isinstance(out, s.DefineUnionResult)
    assert out.name == "Variant" and out.kind == "union"
    assert out.applied is True
    assert ("define_union", _VALID_SID) in _port(ctx).calls


@pytest.mark.critical
def test_define_struct_rejects_self_embed_before_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    # A by-value self-embed is rejected by the schema model validator at construction — drive the
    # handler with a model_construct'd payload so validate_composite's own reject branch fires too.
    payload = s.DefineStructIn.model_construct(
        session_id=_VALID_SID,
        name="Node",
        fields=[
            s.FieldSpec.model_construct(
                name="self",
                type=s.TypeRef.model_construct(
                    base=None, named="Node", pointer_levels=0, array_len=None
                ),
                offset=None,
            )
        ],
        packed=False,
    )
    with pytest.raises(GhidraMcpError) as exc:
        reg._handle_define_struct(ctx, payload)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_define_struct_rejects_injection_member_name_before_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    kwargs = _struct_kwargs()
    kwargs["fields"] = [s.FieldSpec(name="../evil", type=_ref())]
    with pytest.raises(GhidraMcpError) as exc:
        handlers["define_struct"](session_id=_VALID_SID, **kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []  # validated after consent, before the worker


@pytest.mark.critical
def test_define_struct_rejects_duplicate_member_names_before_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    kwargs = _struct_kwargs()
    kwargs["fields"] = [s.FieldSpec(name="x", type=_ref()), s.FieldSpec(name="x", type=_ref())]
    with pytest.raises(GhidraMcpError) as exc:
        handlers["define_struct"](session_id=_VALID_SID, **kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


def test_composite_create_on_unknown_session_is_session_invalid(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["define_struct"](session_id="foreign", **_struct_kwargs())
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID
    assert _port(ctx).calls == []


# --- adapter methods + result builders ---------------------------------------------------------
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
def test_adapter_define_struct_builds_typed_result() -> None:
    captured: dict[str, Any] = {}
    canned = {"name": "Packet", "kind": "struct", "size": 12, "field_count": 2, "applied": True}
    adapter = _adapter_with_stubbed_call(captured, canned)
    out = adapter.define_struct(
        "sidX",
        s.DefineStructIn(
            session_id="sidX",
            name="Packet",
            fields=[
                s.FieldSpec(name="id", type=_ref(), offset=0),
                s.FieldSpec(name="next", type=s.TypeRef(named="Packet", pointer_levels=1)),
            ],
            packed=True,
        ),
    )
    assert captured["method"] == "define_struct"
    assert captured["params"]["name"] == "Packet"
    assert captured["params"]["packed"] is True
    assert captured["params"]["fields"] == [
        {
            "name": "id",
            "type": {"base": "int", "named": None, "pointer_levels": 0, "array_len": None},
            "offset": 0,
        },
        {
            "name": "next",
            "type": {"base": None, "named": "Packet", "pointer_levels": 1, "array_len": None},
            "offset": None,
        },
    ]
    assert isinstance(out, s.DefineStructResult)
    assert out.name == "Packet" and out.size == 12 and out.applied is True


@pytest.mark.critical
def test_adapter_define_union_builds_typed_result() -> None:
    captured: dict[str, Any] = {}
    canned = {"name": "V", "kind": "union", "size": 8, "field_count": 2, "applied": True}
    adapter = _adapter_with_stubbed_call(captured, canned)
    out = adapter.define_union(
        "sidX",
        s.DefineUnionIn(
            session_id="sidX",
            name="V",
            fields=[
                s.FieldSpec(name="i", type=_ref()),
                s.FieldSpec(name="f", type=_ref(base="float")),
            ],
        ),
    )
    assert captured["method"] == "define_union"
    assert captured["params"]["name"] == "V"
    assert "packed" not in captured["params"]  # union has no packed/offset
    assert out.kind == "union" and out.size == 8 and out.applied is True


def test_field_spec_params_serializes_named_with_modifiers() -> None:
    params = _field_spec_params(
        s.FieldSpec(
            name="kids", type=s.TypeRef(named="Node", pointer_levels=1, array_len=4), offset=16
        )
    )
    assert params == {
        "name": "kids",
        "type": {"base": None, "named": "Node", "pointer_levels": 1, "array_len": 4},
        "offset": 16,
    }


def test_build_define_struct_result_fields_are_safe() -> None:
    out = _build_define_struct_result(
        {"name": "Packet", "kind": "struct", "size": 32, "field_count": 3, "applied": True}
    )
    assert out.name == "Packet" and out.kind == "struct"
    assert out.size == 32 and out.field_count == 3 and out.applied is True


def test_build_define_union_result_fields_are_safe() -> None:
    out = _build_define_union_result(
        {"name": "V", "kind": "union", "size": 8, "field_count": 2, "applied": True}
    )
    assert out.name == "V" and out.kind == "union"
    assert out.size == 8 and out.field_count == 2 and out.applied is True
