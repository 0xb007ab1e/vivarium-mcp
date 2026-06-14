"""Unit tests for the ADR-014 Phase B structural type-aware tools — critical-path gate.

Covers ``set_function_signature`` / ``apply_data_type``: they reuse the ADR-013 structural gate
(``require_write_consent(structural=True)``) and add the structured-input validators
(``validate_signature`` / ``validate_type_ref``). Drives the two handlers via ``build_handlers``
with fakes (no JVM/worker — ADR-001), plus the adapter methods + result builders. Security
assertions (TB7 structural Phase B, abuse-cases 31-40):

- a structural write WITHOUT the ``allow_structural`` opt-in is denied with VALIDATION, port
  untouched (the structural gate is real, not just plain write-consent);
- with the opt-in, a consented call delegates to the port and returns the typed result with the
  echoed binary-derived fields wrapped ``Untrusted`` (ADR-005);
- an injection-steered ``TypeRef.named`` / ``ParamSpec.name`` is rejected BEFORE the port;
- BOLA: a structural write on an unknown session id yields SESSION_INVALID, no port call.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ghidra_mcp.config import Config
from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from ghidra_mcp.ghidra.port import GhidraPort
from ghidra_mcp.ghidra.rpc_client import (
    RpcGhidraAdapter,
    _build_apply_data_type_result,
    _build_set_function_signature_result,
    _type_ref_params,
)
from ghidra_mcp.security.limits import Limits
from ghidra_mcp.sessions.manager import SessionManager
from ghidra_mcp.tools import registry as reg
from ghidra_mcp.tools import schemas as s

_VALID_SID = "sid1"


def _u(text: str) -> Untrusted[str]:
    return Untrusted(value=text, origin=DataOrigin.BINARY)


def _ref(**kw: object) -> s.TypeRef:
    base = kw.pop("base", "int")
    return s.TypeRef(base=base, **kw)  # type: ignore[arg-type]


# --- handler harness (mirrors test_structural_mutation's fakes) --------------------------------
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
    """Records the structural type-aware write calls; returns a minimal valid result."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def set_function_signature(
        self, sid: str, a: s.SetFunctionSignatureIn
    ) -> s.SetFunctionSignatureResult:
        self.calls.append(("set_function_signature", sid))
        return s.SetFunctionSignatureResult(
            address="0x401000",
            function=_u("FUN_00401000"),
            old_signature=_u("undefined FUN_00401000(void)"),
            new_signature=_u("int FUN_00401000(int argc)"),
            applied=True,
        )

    def apply_data_type(self, sid: str, a: s.ApplyDataTypeIn) -> s.ApplyDataTypeResult:
        self.calls.append(("apply_data_type", sid))
        return s.ApplyDataTypeResult(address="0x401000", type_name=_u("int"), size=4, applied=True)


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


def _sig_kwargs() -> dict[str, object]:
    return {
        "function": "FUN_00401000",
        "return_type": _ref(base="int"),
        "parameters": [s.ParamSpec(name="argc", type=_ref(base="int"))],
        "calling_convention": "__cdecl",
    }


def _apply_kwargs() -> dict[str, object]:
    return {"address": "0x401000", "type": _ref(base="int"), "clear_existing": False}


# --- the structural gate (allow_structural) — the new agency control ----------------------------
@pytest.mark.critical
@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        ("set_function_signature", _sig_kwargs()),
        ("apply_data_type", _apply_kwargs()),
    ],
)
def test_structural_type_write_without_allow_structural_is_denied(
    ctx: reg.ToolContext, tool: str, kwargs: dict[str, object]
) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=False)
    with pytest.raises(GhidraMcpError) as exc:
        handlers[tool](session_id=_VALID_SID, **kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []  # fail closed — no write reached the worker


@pytest.mark.critical
def test_set_function_signature_with_structural_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    out = handlers["set_function_signature"](session_id=_VALID_SID, **_sig_kwargs())
    assert isinstance(out, s.SetFunctionSignatureResult)
    assert out.old_signature.origin is DataOrigin.BINARY  # prior prototype — untrusted
    assert out.new_signature.origin is DataOrigin.BINARY  # re-rendered prototype — untrusted
    assert out.function.origin is DataOrigin.BINARY  # function name — untrusted
    assert out.applied is True
    assert ("set_function_signature", _VALID_SID) in _port(ctx).calls
    assert (_VALID_SID, True) in cast(_FakeSessions, ctx.sessions).consent_checks


@pytest.mark.critical
def test_apply_data_type_with_structural_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    out = handlers["apply_data_type"](session_id=_VALID_SID, **_apply_kwargs())
    assert isinstance(out, s.ApplyDataTypeResult)
    assert out.type_name.origin is DataOrigin.BINARY  # resolved type name — untrusted
    assert out.size == 4 and out.applied is True
    assert ("apply_data_type", _VALID_SID) in _port(ctx).calls


@pytest.mark.critical
def test_set_function_signature_rejects_injection_param_name_before_port(
    ctx: reg.ToolContext,
) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    kwargs = _sig_kwargs()
    kwargs["parameters"] = [s.ParamSpec(name="../evil", type=_ref(base="int"))]
    with pytest.raises(GhidraMcpError) as exc:
        handlers["set_function_signature"](session_id=_VALID_SID, **kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []  # validated after consent, before the worker


@pytest.mark.critical
def test_apply_data_type_rejects_injection_named_type_before_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    kwargs = _apply_kwargs()
    kwargs["type"] = s.TypeRef(named="MyStruct").model_copy(update={"named": "../p", "base": None})
    with pytest.raises(GhidraMcpError) as exc:
        handlers["apply_data_type"](session_id=_VALID_SID, **kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_apply_data_type_rejects_bad_address_before_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    kwargs = _apply_kwargs()
    kwargs["address"] = "not-hex"
    with pytest.raises(GhidraMcpError) as exc:
        handlers["apply_data_type"](session_id=_VALID_SID, **kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


def test_structural_type_write_on_unknown_session_is_session_invalid(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["set_function_signature"](session_id="foreign", **_sig_kwargs())
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
def test_adapter_set_function_signature_builds_typed_result() -> None:
    captured: dict[str, Any] = {}
    canned = {
        "address": "0x401000",
        "function": "FUN_00401000",
        "old_signature": "undefined FUN(void)",
        "new_signature": "int FUN(int a)",
        "applied": True,
    }
    adapter = _adapter_with_stubbed_call(captured, canned)
    out = adapter.set_function_signature(
        "sidX",
        s.SetFunctionSignatureIn(
            session_id="sidX",
            function="f",
            return_type=_ref(base="int"),
            parameters=[s.ParamSpec(name="a", type=_ref(base="int"))],
            calling_convention="__cdecl",
        ),
    )
    assert captured["method"] == "set_function_signature"
    assert captured["params"]["function"] == "f"
    assert captured["params"]["calling_convention"] == "__cdecl"
    assert captured["params"]["return_type"] == {
        "base": "int",
        "named": None,
        "pointer_levels": 0,
        "array_len": None,
    }
    assert captured["params"]["parameters"] == [
        {
            "name": "a",
            "type": {"base": "int", "named": None, "pointer_levels": 0, "array_len": None},
        }
    ]
    assert isinstance(out, s.SetFunctionSignatureResult)
    assert out.old_signature.origin is DataOrigin.BINARY
    assert out.new_signature.origin is DataOrigin.BINARY
    assert out.function.origin is DataOrigin.BINARY
    assert out.applied is True


@pytest.mark.critical
def test_adapter_apply_data_type_builds_typed_result() -> None:
    captured: dict[str, Any] = {}
    canned = {"address": "0x401000", "type_name": "int", "size": 4, "applied": True}
    adapter = _adapter_with_stubbed_call(captured, canned)
    out = adapter.apply_data_type(
        "sidX",
        s.ApplyDataTypeIn(
            session_id="sidX", address="0x401000", type=_ref(base="int"), clear_existing=True
        ),
    )
    assert captured["method"] == "apply_data_type"
    assert captured["params"]["address"] == "0x401000"
    assert captured["params"]["clear_existing"] is True
    assert captured["params"]["type"] == {
        "base": "int",
        "named": None,
        "pointer_levels": 0,
        "array_len": None,
    }
    assert out.type_name.origin is DataOrigin.BINARY
    assert out.size == 4 and out.applied is True


def test_type_ref_params_serializes_named_with_modifiers() -> None:
    params = _type_ref_params(s.TypeRef(named="MyStruct", pointer_levels=2, array_len=8))
    assert params == {
        "base": None,
        "named": "MyStruct",
        "pointer_levels": 2,
        "array_len": 8,
    }


def test_build_set_function_signature_result_wraps_binary_fields() -> None:
    out = _build_set_function_signature_result(
        {
            "address": "0x401000",
            "function": "FUN_00401000",
            "old_signature": "undefined FUN(void)",
            "new_signature": "int FUN(int a)",
            "applied": True,
        }
    )
    assert out.function.value == "FUN_00401000" and out.function.origin is DataOrigin.BINARY
    assert out.old_signature.origin is DataOrigin.BINARY
    assert out.new_signature.value == "int FUN(int a)"
    assert out.address == "0x401000" and out.applied is True


def test_build_apply_data_type_result_wraps_binary_fields() -> None:
    out = _build_apply_data_type_result(
        {"address": "0x401000", "type_name": "MyStruct", "size": 16, "applied": True}
    )
    assert out.type_name.value == "MyStruct" and out.type_name.origin is DataOrigin.BINARY
    assert out.size == 16 and out.address == "0x401000" and out.applied is True
