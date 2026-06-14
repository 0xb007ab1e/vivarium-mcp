"""Unit + abuse tests for the structural mutation tools (ADR-013 Phase A) — critical-path gate.

Covers `rename_local_variable` / `rename_parameter`: they extend the ADR-012 write gate with the
`allow_structural` opt-in (`require_write_consent(structural=True)`) and are **name-only**. Drives
the two handlers via `build_handlers` with fakes (no JVM/worker — ADR-001), the
`validate_target_ref` selector validator, and the adapter methods + result builder. Security
assertions (TB7 structural, abuse-cases 22-30):

- a structural write WITHOUT the `allow_structural` opt-in is denied with VALIDATION, port untouched
  (the structural gate is real, not just plain write-consent);
- with the opt-in, a consented rename delegates to the port and returns the typed result with the
  echoed `function`/`old_name` wrapped `Untrusted` (ADR-005);
- an injection-steered `new_name` is rejected by `validate_write_name` BEFORE the port;
- BOLA: a structural write on an unknown session id yields SESSION_INVALID, no port call.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ghidra_mcp.config import Config
from ghidra_mcp.core import validation as v
from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from ghidra_mcp.ghidra.port import GhidraPort
from ghidra_mcp.ghidra.rpc_client import RpcGhidraAdapter, _build_structural_rename_result
from ghidra_mcp.security.limits import Limits
from ghidra_mcp.sessions.manager import SessionManager
from ghidra_mcp.tools import registry as reg
from ghidra_mcp.tools import schemas as s

_VALID_SID = "sid1"


def _u(text: str) -> Untrusted[str]:
    return Untrusted(value=text, origin=DataOrigin.BINARY)


# --- validate_target_ref (the local/param selector validator) ----------------------------------
@pytest.mark.critical
@pytest.mark.parametrize("ref", ["local_28", "param_1", "uVar3", "my_local"])
def test_validate_target_ref_accepts_decompiler_names(ref: str) -> None:
    assert v.validate_target_ref(ref) == ref


@pytest.mark.critical
@pytest.mark.parametrize("bad", ["ctrl\x01here", "tab\there", "", "x" * 2000])
def test_validate_target_ref_rejects_control_separator_and_oversize(bad: str) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_target_ref(bad)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.parametrize("fmt", ["zero​width", "rtl‮name"])
def test_validate_target_ref_accepts_format_chars_confined_by_worker(fmt: str) -> None:
    # A SELECTOR is not persisted (ADR-013 §6): format chars (zero-width/RTL) pass validation here;
    # a non-matching ref is confined by the worker's ``not-found``, not rejected at the boundary.
    # (Contrast ``validate_write_name``, which DOES reject them — the new_name IS persisted.)
    assert v.validate_target_ref(fmt) == fmt


# --- handler harness (mirrors test_mutation_registry's fakes, extended for structural) ----------
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
    """Records the structural write calls; returns a minimal valid result."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def rename_local_variable(
        self, sid: str, a: s.RenameLocalVariableIn
    ) -> s.StructuralRenameResult:
        self.calls.append(("rename_local_variable", sid))
        return s.StructuralRenameResult(
            address="0x401000",
            function=_u("FUN_00401000"),
            old_name=_u(a.variable),
            new_name=a.new_name,
            applied=True,
        )

    def rename_parameter(self, sid: str, a: s.RenameParameterIn) -> s.StructuralRenameResult:
        self.calls.append(("rename_parameter", sid))
        return s.StructuralRenameResult(
            address="0x401000",
            function=_u("FUN_00401000"),
            old_name=_u(a.parameter),
            new_name=a.new_name,
            applied=True,
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


# --- the structural gate (allow_structural) — the new agency control ----------------------------
@pytest.mark.critical
@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        ("rename_local_variable", {"function": "f", "variable": "local_8", "new_name": "len"}),
        ("rename_parameter", {"function": "f", "parameter": "param_1", "new_name": "buf"}),
    ],
)
def test_structural_write_without_allow_structural_is_denied(
    ctx: reg.ToolContext, tool: str, kwargs: dict[str, object]
) -> None:
    handlers = reg.build_handlers(ctx)
    # Plain write consent granted, but NOT the structural opt-in.
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=False)
    with pytest.raises(GhidraMcpError) as exc:
        handlers[tool](session_id=_VALID_SID, **kwargs)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []  # fail closed — no structural write reached the worker


@pytest.mark.critical
def test_rename_local_variable_with_structural_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    out = handlers["rename_local_variable"](
        session_id=_VALID_SID, function="FUN_00401000", variable="local_28", new_name="key_len"
    )
    assert isinstance(out, s.StructuralRenameResult)
    assert out.new_name == "key_len"  # validated name we set — bare/safe
    assert out.old_name.origin is DataOrigin.BINARY  # prior decompiler name — untrusted
    assert out.function.origin is DataOrigin.BINARY  # function name — untrusted
    assert out.applied is True
    assert ("rename_local_variable", _VALID_SID) in _port(ctx).calls
    # the consent check requested the structural tier
    assert (_VALID_SID, True) in cast(_FakeSessions, ctx.sessions).consent_checks


@pytest.mark.critical
def test_rename_parameter_with_structural_consent_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    out = handlers["rename_parameter"](
        session_id=_VALID_SID, function="f", parameter="param_1", new_name="buffer"
    )
    assert out.new_name == "buffer"
    assert ("rename_parameter", _VALID_SID) in _port(ctx).calls


@pytest.mark.critical
@pytest.mark.parametrize("malicious", ["<b>x</b>", "../p", "bad name", "rtl‮name"])
def test_structural_rename_rejects_injection_name_before_port(
    ctx: reg.ToolContext, malicious: str
) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_VALID_SID, allow_structural=True)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["rename_local_variable"](
            session_id=_VALID_SID, function="f", variable="local_8", new_name=malicious
        )
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []  # validated after consent, before the worker


def test_structural_write_on_unknown_session_is_session_invalid(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["rename_parameter"](
            session_id="foreign", function="f", parameter="p", new_name="x"
        )
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID
    assert _port(ctx).calls == []


# --- adapter methods + result builder -----------------------------------------------------------
def _adapter_with_stubbed_call(captured: dict[str, Any]) -> RpcGhidraAdapter:
    """An adapter whose ``_tool_call`` is stubbed to capture args + return a canned result."""
    adapter = RpcGhidraAdapter.__new__(RpcGhidraAdapter)  # no real transport/launcher needed

    def _fake_tool_call(sid: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        captured["sid"] = sid
        captured["method"] = method
        captured["params"] = params
        return {
            "address": "0x401000",
            "function": "FUN_00401000",
            "old_name": "local_28",
            "new_name": params["new_name"],
            "applied": True,
        }

    adapter._tool_call = _fake_tool_call  # type: ignore[method-assign]  # instance-level test stub
    return adapter


@pytest.mark.critical
def test_adapter_rename_local_variable_builds_typed_result() -> None:
    captured: dict[str, Any] = {}
    adapter = _adapter_with_stubbed_call(captured)
    out = adapter.rename_local_variable(
        "sidX",
        s.RenameLocalVariableIn(session_id="sidX", function="f", variable="local_28", new_name="n"),
    )
    assert captured["method"] == "rename_local_variable"
    assert captured["params"] == {"function": "f", "variable": "local_28", "new_name": "n"}
    assert isinstance(out, s.StructuralRenameResult)
    assert out.old_name.origin is DataOrigin.BINARY and out.function.origin is DataOrigin.BINARY
    assert out.new_name == "n" and out.applied is True


@pytest.mark.critical
def test_adapter_rename_parameter_builds_typed_result() -> None:
    captured: dict[str, Any] = {}
    adapter = _adapter_with_stubbed_call(captured)
    out = adapter.rename_parameter(
        "sidX",
        s.RenameParameterIn(session_id="sidX", function="f", parameter="param_1", new_name="b"),
    )
    assert captured["method"] == "rename_parameter"
    assert captured["params"] == {"function": "f", "parameter": "param_1", "new_name": "b"}
    assert out.new_name == "b"


def test_build_structural_rename_result_wraps_binary_fields() -> None:
    out = _build_structural_rename_result(
        {
            "address": "0x401000",
            "function": "FUN_00401000",
            "old_name": "local_28",
            "new_name": "len",
            "applied": True,
        }
    )
    assert out.function.value == "FUN_00401000" and out.function.origin is DataOrigin.BINARY
    assert out.old_name.value == "local_28" and out.old_name.origin is DataOrigin.BINARY
    assert out.new_name == "len" and out.address == "0x401000" and out.applied is True


# --- _in_transaction atomicity (the CWE-460 fix — ADR-013 §4; all three branches) ---------------
# Pure control flow over the program's transaction API, exercised with a fake program (no JVM —
# the ``_gh_*`` callers stay coverage-omitted). Asserts: commit on success, rollback on a write
# failure, and rollback on a COMMIT failure (the CWE-460 case) — never a dangling txn or raw escape.
class _FakeProgram:
    """Records start/end-transaction events; can simulate a commit-time (``endTransaction(_,True)``)
    failure to exercise the CWE-460 path."""

    def __init__(self, *, commit_raises: bool = False) -> None:
        self.events: list[tuple[Any, ...]] = []
        self._commit_raises = commit_raises
        self._txn = 0

    def startTransaction(self, name: str) -> int:  # noqa: N802  # Ghidra Java API name
        self._txn += 1
        self.events.append(("start", name))
        return self._txn

    def endTransaction(self, txn: int, commit: bool) -> None:  # noqa: N802  # Ghidra Java API name
        self.events.append(("end", txn, commit))
        if commit and self._commit_raises:
            raise RuntimeError("end-of-transaction fixup failed")


def _backend_with(program: _FakeProgram) -> Any:
    from ghidra_mcp.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    backend._program = program
    return backend


@pytest.mark.critical
def test_in_transaction_commits_on_success() -> None:
    prog = _FakeProgram()
    wrote: list[str] = []
    _backend_with(prog)._in_transaction("rename_local_variable", lambda: wrote.append("w"))
    assert wrote == ["w"]
    assert prog.events == [("start", "rename_local_variable"), ("end", 1, True)]  # committed only


@pytest.mark.critical
def test_in_transaction_rolls_back_on_write_failure() -> None:
    from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

    prog = _FakeProgram()

    def _boom() -> None:
        raise RuntimeError("write blew up")

    with pytest.raises(WorkerError) as exc:
        _backend_with(prog)._in_transaction("rename_local_variable", _boom)
    assert exc.value.code == CODE_ANALYSIS_FAILED
    assert prog.events == [("start", "rename_local_variable"), ("end", 1, False)]  # rolled back


@pytest.mark.critical
def test_in_transaction_rolls_back_on_commit_failure() -> None:
    # CWE-460: the commit (endTransaction(_, True)) itself raises (end-of-txn fixups) → must roll
    # back AND surface analysis-failed — never a dangling transaction, never a raw exception escape.
    from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

    prog = _FakeProgram(commit_raises=True)
    with pytest.raises(WorkerError) as exc:
        _backend_with(prog)._in_transaction("rename_local_variable", lambda: None)
    assert exc.value.code == CODE_ANALYSIS_FAILED
    # commit attempted (True), then best-effort rollback (False): no double-commit, no escape.
    assert prog.events == [
        ("start", "rename_local_variable"),
        ("end", 1, True),
        ("end", 1, False),
    ]
