"""Unit tests for the Tier-1 tool registry and handlers (WS1).

Verifies the allow-list is exactly the 22 frozen tools, that handlers authorize the session first
(BOLA defense), apply semantic validation before touching the port, and delegate to the injected
:class:`GhidraPort`. Collaborators are local fakes implementing the frozen interfaces (no real
worker, no JVM — ADR-001).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

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


class FakeSessionManager:
    """In-test session manager implementing the methods the handlers call.

    Authorizes only ``_VALID_SID``; anything else raises the BOLA-safe ``session-invalid`` error.
    Records each authorized id so tests can assert authorization happened before port calls.
    """

    def __init__(self) -> None:
        """Initialize with empty audit trails."""
        self.authorized: list[str] = []
        self.evicted: list[tuple[str, str]] = []
        self.created = 0

    def create(self, *, label: str | None = None) -> s.SessionInfo:
        """Create a session, returning a fixed valid id."""
        self.created += 1
        return s.SessionInfo(session_id=_VALID_SID, state="open", created_at=0, expires_at=10)

    def authorize(self, session_id: str) -> s.SessionInfo:
        """Authorize ``_VALID_SID`` only; otherwise raise the BOLA-safe error."""
        if session_id != _VALID_SID:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.SESSION_INVALID, title="x", detail="unknown", status=404
                )
            )
        self.authorized.append(session_id)
        return s.SessionInfo(session_id=session_id, state="ready", created_at=0, expires_at=10)

    def evict(self, session_id: str, *, reason: str) -> bool:
        """Record the eviction and report a verified wipe."""
        self.evicted.append((session_id, reason))
        return True


def _u(text: str, origin: DataOrigin = DataOrigin.BINARY) -> Untrusted[str]:
    return Untrusted(value=text, origin=origin)


class FakePort:
    """In-test :class:`GhidraPort` recording the last call and returning minimal valid outputs."""

    def __init__(self) -> None:
        """Initialize with an empty call log."""
        self.calls: list[tuple[str, str]] = []

    def _rec(self, method: str, sid: str) -> None:
        self.calls.append((method, sid))

    def start_worker(self, session_id: str) -> None:
        self._rec("start_worker", session_id)

    def kill_worker(self, session_id: str) -> None:
        self._rec("kill_worker", session_id)

    def import_binary(self, sid: str, a: s.SessionImportIn) -> s.SessionInfo:
        self._rec("import_binary", sid)
        # Worker contributes only ``binary_sha256``; the forged lifecycle fields here MUST be
        # discarded by the handler in favor of the manager's authoritative values (#9 overlay).
        return s.SessionInfo(
            session_id="WORKER-FORGED",
            state="worker-forged",
            created_at=999_999,
            expires_at=1,
            binary_sha256="a" * 64,
        )

    def analyze(self, sid: str, a: s.SessionAnalyzeIn) -> s.SessionInfo:
        self._rec("analyze", sid)
        return s.SessionInfo(
            session_id="WORKER-FORGED",
            state="worker-forged",
            created_at=999_999,
            expires_at=1,
            binary_sha256="b" * 64,
        )

    def decompile_function(self, sid: str, a: s.DecompileFunctionIn) -> s.DecompiledFunction:
        self._rec("decompile_function", sid)
        return s.DecompiledFunction(
            address="0x401000",
            name=_u("main"),
            c_code=_u("int main(){}", DataOrigin.GHIDRA),
            signature=_u("int main()", DataOrigin.GHIDRA),
        )

    def disassemble(self, sid: str, a: s.DisassembleIn) -> s.DisassembleOut:
        self._rec("disassemble", sid)
        return s.DisassembleOut(instructions=[])

    def list_functions(self, sid: str, a: s.ListFunctionsIn) -> s.FunctionListOut:
        self._rec("list_functions", sid)
        return s.FunctionListOut(functions=[], total=0)

    def get_function(self, sid: str, a: s.GetFunctionIn) -> s.FunctionDetail:
        self._rec("get_function", sid)
        return s.FunctionDetail(
            address="0x401000", name=_u("main"), signature=_u("int main()"), size=10, is_thunk=False
        )

    def xrefs_to(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        self._rec("xrefs_to", sid)
        return s.XrefsOut(xrefs=[], total=0)

    def xrefs_from(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        self._rec("xrefs_from", sid)
        return s.XrefsOut(xrefs=[], total=0)

    def list_strings(self, sid: str, a: s.ListStringsIn) -> s.StringListOut:
        self._rec("list_strings", sid)
        return s.StringListOut(strings=[], total=0)

    def list_symbols(self, sid: str, a: s.ListSymbolsIn) -> s.SymbolListOut:
        self._rec("list_symbols", sid)
        return s.SymbolListOut(symbols=[], total=0)

    def get_symbol(self, sid: str, a: s.GetSymbolIn) -> s.Symbol:
        self._rec("get_symbol", sid)
        return s.Symbol(address="0x401000", name=_u("main"), kind="FUNCTION")

    def list_data(self, sid: str, a: s.ListDataIn) -> s.DataListOut:
        self._rec("list_data", sid)
        return s.DataListOut(data=[], total=0)

    def get_data_type(self, sid: str, a: s.GetDataTypeIn) -> s.DataType:
        self._rec("get_data_type", sid)
        return s.DataType(name=_u("int"), kind="typedef", size=4, definition=_u("int"))

    def get_comments(self, sid: str, a: s.GetCommentsIn) -> s.CommentListOut:
        self._rec("get_comments", sid)
        return s.CommentListOut(comments=[], total=0)

    def memory_map(self, sid: str, a: s.MemoryMapIn) -> s.MemoryMapOut:
        self._rec("memory_map", sid)
        return s.MemoryMapOut(blocks=[])

    def read_bytes(self, sid: str, a: s.ReadBytesIn) -> s.ReadBytesOut:
        self._rec("read_bytes", sid)
        return s.ReadBytesOut(address="0x401000", data=_u("deadbeef"), length=4)

    def search_bytes(self, sid: str, a: s.SearchBytesIn) -> s.SearchBytesOut:
        self._rec("search_bytes", sid)
        return s.SearchBytesOut(matches=[], total=0)

    def search_strings(self, sid: str, a: s.SearchStringsIn) -> s.SearchStringsOut:
        self._rec("search_strings", sid)
        return s.SearchStringsOut(strings=[], total=0)

    def program_metadata(self, sid: str, a: s.ProgramMetadataIn) -> s.ProgramMetadata:
        self._rec("program_metadata", sid)
        return s.ProgramMetadata(
            sha256="0" * 64,
            size_bytes=1,
            format="ELF",
            architecture="x86",
            endianness="little",
            compiler=None,
            entry_point=None,
            function_count=0,
            analysis_complete=True,
        )


class RecordingRegistrar:
    """Captures ``add_tool`` calls so tests can assert exhaustive registration."""

    def __init__(self) -> None:
        """Initialize with an empty registration log."""
        self.registered: list[str] = []

    def add_tool(
        self,
        fn: object,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
    ) -> None:
        """Record the registered tool name."""
        assert name is not None
        self.registered.append(name)


@pytest.fixture
def ctx() -> reg.ToolContext:
    """Build a tool context with fake collaborators."""
    config = Config(
        log_level="INFO",
        log_format="json",
        session_ttl_s=3600,
        session_idle_s=900,
        limits=Limits(),
        worker_image="x",
        worker_runtime="runsc",
        rpc_socket_dir="/run/x",
    )
    # The fakes implement the methods the handlers exercise; ``cast`` satisfies the static types
    # (``SessionManager`` is a concrete class, ``GhidraPort`` a Protocol) without a real worker/JVM.
    return reg.ToolContext(
        config=config,
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, FakePort()),
    )


def test_catalog_is_exactly_22_unique_tools() -> None:
    assert len(reg.TIER1_TOOL_NAMES) == 22
    assert len(set(reg.TIER1_TOOL_NAMES)) == 22


def test_handler_table_matches_frozen_allow_list() -> None:
    assert set(reg._HANDLERS) == set(reg.TIER1_TOOL_NAMES)


def test_build_handlers_is_exhaustive(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    assert set(handlers) == set(reg.TIER1_TOOL_NAMES)


def test_register_tools_registers_every_tool_exactly_once(ctx: reg.ToolContext) -> None:
    registrar = RecordingRegistrar()
    reg.register_tools(registrar, ctx)
    assert sorted(registrar.registered) == sorted(reg.TIER1_TOOL_NAMES)


def test_register_tools_applies_wrap_to_each_handler(ctx: reg.ToolContext) -> None:
    wrapped: list[str] = []

    def wrap(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        wrapped.append(name)
        return fn

    reg.register_tools(RecordingRegistrar(), ctx, wrap=wrap)
    assert sorted(wrapped) == sorted(reg.TIER1_TOOL_NAMES)


def test_build_handlers_fails_closed_on_table_drift(
    ctx: reg.ToolContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad_table = dict(reg._HANDLERS)
    bad_table.pop("read_bytes")
    monkeypatch.setattr(reg, "_HANDLERS", bad_table)
    with pytest.raises(RuntimeError, match="allow-list"):
        reg.build_handlers(ctx)


# --- handler behavior (via build_handlers, exercising the synthesized flat-kwargs signature) ----
def test_session_create_does_not_require_a_session(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    info = handlers["session_create"](label="job-1")
    assert info.session_id == _VALID_SID
    assert ctx.sessions.created == 1  # type: ignore[attr-defined]


def test_decompile_authorizes_then_calls_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    out = handlers["decompile_function"](session_id=_VALID_SID, function="main")
    assert out.c_code.origin is DataOrigin.GHIDRA
    assert ctx.sessions.authorized == [_VALID_SID]  # type: ignore[attr-defined]
    assert ("decompile_function", _VALID_SID) in ctx.port.calls  # type: ignore[attr-defined]


def test_foreign_session_is_rejected_before_port_call(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["decompile_function"](session_id="someone-elses", function="main")
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID
    assert ctx.port.calls == []  # type: ignore[attr-defined]  # never reached the worker


def test_read_bytes_validates_address_before_port(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["read_bytes"](session_id=_VALID_SID, address="NOTHEX", length=4)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert ctx.port.calls == []  # type: ignore[attr-defined]


def test_search_bytes_validates_pattern(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError):
        handlers["search_bytes"](session_id=_VALID_SID, pattern_hex="zz")


def test_disassemble_requires_start_or_function(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["disassemble"](session_id=_VALID_SID)
    assert exc.value.envelope.type is ErrorType.VALIDATION


def test_session_close_evicts_and_reports_wipe(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    out = handlers["session_close"](session_id=_VALID_SID)
    assert out.store_wiped is True
    assert (_VALID_SID, "close") in ctx.sessions.evicted  # type: ignore[attr-defined]


def test_session_status_returns_info(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    info = handlers["session_status"](session_id=_VALID_SID)
    assert info.session_id == _VALID_SID


@pytest.mark.critical
def test_session_import_uses_manager_lifecycle_keeps_worker_sha256(ctx: reg.ToolContext) -> None:
    """#9 overlay: the manager owns identity/timing/state; the worker contributes only sha256.

    The fake port returns forged ``session_id``/``state``/``created_at``/``expires_at`` — these MUST
    be discarded in favor of the manager's authoritative values, so a hostile worker can't forge a
    session's lifecycle. Only ``binary_sha256`` is carried through from the worker.
    """
    handlers = reg.build_handlers(ctx)
    info = handlers["session_import"](session_id=_VALID_SID, source_ref="upload-1")
    # Authoritative lifecycle from the manager's authorize() (id/state/created_at/expires_at).
    assert info.session_id == _VALID_SID
    assert info.state == "ready"
    assert info.created_at == 0
    assert info.expires_at == 10
    # Worker-only contribution survives the overlay.
    assert info.binary_sha256 == "a" * 64


@pytest.mark.critical
def test_session_analyze_uses_manager_lifecycle_keeps_worker_sha256(ctx: reg.ToolContext) -> None:
    """#9 overlay for ``session_analyze`` — same authority split as import."""
    handlers = reg.build_handlers(ctx)
    info = handlers["session_analyze"](session_id=_VALID_SID)
    assert info.session_id == _VALID_SID
    assert info.state == "ready"
    assert info.created_at == 0
    assert info.expires_at == 10
    assert info.binary_sha256 == "b" * 64


@pytest.mark.parametrize(
    ("tool", "kwargs", "method"),
    [
        ("session_import", {"session_id": _VALID_SID, "source_ref": "upload-1"}, "import_binary"),
        ("session_analyze", {"session_id": _VALID_SID}, "analyze"),
        ("list_functions", {"session_id": _VALID_SID}, "list_functions"),
        ("get_function", {"session_id": _VALID_SID, "function": "main"}, "get_function"),
        ("xrefs_to", {"session_id": _VALID_SID, "target": "main"}, "xrefs_to"),
        ("xrefs_from", {"session_id": _VALID_SID, "target": "main"}, "xrefs_from"),
        ("list_strings", {"session_id": _VALID_SID}, "list_strings"),
        ("list_symbols", {"session_id": _VALID_SID}, "list_symbols"),
        ("get_symbol", {"session_id": _VALID_SID, "identifier": "main"}, "get_symbol"),
        ("list_data", {"session_id": _VALID_SID}, "list_data"),
        ("get_data_type", {"session_id": _VALID_SID, "name": "int"}, "get_data_type"),
        ("get_comments", {"session_id": _VALID_SID}, "get_comments"),
        ("memory_map", {"session_id": _VALID_SID}, "memory_map"),
        (
            "read_bytes",
            {"session_id": _VALID_SID, "address": "0x401000", "length": 4},
            "read_bytes",
        ),
        ("search_bytes", {"session_id": _VALID_SID, "pattern_hex": "de??ff"}, "search_bytes"),
        ("search_strings", {"session_id": _VALID_SID, "query": "http"}, "search_strings"),
        ("program_metadata", {"session_id": _VALID_SID}, "program_metadata"),
    ],
)
def test_each_worker_tool_authorizes_and_delegates(
    ctx: reg.ToolContext, tool: str, kwargs: dict[str, object], method: str
) -> None:
    handlers = reg.build_handlers(ctx)
    handlers[tool](**kwargs)
    assert ctx.sessions.authorized == [_VALID_SID]  # type: ignore[attr-defined]
    assert (method, _VALID_SID) in ctx.port.calls  # type: ignore[attr-defined]
