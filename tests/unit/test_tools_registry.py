"""Unit tests for the Tier-1 tool registry and handlers (WS1).

Verifies the allow-list is exactly the 35 frozen tools (22 Tier-1 + 5 v1.1 semantic-naming
(ADR-007) + 8 v1.1 Tier-2 reporting/metrics (ADR-008)), that handlers authorize the session first
(BOLA defense), apply semantic validation before touching the port, and delegate to the injected
:class:`GhidraPort`. Collaborators are local fakes implementing the frozen interfaces (no real
worker, no JVM — ADR-001).
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import Any, cast

import pytest

from vivarium.config import Config
from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.ghidra.port import GhidraPort
from vivarium.security.limits import Limits
from vivarium.server.app import _with_error_boundary
from vivarium.server.auth import CAP_READ, CAP_WRITE, Principal
from vivarium.sessions.manager import SessionManager
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s


def _invoke(handler: Callable[..., Any], **kwargs: Any) -> Any:
    """Call a bound tool handler, awaiting it if it is the async ``session_analyze`` binding.

    Every tool is a synchronous flat-kwargs callable EXCEPT ``session_analyze``, which ADR-030
    Phase 2 makes async (so the loop can stream progress). This shim lets the existing
    authorize-then-delegate assertions drive either shape uniformly.
    """
    result = handler(**kwargs)
    return asyncio.run(result) if inspect.iscoroutine(result) else result


_VALID_SID = "sid1"


def _config() -> Config:
    """A minimal valid stdio config for building tool contexts in tests."""
    return Config(
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


class FakeSessionManager:
    """In-test session manager implementing the methods the handlers call.

    Authorizes only ``_VALID_SID``; anything else raises the BOLA-safe ``session-invalid`` error.
    Records each authorized id so tests can assert authorization happened before port calls.
    """

    def __init__(self) -> None:
        """Initialize with empty audit trails."""
        self.authorized: list[str] = []
        self.callers: list[str] = []  # ADR-017: caller principal threaded into authorize
        self.created_owners: list[str] = []  # ADR-017: owner principal threaded into create
        self.evicted: list[tuple[str, str]] = []
        self.ensured: list[str] = []
        self.recorded_hashes: list[tuple[str, str]] = []  # ADR-018: program-hash binding records
        # ADR-018 advisory provenance (size/name) recorded alongside the hash.
        self.recorded_metadata: list[tuple[str, int | None, str | None]] = []
        self.recorded_profiles: list[tuple[str, str]] = []  # ADR-029 B: effective analysis profile
        self.created = 0
        # ADR-025 / F4: in-flight markers the dispatch chokepoint wraps session-scoped calls with.
        # ``events`` records the interleaving so tests can assert begin → handler → end ordering.
        self.events: list[str] = []

    def begin_call(self, session_id: str, *, caller: str | None = None) -> None:
        """Record the start-of-call in-flight mark (best-effort; no auth)."""
        self.events.append(f"begin:{session_id}")

    def end_call(self, session_id: str, *, caller: str | None = None) -> None:
        """Record the end-of-call clear (the dispatch ``finally`` counterpart)."""
        self.events.append(f"end:{session_id}")

    def ensure_worker(self, session_id: str, *, caller: str = "local") -> None:
        """Record an idempotent worker-spawn request (the import handler calls this)."""
        self.ensured.append(session_id)

    def create(self, *, owner: str = "local", label: str | None = None) -> s.SessionInfo:
        """Create a session, returning a fixed valid id (records the owner principal — ADR-017)."""
        self.created += 1
        self.created_owners.append(owner)
        return s.SessionInfo(session_id=_VALID_SID, state="open", created_at=0, expires_at=10)

    def authorize(self, session_id: str, *, caller: str = "local") -> s.SessionInfo:
        """Authorize ``_VALID_SID`` only; otherwise raise the BOLA-safe error."""
        if session_id != _VALID_SID:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.SESSION_INVALID, title="x", detail="unknown", status=404
                )
            )
        self.authorized.append(session_id)
        self.callers.append(caller)
        self.events.append(f"authorize:{session_id}")
        return s.SessionInfo(session_id=session_id, state="ready", created_at=0, expires_at=10)

    def evict(self, session_id: str, *, reason: str, caller: str | None = None) -> bool:
        """Record the eviction and report a verified wipe (caller for owner-scoped close)."""
        self.evicted.append((session_id, reason))
        return True

    def record_binary_hash(
        self,
        session_id: str,
        sha256: str,
        *,
        size: int | None = None,
        name: str | None = None,
        caller: str = "local",
    ) -> None:
        """Record the worker-computed hash + advisory provenance (import handler — ADR-018)."""
        self.recorded_hashes.append((session_id, sha256))
        self.recorded_metadata.append((session_id, size, name))

    def record_analysis_profile(
        self, session_id: str, profile: str, *, caller: str = "local"
    ) -> None:
        """Echo the effective analyzer profile on the session (the analyze handler — ADR-029 B)."""
        self.recorded_profiles.append((session_id, profile))


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

    def analyze(
        self, sid: str, a: s.SessionAnalyzeIn, *, on_progress: object = None
    ) -> s.SessionInfo:
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

    def get_pcode(self, sid: str, a: s.GetPcodeIn) -> s.GetPcodeOut:
        self._rec("get_pcode", sid)
        return s.GetPcodeOut(instructions=[])

    def get_high_pcode(self, sid: str, a: s.GetHighPcodeIn) -> s.GetHighPcodeOut:
        self._rec("get_high_pcode", sid)
        return s.GetHighPcodeOut(ops=[])

    def stack_frame(self, sid: str, a: s.StackFrameIn) -> s.StackFrameOut:
        self._rec("stack_frame", sid)
        return s.StackFrameOut(frame_size=0, variables=[])

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

    def emulate(self, sid: str, a: s.EmulateIn) -> s.EmulateOut:
        self._rec("emulate", sid)
        return s.EmulateOut(steps_executed=1, stop_reason="halted", registers=[], memory=[])

    def demangle(self, sid: str, a: s.DemangleIn) -> s.DemangleOut:
        self._rec("demangle", sid)
        return s.DemangleOut(demangled=_u("ns::fn(int)"), scheme="gnu")

    def apply_type_archive(self, sid: str, a: s.ApplyTypeArchiveIn) -> s.ApplyTypeArchiveResult:
        self._rec("apply_type_archive", sid)
        return s.ApplyTypeArchiveResult(archive=a.archive, functions_updated=0, applied=True)

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

    def call_graph(self, sid: str, a: s.CallGraphIn) -> s.CallGraphOut:
        self._rec("call_graph", sid)
        return s.CallGraphOut(nodes=[], edges=[], unresolved_callers=[])

    def callees(self, sid: str, a: s.CalleesIn) -> s.CallNeighborsOut:
        self._rec("callees", sid)
        return s.CallNeighborsOut(neighbors=[], total=0)

    def callers(self, sid: str, a: s.CallersIn) -> s.CallNeighborsOut:
        self._rec("callers", sid)
        return s.CallNeighborsOut(neighbors=[], total=0)

    def analysis_order(self, sid: str, a: s.AnalysisOrderIn) -> s.AnalysisOrderOut:
        self._rec("analysis_order", sid)
        return s.AnalysisOrderOut(components=[], unresolved_callers=[], self_recursive=[])

    def function_context(self, sid: str, a: s.FunctionContextIn) -> s.FunctionContext:
        self._rec("function_context", sid)
        return s.FunctionContext(
            address="0x401000",
            name=_u("main"),
            signature=_u("int main()", DataOrigin.GHIDRA),
            is_external=False,
        )

    # --- Tier-2 reporting / metrics (v1.1 — ADR-008) ---
    def cyclomatic_complexity(
        self, sid: str, a: s.CyclomaticComplexityIn
    ) -> s.CyclomaticComplexity:
        self._rec("cyclomatic_complexity", sid)
        return s.CyclomaticComplexity(
            address="0x401000", name=_u("main"), complexity=1, block_count=1, edge_count=0
        )

    def list_imports(self, sid: str, a: s.ListImportsIn) -> s.ImportListOut:
        self._rec("list_imports", sid)
        return s.ImportListOut(imports=[], total=0)

    def list_exports(self, sid: str, a: s.ListExportsIn) -> s.ExportListOut:
        self._rec("list_exports", sid)
        return s.ExportListOut(exports=[], total=0)

    def coverage(self, sid: str, a: s.CoverageIn) -> s.CoverageOut:
        self._rec("coverage", sid)
        return s.CoverageOut(
            total_bytes=0,
            defined_code_bytes=0,
            defined_data_bytes=0,
            undefined_bytes=0,
            code_ratio=0.0,
            data_ratio=0.0,
            function_count=0,
        )

    def ioc_scan(self, sid: str, a: s.IocScanIn) -> s.IocScanOut:
        self._rec("ioc_scan", sid)
        return s.IocScanOut(matches=[], total=0)

    def crypto_constant_scan(self, sid: str, a: s.CryptoConstantScanIn) -> s.CryptoConstantScanOut:
        self._rec("crypto_constant_scan", sid)
        return s.CryptoConstantScanOut(findings=[], total=0)

    def call_graph_metrics(self, sid: str, a: s.CallGraphMetricsIn) -> s.CallGraphMetricsOut:
        self._rec("call_graph_metrics", sid)
        return s.CallGraphMetricsOut(
            function_count=0,
            edge_count=0,
            leaf_count=0,
            root_count=0,
            recursive_component_count=0,
            self_recursive_count=0,
            unresolved_caller_count=0,
            top_fan_in=[],
            top_fan_out=[],
        )

    def program_summary(self, sid: str, a: s.ProgramSummaryIn) -> s.ProgramSummary:
        self._rec("program_summary", sid)
        return s.ProgramSummary(
            metadata=s.ProgramMetadata(
                sha256="a" * 64,
                size_bytes=0,
                format="ELF",
                architecture="x86:LE:64:default",
                endianness="little",
                compiler=None,
                entry_point=None,
                function_count=0,
                analysis_complete=True,
            ),
            function_count=0,
            import_count=0,
            export_count=0,
            string_count=0,
        )

    # --- Function ID library-match identification (ADR-042 Phase 1) ---
    def identify_functions(self, sid: str, a: s.IdentifyFunctionsIn) -> s.IdentifyFunctionsOut:
        self._rec("identify_functions", sid)
        return s.IdentifyFunctionsOut(matches=[], total=0)


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
        worker_uid=65532,
        worker_gid=65532,
        rpc_socket_dir="/run/x",
        import_root="/work/imports",
    )
    # The fakes implement the methods the handlers exercise; ``cast`` satisfies the static types
    # (``SessionManager`` is a concrete class, ``GhidraPort`` a Protocol) without a real worker/JVM.
    return reg.ToolContext(
        config=config,
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, FakePort()),
    )


def test_catalog_is_exactly_62_unique_tools() -> None:
    # 22 Tier-1 + 5 v1.1 semantic-naming (ADR-007) + 8 v1.1 Tier-2 metrics (ADR-008; READ-ONLY)
    # + 1 Function ID library-match (ADR-042 Phase 1: identify_functions; READ-ONLY)
    # + 6 v1.1 mutation/write (ADR-012) + 2 v1.1 structural mutation (ADR-013 Phase A) + 2 v1.1
    # structural type-aware mutation (ADR-014 Phase B) + 2 v1.1 composite-type creation (ADR-015
    # Phase C) + 2 v1.2 annotation persistence (ADR-018: export read-only + import GATED) + 1 v1.2
    # multi-type composite batch (ADR-021: define_types, GATED by allow_structural) + 1 v1.4
    # composite deletion (ADR-031: delete_type, session-authored only, GATED by allow_structural)
    # + 4 v1.x streaming-extraction tools (ADR-040: start_decompile_stream + fetch_job_results /
    # job_status / cancel_job; READ-ONLY, output-only) + 1 v1.8 p-code emulation (ADR-049: emulate;
    # READ-ONLY, program DB not mutated) + 1 v1.8 C++ demangler (ADR-050: demangle; READ-ONLY,
    # program-independent) + 1 v1.8 bundled type-archive apply (ADR-051: apply_type_archive;
    # structural WRITE) + 1 v1.8 p-code listing (ADR-052: get_pcode; read-only) + 1 v1.8 high (SSA)
    # p-code (ADR-053: get_high_pcode; read-only) + 1 v1.8 stack-frame layout (ADR-054: stack_frame;
    # read-only) — the 15 mutation tools GATED by per-session write-consent (the structural 9
    # additionally by allow_structural); import is GATED identically (+ allow_structural for
    # structural entries).
    assert len(reg.TIER1_TOOL_NAMES) == 62
    assert len(set(reg.TIER1_TOOL_NAMES)) == 62


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


# --- ADR-017: the principal is threaded server-side into the manager (owner on create, caller on
# authorize); handlers read ``ctx.caller_id`` (static principal for stdio, resolver for HTTP).
def test_create_threads_static_principal_as_owner(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_create"](label="job-1")
    # The default static principal is the local operator (stdio path).
    assert ctx.sessions.created_owners == ["local"]  # type: ignore[attr-defined]


def test_authorize_threads_static_principal_as_caller(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["decompile_function"](session_id=_VALID_SID, function="main")
    assert ctx.sessions.callers == ["local"]  # type: ignore[attr-defined]


# --- optional-argument validation branches (gap N16) ---
# These handlers validate an OPTIONAL arg only when it is supplied. Existing tests exercised the
# omitted-arg path (+ the disassemble cross-field require, below); these cover the supplied-arg
# branches, taking registry.py to 100% branch coverage.
def test_disassemble_validates_start_when_provided(ctx: reg.ToolContext) -> None:
    """disassemble with an explicit start runs the address validator + dispatches."""
    handlers = reg.build_handlers(ctx)
    out = handlers["disassemble"](session_id=_VALID_SID, start="0x401000")
    assert isinstance(out, s.DisassembleOut)


def test_disassemble_validates_function_when_provided(ctx: reg.ToolContext) -> None:
    """disassemble with an explicit function runs the name validator + dispatches."""
    handlers = reg.build_handlers(ctx)
    out = handlers["disassemble"](session_id=_VALID_SID, function="main")
    assert isinstance(out, s.DisassembleOut)


def test_get_pcode_validates_start_and_dispatches(ctx: reg.ToolContext) -> None:
    """get_pcode with an explicit start runs the address validator + dispatches (ADR-052)."""
    handlers = reg.build_handlers(ctx)
    out = handlers["get_pcode"](session_id=_VALID_SID, start="0x401000")
    assert isinstance(out, s.GetPcodeOut)


def test_get_pcode_validates_function_and_dispatches(ctx: reg.ToolContext) -> None:
    """get_pcode with an explicit function runs the name validator + dispatches (ADR-052)."""
    handlers = reg.build_handlers(ctx)
    out = handlers["get_pcode"](session_id=_VALID_SID, function="main")
    assert isinstance(out, s.GetPcodeOut)


def test_get_pcode_requires_start_or_function(ctx: reg.ToolContext) -> None:
    """get_pcode with neither start nor function fails closed as VALIDATION (ADR-052)."""
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as ei:
        handlers["get_pcode"](session_id=_VALID_SID)
    assert ei.value.envelope.type is ErrorType.VALIDATION


def test_get_high_pcode_validates_function_and_dispatches(ctx: reg.ToolContext) -> None:
    """get_high_pcode runs the function-name validator + dispatches (ADR-053)."""
    handlers = reg.build_handlers(ctx)
    out = handlers["get_high_pcode"](session_id=_VALID_SID, function="main")
    assert isinstance(out, s.GetHighPcodeOut)


def test_stack_frame_validates_function_and_dispatches(ctx: reg.ToolContext) -> None:
    """stack_frame runs the function-name validator + dispatches (ADR-054)."""
    handlers = reg.build_handlers(ctx)
    out = handlers["stack_frame"](session_id=_VALID_SID, function="main")
    assert isinstance(out, s.StackFrameOut)


def test_list_functions_validates_name_contains_when_provided(ctx: reg.ToolContext) -> None:
    """list_functions with a name_contains filter runs the name validator + dispatches."""
    handlers = reg.build_handlers(ctx)
    out = handlers["list_functions"](session_id=_VALID_SID, name_contains="ma")
    assert isinstance(out, s.FunctionListOut)


def test_list_symbols_validates_name_contains_when_provided(ctx: reg.ToolContext) -> None:
    """list_symbols with a name_contains filter runs the name validator + dispatches."""
    handlers = reg.build_handlers(ctx)
    out = handlers["list_symbols"](session_id=_VALID_SID, name_contains="ma")
    assert isinstance(out, s.SymbolListOut)


def test_get_comments_validates_address_when_provided(ctx: reg.ToolContext) -> None:
    """get_comments with an explicit address runs the address validator + dispatches."""
    handlers = reg.build_handlers(ctx)
    out = handlers["get_comments"](session_id=_VALID_SID, address="0x401000")
    assert isinstance(out, s.CommentListOut)


def test_emulate_parse_checks_every_address_then_dispatches(ctx: reg.ToolContext) -> None:
    """emulate parse-checks start/stop_at/write+read addresses (ADR-049) then dispatches."""
    handlers = reg.build_handlers(ctx)
    out = handlers["emulate"](
        session_id=_VALID_SID,
        start="0x401000",
        stop_at="0x401010",
        write_memory=[{"address": "0x402000", "data_hex": "9090"}],
        read_registers=["RAX"],
        read_memory=[{"address": "0x402000", "length": 4}],
    )
    assert isinstance(out, s.EmulateOut)


def test_emulate_without_stop_at_dispatches(ctx: reg.ToolContext) -> None:
    """emulate with no stop_at skips the stop-address parse-check and still dispatches (ADR-049)."""
    handlers = reg.build_handlers(ctx)
    out = handlers["emulate"](session_id=_VALID_SID, start="0x401000", read_registers=["RAX"])
    assert isinstance(out, s.EmulateOut)


def test_emulate_rejects_malformed_start_address(ctx: reg.ToolContext) -> None:
    """A malformed start address fails closed as VALIDATION before the worker (ADR-049)."""
    handlers = reg.build_handlers(ctx)
    with pytest.raises(GhidraMcpError) as ei:
        handlers["emulate"](session_id=_VALID_SID, start="not-an-address")
    assert ei.value.envelope.type is ErrorType.VALIDATION


def test_demangle_authorizes_then_dispatches(ctx: reg.ToolContext) -> None:
    """demangle authorizes the session (BOLA) and dispatches, returning a DemangleOut (ADR-050)."""
    handlers = reg.build_handlers(ctx)
    out = handlers["demangle"](session_id=_VALID_SID, mangled="_ZN3foo3barEi")
    assert isinstance(out, s.DemangleOut)
    assert out.scheme in ("gnu", "msvc")


def test_caller_id_uses_static_principal_by_default() -> None:
    c = reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, FakePort()),
        principal=Principal(id="static-p"),
    )
    assert c.caller_id == "static-p"


def test_caller_id_uses_resolver_when_wired() -> None:
    """When a per-request resolver is set (HTTP), ``caller_id`` returns the resolved principal."""
    c = reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, FakePort()),
        principal=Principal(id="ignored-static"),
        resolve_principal=lambda: Principal(id="alice"),
    )
    assert c.caller_id == "alice"


def test_handler_threads_resolved_principal_per_request() -> None:
    """A handler owns/authorizes under the RESOLVED principal, not the static fallback (HTTP)."""
    sessions = FakeSessionManager()
    c = reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, sessions),
        port=cast(GhidraPort, FakePort()),
        principal=Principal(id="ignored-static"),
        resolve_principal=lambda: Principal(id="bob"),
    )
    handlers = reg.build_handlers(c)
    handlers["session_create"](label="j")
    handlers["decompile_function"](session_id=_VALID_SID, function="main")
    assert sessions.created_owners == ["bob"]
    assert sessions.callers == ["bob"]


# --- ADR-025 / F4: the dispatch chokepoint wraps session-scoped calls in begin_call/end_call -----
def _ctx_with_resolver(
    resolver: Callable[[], Principal],
) -> tuple[reg.ToolContext, FakeSessionManager]:
    """A ToolContext (+ its fake session mgr) whose per-request resolver is ``resolver``."""
    sessions = FakeSessionManager()
    ctx = reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, sessions),
        port=cast(GhidraPort, FakePort()),
        principal=Principal(id="ignored-static"),
        resolve_principal=resolver,
    )
    return ctx, sessions


def test_resolver_raise_surfaces_as_failclosed_envelope_not_leaked_exception() -> None:
    """R14: a resolve_principal that raises (HTTP fail-closed) surfaces as a safe error envelope.

    The real `_http_principal_resolver` raises `GhidraMcpError(INTERNAL)` when no server-derived
    principal is on the request scope (fail closed — ADR-017 / master §2). When that raise happens
    inside the capability check (`ctx.caller_capabilities`) / `caller_id` during dispatch, the tool
    error boundary must map it to the frozen fail-closed envelope — never leak the exception to the
    transport — and no in-flight mark may leak.
    """

    def _raising_resolver() -> Principal:
        raise GhidraMcpError(
            ErrorEnvelope(
                type=ErrorType.INTERNAL,
                title="Internal error",
                detail="Authenticated principal missing from the request context.",
                status=500,
            )
        )

    ctx, sessions = _ctx_with_resolver(_raising_resolver)
    handlers = reg.build_handlers(ctx)
    wrapped = _with_error_boundary("decompile_function", handlers["decompile_function"])

    result = wrapped(session_id=_VALID_SID, function="main")

    assert isinstance(result, ErrorEnvelope)  # returned, NOT raised out to the transport
    assert result.type is ErrorType.INTERNAL  # fail closed
    assert result.correlation_id is not None  # boundary attached a correlation id
    # caller_id raised before begin_call could run → no unbalanced in-flight mark leaked.
    begins = sessions.events.count(f"begin:{_VALID_SID}")
    ends = sessions.events.count(f"end:{_VALID_SID}")
    assert begins == ends


def test_resolver_unexpected_fault_maps_to_generic_internal_without_leak() -> None:
    """R14: an UNEXPECTED resolver fault maps to a generic internal-error, leaking no text.

    A GhidraMcpError forwards its (author-controlled, safe) envelope; a plain exception (a wiring
    bug) must instead map to the generic `_internal_envelope` — its message (which could echo
    sensitive context) is never forwarded to the client (master §5 / topic-error-handling).
    """

    def _buggy_resolver() -> Principal:
        raise RuntimeError("resolver misconfigured: token=SUPERSECRET at /internal/path")

    ctx, _sessions = _ctx_with_resolver(_buggy_resolver)
    handlers = reg.build_handlers(ctx)
    wrapped = _with_error_boundary("decompile_function", handlers["decompile_function"])

    result = wrapped(session_id=_VALID_SID, function="main")

    assert isinstance(result, ErrorEnvelope)
    assert result.type is ErrorType.INTERNAL
    for leak in ("SUPERSECRET", "misconfigured", "/internal/path", "RuntimeError"):
        assert leak not in result.detail  # the raw exception text never crosses the boundary


def test_session_scoped_call_is_wrapped_in_begin_and_end_call(ctx: reg.ToolContext) -> None:
    """A session-scoped tool marks the session in-flight around the handler (begin → … → end)."""
    handlers = reg.build_handlers(ctx)
    handlers["decompile_function"](session_id=_VALID_SID, function="main")
    events = ctx.sessions.events  # type: ignore[attr-defined]
    assert events[0] == f"begin:{_VALID_SID}"  # marked in-flight first
    assert events[-1] == f"end:{_VALID_SID}"  # cleared last (the finally)
    assert f"authorize:{_VALID_SID}" in events  # the handler's auth ran between


def test_session_create_is_not_wrapped(ctx: reg.ToolContext) -> None:
    """``session_create`` has no session_id → no begin/end_call (nothing to mark in-flight)."""
    handlers = reg.build_handlers(ctx)
    handlers["session_create"](label="j")
    assert ctx.sessions.events == []  # type: ignore[attr-defined]


def test_end_call_runs_even_when_handler_raises(ctx: reg.ToolContext) -> None:
    """The in-flight mark is cleared in a ``finally`` even when the call fails (no leaked mark)."""
    handlers = reg.build_handlers(ctx)
    # An unknown session id makes the handler's authorize raise the BOLA-safe error; begin_call
    # still ran (best-effort, keyed on the id) and end_call MUST still run despite the exception.
    with pytest.raises(GhidraMcpError):
        handlers["decompile_function"](session_id="not-the-valid-sid", function="main")
    events = ctx.sessions.events  # type: ignore[attr-defined]
    assert events[0] == "begin:not-the-valid-sid"
    assert events[-1] == "end:not-the-valid-sid"


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
    # Import triggers the manager-owned worker spawn (idempotent) before contacting the worker.
    sessions = cast(FakeSessionManager, ctx.sessions)
    assert sessions.ensured == [_VALID_SID]
    # The worker-computed program hash is recorded on the session (ADR-018 binding source).
    assert sessions.recorded_hashes == [(_VALID_SID, "a" * 64)]
    # Advisory provenance is stamped in the SAME chokepoint: the basename of the resolved ref and
    # (here) the worker's absent size (None — the default fake reports no size; ADR-018 fill).
    assert sessions.recorded_metadata == [(_VALID_SID, None, "upload-1")]


@pytest.mark.critical
def test_session_import_records_resolved_binary_size_and_basename_name() -> None:
    """Item 2 (ADR-018): the import handler stamps advisory size + basename provenance.

    The adapter overlays the server-resolved ``binary_size``; the handler records it plus the
    basename of the (possibly path-like) ``source_ref`` — no binary parse (ADR-001).
    """

    class _SizePort(FakePort):
        def import_binary(self, sid: str, a: s.SessionImportIn) -> s.SessionInfo:
            self._rec("import_binary", sid)
            return s.SessionInfo(
                session_id="WORKER-FORGED",
                state="worker-forged",
                created_at=1,
                expires_at=2,
                binary_sha256="c" * 64,
                binary_size=8192,
            )

    sessions = FakeSessionManager()
    ctx2 = reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, sessions),
        port=cast(GhidraPort, _SizePort()),
    )
    handlers = reg.build_handlers(ctx2)
    handlers["session_import"](session_id=_VALID_SID, source_ref="/work/imports/firmware.bin")
    # size from the adapter overlay; name is the BASENAME of the ref (a path → label, CWE-22 safe).
    assert sessions.recorded_metadata == [(_VALID_SID, 8192, "firmware.bin")]


@pytest.mark.critical
def test_session_import_skips_hash_record_when_worker_returns_no_hash(
    ctx: reg.ToolContext,
) -> None:
    """ADR-018: a worker import that yields no digest records no hash (the branch stays skipped)."""

    class _NoHashPort(FakePort):
        def import_binary(self, sid: str, a: s.SessionImportIn) -> s.SessionInfo:
            self._rec("import_binary", sid)
            return s.SessionInfo(
                session_id="WORKER-FORGED",
                state="worker-forged",
                created_at=1,
                expires_at=2,
                binary_sha256=None,
            )

    ctx2 = reg.ToolContext(
        config=ctx.config, sessions=ctx.sessions, port=cast(GhidraPort, _NoHashPort())
    )
    handlers = reg.build_handlers(ctx2)
    handlers["session_import"](session_id=_VALID_SID, source_ref="upload-1")
    assert cast(FakeSessionManager, ctx2.sessions).recorded_hashes == []


@pytest.mark.critical
def test_session_analyze_uses_manager_lifecycle_keeps_worker_sha256(ctx: reg.ToolContext) -> None:
    """#9 overlay for ``session_analyze`` — same authority split as import."""
    handlers = reg.build_handlers(ctx)
    info = _invoke(handlers["session_analyze"], session_id=_VALID_SID)
    assert info.session_id == _VALID_SID
    assert info.state == "ready"
    assert info.created_at == 0
    assert info.expires_at == 10
    assert info.binary_sha256 == "b" * 64


@pytest.mark.critical
@pytest.mark.parametrize("profile", ["default", "light", "deep"])
def test_session_analyze_echoes_effective_profile(ctx: reg.ToolContext, profile: str) -> None:
    """Item 1 (ADR-029 B): the returned SessionInfo carries the effective analysis profile.

    The sync handler records the validated input profile on the session AFTER a successful analyze
    and the returned (merged) info reflects it — so a client/operator can see which preset ran.
    """
    handlers = reg.build_handlers(ctx)
    info = _invoke(handlers["session_analyze"], session_id=_VALID_SID, profile=profile)
    assert info.analysis_profile == profile
    # The same value was recorded on the session (the source of truth for a later session_status).
    sessions = cast(FakeSessionManager, ctx.sessions)
    assert sessions.recorded_profiles == [(_VALID_SID, profile)]


def test_session_analyze_default_profile_when_unspecified(ctx: reg.ToolContext) -> None:
    """Omitting ``profile`` defaults to ``"default"`` and that is echoed/recorded (ADR-029 B)."""
    handlers = reg.build_handlers(ctx)
    info = _invoke(handlers["session_analyze"], session_id=_VALID_SID)
    assert info.analysis_profile == "default"
    assert cast(FakeSessionManager, ctx.sessions).recorded_profiles == [(_VALID_SID, "default")]


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
        # v1.1 semantic-naming tools (ADR-007) — same authorize-then-delegate contract.
        ("call_graph", {"session_id": _VALID_SID}, "call_graph"),
        ("call_graph", {"session_id": _VALID_SID, "root": "main"}, "call_graph"),
        ("callees", {"session_id": _VALID_SID, "function": "main"}, "callees"),
        ("callers", {"session_id": _VALID_SID, "function": "main"}, "callers"),
        ("analysis_order", {"session_id": _VALID_SID}, "analysis_order"),
        ("analysis_order", {"session_id": _VALID_SID, "root": "main"}, "analysis_order"),
        (
            "function_context",
            {"session_id": _VALID_SID, "function": "main"},
            "function_context",
        ),
        # v1.1 Tier-2 reporting/metrics tools (ADR-008) — same authorize-then-delegate contract.
        (
            "cyclomatic_complexity",
            {"session_id": _VALID_SID, "function": "main"},
            "cyclomatic_complexity",
        ),
        ("list_imports", {"session_id": _VALID_SID}, "list_imports"),
        ("list_exports", {"session_id": _VALID_SID}, "list_exports"),
        ("coverage", {"session_id": _VALID_SID}, "coverage"),
        ("ioc_scan", {"session_id": _VALID_SID}, "ioc_scan"),
        ("crypto_constant_scan", {"session_id": _VALID_SID}, "crypto_constant_scan"),
        ("call_graph_metrics", {"session_id": _VALID_SID}, "call_graph_metrics"),
        ("call_graph_metrics", {"session_id": _VALID_SID, "root": "main"}, "call_graph_metrics"),
        ("program_summary", {"session_id": _VALID_SID}, "program_summary"),
    ],
)
def test_each_worker_tool_authorizes_and_delegates(
    ctx: reg.ToolContext, tool: str, kwargs: dict[str, object], method: str
) -> None:
    handlers = reg.build_handlers(ctx)
    _invoke(handlers[tool], **kwargs)
    assert ctx.sessions.authorized == [_VALID_SID]  # type: ignore[attr-defined]
    assert (method, _VALID_SID) in ctx.port.calls  # type: ignore[attr-defined]


# ==============================================================================================
# ADR-033 — per-tool capability authorization. ``WRITE_TOOLS`` is the single source of truth; the
# dispatch chokepoint (_bind / _bind_analyze) denies a tool whose required capability the principal
# lacks, BEFORE any handler work (complete mediation — std-owasp-api API5). A read-only principal
# (an OAuth token without the write-scope) can run reads + the session/analyze workflow but is
# barred from every mutation tool, fail closed → FORBIDDEN (403, ADR-036), no session/port call.
# ==============================================================================================

#: The exact 15 mutation tools the ADR designates as ``write`` (asserted to catch drift).
_EXPECTED_WRITE_TOOLS = frozenset(
    {
        "session_enable_writes",
        "session_disable_writes",
        "session_undo",
        "rename_function",
        "rename_symbol",
        "set_comment",
        "rename_local_variable",
        "rename_parameter",
        "set_function_signature",
        "apply_data_type",
        "apply_type_archive",
        "define_struct",
        "define_union",
        "define_types",
        "delete_type",
        "session_import_annotations",
    }
)

#: Representative read tools that MUST require ``read`` (lifecycle + query + read-only export).
_REPRESENTATIVE_READ_TOOLS = (
    "decompile_function",
    "session_create",
    "session_export_annotations",
    "session_analyze",
)


# --- required_capability: writes → write, everything else → read ---------------------------------
@pytest.mark.parametrize("tool", sorted(reg.WRITE_TOOLS))
def test_required_capability_is_write_for_every_write_tool(tool: str) -> None:
    assert reg.required_capability(tool) == CAP_WRITE


@pytest.mark.parametrize("tool", _REPRESENTATIVE_READ_TOOLS)
def test_required_capability_is_read_for_representative_read_tools(tool: str) -> None:
    assert reg.required_capability(tool) == CAP_READ


def test_required_capability_read_for_every_non_write_catalog_tool() -> None:
    """Exhaustive: every catalog tool NOT in WRITE_TOOLS requires ``read`` (no third capability)."""
    for tool in reg.TIER1_TOOL_NAMES:
        expected = CAP_WRITE if tool in reg.WRITE_TOOLS else CAP_READ
        assert reg.required_capability(tool) == expected


# --- WRITE_TOOLS completeness / correctness vs. the catalog --------------------------------------
def test_write_tools_is_subset_of_catalog() -> None:
    assert set(reg.TIER1_TOOL_NAMES) >= reg.WRITE_TOOLS


def test_write_tools_is_exactly_the_expected_set() -> None:
    """Pin the exact write set so a new mutator (or a misclassified read tool) trips a test."""
    assert reg.WRITE_TOOLS == _EXPECTED_WRITE_TOOLS
    assert len(reg.WRITE_TOOLS) == 16


@pytest.mark.parametrize(
    "tool", ["session_export_annotations", "session_create", "session_analyze"]
)
def test_read_only_session_tools_are_not_write_tools(tool: str) -> None:
    """The session lifecycle + read-only export must NOT be gated as writes (ADR-033 D1)."""
    assert tool not in reg.WRITE_TOOLS


# --- ToolContext.caller_capabilities mirrors caller_id -------------------------------------------
def test_caller_capabilities_uses_static_principal_by_default() -> None:
    c = reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, FakePort()),
        principal=Principal(id="static-p"),  # default full capabilities
    )
    assert c.caller_capabilities == frozenset({CAP_READ, CAP_WRITE})


def test_caller_capabilities_uses_resolver_when_wired() -> None:
    """A per-request read-only resolver narrows the capabilities seen by the chokepoint (HTTP)."""
    c = reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, FakePort()),
        principal=Principal(id="ignored-static"),  # would be full
        resolve_principal=lambda: Principal(id="reader", capabilities=frozenset({CAP_READ})),
    )
    assert c.caller_capabilities == frozenset({CAP_READ})


# --- The gate (headline): a read-only principal is denied every write tool, no work done ---------
class _RecordingSessionManager(FakeSessionManager):
    """Records EVERY session-touching call so a denial test can assert none happened.

    Extends the read-aware fake with the write-consent surface; if the gate ever let a write
    handler run under a read-only principal, one of these would be recorded (and the test fails).
    """

    def __init__(self) -> None:
        """Track write-consent + lifecycle calls beyond the base read fake."""
        super().__init__()
        self.consent_checks: list[str] = []
        self.enabled: list[str] = []
        self.disabled: list[str] = []

    def require_write_consent(
        self, session_id: str, *, structural: bool = False, caller: str = "local"
    ) -> s.SessionInfo:
        """Record + grant (the gate must prevent this from ever running for a read-only token)."""
        self.consent_checks.append(session_id)
        return s.SessionInfo(session_id=session_id, state="ready", created_at=0, expires_at=10)

    def enable_writes(
        self, session_id: str, *, allow_structural: bool = False, caller: str = "local"
    ) -> s.SessionInfo:
        """Record an enable-writes attempt (gated as a write tool)."""
        self.enabled.append(session_id)
        return s.SessionInfo(
            session_id=session_id,
            state="ready",
            created_at=0,
            expires_at=10,
            writes_enabled=True,
            allow_structural=allow_structural,
        )

    def disable_writes(self, session_id: str, *, caller: str = "local") -> s.SessionInfo:
        """Record a disable-writes attempt (gated as a write tool)."""
        self.disabled.append(session_id)
        return s.SessionInfo(session_id=session_id, state="ready", created_at=0, expires_at=10)


def _readonly_ctx(sessions: _RecordingSessionManager, port: FakePort) -> reg.ToolContext:
    """A context whose per-request principal is read-only (no ``write`` capability)."""
    return reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, sessions),
        port=cast(GhidraPort, port),
        principal=Principal(id="ignored-static"),  # full — must be ignored in favor of resolver
        resolve_principal=lambda: Principal(id="reader", capabilities=frozenset({CAP_READ})),
    )


# Write tools spanning the kinds: consent toggle, annotation write, structural, composite, delete,
# and the import-replay. Minimal kwargs suffice: the gate fires BEFORE input model validation.
_GATED_WRITE_CALLS = [
    ("session_enable_writes", {"session_id": _VALID_SID}),
    ("session_disable_writes", {"session_id": _VALID_SID}),
    ("session_undo", {"session_id": _VALID_SID}),
    ("rename_function", {"session_id": _VALID_SID, "function": "main", "new_name": "parse"}),
    ("define_struct", {"session_id": _VALID_SID, "name": "S", "fields": []}),
    ("apply_type_archive", {"session_id": _VALID_SID, "archive": "generic_clib_64"}),
    ("delete_type", {"session_id": _VALID_SID, "name": "S"}),
    ("session_import_annotations", {"session_id": _VALID_SID, "annotations": {}}),
]


@pytest.mark.parametrize(("tool", "kwargs"), _GATED_WRITE_CALLS)
def test_read_only_principal_is_denied_every_write_tool(
    tool: str, kwargs: dict[str, object]
) -> None:
    sessions = _RecordingSessionManager()
    port = FakePort()
    handlers = reg.build_handlers(_readonly_ctx(sessions, port))
    with pytest.raises(GhidraMcpError) as exc:
        _invoke(handlers[tool], **kwargs)
    # Denial maps to the dedicated FORBIDDEN envelope (403, ADR-036 — superseding the ADR-033 D4
    # interim VALIDATION mapping): authenticated but lacking the tool's required capability.
    assert exc.value.envelope.type is ErrorType.FORBIDDEN
    assert exc.value.envelope.status == 403
    # Denied BEFORE any handler work: nothing authorized, no consent check, no port call, no
    # enable/disable — the read-only token reached no mutation surface (complete mediation).
    assert sessions.authorized == []
    assert sessions.consent_checks == []
    assert sessions.enabled == []
    assert sessions.disabled == []
    assert port.calls == []


def test_read_only_principal_can_run_read_tool() -> None:
    """A read tool succeeds for a read-only principal (it requires only ``read``)."""
    sessions = _RecordingSessionManager()
    port = FakePort()
    handlers = reg.build_handlers(_readonly_ctx(sessions, port))
    out = handlers["decompile_function"](session_id=_VALID_SID, function="main")
    assert out.name.value == "main"
    assert sessions.authorized == [_VALID_SID]  # the read handler ran (authorized) under reader
    assert ("decompile_function", _VALID_SID) in port.calls


def test_read_only_principal_can_create_session() -> None:
    """``session_create`` is a read-capability tool — a read-only principal may open sessions."""
    sessions = _RecordingSessionManager()
    handlers = reg.build_handlers(_readonly_ctx(sessions, FakePort()))
    info = handlers["session_create"](label="job")
    assert info.session_id == _VALID_SID
    assert sessions.created_owners == ["reader"]


def test_read_only_principal_can_run_analyze() -> None:
    """``session_analyze`` is a READ tool (ADR-033 D1) — the async binder permits a reader."""
    sessions = _RecordingSessionManager()
    port = FakePort()
    handlers = reg.build_handlers(_readonly_ctx(sessions, port))
    info = _invoke(handlers["session_analyze"], session_id=_VALID_SID)
    assert info.session_id == _VALID_SID
    assert ("analyze", _VALID_SID) in port.calls


def test_read_only_principal_denied_analyze_is_not_the_outcome() -> None:
    """Guard against a misclassification: analyze must NOT raise for a read-only principal."""
    sessions = _RecordingSessionManager()
    handlers = reg.build_handlers(_readonly_ctx(sessions, FakePort()))
    # No exception — analyze is read-capability; a regression making it ``write`` would raise here.
    _invoke(handlers["session_analyze"], session_id=_VALID_SID)


# --- A full-capability principal is permitted every tool (the gate is a no-op for full) ----------
def test_full_principal_passes_gate_for_a_write_tool() -> None:
    """With a full principal the gate is a no-op — a write tool reaches its handler (consent check).

    Uses the write-aware recording manager so the handler's ``require_write_consent`` runs (the
    point is the *capability* gate let it through; the per-session consent gate is a separate
    control, covered in test_mutation_registry).
    """

    class _UndoPort(FakePort):
        def undo(self, sid: str, a: s.SessionUndoIn) -> s.SessionUndoOut:
            self._rec("undo", sid)
            return s.SessionUndoOut(session_id=sid, undone=True)

    sessions = _RecordingSessionManager()
    port = _UndoPort()
    c = reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, sessions),
        port=cast(GhidraPort, port),
        principal=Principal(id="full"),  # default ALL_CAPABILITIES
    )
    handlers = reg.build_handlers(c)
    out = handlers["session_undo"](session_id=_VALID_SID)
    # The capability gate passed → the handler ran (consent check + port delegate); not blocked.
    assert out.undone is True
    assert sessions.consent_checks == [_VALID_SID]
    assert ("undo", _VALID_SID) in port.calls
