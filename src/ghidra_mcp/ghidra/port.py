"""Ghidra adapter PORT — the interface the core/sessions depend on (ports & adapters).

This is the abstraction (a ``Protocol``) the session manager and tool handlers depend on, so they
remain ignorant of HOW Ghidra is reached (RPC mechanism, container runtime, serialization). The
concrete adapter (:mod:`ghidra_mcp.ghidra.rpc_client`) implements it and is injected at the
composition root (dependency inversion — topic-dependency-injection).

The port speaks in terms of the frozen tool schemas (:mod:`ghidra_mcp.tools.schemas`): the server
validates arguments, then asks the port for results. The port implementation is responsible for
the process/container boundary (trust boundary 2), per-call timeouts, and worker-kill semantics.

WS0 freezes the interface; WS2 implements the adapter.
"""

from __future__ import annotations

from typing import Protocol

from ghidra_mcp.tools import schemas as s


class GhidraPort(Protocol):
    """Abstract operations the server invokes against an out-of-process Ghidra worker.

    All methods are session-scoped and bounded by the per-call timeout; on timeout the adapter
    kills the worker and raises a ``TIMEOUT``/``WORKER_UNAVAILABLE`` error. Methods return frozen
    output schemas with binary-derived fields already wrapped in the untrusted-data envelope.
    """

    # --- worker/session lifecycle ---
    def start_worker(self, session_id: str) -> None:
        """Spawn a hardened worker container bound to ``session_id`` (no binary yet)."""
        ...

    def import_binary(self, session_id: str, args: s.SessionImportIn) -> s.SessionInfo:
        """Import the (size-checked) binary into the session's worker."""
        ...

    def analyze(self, session_id: str, args: s.SessionAnalyzeIn) -> s.SessionInfo:
        """Run Ghidra auto-analysis, bounded by the analysis timeout (kills worker on expiry)."""
        ...

    def kill_worker(self, session_id: str) -> None:
        """Forcibly terminate the session's worker (eviction/timeout/poison)."""
        ...

    # --- read-only tool operations (one per Tier-1 tool that touches Ghidra) ---
    def decompile_function(self, sid: str, a: s.DecompileFunctionIn) -> s.DecompiledFunction:
        """Decompile one function."""
        ...

    def disassemble(self, sid: str, a: s.DisassembleIn) -> s.DisassembleOut:
        """Disassemble a bounded range or function."""
        ...

    def list_functions(self, sid: str, a: s.ListFunctionsIn) -> s.FunctionListOut:
        """List functions (paginated/bounded)."""
        ...

    def get_function(self, sid: str, a: s.GetFunctionIn) -> s.FunctionDetail:
        """Get one function's detail."""
        ...

    def xrefs_to(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References TO a target."""
        ...

    def xrefs_from(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References FROM a target."""
        ...

    def list_strings(self, sid: str, a: s.ListStringsIn) -> s.StringListOut:
        """List defined strings (paginated/bounded)."""
        ...

    def list_symbols(self, sid: str, a: s.ListSymbolsIn) -> s.SymbolListOut:
        """List symbols (paginated/bounded)."""
        ...

    def get_symbol(self, sid: str, a: s.GetSymbolIn) -> s.Symbol:
        """Resolve one symbol."""
        ...

    def list_data(self, sid: str, a: s.ListDataIn) -> s.DataListOut:
        """List defined data (paginated/bounded)."""
        ...

    def get_data_type(self, sid: str, a: s.GetDataTypeIn) -> s.DataType:
        """Resolve one data type."""
        ...

    def get_comments(self, sid: str, a: s.GetCommentsIn) -> s.CommentListOut:
        """Read comments (paginated/bounded)."""
        ...

    def memory_map(self, sid: str, a: s.MemoryMapIn) -> s.MemoryMapOut:
        """List memory blocks/segments."""
        ...

    def read_bytes(self, sid: str, a: s.ReadBytesIn) -> s.ReadBytesOut:
        """Bounded raw byte read."""
        ...

    def search_bytes(self, sid: str, a: s.SearchBytesIn) -> s.SearchBytesOut:
        """Bounded byte-pattern search."""
        ...

    def search_strings(self, sid: str, a: s.SearchStringsIn) -> s.SearchStringsOut:
        """Bounded defined-string search."""
        ...

    def program_metadata(self, sid: str, a: s.ProgramMetadataIn) -> s.ProgramMetadata:
        """High-level program metadata."""
        ...

    # --- call-graph / semantic-naming operations (v1.1 — ADR-007) ---
    def call_graph(self, sid: str, a: s.CallGraphIn) -> s.CallGraphOut:
        """Extract the bounded function call adjacency (resolved edges + unresolved callers)."""
        ...

    def callees(self, sid: str, a: s.CalleesIn) -> s.CallNeighborsOut:
        """List the functions a given function directly calls (one hop, paginated/bounded)."""
        ...

    def callers(self, sid: str, a: s.CallersIn) -> s.CallNeighborsOut:
        """List the functions that directly call a given function (one hop, paginated/bounded)."""
        ...

    def analysis_order(self, sid: str, a: s.AnalysisOrderIn) -> s.AnalysisOrderOut:
        """Leaf-first reverse-topological order over the call graph (server computes the ordering).

        The adjacency is extracted by the worker; the ordering is the PURE server-side core
        (:mod:`ghidra_mcp.core.callgraph`) — no JVM on this path (ADR-001/ADR-007).
        """
        ...

    def function_context(self, sid: str, a: s.FunctionContextIn) -> s.FunctionContext:
        """Assemble the per-function naming/synthesis context bundle (server-side aggregation)."""
        ...

    # --- Tier-2 reporting / metrics (v1.1 — ADR-008; READ-ONLY) ---
    def cyclomatic_complexity(
        self, sid: str, a: s.CyclomaticComplexityIn
    ) -> s.CyclomaticComplexity:
        """McCabe complexity of one function (worker CFG counts → pure core)."""
        ...

    def list_imports(self, sid: str, a: s.ListImportsIn) -> s.ImportListOut:
        """List imported symbols/functions (paginated/bounded)."""
        ...

    def list_exports(self, sid: str, a: s.ListExportsIn) -> s.ExportListOut:
        """List exported symbols/entry points (paginated/bounded)."""
        ...

    def coverage(self, sid: str, a: s.CoverageIn) -> s.CoverageOut:
        """Defined-code/data byte coverage of the program (worker counts → pure ratios)."""
        ...

    def ioc_scan(self, sid: str, a: s.IocScanIn) -> s.IocScanOut:
        """Heuristic IOC scan over defined strings (pure core over the list_strings RPC)."""
        ...

    def crypto_constant_scan(self, sid: str, a: s.CryptoConstantScanIn) -> s.CryptoConstantScanOut:
        """Heuristic crypto-constant search (pure signature table over the search_bytes RPC)."""
        ...

    def call_graph_metrics(self, sid: str, a: s.CallGraphMetricsIn) -> s.CallGraphMetricsOut:
        """Structural call-graph metrics (pure core over the call_graph RPC)."""
        ...

    def program_summary(self, sid: str, a: s.ProgramSummaryIn) -> s.ProgramSummary:
        """One-shot aggregate triage report (server-side aggregation of Tier-1 + Tier-2)."""
        ...

    # --- mutation / write operations (v1.1 — ADR-012; gated by session write-consent) ---
    # The server checks write consent + validates the (attacker-influenced) inputs BEFORE calling
    # these; the worker performs each write inside one Ghidra transaction (rollback on failure). The
    # adapter wraps the binary-derived prior ``old_name`` as ``Untrusted`` in the result.
    def rename_function(self, sid: str, a: s.RenameFunctionIn) -> s.RenameResult:
        """Rename one function (write; one transaction, rollback on failure — ADR-012 §4)."""
        ...

    def rename_symbol(self, sid: str, a: s.RenameSymbolIn) -> s.RenameSymbolResult:
        """Rename one data/label/global symbol (write; transaction-wrapped)."""
        ...

    def set_comment(self, sid: str, a: s.SetCommentIn) -> s.SetCommentResult:
        """Set or clear one comment at an address (write; transaction-wrapped)."""
        ...

    def undo(self, sid: str, a: s.SessionUndoIn) -> s.SessionUndoOut:
        """Undo the last committed mutation transaction in the session (ADR-012 §4)."""
        ...

    # --- structural writes (v1.1 — ADR-013 Phase A; HighFunction path, name-only) ---
    def rename_local_variable(
        self, sid: str, a: s.RenameLocalVariableIn
    ) -> s.StructuralRenameResult:
        """Rename one function-local variable (name-only; transaction-wrapped — ADR-013)."""
        ...

    def rename_parameter(self, sid: str, a: s.RenameParameterIn) -> s.StructuralRenameResult:
        """Rename one function parameter (name-only; transaction-wrapped — ADR-013)."""
        ...

    # --- structural type-aware writes (v1.1 — ADR-014 Phase B; structured TypeRef input) ---
    # The server checks structural write consent + validates the structured signature/type
    # (validate_signature / validate_type_ref / validate_calling_convention) BEFORE calling these;
    # the worker resolves every TypeRef against the DataTypeManager (read-only, before the txn —
    # NO C parser) then performs one transacted write. The adapter wraps binary-derived fields
    # (function/old_signature/new_signature/type_name) as Untrusted.
    def set_function_signature(
        self, sid: str, a: s.SetFunctionSignatureIn
    ) -> s.SetFunctionSignatureResult:
        """Set a function's structured signature (resolved types; transaction-wrapped — ADR-014)."""
        ...

    def apply_data_type(self, sid: str, a: s.ApplyDataTypeIn) -> s.ApplyDataTypeResult:
        """Apply a resolvable type at an address (transaction-wrapped — ADR-014)."""
        ...

    # --- composite-type creation (v1.1 — ADR-015 Phase C; structured FieldSpec input) ---
    # The server checks structural write consent + validates the composite (validate_composite:
    # bounded FieldSpec list of resolved TypeRefs, no duplicate/self-embed) BEFORE calling these;
    # the worker pre-registers the empty composite in the DataTypeManager, resolves each field's
    # TypeRef (read-only), adds members (size-checked), REJECTs a name collision, and finalizes —
    # ALL inside one transaction so any failure rolls back the pre-registered type (no partial type
    # — ADR-015 §3). Every result field is server/worker-controlled (no binary-derived echo).
    def define_struct(self, sid: str, a: s.DefineStructIn) -> s.DefineStructResult:
        """Create a new struct from a resolved field list (one transaction — ADR-015)."""
        ...

    def define_union(self, sid: str, a: s.DefineUnionIn) -> s.DefineUnionResult:
        """Create a new union from a resolved field list (one transaction — ADR-015)."""
        ...
