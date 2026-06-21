"""Ghidra adapter PORT — the interface the core/sessions depend on (ports & adapters).

This is the abstraction (a ``Protocol``) the session manager and tool handlers depend on, so they
remain ignorant of HOW Ghidra is reached (RPC mechanism, container runtime, serialization). The
concrete adapter (:mod:`vivarium.ghidra.rpc_client`) implements it and is injected at the
composition root (dependency inversion — topic-dependency-injection).

The port speaks in terms of the frozen tool schemas (:mod:`vivarium.tools.schemas`): the server
validates arguments, then asks the port for results. The port implementation is responsible for
the process/container boundary (trust boundary 2), per-call timeouts, and worker-kill semantics.

WS0 freezes the interface; WS2 implements the adapter.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Protocol

from vivarium.jobs import streaming as st
from vivarium.tools import schemas as s

#: Progress relay callback (ADR-030 Phase 2). The adapter invokes it for each (already coalesced +
#: bounded) worker ``$/progress`` frame with the SAFE ``(percent, phase)`` only — percent is
#: ``0..100`` or ``None`` (no estimate yet), phase is the closed vocabulary. It carries NO
#: binary-derived text (structural redaction — master §5). The server wires it to
#: ``Context.report_progress`` so a long ``analyze`` streams progress to the MCP client; ``None``
#: (the default, and the only value on stdio / when no ``progressToken`` was sent) means no client
#: relay — byte-for-byte the pre-Phase-2 path.
type OnProgress = Callable[[int | None, str], None]


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

    def analyze(
        self, session_id: str, args: s.SessionAnalyzeIn, *, on_progress: OnProgress | None = None
    ) -> s.SessionInfo:
        """Run Ghidra auto-analysis, bounded by the analysis timeout (kills worker on expiry).

        ``args.profile`` (ADR-029 B; additive) selects the analyzer-depth preset. The default
        (``"default"``) reproduces today's analysis byte-for-byte (the adapter omits the ``profile``
        RPC param entirely, so the worker takes the unchanged code path); ``"light"``/``"deep"``
        adjust depth. The profile only reduces/adjusts depth — no new capability (ADR-001 intact).

        ``on_progress`` (ADR-030 Phase 2; additive) is the client-relay callback. When non-``None``
        the adapter forces worker progress emission on and invokes the callback for each bounded,
        coalesced ``$/progress`` frame (the server forwards it to ``Context.report_progress``). When
        ``None`` (the default) the read path is byte-for-byte the pre-Phase-2 behaviour — the worker
        emits frames only if the caller separately set ``args.progress`` (Phase-1 log-only).
        """
        ...

    def kill_worker(self, session_id: str) -> None:
        """Forcibly terminate the session's worker (eviction/timeout/poison)."""
        ...

    # --- read-only tool operations (one per Tier-1 tool that touches Ghidra) ---
    def decompile_function(self, sid: str, a: s.DecompileFunctionIn) -> s.DecompiledFunction:
        """Decompile one function."""
        ...

    # --- streaming-decompile capability (ADR-040; worker → server INCREMENTAL delivery) ---
    def decompile_stream(self, sid: str, a: st.DecompileStreamIn) -> Iterator[s.DecompiledFunction]:
        """Stream decompiled functions one at a time as they are produced (ADR-040).

        The worker-streaming source that feeds a :class:`~vivarium.jobs.streaming.StreamingJob`: it
        yields each :class:`~vivarium.tools.schemas.DecompiledFunction` (binary-derived fields
        already :class:`~vivarium.core.envelope.Untrusted`-wrapped) AS it is decompiled, enabling
        the extraction/inference overlap (design §4 axis 2 — genuine incremental delivery, not
        chunking a complete result). Bounded by ``a.limit`` functions. A failure mid-iteration
        raises a safe :class:`~vivarium.core.errors.GhidraMcpError`, which the job machinery turns
        into a terminal error (honest end — never an ambiguous early stop). The server NEVER buffers
        the whole stream: it pulls one unit at a time under the job's bounded buffer + backpressure.

        For THIS increment the concrete worker emit is out of scope; the deterministic fake yields
        synthetic per-function chunks so the job machinery is testable hermetically.
        """
        ...

    # --- streaming job management (ADR-040; server-side job machinery over decompile_stream) ---
    # These authorize through the session-ownership chokepoint (BOLA), bind the job to its session,
    # and bound the buffer with backpressure (jobs.streaming). They are SERVER-SIDE orchestration on
    # top of decompile_stream — not a worker RPC each (the worker only streams units).
    def attach_stream_jobs(self, manager: st.StreamingJobManager) -> None:
        """Inject the streaming-job manager at the composition root (ADR-040; build_app wiring).

        The job manager carries the session-ownership authorizer (BOLA) + buffer limits + injected
        clock; binding it after construction resolves the composition cycle (the manager needs the
        session manager, which needs the port). Until injected, the four stream methods fail closed
        ``worker-unavailable``.

        Args:
            manager: The constructed :class:`vivarium.jobs.streaming.StreamingJobManager`.
        """
        ...

    def start_decompile_stream(self, sid: str, a: st.DecompileStreamIn, *, caller: str) -> str:
        """Start a bounded bulk-decompile streaming job; return its opaque handle (ADR-040)."""
        ...

    def fetch_job_results(
        self, sid: str, a: st.FetchJobResultsIn, *, caller: str
    ) -> st.StreamFetchResult:
        """Pull the next bounded, ordered batch of chunks from a job (cursor resume — ADR-040)."""
        ...

    def job_status(self, sid: str, a: st.JobHandleIn, *, caller: str) -> st.StreamJobStatus:
        """Return a job's server-authored status (counts/state/ETA; no binary content — ADR-040)."""
        ...

    def cancel_job(self, sid: str, a: st.JobHandleIn, *, caller: str) -> st.StreamJobStatus:
        """Cancel a job (free the worker early), returning its terminal status (ADR-040)."""
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
        (:mod:`vivarium.core.callgraph`) — no JVM on this path (ADR-001/ADR-007).
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

    # --- multi-type composite batch (v1.2 — ADR-021; GATED by allow_structural) ---
    # The server checks structural write consent + validates the batch (validate_types_batch:
    # per-type validate_composite, intra-batch dup-name, and the BY-VALUE CYCLE DETECTOR) BEFORE
    # calling this; the worker pre-registers ALL empty composites, resolves each field's TypeRef
    # (in-batch refs against the pre-registered handles), adds members (batch-total size-checked),
    # REJECTs a name collision, and finalizes — ALL inside ONE transaction so any failure rolls back
    # the WHOLE batch (no partial type — ADR-021). Every result field is server/worker-controlled.
    def define_types(self, sid: str, a: s.DefineTypesIn) -> s.DefineTypesResult:
        """Create a batch of interdependent composites in one transaction (ADR-021)."""
        ...

    # --- composite deletion (v1.4 — ADR-031; GATED by allow_structural) ---
    # The server validates the name AND confirms it is session-authored (ADR-031 D2 — only a
    # composite THIS session created may be deleted; the change-log authority is server-side) BEFORE
    # calling this. The worker looks the name up, rejects a non-composite/built-in (defense in
    # depth), counts dependents read-only, and removes it inside ONE transaction (rollback on
    # failure). Every result field is a server/worker-controlled scalar (no binary-derived echo).
    def delete_type(self, sid: str, a: s.DeleteTypeIn) -> s.DeleteTypeResult:
        """Delete a session-authored composite by name, reporting reverted dependents (ADR-031)."""
        ...

    # --- cross-session annotation persistence (v1.2 — ADR-018; TB8) ---
    # ONE new worker method (`export_annotations`): the worker enumerates the program's
    # USER_DEFINED annotations only, dependency-ordered, bounded. IMPORT adds NO new port/worker
    # method — it is server-side orchestration (the registry) that replays each entry via the
    # EXISTING write methods above (rename_function/.../define_union). The adapter wraps every
    # binary-derived string in the exported document as Untrusted (ADR-005).
    def export_annotations(
        self,
        sid: str,
        a: s.SessionExportAnnotationsIn,
        *,
        targets: s.ExportTargets,
    ) -> s.SessionExportAnnotationsOut:
        """Read out the session's USER_DEFINED annotations as a versioned, hash-bound document.

        Read-only (no write consent). For **symbols + function signatures** the worker enumerates
        ONLY ``USER_DEFINED`` items (never Ghidra auto-analysis output). For **comments + composite
        types** — which carry no reliable Ghidra provenance signal — the worker reads ONLY the
        server-supplied ``targets`` (the session change-log of what this session authored — ADR-027
        D4), never blind-enumerating (the F7 over-inclusion fix). Dependency-ordered (composites
        first); over the entry cap → ``limit-exceeded`` (no silent truncation). The adapter
        assembles the document, wrapping binary-derived strings as ``Untrusted`` (ADR-005). The
        server overlays the authoritative ``binary.sha256`` binding.

        Args:
            sid: The session id.
            a: The export tool arguments (session-scoped; no client-supplied targets).
            targets: Server-supplied change-log selection — the comment + composite targets to read
                (identity keys only, never values). Empty lists mean nothing of those kinds is
                exported.

        Returns:
            The exported annotation document (untrusted-wrapped).
        """
        ...
