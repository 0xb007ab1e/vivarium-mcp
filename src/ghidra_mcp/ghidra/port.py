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
