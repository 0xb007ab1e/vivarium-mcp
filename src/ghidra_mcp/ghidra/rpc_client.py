"""RPC adapter: spawns hardened workers and speaks the internal protocol (WS2).

Concrete :class:`ghidra_mcp.ghidra.port.GhidraPort` implementation. It:

- Spawns/kills the worker as a hardened container (non-root, ro-rootfs, all caps dropped, seccomp,
  **no network**, gVisor runtime, CPU/mem/pids limits — ADR-004; the concrete runtime flags are
  injected by WS3/deploy via the :data:`WorkerLauncher` callable, so this module stays runtime-
  agnostic and unit-testable).
- Connects to the worker over the internal RPC transport (JSON-RPC 2.0 over a per-session Unix
  domain socket — ``docs/contracts/rpc-protocol.md``) with 4-byte big-endian length-prefixed
  framing.
- Enforces per-call timeouts and **SIGKILLs the worker** on expiry (no graceful wait for a hung
  JVM — rpc-protocol.md §6).
- Treats the worker as a fault domain: an oversized frame, protocol violation, timeout, or crash
  all resolve to **kill + ``worker-unavailable``/``timeout``** and signal eviction. It never
  destabilizes the server.

This module runs IN THE SERVER process and MUST NOT import the JVM bridge (ADR-001). It only ever
sends/receives bytes over the socket; the framing/JSON-RPC codec lives in the JVM-free
:mod:`ghidra_mcp.ghidra.rpc_framing`.

**Untrusted-data wrap chokepoint (PM #9, ADR-005).** The worker returns *plain* JSON (rpc-protocol
§4: "the worker returns plain structured data"). This adapter is the single server-side place that
turns those plain values into typed ``*Out`` models, calling :func:`ghidra_mcp.core.envelope.wrap`
on every binary-derived field as it constructs each model — ``DataOrigin.BINARY`` for content
*extracted* from the binary (strings, bytes, names, comments) and ``DataOrigin.GHIDRA`` for content
*synthesized* by the decompiler/analysis over hostile input (pseudo-C, signatures, recovered
mnemonics/types). Nothing binary-derived leaves this adapter un-wrapped.
"""

from __future__ import annotations

import contextlib
import functools
import socket
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError

from ghidra_mcp.core.envelope import DataOrigin, Untrusted, wrap
from ghidra_mcp.core.errors import ErrorType
from ghidra_mcp.ghidra import _errors, rpc_framing
from ghidra_mcp.ghidra.rpc_framing import (
    FramingError,
    RpcCallError,
    RpcProtocolError,
)
from ghidra_mcp.logging import get_logger
from ghidra_mcp.security.limits import Limits, check_binary_size
from ghidra_mcp.tools import schemas as s


class WorkerProcess(Protocol):
    """A spawned worker process/container handle the adapter can SIGKILL (injected by WS3).

    Abstracted so the adapter is independent of the concrete runtime (podman/runsc). The launcher
    returns one of these per session.
    """

    def kill(self) -> None:
        """Forcibly terminate the worker (SIGKILL the container/process). Idempotent."""
        ...

    def is_alive(self) -> bool:
        """Whether the worker is still running."""
        ...


#: A launcher takes a session id and the socket path and returns a running worker process. WS3
#: supplies the concrete container command (arg list — never ``shell=True``); tests supply a fake.
WorkerLauncher = Callable[[str, str], WorkerProcess]

#: Resolves a (server-confined) ``source_ref`` to the byte size of the candidate input, so the
#: server can enforce the binary-size cap BEFORE a single byte reaches the worker (CWE-22 path
#: confinement + DoS cap, both server-side and pre-Ghidra). WS3/deploy injects the concrete,
#: allow-list-confined resolver; the built-in default stats a path under the OS (used only when the
#: composition root wires no resolver). It returns a non-negative ``int`` size.
SourceResolver = Callable[[str], int]


# --- Tier-2 internal scan budgets (ADR-008; bounded BEFORE the worker — std-cwe CWE-400) -----
#: How many defined strings ``ioc_scan`` pulls in one bounded page before scanning (the worker also
#: clamps; ``truncated`` is honest when more exist). Sized to a generous-but-bounded triage window.
_IOC_STRING_BUDGET = 10_000
#: Max ``search_bytes`` matches requested per crypto signature (each search is already bounded; this
#: caps the per-signature contribution to the aggregate and feeds ``truncated``).
_CRYPTO_MATCH_BUDGET = 1_000
#: Poll interval between worker-socket connect attempts while the worker is still binding/warming
#: up (bounded overall by ``connect_timeout_s``). Small enough for a snappy first call, large
#: enough not to busy-spin.
_CONNECT_RETRY_INTERVAL_S = 0.1

#: Length of the per-session socket *directory* token (a prefix of the session id). Keeps the
#: AF_UNIX host path well under the ~107-byte limit while staying collision-free for the small
#: live-session set (the full id is still the socket filename + the server-side identity). See
#: :meth:`RpcGhidraAdapter._socket_path`.
_SOCKET_DIR_TOKEN_LEN = 16

#: Module logger. RPC-layer failures are logged SERVER-SIDE with the underlying exception
#: (socket/framing errors — no binary content or secrets) before being mapped to the
#: boundary-safe public envelope, so operability does not depend on the client-facing message
#: (topic-logging-observability; master §5).
_log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _TopComplex:
    """Bounded top-by-complexity result for ``program_summary`` (helper return type).

    Attributes:
        functions: The examined functions, sorted by descending cyclomatic complexity.
        truncated: Whether more functions existed than were examined (honesty for the summary).
    """

    functions: list[s.CyclomaticComplexity]
    truncated: bool


def _default_source_size(source_ref: str) -> int:
    """Default ``SourceResolver``: byte size of a filesystem ``source_ref`` (server-side, no JVM).

    This is a conservative built-in used only when no confined resolver is injected; WS3/deploy
    supplies the real allow-list/path-confinement resolver. It performs NO read of the bytes into
    memory — it only stats the size so the cap can be enforced before the worker is fed.

    Args:
        source_ref: The server-resolved reference to the input.

    Returns:
        The size of the referenced input in bytes.
    """
    return Path(source_ref).stat().st_size


class _Session:
    """Per-session worker + socket state owned by the adapter.

    Attributes:
        worker: The spawned worker process/container handle.
        sock: The connected UDS stream socket, or ``None`` before connect / after close.
        socket_path: Filesystem path of the per-session UDS.
    """

    __slots__ = ("sock", "socket_path", "worker")

    def __init__(self, worker: WorkerProcess, socket_path: str) -> None:
        """Initialize per-session state.

        Args:
            worker: The spawned worker handle.
            socket_path: Path of the per-session UDS.
        """
        self.worker = worker
        self.sock: socket.socket | None = None
        self.socket_path = socket_path


class RpcGhidraAdapter:
    """JSON-RPC-over-UDS adapter to per-session Ghidra workers (concrete ``GhidraPort``).

    Construction takes its collaborators by injection (dependency inversion — topic-dependency-
    injection): a :data:`WorkerLauncher` (WS3 container spawn), the socket directory, the per-call
    timeout, the analysis timeout, and the hard frame cap. No I/O happens at construction.
    """

    def __init__(
        self,
        *,
        launcher: WorkerLauncher,
        socket_dir: str,
        tool_timeout_s: float,
        analysis_timeout_s: float,
        max_response_bytes: int,
        limits: Limits | None = None,
        source_resolver: SourceResolver | None = None,
        connect_timeout_s: float = 30.0,
    ) -> None:
        """Initialize the adapter with injected runtime collaborators.

        Args:
            launcher: Callable that spawns a hardened worker bound to a session + socket path.
            socket_dir: Directory under which per-session UDS files live (``<dir>/<sid>.sock``).
            tool_timeout_s: Default per-tool-call wall-clock deadline.
            analysis_timeout_s: Per-analysis wall-clock deadline (kills worker on expiry).
            max_response_bytes: Hard frame cap; a declared length above this kills the worker.
            limits: Resolved resource limits; the binary-size cap is enforced from these BEFORE the
                worker is fed (defaults to built-in safe :class:`Limits`).
            source_resolver: Maps a (confined) ``source_ref`` to its byte size for the pre-Ghidra
                size check (defaults to :func:`_default_source_size`).
            connect_timeout_s: How long to wait for the worker to bind/accept on its socket.
        """
        self._launcher = launcher
        self._socket_dir = socket_dir
        self._tool_timeout_s = tool_timeout_s
        self._analysis_timeout_s = analysis_timeout_s
        self._max_response_bytes = max_response_bytes
        self._limits = limits if limits is not None else Limits()
        self._source_resolver = source_resolver or _default_source_size
        self._connect_timeout_s = connect_timeout_s
        self._sessions: dict[str, _Session] = {}

    # --- worker/session lifecycle -----------------------------------------------------------
    def start_worker(self, session_id: str) -> None:
        """Spawn a hardened worker bound to ``session_id`` (no binary yet).

        Args:
            session_id: The opaque session id (also names the per-session socket).
        """
        if session_id in self._sessions:
            return  # idempotent: a worker already exists for this session
        sock_path = self._socket_path(session_id)
        worker = self._launcher(session_id, sock_path)
        self._sessions[session_id] = _Session(worker, sock_path)

    def kill_worker(self, session_id: str) -> None:
        """Forcibly terminate the session's worker and drop its socket. Idempotent.

        Args:
            session_id: The session whose worker to kill.
        """
        sess = self._sessions.pop(session_id, None)
        if sess is None:
            return
        self._close_socket(sess)
        # Best-effort kill: a launcher/runtime hiccup must not stop eviction (fail closed → drop).
        with contextlib.suppress(Exception):
            sess.worker.kill()

    def import_binary(self, session_id: str, args: s.SessionImportIn) -> s.SessionInfo:
        """Import the binary into the session's worker, enforcing the size cap FIRST.

        The binary-size cap is checked server-side and pre-Ghidra (DoS first line — PLAN §3 F7,
        ADR-001: no byte reaches the JVM until it has passed the cap). The ``source_ref`` is
        resolved by the injected confined resolver; an over-cap input raises ``LIMIT_EXCEEDED``
        before the worker is contacted, and an unresolvable ref fails closed as ``VALIDATION``.

        Args:
            session_id: The session.
            args: Import arguments (digest verification happens in the worker).

        Returns:
            Updated :class:`SessionInfo` (server-computed fields only — no binary-derived content).
        """
        try:
            size_bytes = self._source_resolver(args.source_ref)
        except OSError as exc:
            raise _errors.make_error(
                ErrorType.VALIDATION, "input reference could not be resolved"
            ) from exc
        # Fail closed BEFORE the worker: an over-cap binary is rejected pre-Ghidra (TB3 DoS).
        check_binary_size(size_bytes, self._limits)
        result = self._call(
            session_id,
            "import_binary",
            {"source_ref": args.source_ref, "expected_sha256": args.expected_sha256},
            timeout_s=self._tool_timeout_s,
        )
        return _validate(s.SessionInfo, result)

    def analyze(self, session_id: str, args: s.SessionAnalyzeIn) -> s.SessionInfo:
        """Run Ghidra auto-analysis, bounded by the analysis timeout (kills worker on expiry).

        Args:
            session_id: The session.
            args: Analysis arguments (optional timeout override, already clamped by the server).

        Returns:
            Updated :class:`SessionInfo`.
        """
        # Clamp the client override DOWN to the configured analysis ceiling (defense-in-depth DoS:
        # the schema bounds timeout_seconds to <=3600, but the deployment's configured max may be
        # lower — never let a per-call arg exceed it). No override → use the configured ceiling.
        deadline = (
            min(float(args.timeout_seconds), self._analysis_timeout_s)
            if args.timeout_seconds
            else self._analysis_timeout_s
        )
        result = self._call(
            session_id,
            "analyze",
            {"timeout_seconds": args.timeout_seconds},
            timeout_s=deadline,
        )
        return _validate(s.SessionInfo, result)

    # --- read-only tool operations ----------------------------------------------------------
    # Each method takes the worker's PLAIN result dict and builds the typed ``*Out`` via a module-
    # level builder that wraps every binary-derived field at the right provenance (PM #9, ADR-005).
    def decompile_function(self, sid: str, a: s.DecompileFunctionIn) -> s.DecompiledFunction:
        """Decompile one function (decompiler output → GHIDRA-origin untrusted)."""
        return _build_decompiled(
            self._tool_call(sid, "decompile_function", {"function": a.function})
        )

    def disassemble(self, sid: str, a: s.DisassembleIn) -> s.DisassembleOut:
        """Disassemble a bounded range or function."""
        return _build_disassemble(
            self._tool_call(
                sid,
                "disassemble",
                {"start": a.start, "function": a.function, "max_instructions": a.max_instructions},
            )
        )

    def list_functions(self, sid: str, a: s.ListFunctionsIn) -> s.FunctionListOut:
        """List functions (paginated/bounded)."""
        return _build_function_list(
            self._tool_call(
                sid,
                "list_functions",
                {"offset": a.offset, "limit": a.limit, "name_contains": a.name_contains},
            )
        )

    def get_function(self, sid: str, a: s.GetFunctionIn) -> s.FunctionDetail:
        """Get one function's detail."""
        return _build_function_detail(
            self._tool_call(sid, "get_function", {"function": a.function})
        )

    def xrefs_to(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References TO a target (addresses/ref-types are server-safe — no wrap needed)."""
        return _validate(s.XrefsOut, self._tool_call(sid, "xrefs_to", _xrefs_params(a)))

    def xrefs_from(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References FROM a target (addresses/ref-types are server-safe — no wrap needed)."""
        return _validate(s.XrefsOut, self._tool_call(sid, "xrefs_from", _xrefs_params(a)))

    def list_strings(self, sid: str, a: s.ListStringsIn) -> s.StringListOut:
        """List defined strings (paginated/bounded)."""
        return _build_string_list(
            self._tool_call(
                sid,
                "list_strings",
                {"offset": a.offset, "limit": a.limit, "min_length": a.min_length},
            )
        )

    def list_symbols(self, sid: str, a: s.ListSymbolsIn) -> s.SymbolListOut:
        """List symbols (paginated/bounded)."""
        return _build_symbol_list(
            self._tool_call(
                sid,
                "list_symbols",
                {"offset": a.offset, "limit": a.limit, "name_contains": a.name_contains},
            )
        )

    def get_symbol(self, sid: str, a: s.GetSymbolIn) -> s.Symbol:
        """Resolve one symbol."""
        return _build_symbol(self._tool_call(sid, "get_symbol", {"identifier": a.identifier}))

    def list_data(self, sid: str, a: s.ListDataIn) -> s.DataListOut:
        """List defined data (paginated/bounded)."""
        return _build_data_list(
            self._tool_call(sid, "list_data", {"offset": a.offset, "limit": a.limit})
        )

    def get_data_type(self, sid: str, a: s.GetDataTypeIn) -> s.DataType:
        """Resolve one data type."""
        return _build_data_type(self._tool_call(sid, "get_data_type", {"name": a.name}))

    def get_comments(self, sid: str, a: s.GetCommentsIn) -> s.CommentListOut:
        """Read comments (paginated/bounded)."""
        return _build_comment_list(
            self._tool_call(
                sid,
                "get_comments",
                {"offset": a.offset, "limit": a.limit, "address": a.address},
            )
        )

    def memory_map(self, sid: str, a: s.MemoryMapIn) -> s.MemoryMapOut:
        """List memory blocks/segments."""
        return _build_memory_map(self._tool_call(sid, "memory_map", {}))

    def read_bytes(self, sid: str, a: s.ReadBytesIn) -> s.ReadBytesOut:
        """Bounded raw byte read."""
        return _build_read_bytes(
            self._tool_call(sid, "read_bytes", {"address": a.address, "length": a.length})
        )

    def search_bytes(self, sid: str, a: s.SearchBytesIn) -> s.SearchBytesOut:
        """Bounded byte-pattern search."""
        return _build_search_bytes(
            self._tool_call(
                sid,
                "search_bytes",
                {"pattern_hex": a.pattern_hex, "offset": a.offset, "limit": a.limit},
            )
        )

    def search_strings(self, sid: str, a: s.SearchStringsIn) -> s.SearchStringsOut:
        """Bounded defined-string search (same shape as ``list_strings``)."""
        base = _build_string_list(
            self._tool_call(
                sid,
                "search_strings",
                {"query": a.query, "offset": a.offset, "limit": a.limit},
            )
        )
        return s.SearchStringsOut(strings=base.strings, total=base.total, truncated=base.truncated)

    def program_metadata(self, sid: str, a: s.ProgramMetadataIn) -> s.ProgramMetadata:
        """High-level program metadata."""
        return _build_program_metadata(self._tool_call(sid, "program_metadata", {}))

    # --- call-graph / semantic-naming operations (v1.1 — ADR-007) ---------------------------
    # The worker exposes exactly two extraction primitives for this feature (ADR-001):
    # ``call_graph`` (resolved adjacency) and ``referenced_strings``. Everything else is computed
    # HERE, JVM-free: ``analysis_order`` runs the PURE ordering core (core.callgraph) over the
    # adjacency; ``callees``/``callers`` are one-hop projections of ``call_graph``;
    # ``function_context`` aggregates existing read-only RPCs. All output-only (no DB mutation).
    def call_graph(self, sid: str, a: s.CallGraphIn) -> s.CallGraphOut:
        """Extract the bounded call adjacency (resolved edges + unresolved callers)."""
        return _build_call_graph(
            self._tool_call(
                sid,
                "call_graph",
                {
                    "root": a.root,
                    "max_depth": a.max_depth,
                    "max_nodes": a.max_nodes,
                    "max_edges": a.max_edges,
                },
            )
        )

    def callees(self, sid: str, a: s.CalleesIn) -> s.CallNeighborsOut:
        """List the functions ``a.function`` directly calls (one hop over a depth-1 call graph)."""
        entry = self._resolve_entry(sid, a.function)
        graph = self.call_graph(sid, s.CallGraphIn(session_id=sid, root=a.function, max_depth=1))
        return _one_hop(graph, entry, direction="out", offset=a.offset, limit=a.limit)

    def callers(self, sid: str, a: s.CallersIn) -> s.CallNeighborsOut:
        """List the functions that directly call ``a.function`` (reverse one hop).

        There is no reverse-rooted extraction primitive (ADR-001 keeps graph walking in the worker),
        so this projects the bounded **whole-program** call graph and reverses it; ``truncated``
        honestly reflects a node/edge cap clipping the view (ADR-005).
        """
        entry = self._resolve_entry(sid, a.function)
        graph = self.call_graph(sid, s.CallGraphIn(session_id=sid))
        return _one_hop(graph, entry, direction="in", offset=a.offset, limit=a.limit)

    def analysis_order(self, sid: str, a: s.AnalysisOrderIn) -> s.AnalysisOrderOut:
        """Leaf-first reverse-topological order over the call graph (pure core — ADR-001/ADR-007).

        Extracts the adjacency via the worker ``call_graph`` RPC, then computes the ordering with
        the PURE :func:`ghidra_mcp.core.callgraph.compute_analysis_order` and shapes it via
        :func:`_build_analysis_order`. No JVM on this path — only the extraction hop touched Ghidra.
        """
        return _build_analysis_order(self.call_graph(sid, a))

    def function_context(self, sid: str, a: s.FunctionContextIn) -> s.FunctionContext:
        """Assemble the per-function naming/synthesis context bundle (server-side aggregation).

        Aggregates existing read-only facts — signature (``get_function``), the function's own
        call-graph node + direct callees (a depth-1 ``call_graph``), direct callers (reverse hop),
        decompiled pseudo-C (``decompile_function``), and referenced strings
        (``referenced_strings``) — wrapping every binary-derived field at the ADR-005 chokepoint.
        NO naming or C synthesis
        (no server-side LLM — locked decision #1); the client does that.
        """
        detail = self.get_function(sid, s.GetFunctionIn(session_id=sid, function=a.function))
        entry = detail.address
        graph = self.call_graph(sid, s.CallGraphIn(session_id=sid, root=a.function, max_depth=1))
        own = next((n for n in graph.nodes if n.address == entry), None)

        callees_page = _one_hop(graph, entry, direction="out", offset=0, limit=a.max_callees)
        callers_nodes: list[s.CallGraphNode] = []
        callers_trunc = False
        if a.max_callers:
            callers_page = self.callers(
                sid, s.CallersIn(session_id=sid, function=a.function, limit=a.max_callers)
            )
            callers_nodes = callers_page.neighbors
            callers_trunc = callers_page.truncated

        decompilation = None
        if a.include_decompilation:
            decompilation = self.decompile_function(
                sid, s.DecompileFunctionIn(session_id=sid, function=a.function)
            ).c_code

        referenced_strings: list[Untrusted[str]] = []
        strings_trunc = False
        if a.max_strings:
            rs = self._tool_call(
                sid,
                "referenced_strings",
                {"function": a.function, "max_strings": a.max_strings},
            )
            referenced_strings, strings_trunc = _build_referenced_strings(rs)

        # The function's own attributes come from its graph node when present (``is_external`` /
        # ``has_unresolved_calls`` are graph-only facts); fall back to ``get_function`` otherwise.
        name = own.name if own is not None else detail.name
        is_external = own.is_external if own is not None else detail.is_thunk
        has_unresolved = own.has_unresolved_calls if own is not None else False
        return s.FunctionContext(
            address=entry,
            name=name,
            signature=detail.signature,
            is_external=is_external,
            decompilation=decompilation,
            callees=callees_page.neighbors,
            callers=callers_nodes,
            referenced_strings=referenced_strings,
            has_unresolved_calls=has_unresolved,
            truncated=graph.truncated or callees_page.truncated or callers_trunc or strings_trunc,
        )

    def _resolve_entry(self, sid: str, function: str) -> str:
        """Resolve a function (name or hex) to its server-normalized entry address (via worker)."""
        return self.get_function(sid, s.GetFunctionIn(session_id=sid, function=function)).address

    # --- Tier-2 reporting / metrics (v1.1 — ADR-008; READ-ONLY) ------------------------------
    # The worker exposes four new extraction primitives (ADR-001): ``function_cfg``, ``imports``,
    # ``exports``, ``coverage``. The metric DERIVATION is JVM-free here: ``cyclomatic_complexity``
    # and ``call_graph_metrics`` run the PURE ``core.metrics`` over extracted counts/adjacency;
    # ``ioc_scan`` / ``crypto_constant_scan`` run the PURE ``core.iocscan`` over the existing
    # ``list_strings`` / ``search_bytes`` RPCs; ``program_summary`` aggregates the others. Every
    # binary-derived field is wrapped at the ADR-005 chokepoint; addresses/counts/ratios/labels are
    # safe scalars. NO naming or synthesis (no server-side LLM — locked decision #1).
    def cyclomatic_complexity(
        self, sid: str, a: s.CyclomaticComplexityIn
    ) -> s.CyclomaticComplexity:
        """McCabe complexity of one function (worker CFG counts → pure ``E - N + 2``)."""
        return _build_cyclomatic_complexity(
            self._tool_call(sid, "function_cfg", {"function": a.function})
        )

    def list_imports(self, sid: str, a: s.ListImportsIn) -> s.ImportListOut:
        """List imported symbols/functions (paginated/bounded)."""
        return _build_import_list(
            self._tool_call(sid, "imports", {"offset": a.offset, "limit": a.limit})
        )

    def list_exports(self, sid: str, a: s.ListExportsIn) -> s.ExportListOut:
        """List exported symbols/entry points (paginated/bounded)."""
        return _build_export_list(
            self._tool_call(sid, "exports", {"offset": a.offset, "limit": a.limit})
        )

    def coverage(self, sid: str, a: s.CoverageIn) -> s.CoverageOut:
        """Defined-code/data byte coverage (worker byte counts → pure ratios; no wrap needed)."""
        return _build_coverage(self._tool_call(sid, "coverage", {}))

    def ioc_scan(self, sid: str, a: s.IocScanIn) -> s.IocScanOut:
        """Heuristic IOC scan over defined strings (PURE core over the ``list_strings`` RPC).

        Fetches a bounded page of defined strings, runs the pure :func:`core.iocscan.scan_iocs`,
        then paginates the matches by ``offset``/``limit``. Each matched ``value`` is
        attacker-controlled and wrapped BINARY-origin (ADR-005) — a prime injection vector.
        ``truncated`` reflects either the scanned-string cap or a matches-page cap (honesty).
        """
        from ghidra_mcp.core import iocscan

        strings = _build_string_list(
            self._tool_call(
                sid,
                "list_strings",
                {"offset": 0, "limit": _IOC_STRING_BUDGET, "min_length": a.min_length},
            )
        )
        rows = [(ds.address, ds.value.value) for ds in strings.strings]
        categories = tuple(a.categories) if a.categories else None
        hits = iocscan.scan_iocs(rows, categories=categories, min_length=a.min_length)
        total = len(hits)
        page = hits[a.offset : a.offset + a.limit]
        truncated = strings.truncated or (a.offset + a.limit < total)
        return s.IocScanOut(
            matches=[
                s.IocMatch(
                    category=h.category,
                    value=_w(h.value, DataOrigin.BINARY),
                    source_address=h.source_address,
                )
                for h in page
            ],
            total=total,
            truncated=truncated,
        )

    def crypto_constant_scan(self, sid: str, a: s.CryptoConstantScanIn) -> s.CryptoConstantScanOut:
        """Heuristic crypto-constant search (PURE signature table over the ``search_bytes`` RPC).

        Issues one bounded ``search_bytes`` per known signature (reusing the fail-closed
        :meth:`search_bytes` adapter method, so a malformed worker result is already mapped), then
        shapes the addresses with the pure :func:`core.iocscan.scan_crypto_constants` and paginates.
        All output fields are safe (closed-vocabulary labels + server addresses). HEURISTIC — a
        match is a lead, not proof.
        """
        from ghidra_mcp.core import iocscan

        per_signature: list[tuple[iocscan.CryptoSignature, list[str]]] = []
        search_truncated = False
        for signature in iocscan.CRYPTO_SIGNATURES:
            found = self.search_bytes(
                sid,
                s.SearchBytesIn(
                    session_id=a.session_id,
                    pattern_hex=signature.pattern_hex,
                    limit=_CRYPTO_MATCH_BUDGET,
                ),
            )
            search_truncated = search_truncated or found.truncated
            per_signature.append((signature, [m.address for m in found.matches]))
        hits = iocscan.scan_crypto_constants(per_signature)
        total = len(hits)
        page = hits[a.offset : a.offset + a.limit]
        truncated = search_truncated or (a.offset + a.limit < total)
        return s.CryptoConstantScanOut(
            findings=[
                s.CryptoConstantFinding(algorithm=h.algorithm, kind=h.kind, address=h.address)
                for h in page
            ],
            total=total,
            truncated=truncated,
        )

    def call_graph_metrics(self, sid: str, a: s.CallGraphMetricsIn) -> s.CallGraphMetricsOut:
        """Structural call-graph metrics (PURE ``core.metrics`` over the ``call_graph`` RPC).

        Extracts the bounded adjacency via the worker ``call_graph`` RPC (the only Ghidra hop), then
        computes fan-in/out, leaf/root, and recursion stats with the pure
        :func:`core.metrics.compute_call_graph_metrics` (which reuses the ADR-007 ordering core).
        Hotspot ``name`` fields are taken from the (already-wrapped) graph nodes; addresses/counts
        are safe. ``truncated`` reflects the underlying graph node/edge cap.
        """
        from ghidra_mcp.core.metrics import compute_call_graph_metrics

        graph = self.call_graph(
            sid,
            s.CallGraphIn(
                session_id=a.session_id,
                root=a.root,
                max_depth=a.max_depth,
                max_nodes=a.max_nodes,
                max_edges=a.max_edges,
            ),
        )
        adjacency, unresolved = _adjacency_from_graph(graph)
        result = compute_call_graph_metrics(adjacency, unresolved=tuple(unresolved), top_n=a.top_n)
        names = {node.address: node.name for node in graph.nodes}

        def _rank(entries: tuple[Any, ...]) -> list[s.FanRanking]:
            """Map pure ``FanEntry`` ranks to :class:`FanRanking`, reusing wrapped node names."""
            ranked: list[s.FanRanking] = []
            for entry in entries:
                name = names.get(entry.address)
                if name is None:  # an edge target outside the emitted node set (boundary clip)
                    name = _w(entry.address, DataOrigin.BINARY)
                ranked.append(s.FanRanking(address=entry.address, name=name, count=entry.count))
            return ranked

        return s.CallGraphMetricsOut(
            function_count=result.function_count,
            edge_count=result.edge_count,
            leaf_count=result.leaf_count,
            root_count=result.root_count,
            recursive_component_count=result.recursive_component_count,
            self_recursive_count=result.self_recursive_count,
            unresolved_caller_count=result.unresolved_caller_count,
            top_fan_in=_rank(result.top_fan_in),
            top_fan_out=_rank(result.top_fan_out),
            truncated=graph.truncated,
        )

    def program_summary(self, sid: str, a: s.ProgramSummaryIn) -> s.ProgramSummary:
        """One-shot aggregate triage report (server-side aggregation of Tier-1 + Tier-2).

        Composes bounded sub-results — program metadata, import/export/string totals, coverage, the
        optional call-graph metrics, the top functions by complexity (over a bounded examined set),
        an IOC category histogram, and the detected crypto-algorithm set — wrapping every
        binary-derived field at the ADR-005 chokepoint. NO naming or C synthesis (ADR-008). The
        heavy per-item lists stay in their dedicated tools; ``truncated`` is the OR of any capped
        sub-result so the client never mistakes a bounded view for the whole program.
        """
        sess = a.session_id
        metadata = self.program_metadata(sid, s.ProgramMetadataIn(session_id=sess))
        import_count = self.list_imports(sid, s.ListImportsIn(session_id=sess, limit=1)).total
        export_count = self.list_exports(sid, s.ListExportsIn(session_id=sess, limit=1)).total
        string_count = self.list_strings(sid, s.ListStringsIn(session_id=sess, limit=1)).total
        coverage = self.coverage(sid, s.CoverageIn(session_id=sess))
        truncated = False

        call_graph_metrics: s.CallGraphMetricsOut | None = None
        if a.include_call_graph:
            call_graph_metrics = self.call_graph_metrics(sid, s.CallGraphMetricsIn(session_id=sess))
            truncated = truncated or call_graph_metrics.truncated

        top_complex = self._top_complex_functions(sid, sess, a.max_complex_functions)
        truncated = truncated or top_complex.truncated

        ioc_counts: list[s.IocCategoryCount] = []
        if a.max_iocs:
            scan = self.ioc_scan(sid, s.IocScanIn(session_id=sess, limit=a.max_iocs))
            truncated = truncated or scan.truncated
            counts: dict[str, int] = {}
            for match in scan.matches:
                counts[match.category] = counts.get(match.category, 0) + 1
            ioc_counts = [
                s.IocCategoryCount(category=cat, count=n) for cat, n in sorted(counts.items())
            ]

        crypto = self.crypto_constant_scan(
            sid, s.CryptoConstantScanIn(session_id=sess, limit=_CRYPTO_MATCH_BUDGET)
        )
        truncated = truncated or crypto.truncated
        crypto_algorithms = sorted({f.algorithm for f in crypto.findings})

        return s.ProgramSummary(
            metadata=metadata,
            function_count=metadata.function_count,
            import_count=import_count,
            export_count=export_count,
            string_count=string_count,
            coverage=coverage,
            call_graph_metrics=call_graph_metrics,
            top_complex_functions=top_complex.functions,
            ioc_counts=ioc_counts,
            crypto_algorithms=crypto_algorithms,
            truncated=truncated,
        )

    def _top_complex_functions(self, sid: str, session_id: str, max_functions: int) -> _TopComplex:
        """Return the highest-complexity functions over a bounded examined set (helper for summary).

        Examines the first ``max_functions`` functions (one bounded ``list_functions`` page),
        computes each one's cyclomatic complexity, and returns them sorted descending. ``truncated``
        is set when more functions exist than were examined — so the summary never implies it ranked
        the whole program. With ``max_functions == 0`` it does no work.

        Args:
            sid: The session id.
            session_id: The same session id for sub-call argument models.
            max_functions: Cap on functions examined and returned.

        Returns:
            A :class:`_TopComplex` (sorted functions + truncation flag).
        """
        if max_functions <= 0:
            return _TopComplex(functions=[], truncated=False)
        listing = self.list_functions(
            sid, s.ListFunctionsIn(session_id=session_id, limit=max_functions)
        )
        measured = [
            self.cyclomatic_complexity(
                sid, s.CyclomaticComplexityIn(session_id=session_id, function=fn.address)
            )
            for fn in listing.functions
        ]
        measured.sort(key=lambda c: c.complexity, reverse=True)
        return _TopComplex(functions=measured[:max_functions], truncated=listing.truncated)

    # --- mutation / write operations (v1.1 — ADR-012; transaction-wrapped in the worker) ---
    # The server has already checked write consent (sessions.require_write_consent) and validated
    # the attacker-influenced inputs (validate_write_name / validate_comment_text). Here the adapter
    # issues the write RPC and turns the worker's PLAIN result into the typed ``*Out``, wrapping
    # only binary-derived field, the prior ``old_name``, as ``Untrusted`` (ADR-005 chokepoint).
    def rename_function(self, sid: str, a: s.RenameFunctionIn) -> s.RenameResult:
        """Rename one function (write — ADR-012)."""
        return _build_rename_result(
            self._tool_call(
                sid, "rename_function", {"function": a.function, "new_name": a.new_name}
            )
        )

    def rename_symbol(self, sid: str, a: s.RenameSymbolIn) -> s.RenameSymbolResult:
        """Rename one data/label/global symbol (write — ADR-012)."""
        return _build_rename_symbol_result(
            self._tool_call(
                sid, "rename_symbol", {"identifier": a.identifier, "new_name": a.new_name}
            )
        )

    def set_comment(self, sid: str, a: s.SetCommentIn) -> s.SetCommentResult:
        """Set or clear one comment at an address (write — ADR-012)."""
        return _build_set_comment_result(
            self._tool_call(
                sid,
                "set_comment",
                {"address": a.address, "comment_type": a.comment_type, "text": a.text},
            )
        )

    def undo(self, sid: str, a: s.SessionUndoIn) -> s.SessionUndoOut:
        """Undo the last committed mutation transaction in the session (convenience — ADR-012)."""
        return _build_undo_out(sid, self._tool_call(sid, "undo", {}))

    def rename_local_variable(
        self, sid: str, a: s.RenameLocalVariableIn
    ) -> s.StructuralRenameResult:
        """Rename one function-local variable (structural, name-only — ADR-013)."""
        return _build_structural_rename_result(
            self._tool_call(
                sid,
                "rename_local_variable",
                {"function": a.function, "variable": a.variable, "new_name": a.new_name},
            )
        )

    def rename_parameter(self, sid: str, a: s.RenameParameterIn) -> s.StructuralRenameResult:
        """Rename one function parameter (structural, name-only — ADR-013)."""
        return _build_structural_rename_result(
            self._tool_call(
                sid,
                "rename_parameter",
                {"function": a.function, "parameter": a.parameter, "new_name": a.new_name},
            )
        )

    # --- structural type-aware writes (v1.1 — ADR-014 Phase B; structured TypeRef params) ---
    # The server has already checked structural consent and validated the structured payload
    # (validate_signature / validate_type_ref / validate_calling_convention). Here the adapter
    # serializes the typed schema into plain RPC params (the TypeRef/ParamSpec are dumped to plain
    # dicts) and wraps the binary-derived result fields as ``Untrusted`` (ADR-005 chokepoint).
    def set_function_signature(
        self, sid: str, a: s.SetFunctionSignatureIn
    ) -> s.SetFunctionSignatureResult:
        """Set a function's structured signature (resolved types — ADR-014)."""
        return _build_set_function_signature_result(
            self._tool_call(
                sid,
                "set_function_signature",
                {
                    "function": a.function,
                    "return_type": _type_ref_params(a.return_type),
                    "parameters": [
                        {"name": p.name, "type": _type_ref_params(p.type)} for p in a.parameters
                    ],
                    "calling_convention": a.calling_convention,
                },
            )
        )

    def apply_data_type(self, sid: str, a: s.ApplyDataTypeIn) -> s.ApplyDataTypeResult:
        """Apply a resolvable type at an address (resolved type — ADR-014)."""
        return _build_apply_data_type_result(
            self._tool_call(
                sid,
                "apply_data_type",
                {
                    "address": a.address,
                    "type": _type_ref_params(a.type),
                    "clear_existing": a.clear_existing,
                },
            )
        )

    # --- composite-type creation (v1.1 — ADR-015 Phase C; structured FieldSpec params) ---
    # The server has already checked structural consent and validated the composite payload
    # (validate_composite: bounded FieldSpec list of resolved TypeRefs, no duplicate/self-embed).
    # Here the adapter serializes each field's TypeRef to plain RPC params (one composite per call)
    # and builds the typed result — every field is server/worker-controlled (no Untrusted echo).
    def define_struct(self, sid: str, a: s.DefineStructIn) -> s.DefineStructResult:
        """Create a new struct from a resolved field list (one composite — ADR-015)."""
        return _build_define_struct_result(
            self._tool_call(
                sid,
                "define_struct",
                {
                    "name": a.name,
                    "fields": [_field_spec_params(f) for f in a.fields],
                    "packed": a.packed,
                },
            )
        )

    def define_union(self, sid: str, a: s.DefineUnionIn) -> s.DefineUnionResult:
        """Create a new union from a resolved field list (one composite — ADR-015)."""
        return _build_define_union_result(
            self._tool_call(
                sid,
                "define_union",
                {
                    "name": a.name,
                    "fields": [_field_spec_params(f) for f in a.fields],
                },
            )
        )

    # --- internal: call orchestration -------------------------------------------------------
    def _tool_call(self, sid: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Issue a read-only tool RPC bounded by the per-tool timeout.

        Args:
            sid: The session id.
            method: The RPC method name.
            params: Method parameters (already validated by the schema/core.validation).

        Returns:
            The worker's ``result`` object.
        """
        return self._call(sid, method, params, timeout_s=self._tool_timeout_s)

    def _call(
        self, session_id: str, method: str, params: dict[str, Any], *, timeout_s: float
    ) -> dict[str, Any]:
        """Send one JSON-RPC request and read its response, enforcing kill-on-failure semantics.

        Failure handling (rpc-protocol.md §3/§6):

        - deadline expiry → SIGKILL worker, ``timeout`` error;
        - oversized declared frame / protocol violation → SIGKILL worker, ``worker-unavailable``;
        - worker crash / closed socket mid-call → SIGKILL worker, ``worker-unavailable``;
        - worker JSON-RPC ``error`` response → map ``data.type`` slug → public error type.

        Args:
            session_id: The session whose worker handles the call.
            method: The RPC method name.
            params: Method parameters.
            timeout_s: Wall-clock deadline for this call.

        Returns:
            The worker's ``result`` object.

        Raises:
            GhidraMcpError: On any failure, mapped to the public error envelope.
        """
        sess = self._sessions.get(session_id)
        if sess is None:
            raise _errors.make_error(ErrorType.WORKER_UNAVAILABLE, "no worker for session")

        request_id = uuid.uuid4().hex
        frame = rpc_framing.encode_frame(
            rpc_framing.build_request(request_id, method, params),
            max_frame_bytes=self._max_response_bytes,
        )
        try:
            sock = self._ensure_connected(sess)
            sock.settimeout(timeout_s)
            self._send_all(sock, frame)
            response_obj = self._read_frame(sock)
            return rpc_framing.parse_response(response_obj, expected_id=request_id)
        except RpcCallError as exc:
            # A method-level failure: the worker is healthy; do NOT kill. Map the slug.
            etype = _errors.map_worker_slug(exc.error.type_slug)
            raise _errors.make_error(etype, exc.error.message) from exc
        except TimeoutError as exc:
            _log.warning(
                "worker.rpc_failed",
                extra={"method": method, "cause": "timeout", "detail": str(exc)[:300]},
            )
            self.kill_worker(session_id)
            raise _errors.make_error(
                ErrorType.TIMEOUT, "operation exceeded its time limit"
            ) from exc
        except (FramingError, RpcProtocolError) as exc:
            # Hostile/buggy worker: protocol/framing violation → kill + evict.
            _log.warning(
                "worker.rpc_failed",
                extra={
                    "method": method,
                    "cause": "protocol",
                    "exc": type(exc).__name__,
                    "detail": str(exc)[:300],
                },
            )
            self.kill_worker(session_id)
            raise _errors.make_error(
                ErrorType.WORKER_UNAVAILABLE, "worker protocol violation"
            ) from exc
        except (ConnectionError, EOFError, OSError) as exc:
            # Crash / closed socket mid-call → kill + evict. Log the underlying socket error
            # server-side (boundary-safe: errno/type only, no binary content) so the cause of a
            # worker-unavailable (e.g. ECONNREFUSED on the connect, EOF mid-frame) is diagnosable.
            _log.warning(
                "worker.rpc_failed",
                extra={
                    "method": method,
                    "cause": "transport",
                    "exc": type(exc).__name__,
                    "detail": str(exc)[:300],
                },
            )
            self.kill_worker(session_id)
            raise _errors.make_error(ErrorType.WORKER_UNAVAILABLE, "worker unavailable") from exc

    def _ensure_connected(self, sess: _Session) -> socket.socket:
        """Connect (lazily) to the session's UDS, returning a stream socket.

        Args:
            sess: The per-session state.

        Returns:
            The connected stream socket.

        Raises:
            OSError: If the worker socket cannot be reached (→ ``worker-unavailable``).
        """
        if sess.sock is not None:
            return sess.sock
        # The worker binds its per-session UDS only AFTER its container starts (and the backend
        # warms up), but the spawn (`podman run --detach`) returns before that. A single connect
        # would lose the race and fail closed as worker-unavailable, so retry until the worker is
        # bound and accepting or the connect budget elapses. The two expected transient conditions
        # are ENOENT (socket file not created yet) and ECONNREFUSED (created but not yet
        # listening); any other OSError is non-transient and propagates immediately (fail fast).
        start = time.monotonic()
        while True:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self._connect_timeout_s)
            try:
                sock.connect(sess.socket_path)
            except (FileNotFoundError, ConnectionRefusedError):
                sock.close()
                if time.monotonic() - start >= self._connect_timeout_s:
                    raise
                time.sleep(_CONNECT_RETRY_INTERVAL_S)
                continue
            sess.sock = sock
            return sock

    @staticmethod
    def _send_all(sock: socket.socket, data: bytes) -> None:
        """Write a full frame to the socket.

        Args:
            sock: The connected stream socket.
            data: The complete frame bytes.
        """
        sock.sendall(data)

    def _read_frame(self, sock: socket.socket) -> dict[str, Any]:
        """Read exactly one length-prefixed JSON-RPC frame from the socket.

        Bounds the declared length BEFORE allocating the body buffer (no large-allocation DoS).

        Args:
            sock: The connected stream socket.

        Returns:
            The decoded JSON object.

        Raises:
            FramingError: On a short/oversized frame.
            RpcProtocolError: On malformed JSON.
            EOFError: If the worker closed the socket mid-frame.
        """
        prefix = self._recv_exact(sock, rpc_framing.LENGTH_PREFIX_BYTES)
        n = rpc_framing.decode_length_prefix(prefix, max_frame_bytes=self._max_response_bytes)
        body = self._recv_exact(sock, n) if n else b""
        return rpc_framing.decode_body(body)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        """Receive exactly ``n`` bytes, raising on premature EOF.

        Args:
            sock: The connected stream socket.
            n: Number of bytes to read.

        Returns:
            Exactly ``n`` bytes.

        Raises:
            EOFError: If the peer closed the connection before ``n`` bytes arrived.
        """
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise EOFError("worker closed connection mid-frame")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _close_socket(sess: _Session) -> None:
        """Close and drop the session's socket if open. Never raises.

        Args:
            sess: The per-session state.
        """
        if sess.sock is not None:
            with contextlib.suppress(OSError):
                sess.sock.close()
            sess.sock = None

    def _socket_path(self, session_id: str) -> str:
        """Compute the per-session UDS path (``<socket_dir>/<token>/<sid>.sock`` — ADR-009).

        The socket lives in a **per-session subdirectory** so the launcher can bind-mount only
        that dir into the worker — a hostile worker therefore sees no sibling sessions' sockets
        (rpc-protocol.md §2; reconciled with the WS3 launcher mount scheme).

        The directory is a SHORT prefix of the session id, not the full id: ``AF_UNIX`` paths are
        capped (~107 bytes on Linux), and the 43-char (256-bit) session id already appears in the
        ``<sid>.sock`` filename — using it for the directory too overflowed the limit on realistic
        socket dirs (the default ``/run/ghidra-mcp`` alone reached 108 → ``AF_UNIX path too long``).
        The prefix stays unique per live session (small concurrency cap, high-entropy id), the dir
        is ``0700``, and the full id remains both the socket filename and the server-side identity,
        so isolation/BOLA are unchanged. The in-container path the worker binds is still
        ``/run/ghidra-mcp/<session_id>.sock`` (rpc-protocol §2 unchanged).

        Args:
            session_id: The opaque session id (CSPRNG-generated; safe as a filename component).

        Returns:
            The socket path string.
        """
        base = self._socket_dir.rstrip("/")
        return f"{base}/{session_id[:_SOCKET_DIR_TOKEN_LEN]}/{session_id}.sock"


def _xrefs_params(a: s.XrefsIn) -> dict[str, Any]:
    """Build the params dict for ``xrefs_to`` / ``xrefs_from``.

    Args:
        a: The xrefs input model.

    Returns:
        The RPC params dict.
    """
    return {"target": a.target, "offset": a.offset, "limit": a.limit}


# =====================================================================================
# Untrusted-data wrap builders (PM #9, ADR-005)
# =====================================================================================
# These turn a worker's PLAIN result dict into the typed ``*Out`` model, wrapping every
# binary-derived field via :func:`core.envelope.wrap`. They are the single, auditable map of
# field → provenance. Provenance rule (envelope spec): BINARY = *extracted* from the binary
# (strings, raw/searched bytes, symbol/function/section names, comments, format-reported metadata);
# GHIDRA = *synthesized* by the decompiler/analysis over hostile input (pseudo-C, signatures,
# recovered mnemonics/operands, calling conventions, resolved type names/definitions). Server-
# computed scalars (addresses we normalized, counts, sizes, booleans, ref-types) stay bare.
#
# These builders are pure (dict in → model out, no I/O) and trivially unit-testable. They read
# fields defensively with ``.get`` so a missing optional collapses to ``None``/empty rather than a
# ``KeyError`` crossing the boundary; structural shape is still enforced by the frozen ``*Out``
# models on construction (a bad type fails closed via pydantic).


def _w(value: str, origin: DataOrigin, *, encoding: str | None = None) -> Untrusted[str]:
    """Wrap a required string field at ``origin`` (the chokepoint normalizes/annotates it).

    Args:
        value: The plain, binary-derived string from the worker.
        origin: Provenance (:class:`DataOrigin`).
        encoding: Optional byte-representation tag (e.g. ``"hex"``) for byte payloads.

    Returns:
        The :class:`Untrusted` wrapper.
    """
    return wrap(str(value), origin=origin, encoding=encoding)


def _w_opt(value: object, origin: DataOrigin) -> Untrusted[str] | None:
    """Wrap an OPTIONAL string field, passing ``None`` through unwrapped.

    Args:
        value: The plain value or ``None``.
        origin: Provenance to apply when present.

    Returns:
        The wrapper, or ``None`` if ``value`` is ``None``.
    """
    if value is None:
        return None
    return wrap(str(value), origin=origin)


def _fail_closed[**P, R](builder: Callable[P, R]) -> Callable[P, R]:
    """Map a malformed-worker-result exception in a builder to a safe ``WORKER_UNAVAILABLE``.

    The builders turn the worker's *plain* result dict into a typed ``*Out`` model. A worker that
    returns a structurally-malformed result (a missing required key, a wrong-typed value) would
    otherwise raise a raw ``KeyError``/``ValueError``/``TypeError`` or a pydantic
    ``ValidationError`` out of the adapter — the server shell would then catch it as a *generic*
    ``internal-error``,
    misclassifying a worker fault as a server bug. This decorator catches exactly those shaping
    failures and re-raises the adapter's own ``WORKER_UNAVAILABLE`` (the adapter owns the worker
    fault domain — rpc-protocol.md §6; topic-error-handling fail-closed). It deliberately does NOT
    catch :class:`GhidraMcpError` (an inner builder's already-mapped fault propagates unchanged) or
    any other exception class (a genuine server bug still surfaces as ``internal-error``). The
    untrusted worker detail is never forwarded — only a safe, generic message.

    Args:
        builder: A pure ``dict -> *Out`` (or ``dict -> model``) shaping function.

    Returns:
        The builder wrapped so a malformed-result exception becomes a safe mapped error.
    """

    @functools.wraps(builder)
    def _wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return builder(*args, **kwargs)
        except (KeyError, ValueError, TypeError, ValidationError) as exc:
            raise _errors.make_error(
                ErrorType.WORKER_UNAVAILABLE, "worker returned a malformed result"
            ) from exc

    return _wrapped


@_fail_closed
def _validate[ModelT: BaseModel](model: type[ModelT], result: dict[str, Any]) -> ModelT:
    """Validate a worker result into ``model``, failing closed on a malformed/incomplete result.

    The fail-closed counterpart of a bare ``model.model_validate(result)`` for the few adapter
    methods whose worker result maps 1:1 to a frozen model with no field-wrapping builder
    (lifecycle ``SessionInfo``; ``XrefsOut`` — addresses/ref-types are server-safe). A malformed
    result raises ``ValidationError`` here, which :func:`_fail_closed` maps to a safe envelope.

    Args:
        model: The frozen output model to validate into.
        result: The worker's plain result dict.

    Returns:
        The validated model instance.
    """
    return model.model_validate(result)


@_fail_closed
def _build_decompiled(r: dict[str, Any]) -> s.DecompiledFunction:
    """Build :class:`DecompiledFunction`: name=BINARY; c_code/signature=GHIDRA."""
    return s.DecompiledFunction(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        c_code=_w(r["c_code"], DataOrigin.GHIDRA),
        signature=_w(r["signature"], DataOrigin.GHIDRA),
    )


@_fail_closed
def _build_instruction(r: dict[str, Any]) -> s.Instruction:
    """Build one :class:`Instruction`: mnemonic/operands=GHIDRA; bytes_hex=BINARY (hex)."""
    return s.Instruction(
        address=str(r["address"]),
        mnemonic=_w(r["mnemonic"], DataOrigin.GHIDRA),
        operands=_w(r["operands"], DataOrigin.GHIDRA),
        bytes_hex=_w(r["bytes_hex"], DataOrigin.BINARY, encoding="hex"),
    )


@_fail_closed
def _build_disassemble(r: dict[str, Any]) -> s.DisassembleOut:
    """Build :class:`DisassembleOut` from a plain result."""
    return s.DisassembleOut(
        instructions=[_build_instruction(i) for i in r.get("instructions", [])],
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_function_summary(r: dict[str, Any]) -> s.FunctionSummary:
    """Build one :class:`FunctionSummary`: name=BINARY; size is safe."""
    return s.FunctionSummary(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        size=int(r["size"]),
    )


@_fail_closed
def _build_function_list(r: dict[str, Any]) -> s.FunctionListOut:
    """Build :class:`FunctionListOut` from a plain result."""
    return s.FunctionListOut(
        functions=[_build_function_summary(f) for f in r.get("functions", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_function_detail(r: dict[str, Any]) -> s.FunctionDetail:
    """Build :class:`FunctionDetail`: name=BINARY; signature/calling_convention=GHIDRA."""
    return s.FunctionDetail(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        signature=_w(r["signature"], DataOrigin.GHIDRA),
        size=int(r["size"]),
        is_thunk=bool(r["is_thunk"]),
        calling_convention=_w_opt(r.get("calling_convention"), DataOrigin.GHIDRA),
    )


@_fail_closed
def _build_defined_string(r: dict[str, Any]) -> s.DefinedString:
    """Build one :class:`DefinedString`: value=BINARY (extracted, utf-8-replace)."""
    return s.DefinedString(
        address=str(r["address"]),
        value=_w(r["value"], DataOrigin.BINARY, encoding="utf-8-replace"),
        length=int(r["length"]),
    )


@_fail_closed
def _build_string_list(r: dict[str, Any]) -> s.StringListOut:
    """Build :class:`StringListOut` from a plain result."""
    return s.StringListOut(
        strings=[_build_defined_string(x) for x in r.get("strings", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_symbol(r: dict[str, Any]) -> s.Symbol:
    """Build one :class:`Symbol`: name/namespace=BINARY (extracted); kind is safe."""
    return s.Symbol(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        kind=str(r["kind"]),
        namespace=_w_opt(r.get("namespace"), DataOrigin.BINARY),
    )


@_fail_closed
def _build_symbol_list(r: dict[str, Any]) -> s.SymbolListOut:
    """Build :class:`SymbolListOut` from a plain result."""
    return s.SymbolListOut(
        symbols=[_build_symbol(x) for x in r.get("symbols", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_defined_data(r: dict[str, Any]) -> s.DefinedData:
    """Build one :class:`DefinedData`: data_type=GHIDRA (resolved); value_repr=BINARY."""
    return s.DefinedData(
        address=str(r["address"]),
        data_type=_w(r["data_type"], DataOrigin.GHIDRA),
        value_repr=_w(r["value_repr"], DataOrigin.BINARY),
        length=int(r["length"]),
    )


@_fail_closed
def _build_data_list(r: dict[str, Any]) -> s.DataListOut:
    """Build :class:`DataListOut` from a plain result."""
    return s.DataListOut(
        data=[_build_defined_data(x) for x in r.get("data", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_data_type(r: dict[str, Any]) -> s.DataType:
    """Build :class:`DataType`: name/definition=GHIDRA (resolved over hostile input)."""
    return s.DataType(
        name=_w(r["name"], DataOrigin.GHIDRA),
        kind=str(r["kind"]),
        size=int(r["size"]),
        definition=_w(r["definition"], DataOrigin.GHIDRA),
    )


@_fail_closed
def _build_comment(r: dict[str, Any]) -> s.Comment:
    """Build one :class:`Comment`: text=BINARY (extracted; planted-comment injection vector)."""
    return s.Comment(
        address=str(r["address"]),
        comment_type=str(r["comment_type"]),
        text=_w(r["text"], DataOrigin.BINARY),
    )


@_fail_closed
def _build_comment_list(r: dict[str, Any]) -> s.CommentListOut:
    """Build :class:`CommentListOut` from a plain result."""
    return s.CommentListOut(
        comments=[_build_comment(x) for x in r.get("comments", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_memory_block(r: dict[str, Any]) -> s.MemoryBlock:
    """Build one :class:`MemoryBlock`: name=BINARY (section header); rest are safe."""
    return s.MemoryBlock(
        name=_w(r["name"], DataOrigin.BINARY),
        start=str(r["start"]),
        end=str(r["end"]),
        size=int(r["size"]),
        permissions=str(r["permissions"]),
        initialized=bool(r["initialized"]),
    )


@_fail_closed
def _build_memory_map(r: dict[str, Any]) -> s.MemoryMapOut:
    """Build :class:`MemoryMapOut` from a plain result."""
    return s.MemoryMapOut(blocks=[_build_memory_block(b) for b in r.get("blocks", [])])


@_fail_closed
def _build_read_bytes(r: dict[str, Any]) -> s.ReadBytesOut:
    """Build :class:`ReadBytesOut`: data=BINARY (raw bytes, hex-encoded)."""
    return s.ReadBytesOut(
        address=str(r["address"]),
        data=_w(r["data"], DataOrigin.BINARY, encoding="hex"),
        length=int(r["length"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_byte_match(r: dict[str, Any]) -> s.ByteMatch:
    """Build one :class:`ByteMatch`: context_hex=BINARY (raw bytes, hex-encoded)."""
    return s.ByteMatch(
        address=str(r["address"]),
        context_hex=_w(r["context_hex"], DataOrigin.BINARY, encoding="hex"),
    )


@_fail_closed
def _build_search_bytes(r: dict[str, Any]) -> s.SearchBytesOut:
    """Build :class:`SearchBytesOut` from a plain result."""
    return s.SearchBytesOut(
        matches=[_build_byte_match(m) for m in r.get("matches", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_call_graph(r: dict[str, Any]) -> s.CallGraphOut:
    """Build :class:`CallGraphOut`: node ``name`` is BINARY-untrusted; addresses/flags are safe.

    Args:
        r: The worker's plain ``call_graph`` result dict.

    Returns:
        The typed, wrapped :class:`CallGraphOut`.
    """
    return s.CallGraphOut(
        nodes=[_build_call_graph_node(n) for n in r.get("nodes", [])],
        edges=[
            s.CallEdge(from_address=str(e["from_address"]), to_address=str(e["to_address"]))
            for e in r.get("edges", [])
        ],
        unresolved_callers=[str(c) for c in r.get("unresolved_callers", [])],
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_call_graph_node(r: dict[str, Any]) -> s.CallGraphNode:
    """Build one :class:`CallGraphNode`: name=BINARY (extracted symbol); address/flags safe.

    Args:
        r: One plain node dict.

    Returns:
        The typed node with its name untrusted-wrapped.
    """
    return s.CallGraphNode(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        is_external=bool(r.get("is_external", False)),
        has_unresolved_calls=bool(r.get("has_unresolved_calls", False)),
    )


@_fail_closed
def _build_referenced_strings(rs: dict[str, Any]) -> tuple[list[Untrusted[str]], bool]:
    """Shape a ``referenced_strings`` RPC result into (BINARY-wrapped values, truncation flag).

    Used by ``function_context`` (ADR-007). Each referenced string VALUE is attacker-controlled and
    BINARY-origin wrapped (ADR-005). Failing closed here keeps the worker-fault mapping uniform: a
    malformed result (e.g. a non-iterable ``strings``) maps to ``WORKER_UNAVAILABLE`` rather than
    surfacing as a generic internal error.

    Args:
        rs: The worker's plain ``referenced_strings`` result.

    Returns:
        A ``(referenced_strings, truncated)`` tuple.
    """
    values = [_w(str(v), DataOrigin.BINARY) for v in rs.get("strings", [])]
    return values, bool(rs.get("truncated", False))


def _adjacency_from_graph(graph: s.CallGraphOut) -> tuple[dict[str, list[str]], list[str]]:
    """Project a :class:`CallGraphOut` into a plain adjacency map + unresolved-caller list.

    Pure shaping helper (no I/O) feeding the pure ordering core: every node becomes a key (so
    disconnected/leaf nodes are represented), and each resolved edge appends its callee.

    Args:
        graph: The extracted call graph.

    Returns:
        ``(adjacency, unresolved)`` for :func:`ghidra_mcp.core.callgraph.compute_analysis_order`.
    """
    adjacency: dict[str, list[str]] = {node.address: [] for node in graph.nodes}
    for edge in graph.edges:
        adjacency.setdefault(edge.from_address, []).append(edge.to_address)
    return adjacency, list(graph.unresolved_callers)


def _build_analysis_order(graph: s.CallGraphOut) -> s.AnalysisOrderOut:
    """Compute + shape the leaf-first analysis order from an extracted call graph (PURE, no JVM).

    Delegates the ordering to the pure server-side core
    (:func:`ghidra_mcp.core.callgraph.compute_analysis_order`) — the algorithmic heart of ADR-007 —
    and maps its result to the frozen :class:`AnalysisOrderOut`. No binary-derived *content* is in
    this result (only server-normalized addresses + structural flags), so nothing needs wrapping.

    Args:
        graph: The extracted :class:`CallGraphOut`.

    Returns:
        The leaf-first :class:`AnalysisOrderOut` (sinks first, entry roots last).
    """
    from ghidra_mcp.core.callgraph import compute_analysis_order

    adjacency, unresolved = _adjacency_from_graph(graph)
    order = compute_analysis_order(adjacency, unresolved=unresolved)
    return s.AnalysisOrderOut(
        components=[
            s.OrderedComponent(members=list(c.members), is_recursive=c.is_recursive)
            for c in order.components
        ],
        unresolved_callers=list(order.unresolved_callers),
        self_recursive=list(order.self_recursive),
        truncated=graph.truncated,
    )


def _one_hop(
    graph: s.CallGraphOut, entry: str, *, direction: str, offset: int, limit: int
) -> s.CallNeighborsOut:
    """Project a call graph into one function's one-hop neighbors (PURE, no JVM, no I/O).

    Builds the direct callees (``direction="out"`` — edges *from* ``entry``) or callers
    (``direction="in"`` — edges *to* ``entry``) from the graph's edges, de-duplicated by address
    (a function may call/​be-called-by another at several sites) and paginated. The ``unresolved``
    honesty flag is set for the callee direction when ``entry`` itself has unresolved outgoing calls
    (it is not meaningful for callers — schema). ``truncated`` reflects the underlying graph cap or
    a page cap.

    Args:
        graph: The extracted call graph (whole-program for callers; depth-1-rooted for callees).
        entry: The target function's server-normalized entry address.
        direction: ``"out"`` for callees or ``"in"`` for callers.
        offset: Zero-based pagination offset.
        limit: Maximum neighbors to return in the page.

    Returns:
        The bounded, de-duplicated :class:`CallNeighborsOut`.
    """
    by_addr = {node.address: node for node in graph.nodes}
    if direction == "out":
        neighbor_addrs = [e.to_address for e in graph.edges if e.from_address == entry]
        unresolved = any(n.address == entry and n.has_unresolved_calls for n in graph.nodes)
    else:
        neighbor_addrs = [e.from_address for e in graph.edges if e.to_address == entry]
        unresolved = False
    ordered: list[s.CallGraphNode] = []
    seen: set[str] = set()
    for addr in neighbor_addrs:
        node = by_addr.get(addr)
        if node is None or addr in seen:
            continue
        seen.add(addr)
        ordered.append(node)
    total = len(ordered)
    page = ordered[offset : offset + limit]
    truncated = graph.truncated or (offset + limit < total)
    return s.CallNeighborsOut(
        neighbors=page, total=total, unresolved=unresolved, truncated=truncated
    )


@_fail_closed
def _build_program_metadata(r: dict[str, Any]) -> s.ProgramMetadata:
    """Build :class:`ProgramMetadata`: compiler=BINARY (format-reported); rest are safe."""
    return s.ProgramMetadata(
        sha256=str(r["sha256"]),
        size_bytes=int(r["size_bytes"]),
        format=str(r["format"]),
        architecture=str(r["architecture"]),
        endianness=str(r["endianness"]),
        compiler=_w_opt(r.get("compiler"), DataOrigin.BINARY),
        entry_point=(str(r["entry_point"]) if r.get("entry_point") is not None else None),
        function_count=int(r["function_count"]),
        analysis_complete=bool(r["analysis_complete"]),
    )


# --- Tier-2 builders (v1.1 — ADR-008) --------------------------------------------------------
@_fail_closed
def _build_imported_symbol(r: dict[str, Any]) -> s.ImportedSymbol:
    """Build one :class:`ImportedSymbol`: name/library=BINARY (extracted); address safe-optional."""
    return s.ImportedSymbol(
        name=_w(r["name"], DataOrigin.BINARY),
        library=_w_opt(r.get("library"), DataOrigin.BINARY),
        address=(str(r["address"]) if r.get("address") is not None else None),
    )


@_fail_closed
def _build_import_list(r: dict[str, Any]) -> s.ImportListOut:
    """Build :class:`ImportListOut` from a plain result."""
    return s.ImportListOut(
        imports=[_build_imported_symbol(x) for x in r.get("imports", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_exported_symbol(r: dict[str, Any]) -> s.ExportedSymbol:
    """Build one :class:`ExportedSymbol`: name=BINARY (extracted); address safe."""
    return s.ExportedSymbol(
        name=_w(r["name"], DataOrigin.BINARY),
        address=str(r["address"]),
    )


@_fail_closed
def _build_export_list(r: dict[str, Any]) -> s.ExportListOut:
    """Build :class:`ExportListOut` from a plain result."""
    return s.ExportListOut(
        exports=[_build_exported_symbol(x) for x in r.get("exports", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


@_fail_closed
def _build_coverage(r: dict[str, Any]) -> s.CoverageOut:
    """Build :class:`CoverageOut`: pure ratios from worker byte counts (no binary-derived content).

    Computes ``undefined_bytes`` and the code/data ratios server-side (guarding divide-by-zero with
    a 0.0 ratio when the program has no addressable bytes). All fields are safe scalars.

    Args:
        r: The worker's plain ``coverage`` counts.

    Returns:
        The typed :class:`CoverageOut`.
    """
    total = int(r["total_bytes"])
    code = int(r["defined_code_bytes"])
    data = int(r["defined_data_bytes"])
    undefined = max(0, total - code - data)
    return s.CoverageOut(
        total_bytes=total,
        defined_code_bytes=code,
        defined_data_bytes=data,
        undefined_bytes=undefined,
        code_ratio=(code / total if total else 0.0),
        data_ratio=(data / total if total else 0.0),
        function_count=int(r["function_count"]),
    )


@_fail_closed
def _build_cyclomatic_complexity(r: dict[str, Any]) -> s.CyclomaticComplexity:
    """Build :class:`CyclomaticComplexity` from worker CFG counts: name=BINARY; complexity is pure.

    Computes the McCabe number in the pure core (``ghidra_mcp.core.metrics.cyclomatic_complexity``)
    from the worker-extracted block/edge counts; only the function ``name`` is binary-derived.

    Args:
        r: The worker's plain ``function_cfg`` counts.

    Returns:
        The typed :class:`CyclomaticComplexity`.
    """
    from ghidra_mcp.core.metrics import cyclomatic_complexity as _mccabe

    block_count = int(r["block_count"])
    edge_count = int(r["edge_count"])
    return s.CyclomaticComplexity(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        complexity=_mccabe(block_count, edge_count),
        block_count=block_count,
        edge_count=edge_count,
        incomplete=bool(r.get("incomplete", False)),
    )


# --- mutation (write) result builders (v1.1 — ADR-012; old_name is binary-derived → Untrusted) ---
@_fail_closed
def _build_rename_result(r: dict[str, Any]) -> s.RenameResult:
    """Build a ``RenameResult`` from the worker's plain dict (wraps the prior name Untrusted)."""
    return s.RenameResult(
        address=str(r["address"]),
        old_name=_w(r["old_name"], DataOrigin.BINARY),
        new_name=str(r["new_name"]),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_rename_symbol_result(r: dict[str, Any]) -> s.RenameSymbolResult:
    """Build a ``RenameSymbolResult`` (adds the closed-vocabulary symbol kind)."""
    return s.RenameSymbolResult(
        address=str(r["address"]),
        old_name=_w(r["old_name"], DataOrigin.BINARY),
        new_name=str(r["new_name"]),
        applied=bool(r["applied"]),
        kind=str(r["kind"]),
    )


@_fail_closed
def _build_set_comment_result(r: dict[str, Any]) -> s.SetCommentResult:
    """Build a ``SetCommentResult`` (no binary-derived field — all server/closed-vocabulary)."""
    return s.SetCommentResult(
        address=str(r["address"]),
        comment_type=str(r["comment_type"]),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_undo_out(sid: str, r: dict[str, Any]) -> s.SessionUndoOut:
    """Build a ``SessionUndoOut`` (session id is server-known/safe; ``undone`` from the worker)."""
    return s.SessionUndoOut(session_id=sid, undone=bool(r["undone"]))


@_fail_closed
def _build_structural_rename_result(r: dict[str, Any]) -> s.StructuralRenameResult:
    """Build a ``StructuralRenameResult`` (function + prior name → Untrusted; ADR-013)."""
    return s.StructuralRenameResult(
        address=str(r["address"]),
        function=_w(r["function"], DataOrigin.BINARY),
        old_name=_w(r["old_name"], DataOrigin.BINARY),
        new_name=str(r["new_name"]),
        applied=bool(r["applied"]),
    )


# --- structural type-aware (ADR-014 Phase B) — echoed signature/type fields are binary-derived ---
def _type_ref_params(ref: s.TypeRef) -> dict[str, Any]:
    """Serialize a :class:`TypeRef` into plain RPC params (no C string — ADR-014 §2).

    The worker resolves these fields against the program's ``DataTypeManager``; only one of
    ``base``/``named`` is set (model-validated), and the modifiers are bounded.

    Args:
        ref: The validated :class:`TypeRef` to serialize.

    Returns:
        A plain, JSON-serializable dict mirroring the ``TypeRef`` shape.
    """
    return {
        "base": ref.base,
        "named": ref.named,
        "pointer_levels": ref.pointer_levels,
        "array_len": ref.array_len,
    }


@_fail_closed
def _build_set_function_signature_result(r: dict[str, Any]) -> s.SetFunctionSignatureResult:
    """Build a ``SetFunctionSignatureResult`` (echoed signatures → Untrusted; ADR-014 §6).

    ``new_signature`` is untrusted because Ghidra RE-RENDERS our applied prototype (the worker is
    untrusted on the way out — ADR-005); ``address``/``applied`` are server/worker-controlled.
    """
    return s.SetFunctionSignatureResult(
        address=str(r["address"]),
        function=_w(r["function"], DataOrigin.BINARY),
        old_signature=_w(r["old_signature"], DataOrigin.BINARY),
        new_signature=_w(r["new_signature"], DataOrigin.BINARY),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_apply_data_type_result(r: dict[str, Any]) -> s.ApplyDataTypeResult:
    """Build an ``ApplyDataTypeResult`` (resolved type name → Untrusted; ADR-014 §6)."""
    return s.ApplyDataTypeResult(
        address=str(r["address"]),
        type_name=_w(r["type_name"], DataOrigin.BINARY),
        size=int(r["size"]),
        applied=bool(r["applied"]),
    )


# --- composite-type creation (ADR-015 Phase C) — every result field is server/worker-controlled
# (the name is the one WE set + validated; size/field_count/applied are worker scalars), so NONE is
# Untrusted-wrapped (ADR-015 §7). A future field echoing Ghidra's rendered layout MUST be Untrusted.
def _field_spec_params(field: s.FieldSpec) -> dict[str, Any]:
    """Serialize a :class:`FieldSpec` into plain RPC params (no C string — ADR-015 §2).

    The worker resolves ``type`` against the program's ``DataTypeManager`` (NEVER parses it); the
    bounded ``name``/``offset`` are passed through as-is.

    Args:
        field: The validated :class:`FieldSpec` to serialize.

    Returns:
        A plain, JSON-serializable dict mirroring the ``FieldSpec`` shape (``type`` a TypeRef dict).
    """
    return {"name": field.name, "type": _type_ref_params(field.type), "offset": field.offset}


@_fail_closed
def _build_define_struct_result(r: dict[str, Any]) -> s.DefineStructResult:
    """Build a ``DefineStructResult`` — all fields server/worker-controlled, SAFE (ADR-015 §7)."""
    return s.DefineStructResult(
        name=str(r["name"]),
        kind=str(r["kind"]),
        size=int(r["size"]),
        field_count=int(r["field_count"]),
        applied=bool(r["applied"]),
    )


@_fail_closed
def _build_define_union_result(r: dict[str, Any]) -> s.DefineUnionResult:
    """Build a ``DefineUnionResult`` — all fields server/worker-controlled, SAFE (ADR-015 §7)."""
    return s.DefineUnionResult(
        name=str(r["name"]),
        kind=str(r["kind"]),
        size=int(r["size"]),
        field_count=int(r["field_count"]),
        applied=bool(r["applied"]),
    )
