"""JVM-free RPC dispatch + server loop for the Ghidra worker (WS2).

This module is the worker's *imperative shell* around a JVM-touching *backend*. It is deliberately
JVM-free: it speaks the frozen length-prefixed JSON-RPC protocol (via
:mod:`vivarium.ghidra.rpc_framing`), validates each request against the worker-facing method
allow-list, and routes to a :class:`GhidraBackend` whose concrete implementation
(:mod:`vivarium.ghidra._jvm_bridge`) is the only code that loads the JVM.

Because the backend is injected behind a ``Protocol``, the entire dispatch/framing path is
unit-testable with a fake backend — no Ghidra, no JVM, no container (topic-architecture-patterns:
functional-core/imperative-shell; the JVM is pushed to the edge).

Security:

- **Allow-list dispatch:** only the frozen worker method names are accepted; unknown methods → a
  ``-32601`` method-not-found error. No dynamic/`runScript` path (read-only v1).
- **Bounded frames:** the server enforces ``max_frame_bytes`` on both directions; the backend is
  responsible for size-capping its structured results before returning (the server caps the wire).
- **Safe errors:** the worker never returns a stack trace or host path; only the safe slugs from
  rpc-protocol.md §5 cross the boundary.
"""

from __future__ import annotations

import select
import time
from collections.abc import Callable
from typing import Any, Protocol

from vivarium.ghidra import rpc_framing
from vivarium.ghidra.rpc_framing import FramingError, RpcProtocolError

#: A worker-side progress emitter: ``emit_progress(percent, phase)`` frames + sends one
#: ``$/progress`` notification on the session socket (ADR-030 Phase 1). Threaded into ``analyze``
#: ONLY when the request opted in; the default-path backend never receives one (byte-for-byte same).
ProgressEmitter = Callable[[int | None, str], None]

#: A worker-side partial-result emitter: ``emit_chunk(seq, kind, payload)`` frames + sends one
#: ``$/chunk`` notification on the session socket (ADR-040 Phase 2). Threaded into
#: ``start_decompile_stream`` so the backend streams one chunk per decompiled function BEFORE the
#: terminal response. ``payload`` is the plain (un-enveloped) unit — the server envelopes on
#: receipt; the worker never envelopes (rpc-protocol.md §4).
ChunkEmitter = Callable[[int, str, dict[str, Any]], None]

#: A worker-side cancel predicate: ``poll_cancel()`` returns ``True`` once a ``$/cancel``
#: notification for the in-flight streaming call has been observed (ADR-041). The dispatch builds
#: it bound to the session ``conn`` (a non-blocking poll); the JVM backend consults it BETWEEN
#: functions and stops production at the next boundary. The backend never touches the socket — it
#: only calls this plain callable (ADR-001 boundary: dispatch owns ``conn``).
CancelPoll = Callable[[], bool]

#: Worker-side minimum spacing between EMITTED progress frames (ADR-030 Phase 1). The worker
#: coalesces (drops) progress callbacks arriving sooner than this so a Ghidra ``TaskMonitor`` that
#: fires very frequently cannot flood the socket; the server ALSO bounds count/interval (defense in
#: depth — TB2/TB3). Independent of analysis correctness — dropping a frame only drops a heartbeat.
_WORKER_MIN_PROGRESS_INTERVAL_S = 0.25

# JSON-RPC error codes (rpc-protocol.md §5). Public so the JVM backend can raise WorkerError with
# the right code without importing private names.
CODE_INVALID_REQUEST = -32600
CODE_METHOD_NOT_FOUND = -32601
CODE_INVALID_PARAMS = -32602
CODE_NOT_FOUND = -32004
CODE_LIMIT_EXCEEDED = -32008
CODE_ANALYSIS_FAILED = -32010
CODE_INTERNAL = -32603

# Slug per code (the server maps these to public ErrorTypes).
_SLUG_BY_CODE = {
    CODE_INVALID_PARAMS: "invalid-params",
    CODE_NOT_FOUND: "not-found",
    CODE_LIMIT_EXCEEDED: "limit-exceeded",
    CODE_ANALYSIS_FAILED: "analysis-failed",
    CODE_INTERNAL: "internal-error",
}

#: Worker-facing RPC methods (rpc-protocol.md §4). Frozen allow-list — exactly these, no others.
RPC_METHODS = frozenset(
    {
        "import_binary",
        "analyze",
        "decompile_function",
        "disassemble",
        "get_pcode",
        "get_high_pcode",
        "stack_frame",
        "basic_blocks",
        "list_functions",
        "get_function",
        "xrefs_to",
        "xrefs_from",
        "list_strings",
        "list_symbols",
        "get_symbol",
        "list_data",
        "get_data_type",
        "get_comments",
        "memory_map",
        "read_bytes",
        "emulate",
        "demangle",
        "search_bytes",
        "search_strings",
        "program_metadata",
        # call-graph + naming-context extraction (v1.1 — ADR-007; worker-only, ADR-001)
        "call_graph",
        "referenced_strings",
        # Tier-2 metric extraction (v1.1 — ADR-008; worker-only, ADR-001)
        "function_cfg",
        "imports",
        "exports",
        "coverage",
        # Function ID library-match identification (v1.x — ADR-042 Phase 1; worker-only, ADR-001;
        # READ-ONLY — runs the FID service, no DB mutation).
        "identify_functions",
        # mutation (write) methods (v1.1 — ADR-012; worker-only, ADR-001; one txn per call, §4).
        # The server validates the name/address/comment-type as hostile input and checks write
        # consent BEFORE routing here (ADR-012 §3/§7); a rolled-back write maps to analysis-failed.
        "rename_function",
        "rename_symbol",
        "set_comment",
        "undo",
        # structural writes (v1.1 — ADR-013 Phase A; HighFunction path; gated by allow_structural)
        "rename_local_variable",
        "rename_parameter",
        # structural type-aware writes (v1.1 — ADR-014 Phase B; resolved TypeRefs, NO C parser)
        "set_function_signature",
        "apply_data_type",
        # bundled type-archive application (v1.8 — ADR-051; allow-listed GDT, no client path)
        "apply_type_archive",
        # composite-type creation (v1.1 — ADR-015 Phase C; resolved FieldSpec list, NO C parser)
        "define_struct",
        "define_union",
        # multi-type composite batch (v1.2 — ADR-021; pre-register ALL empties, one txn, rollback)
        "define_types",
        # composite deletion (v1.4 — ADR-031; delete-by-name, one txn, rollback; server gates which
        # names are session-authored — the worker only deletes the name the server authorized)
        "delete_type",
        # annotation persistence (v1.2 — ADR-018; export read-out ONLY — import is server-side
        # orchestration that replays the EXISTING write methods above, NO new import RPC).
        "export_annotations",
        # streaming bulk decompile (v1.x — ADR-040 Phase 2; worker-only, read-only/output-only per
        # ADR-001). ``start_decompile_stream`` is the long call that emits one ``$/chunk`` per
        # decompiled function then a terminal ``{total, truncated, done}`` response. It is aborted
        # mid-stream by the server→worker ``$/cancel`` control NOTIFICATION (ADR-041) the worker
        # polls for between functions — NOT a ``cancel_stream`` request method (ADR-041 superseded
        # it: a request would interleave a second request/response pair onto the streaming socket).
        "start_decompile_stream",
        "ping",
        "shutdown",
    }
)


class WorkerError(Exception):
    """A worker-side failure mapped to a JSON-RPC error with a safe slug.

    Attributes:
        code: JSON-RPC numeric code.
        safe_message: A message safe to cross the boundary (no host detail).
        detail: Optional **log-only**, **redacted** diagnostic (ADR-024 ``data.detail``) — it is
            logged by the server under a correlation id and **never reaches the client envelope**.
            Must already be free of binary-derived content (e.g. a fixed template + our own
            constants, never decompiled text / symbol names — master §5).
    """

    def __init__(self, code: int, safe_message: str, *, detail: str | None = None) -> None:
        """Initialize a worker error.

        Args:
            code: JSON-RPC numeric error code.
            safe_message: Boundary-safe message.
            detail: Optional redacted, log-only diagnostic (see the class docstring); defaults to
                ``None`` (no detail — unchanged behaviour for every existing call site).
        """
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message
        self.detail = detail


class GhidraBackend(Protocol):
    """The JVM-touching operations the dispatcher routes to (implemented only in the worker).

    Every method takes the request ``params`` (the tool schema minus ``session_id``) and returns a
    plain, JSON-serializable, **size-capped** dict matching the corresponding output schema. The
    concrete implementation (:class:`vivarium.ghidra._jvm_bridge.PyGhidraBackend`) is the sole
    JVM consumer; this Protocol lets the dispatcher be tested with a fake.
    """

    def import_binary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Import the binary into the worker's project."""
        ...

    def analyze(
        self, params: dict[str, Any], *, emit_progress: ProgressEmitter | None = None
    ) -> dict[str, Any]:
        """Run auto-analysis (bounded by the worker's own analysis budget).

        ``emit_progress`` is supplied by the dispatch ONLY when the request opted in (ADR-030
        Phase 1; ``params["progress"]`` truthy). When ``None`` (the default, and for every
        non-opted-in call) the backend runs the byte-for-byte unchanged analysis with no frames.
        """
        ...

    def decompile_function(self, params: dict[str, Any]) -> dict[str, Any]:
        """Decompile one function."""
        ...

    def disassemble(self, params: dict[str, Any]) -> dict[str, Any]:
        """Disassemble a bounded range or function."""
        ...

    def get_pcode(self, params: dict[str, Any]) -> dict[str, Any]:
        """List lifted low p-code for a bounded range or function — v1.8 (ADR-052)."""
        ...

    def get_high_pcode(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a function's decompiler-refined high (SSA) p-code — v1.8 (ADR-053)."""
        ...

    def stack_frame(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a function's recovered stack-frame layout — v1.8 (ADR-054)."""
        ...

    def basic_blocks(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a function's basic blocks + successor edges — v1.8 (ADR-055)."""
        ...

    def list_functions(self, params: dict[str, Any]) -> dict[str, Any]:
        """List functions (paginated/bounded)."""
        ...

    def get_function(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get one function's detail."""
        ...

    def xrefs_to(self, params: dict[str, Any]) -> dict[str, Any]:
        """References TO a target."""
        ...

    def xrefs_from(self, params: dict[str, Any]) -> dict[str, Any]:
        """References FROM a target."""
        ...

    def list_strings(self, params: dict[str, Any]) -> dict[str, Any]:
        """List defined strings (paginated/bounded)."""
        ...

    def list_symbols(self, params: dict[str, Any]) -> dict[str, Any]:
        """List symbols (paginated/bounded)."""
        ...

    def get_symbol(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve one symbol."""
        ...

    def list_data(self, params: dict[str, Any]) -> dict[str, Any]:
        """List defined data (paginated/bounded)."""
        ...

    def get_data_type(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve one data type."""
        ...

    def get_comments(self, params: dict[str, Any]) -> dict[str, Any]:
        """Read comments (paginated/bounded)."""
        ...

    def memory_map(self, params: dict[str, Any]) -> dict[str, Any]:
        """List memory blocks/segments."""
        ...

    def read_bytes(self, params: dict[str, Any]) -> dict[str, Any]:
        """Bounded raw byte read."""
        ...

    def emulate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Bounded p-code emulation (ADR-049)."""
        ...

    def demangle(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve a mangled C++ symbol to a readable name (ADR-050)."""
        ...

    def search_bytes(self, params: dict[str, Any]) -> dict[str, Any]:
        """Bounded byte-pattern search."""
        ...

    def search_strings(self, params: dict[str, Any]) -> dict[str, Any]:
        """Bounded defined-string search."""
        ...

    def program_metadata(self, params: dict[str, Any]) -> dict[str, Any]:
        """High-level program metadata."""
        ...

    def call_graph(self, params: dict[str, Any]) -> dict[str, Any]:
        """Extract the bounded call adjacency (resolved edges + unresolved callers) — v1.1."""
        ...

    def referenced_strings(self, params: dict[str, Any]) -> dict[str, Any]:
        """List the (bounded) defined-string values one function references — v1.1."""
        ...

    def function_cfg(self, params: dict[str, Any]) -> dict[str, Any]:
        """CFG block/edge counts for one function (for cyclomatic complexity) — v1.1."""
        ...

    def imports(self, params: dict[str, Any]) -> dict[str, Any]:
        """List imported symbols/functions (paginated/bounded) — v1.1."""
        ...

    def exports(self, params: dict[str, Any]) -> dict[str, Any]:
        """List exported symbols/entry points (paginated/bounded) — v1.1."""
        ...

    def coverage(self, params: dict[str, Any]) -> dict[str, Any]:
        """Defined-code/data byte counts for program coverage — v1.1."""
        ...

    def identify_functions(self, params: dict[str, Any]) -> dict[str, Any]:
        """Match functions against library FID databases (READ-ONLY) — v1.x (ADR-042)."""
        ...

    # --- mutation (write) operations (v1.1 — ADR-012; one transaction per call, §4) ---
    def rename_function(self, params: dict[str, Any]) -> dict[str, Any]:
        """Rename one function inside a transaction (commit / roll back on failure) — v1.1."""
        ...

    def rename_symbol(self, params: dict[str, Any]) -> dict[str, Any]:
        """Rename one data/label/global symbol inside a transaction — v1.1."""
        ...

    def set_comment(self, params: dict[str, Any]) -> dict[str, Any]:
        """Set or clear one comment at an address inside a transaction — v1.1."""
        ...

    def undo(self, params: dict[str, Any]) -> dict[str, Any]:
        """Undo the last committed mutation transaction in this session — v1.1."""
        ...

    # --- structural writes (v1.1 — ADR-013 Phase A; one transaction per call) ---
    def rename_local_variable(self, params: dict[str, Any]) -> dict[str, Any]:
        """Rename one function-local variable inside a transaction (name-only) — v1.1."""
        ...

    def rename_parameter(self, params: dict[str, Any]) -> dict[str, Any]:
        """Rename one function parameter inside a transaction (name-only) — v1.1."""
        ...

    # --- structural type-aware writes (v1.1 — ADR-014 Phase B; resolved TypeRefs, one txn) ---
    def set_function_signature(self, params: dict[str, Any]) -> dict[str, Any]:
        """Set a function's structured signature from resolved types inside a transaction — v1.1."""
        ...

    def apply_data_type(self, params: dict[str, Any]) -> dict[str, Any]:
        """Apply a resolvable type at an address inside a transaction — v1.1."""
        ...

    def apply_type_archive(self, params: dict[str, Any]) -> dict[str, Any]:
        """Apply a bundled Ghidra Data Type archive inside a transaction — v1.8 (ADR-051)."""
        ...

    # --- composite-type creation (v1.1 — ADR-015 Phase C; resolved FieldSpec list, one txn) ---
    def define_struct(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create a new struct from a resolved field list inside a transaction — v1.1."""
        ...

    def define_union(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create a new union from a resolved field list inside a transaction — v1.1."""
        ...

    # --- multi-type composite batch (v1.2 — ADR-021; pre-register all empties, one txn) ---
    def define_types(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create a batch of interdependent composites inside ONE transaction — v1.2."""
        ...

    # --- composite deletion (v1.4 — ADR-031; delete-by-name, one txn, rollback) ---
    def delete_type(self, params: dict[str, Any]) -> dict[str, Any]:
        """Delete a composite by name inside a transaction, reporting reverted dependents — v1.4."""
        ...

    # --- annotation persistence (v1.2 — ADR-018; export read-out ONLY) ---
    def export_annotations(self, params: dict[str, Any]) -> dict[str, Any]:
        """Export user-authored annotations, dependency-ordered, bounded — v1.2 / ADR-027.

        Read-only. Returns a plain ``{"schema_version", "binary": {...}, "entries": [...]}``.
        Symbols and signatures are enumerated by ``SourceType.USER_DEFINED`` (never auto-analysis).
        Comments and composites — which lack a reliable Ghidra provenance signal — are read ONLY for
        the server-supplied change-log selection (ADR-027 D4):
        ``params = {"targets": {"comments": [{address, comment_type}], "composites": [name]}}``.
        Over the entry cap → ``limit-exceeded``. Import adds NO worker method — it replays the
        existing write RPCs.
        """
        ...

    # --- streaming bulk decompile (v1.x — ADR-040 Phase 2; emits $/chunk per function) ---
    def start_decompile_stream(
        self,
        params: dict[str, Any],
        *,
        emit_chunk: ChunkEmitter | None = None,
        poll_cancel: CancelPoll | None = None,
    ) -> dict[str, Any]:
        """Stream a bounded bulk decompile, emitting one ``$/chunk`` per function — v1.x / ADR-040.

        Iterates the (optionally name-filtered) function set, decompiles each (disposing the
        decompiler per function — the ADR-002 memory discipline), and calls ``emit_chunk(seq,
        "function", payload)`` for each as it is produced (the dispatch supplies the socket-bound
        emitter). Returns a plain terminal ``{"total": int, "truncated": bool, "done": True}``
        AFTER the last chunk. Read-only/output-only (ADR-001). When ``emit_chunk`` is ``None`` (a
        fake/no-emitter path) the backend still produces no chunks — only the terminal summary.

        ``poll_cancel`` (ADR-041) is a dispatch-supplied predicate the backend consults BETWEEN
        functions: a non-blocking check for a ``$/cancel`` notification on the session socket. When
        it returns ``True`` the stream ends early at the next function boundary (the terminal
        summary reports the produced count). The backend calls a plain callable only — it NEVER
        touches the socket (ADR-001: dispatch owns ``conn``, the JVM backend owns Ghidra). When
        ``None`` (a fake/no-poll path) the stream runs to completion as before.
        """
        ...


def dispatch(
    backend: GhidraBackend,
    method: str,
    params: dict[str, Any],
    *,
    emit_progress: ProgressEmitter | None = None,
    emit_chunk: ChunkEmitter | None = None,
    poll_cancel: CancelPoll | None = None,
) -> dict[str, Any]:
    """Route one validated request to the backend; control methods are handled here.

    ``ping`` returns a liveness probe; ``shutdown`` is signaled to the loop by the server (not the
    backend). Both bypass the backend.

    The ``emit_progress`` callable (built by the loop, bound to the session socket) is forwarded to
    ``analyze`` ONLY when the request opted in (ADR-030 Phase 1: ``params["progress"]`` truthy). The
    ``emit_chunk`` callable (also socket-bound) and the ``poll_cancel`` predicate (ADR-041) are
    forwarded to ``start_decompile_stream`` so it can stream one ``$/chunk`` per function BEFORE its
    terminal response and stop early when a ``$/cancel`` notification arrives. For every other
    method — and for an ``analyze`` that did NOT opt in — the backend is called exactly as before
    (no emitter), so the default path is byte-for-byte unchanged.

    Args:
        backend: The JVM-touching backend.
        method: The RPC method name (already known to be in :data:`RPC_METHODS`).
        params: The request parameters.
        emit_progress: The socket-bound progress emitter from the loop, or ``None``.
        emit_chunk: The socket-bound partial-result emitter from the loop, or ``None``.
        poll_cancel: The socket-bound cancel predicate from the loop (ADR-041), or ``None``.

    Returns:
        The backend's plain result dict (or ``{"ok": true}`` for ``ping``).

    Raises:
        WorkerError: For a method-level failure (mapped to a JSON-RPC error by the loop).
    """
    if method == "ping":
        return {"ok": True}
    if method == "shutdown":
        return {"ok": True}
    handler = getattr(backend, method, None)
    if handler is None:  # defensive: method in allow-list but backend lacks it
        raise WorkerError(CODE_METHOD_NOT_FOUND, "method not implemented")
    if method == "analyze" and emit_progress is not None and _progress_opted_in(params):
        # Opted-in analyze: thread the socket-bound emitter so the backend's TaskMonitor can stream
        # bounded $/progress frames BEFORE the response (ADR-030 Phase 1). Keyword-only so a backend
        # that ignores it (or a fake) still satisfies the contract.
        analyzed: dict[str, Any] = backend.analyze(params, emit_progress=emit_progress)
        return analyzed
    if method == "start_decompile_stream":
        # Streaming bulk decompile: thread the socket-bound chunk emitter so the backend streams one
        # $/chunk per function BEFORE the terminal {total, truncated, done} response (ADR-040
        # Phase 2), and the poll_cancel predicate so it stops at the next function boundary on a
        # $/cancel notification (ADR-041). Keyword-only so a fake backend that ignores either still
        # satisfies the contract.
        streamed: dict[str, Any] = backend.start_decompile_stream(
            params, emit_chunk=emit_chunk, poll_cancel=poll_cancel
        )
        return streamed
    result: dict[str, Any] = handler(params)  # narrow the dynamic getattr result to the contract
    return result


def _progress_opted_in(params: dict[str, Any]) -> bool:
    """Return whether an ``analyze`` request opted into ``$/progress`` frames (ADR-030 Phase 1).

    Strict truthiness on the additive ``progress`` key: ONLY a literal ``True`` opts in; a missing
    key, ``False``, or any non-bool is treated as not-opted-in (fail safe — a malformed value can
    only ever DISABLE progress, never silently enable it). Pure; unit-tested.

    Args:
        params: The ``analyze`` request params.

    Returns:
        ``True`` only when ``params["progress"]`` is the boolean ``True``.
    """
    return params.get("progress") is True


def build_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response.

    Args:
        request_id: The originating request id.
        result: The result object.

    Returns:
        A JSON-RPC success response dict.
    """
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _redacted_detail(exc: BaseException) -> str:
    """Build a redacted, log-only diagnostic summary for an unexpected worker exception.

    STRICT SCRUB (ADR-024, master §5): the worker's exception *text* may be binary-derived (a JVM
    message can echo a symbol name, an address, or decompiled content from a hostile input), so it
    is treated as untrusted and is **never forwarded verbatim**. The summary is the exception
    **class name** plus a fixed template — enough to diagnose *which* JVM/Python exception class
    fired (e.g. ``NullPointerException``, ``ValidationError``) without leaking any value-bearing
    message. This crosses the worker→server boundary on the JSON-RPC error object's optional
    ``data.detail`` ONLY; it is log-only on the server and never reaches the client envelope.

    Args:
        exc: The unexpected exception caught at the dispatch boundary.

    Returns:
        A safe, fixed-template string: ``"<ExceptionClassName>: unhandled worker exception"``.
    """
    # type(exc).__name__ is the class name only (e.g. "NullPointerException") — no message, no
    # module path, no host detail. The free-form str(exc) is deliberately dropped.
    return f"{type(exc).__name__}: unhandled worker exception"


def build_error(
    request_id: Any, code: int, message: str, *, detail: str | None = None
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response with a safe slug and optional redacted detail.

    Args:
        request_id: The originating request id (may be ``None`` for unparseable requests).
        code: JSON-RPC numeric error code.
        message: Safe, boundary-crossing message (no host detail).
        detail: Optional **redacted** log-only diagnostic (ADR-024). When present it is added to
            the error object's ``data.detail`` for the server to log under a correlation id. It is
            server-side-only — the client-facing :class:`ErrorEnvelope` never carries it. MUST
            already be scrubbed of binary-derived content (see :func:`_redacted_detail`).

    Returns:
        A JSON-RPC error response dict.
    """
    slug = _SLUG_BY_CODE.get(code, "internal-error")
    data: dict[str, Any] = {"type": slug}
    if detail is not None:
        data["detail"] = detail
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message, "data": data},
    }


def handle_request(
    backend: GhidraBackend,
    obj: dict[str, Any],
    *,
    emit_progress: ProgressEmitter | None = None,
    emit_chunk: ChunkEmitter | None = None,
    poll_cancel: CancelPoll | None = None,
) -> dict[str, Any]:
    """Validate one decoded request and produce its response (success or error).

    Pure of socket I/O for the request/response itself (it returns the response object the loop
    frames); the optional ``emit_progress`` / ``emit_chunk`` / ``poll_cancel`` (built by the loop,
    bound to the session socket) are the only side-effecting collaborators — forwarded to
    :func:`dispatch` so an opted-in ``analyze`` can stream bounded ``$/progress`` frames (ADR-030
    Phase 1) and ``start_decompile_stream`` can stream ``$/chunk`` frames (ADR-040 Phase 2) BEFORE
    this response and stop early on a ``$/cancel`` (ADR-041). ``None`` (the default, and every other
    call) leaves the path byte-for-byte unchanged.

    Args:
        backend: The JVM-touching backend.
        obj: The decoded JSON-RPC request object.
        emit_progress: The socket-bound progress emitter from the loop, or ``None``.
        emit_chunk: The socket-bound partial-result emitter from the loop, or ``None``.
        poll_cancel: The socket-bound cancel predicate from the loop (ADR-041), or ``None``.

    Returns:
        The JSON-RPC response object to frame and send.
    """
    request_id = obj.get("id")
    if obj.get("jsonrpc") != "2.0" or not isinstance(request_id, str):
        return build_error(request_id, CODE_INVALID_REQUEST, "invalid request envelope")
    method = obj.get("method")
    params = obj.get("params", {})
    if not isinstance(method, str) or method not in RPC_METHODS:
        return build_error(request_id, CODE_METHOD_NOT_FOUND, "unknown method")
    if not isinstance(params, dict):
        return build_error(request_id, CODE_INVALID_PARAMS, "params must be an object")
    try:
        result = dispatch(
            backend,
            method,
            params,
            emit_progress=emit_progress,
            emit_chunk=emit_chunk,
            poll_cancel=poll_cancel,
        )
    except WorkerError as exc:
        # exc.detail (when set) is the redacted, log-only ADR-024 ``data.detail`` — the server logs
        # it under a correlation id; it never reaches the client envelope. Default None ⇒ no detail.
        return build_error(request_id, exc.code, exc.safe_message, detail=exc.detail)
    except (FramingError, RpcProtocolError, EOFError):
        # A wire-protocol/transport violation surfaced by the ADR-041 cancel poll (a non-$/cancel/
        # malformed/oversized frame, or a closed socket mid-frame, on the streaming socket — §6).
        # This is NOT a recoverable method error: it must propagate so ``serve_connection`` closes
        # the connection → kill + evict, exactly like a bad frame on the request read. Re-raise
        # BEFORE the generic Exception catch so it is not masked as a benign ``internal-error``
        # response (fail closed). (A select-level OSError is already converted to FramingError in
        # the poll, so it is covered here too.)
        raise
    except Exception as exc:
        # The client-facing message stays generic (no host/JVM detail crosses to the client).
        # The optional, redacted ``data.detail`` (class name + fixed template, NOT str(exc)) lets
        # the SERVER log *which* exception class fired so a real worker fault is diagnosable
        # (ADR-024 PR-1) — without forwarding any binary-derived exception text.
        return build_error(
            request_id, CODE_INTERNAL, "internal worker error", detail=_redacted_detail(exc)
        )
    return build_response(request_id, result)


def is_shutdown(obj: dict[str, Any]) -> bool:
    """Whether a decoded request is the control ``shutdown`` method.

    Args:
        obj: The decoded request object.

    Returns:
        ``True`` if the loop should exit after responding.
    """
    return obj.get("method") == "shutdown"


class _Conn(Protocol):
    """The minimal stream-socket surface the serve loop needs.

    ``recv``/``sendall`` carry the request/response + notification frames; ``fileno`` exposes the
    underlying descriptor for the non-blocking ``select`` the ADR-041 cancel poll uses to check
    whether a ``$/cancel`` frame is readable WITHOUT blocking the streaming producer.
    """

    def recv(self, bufsize: int) -> bytes:
        """Receive up to ``bufsize`` bytes."""
        ...

    def sendall(self, data: bytes) -> None:
        """Send all of ``data``."""
        ...

    def fileno(self) -> int:
        """Return the underlying file descriptor (for a non-blocking ``select`` readiness check)."""
        ...


def _recv_exact(conn: _Conn, n: int) -> bytes:
    """Receive exactly ``n`` bytes from a connection, raising EOFError on premature close.

    Args:
        conn: The connection.
        n: Number of bytes to read.

    Returns:
        Exactly ``n`` bytes.

    Raises:
        EOFError: If the peer closed before ``n`` bytes arrived.
    """
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise EOFError("peer closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(conn: _Conn, *, max_frame_bytes: int) -> dict[str, Any]:
    """Read one length-prefixed JSON-RPC frame from a connection.

    Args:
        conn: The connection.
        max_frame_bytes: Hard cap on the declared frame length.

    Returns:
        The decoded JSON object.

    Raises:
        FramingError: On a short/oversized declared frame.
        RpcProtocolError: On malformed JSON.
        EOFError: If the peer closed mid-frame.
    """
    prefix = _recv_exact(conn, rpc_framing.LENGTH_PREFIX_BYTES)
    n = rpc_framing.decode_length_prefix(prefix, max_frame_bytes=max_frame_bytes)
    body = _recv_exact(conn, n) if n else b""
    return rpc_framing.decode_body(body)


def _make_progress_emitter(
    conn: _Conn, request_id: str, *, max_frame_bytes: int
) -> ProgressEmitter:
    """Build a socket-bound ``$/progress`` emitter for one request (ADR-030 Phase 1).

    The returned ``emit_progress(percent, phase)`` frames a ``$/progress`` notification (correlated
    to ``request_id``) and sends it on ``conn``, BEFORE the request's eventual response. It is the
    worker side of the additive protocol and carries the SAFE percent + closed-vocabulary phase ONLY
    — the caller (the backend's ``TaskMonitor`` bridge) MUST already have mapped any Ghidra state to
    a closed phase; no binary-derived ``TaskMonitor`` text is ever passed here (master §5).

    Bounds (defense in depth — the server also bounds count/interval): the emitter COALESCES (drops)
    a call arriving sooner than :data:`_WORKER_MIN_PROGRESS_INTERVAL_S` after the last EMITTED one,
    and silently swallows a send error / an out-of-vocabulary phase (a progress heartbeat must never
    crash analysis or leak — :func:`rpc_framing.build_progress` validates the phase and raises
    ``ValueError`` on a bad one, which is caught here and dropped).

    Args:
        conn: The session connection to send frames on.
        request_id: The id of the request these frames correlate to.
        max_frame_bytes: Hard frame cap (shared §3 cap).

    Returns:
        A ``emit_progress(percent, phase)`` callable.
    """
    state = {"last_emit": None}  # type: dict[str, float | None]

    def emit_progress(percent: int | None, phase: str) -> None:
        now = time.monotonic()
        last = state["last_emit"]
        if last is not None and (now - last) < _WORKER_MIN_PROGRESS_INTERVAL_S:
            return  # coalesce: too soon since the last emitted frame
        try:
            notification = rpc_framing.build_progress(request_id, percent, phase)
            frame = rpc_framing.encode_frame(notification, max_frame_bytes=max_frame_bytes)
            conn.sendall(frame)
        except (ValueError, FramingError, OSError):
            # A heartbeat must never crash analysis: an invalid phase (ValueError), an over-cap
            # frame (FramingError — impossible for a tiny progress frame, but defensive), or a
            # transient socket error are all swallowed (the response/EOF path still governs).
            return
        state["last_emit"] = now

    return emit_progress


def _make_chunk_emitter(conn: _Conn, request_id: str, *, max_frame_bytes: int) -> ChunkEmitter:
    """Build a socket-bound ``$/chunk`` emitter for one streaming request (ADR-040 Phase 2).

    The returned ``emit_chunk(seq, kind, payload)`` frames a ``$/chunk`` notification (correlated to
    ``request_id``) and sends it on ``conn``, BEFORE the streaming call's terminal response. It is
    the worker side of the additive partial-result protocol.

    Unlike the progress emitter, it does **NOT** coalesce or swallow: every chunk MUST be delivered
    in ``seq`` order with no drop or reorder (ADR-040 D5 — backpressure is a pause via UDS flow
    control, never shedding). A frame is sent unconditionally; if the build/send fails the
    exception propagates to the streaming backend, which surfaces it as a terminal error (an honest
    end — ADR-005), never a silently truncated success.

    Args:
        conn: The session connection to send frames on.
        request_id: The id of the streaming request these chunks correlate to.
        max_frame_bytes: Hard frame cap (shared §3 cap).

    Returns:
        An ``emit_chunk(seq, kind, payload)`` callable.
    """

    def emit_chunk(seq: int, kind: str, payload: dict[str, Any]) -> None:
        # build_chunk asserts kind ∈ vocab + seq ≥ 0 (loud on a coding mistake); encode_frame
        # enforces the shared size cap; sendall pushes the frame (UDS flow control applies the
        # backpressure pause naturally when the server stops reading). No coalesce, no swallow.
        notification = rpc_framing.build_chunk(request_id, seq, kind, payload)
        frame = rpc_framing.encode_frame(notification, max_frame_bytes=max_frame_bytes)
        conn.sendall(frame)

    return emit_chunk


def _make_cancel_poll(conn: _Conn, request_id: str, *, max_frame_bytes: int) -> CancelPoll:
    """Build a non-blocking ``$/cancel`` poll for one streaming request (ADR-041).

    The returned ``poll_cancel()`` is consulted by the streaming backend BETWEEN functions. It does
    a **non-blocking** ``select`` on ``conn``; if nothing is readable it returns ``False`` at once
    (the common case — negligible per-boundary cost, ADR-041 D2). If the socket IS readable it reads
    **exactly one** framed control notification (subject to the shared §3 size cap) and:

    - a ``$/cancel`` for THIS ``request_id`` → ``True`` (and it stays ``True`` thereafter — the
      cancel latches so a later boundary need not re-read);
    - a ``$/cancel`` for an unknown/other id → ``False`` (a safe no-op — ADR-041 D6);
    - **anything else** on the stream socket server→worker (a non-``$/cancel`` frame, a malformed/
      oversized frame, or a closed socket) → a §6 protocol violation: the exception propagates, the
      streaming call aborts, and ``serve_connection`` returns so the worker exits and is evicted
      (kill + evict — the universal failure handler, ADR-041 D4).

    Non-blocking guarantee (ADR-041 D4): the producer is only ever made to read once ``select``
    reports the socket readable, and then for at most one small control frame. A ``$/cancel`` is a
    tiny (~60-byte) frame, so once any of it is readable the whole frame is realistically already in
    the kernel buffer; the bounded ``read_frame`` completes it without meaningfully blocking. A
    truly partial frame (only the prefix readable, no body yet) is the pathological case — it would
    block for the few remaining bytes of one tiny frame; the §3 cap bounds the read, and a peer that
    declares a body it never sends trips the kill-on-deadline backstop (§6).

    Args:
        conn: The session connection to poll (dispatch owns it; the backend never sees it).
        request_id: The id of the in-flight streaming request a ``$/cancel`` must correlate to.
        max_frame_bytes: Hard frame cap (shared §3 cap; bounds the one control-frame read).

    Returns:
        A ``poll_cancel() -> bool`` predicate (latches ``True`` once this stream is cancelled).
    """
    state = {"cancelled": False}  # type: dict[str, bool]

    def poll_cancel() -> bool:
        if state["cancelled"]:
            return True  # latched: a prior boundary already saw the cancel
        # Non-blocking readiness check: 0 timeout → return immediately. If the socket is not
        # readable there is no pending control frame, so there is nothing to cancel right now.
        try:
            readable, _, _ = select.select([conn.fileno()], [], [], 0)
        except (OSError, ValueError):
            # A closed/invalid descriptor surfaced as a select error: treat as a transport failure
            # → let the streaming path end (the loop returns; the server evicts).
            raise FramingError("cancel poll: socket select failed") from None
        if not readable:
            return False
        # Readable: read exactly one framed control notification. read_frame enforces the §3 cap and
        # raises FramingError/RpcProtocolError/EOFError on a bad/oversized/closed frame — those are
        # §6 protocol violations that propagate to serve_connection (kill + evict).
        frame = read_frame(conn, max_frame_bytes=max_frame_bytes)
        if not rpc_framing.is_cancel_notification(frame):
            # Any non-$/cancel frame on the stream socket server→worker is a protocol violation
            # (only $/cancel is valid here mid-stream) → fail closed (ADR-041 D4).
            raise RpcProtocolError("unexpected non-$/cancel frame on the streaming socket")
        cancel = rpc_framing.parse_cancel(frame, expected_id=request_id)
        if cancel.request_id == request_id:
            state["cancelled"] = True
            return True
        return False  # a cancel for an unknown/other id is a safe no-op (ADR-041 D6)

    return poll_cancel


def serve_connection(conn: _Conn, backend: GhidraBackend, *, max_frame_bytes: int) -> None:
    """Serve requests on one accepted connection until shutdown/EOF/protocol error.

    The server is the worker's sole client (one connection per session). On a framing/protocol
    violation or EOF the loop returns; the worker then exits (the server treats a closed socket as
    worker-unavailable and evicts — rpc-protocol.md §6).

    For an opted-in ``analyze`` (ADR-030 Phase 1) a per-request, socket-bound progress emitter is
    built and threaded through :func:`handle_request`; for ``start_decompile_stream`` (ADR-040
    Phase 2) a socket-bound chunk emitter AND a non-blocking ``$/cancel`` poll (ADR-041) are built
    instead. The backend calls the relevant emitter to stream bounded ``$/progress`` / ``$/chunk``
    frames BEFORE the response, and consults the poll between functions to stop early on a cancel.
    Every other request path is unchanged.

    Args:
        conn: The accepted stream connection.
        backend: The JVM-touching backend.
        max_frame_bytes: Hard frame cap (both directions).
    """
    while True:
        try:
            obj = read_frame(conn, max_frame_bytes=max_frame_bytes)
        except (FramingError, RpcProtocolError, EOFError, OSError):
            return  # close the connection; worker will exit and be evicted by the server
        emitter: ProgressEmitter | None = None
        chunk_emitter: ChunkEmitter | None = None
        cancel_poll: CancelPoll | None = None
        method = obj.get("method")
        request_id = obj.get("id")
        if method == "analyze" and isinstance(request_id, str):
            # Build the emitter for any analyze with a valid id; dispatch only USES it when the
            # request actually opted in (_progress_opted_in), so building it unconditionally here is
            # cheap and keeps the opt-in decision in one place.
            emitter = _make_progress_emitter(conn, request_id, max_frame_bytes=max_frame_bytes)
        elif method == "start_decompile_stream" and isinstance(request_id, str):
            chunk_emitter = _make_chunk_emitter(conn, request_id, max_frame_bytes=max_frame_bytes)
            # ADR-041: the poll reads from the SAME conn between functions; only this streaming call
            # is in flight, so the socket carries nothing but a possible $/cancel until it returns.
            cancel_poll = _make_cancel_poll(conn, request_id, max_frame_bytes=max_frame_bytes)
        try:
            response = handle_request(
                backend,
                obj,
                emit_progress=emitter,
                emit_chunk=chunk_emitter,
                poll_cancel=cancel_poll,
            )
        except (FramingError, RpcProtocolError, EOFError, OSError):
            # A protocol/transport violation surfaced by the cancel poll mid-stream (ADR-041 D4):
            # close the connection so the worker exits and is evicted (kill + evict). This mirrors
            # the read_frame guard above for a bad frame on the streaming socket.
            return
        try:
            frame = rpc_framing.encode_frame(response, max_frame_bytes=max_frame_bytes)
            conn.sendall(frame)
        except (FramingError, OSError):
            return
        if is_shutdown(obj):
            return
