"""JVM-free RPC dispatch + server loop for the Ghidra worker (WS2).

This module is the worker's *imperative shell* around a JVM-touching *backend*. It is deliberately
JVM-free: it speaks the frozen length-prefixed JSON-RPC protocol (via
:mod:`ghidra_mcp.ghidra.rpc_framing`), validates each request against the worker-facing method
allow-list, and routes to a :class:`GhidraBackend` whose concrete implementation
(:mod:`ghidra_mcp.ghidra._jvm_bridge`) is the only code that loads the JVM.

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

from typing import Any, Protocol

from ghidra_mcp.ghidra import rpc_framing
from ghidra_mcp.ghidra.rpc_framing import FramingError, RpcProtocolError

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
        # composite-type creation (v1.1 — ADR-015 Phase C; resolved FieldSpec list, NO C parser)
        "define_struct",
        "define_union",
        # multi-type composite batch (v1.2 — ADR-021; pre-register ALL empties, one txn, rollback)
        "define_types",
        # annotation persistence (v1.2 — ADR-018; export read-out ONLY — import is server-side
        # orchestration that replays the EXISTING write methods above, NO new import RPC).
        "export_annotations",
        "ping",
        "shutdown",
    }
)


class WorkerError(Exception):
    """A worker-side failure mapped to a JSON-RPC error with a safe slug.

    Attributes:
        code: JSON-RPC numeric code.
        safe_message: A message safe to cross the boundary (no host detail).
    """

    def __init__(self, code: int, safe_message: str) -> None:
        """Initialize a worker error.

        Args:
            code: JSON-RPC numeric error code.
            safe_message: Boundary-safe message.
        """
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message


class GhidraBackend(Protocol):
    """The JVM-touching operations the dispatcher routes to (implemented only in the worker).

    Every method takes the request ``params`` (the tool schema minus ``session_id``) and returns a
    plain, JSON-serializable, **size-capped** dict matching the corresponding output schema. The
    concrete implementation (:class:`ghidra_mcp.ghidra._jvm_bridge.PyGhidraBackend`) is the sole
    JVM consumer; this Protocol lets the dispatcher be tested with a fake.
    """

    def import_binary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Import the binary into the worker's project."""
        ...

    def analyze(self, params: dict[str, Any]) -> dict[str, Any]:
        """Run auto-analysis (bounded by the worker's own analysis budget)."""
        ...

    def decompile_function(self, params: dict[str, Any]) -> dict[str, Any]:
        """Decompile one function."""
        ...

    def disassemble(self, params: dict[str, Any]) -> dict[str, Any]:
        """Disassemble a bounded range or function."""
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

    # --- annotation persistence (v1.2 — ADR-018; export read-out ONLY) ---
    def export_annotations(self, params: dict[str, Any]) -> dict[str, Any]:
        """Enumerate the program's USER_DEFINED annotations, dependency-ordered, bounded — v1.2.

        Read-only. Returns a plain ``{"schema_version", "binary": {...}, "entries": [...]}`` of the
        program's user-defined annotations only (never auto-analysis output); over the entry cap →
        ``limit-exceeded``. Import adds NO worker method — it replays the existing write RPCs.
        """
        ...


def dispatch(backend: GhidraBackend, method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Route one validated request to the backend; control methods are handled here.

    ``ping`` returns a liveness probe; ``shutdown`` is signaled to the loop by the server (not the
    backend). Both bypass the backend.

    Args:
        backend: The JVM-touching backend.
        method: The RPC method name (already known to be in :data:`RPC_METHODS`).
        params: The request parameters.

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
    result: dict[str, Any] = handler(params)  # narrow the dynamic getattr result to the contract
    return result


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


def handle_request(backend: GhidraBackend, obj: dict[str, Any]) -> dict[str, Any]:
    """Validate one decoded request and produce its response (success or error).

    Pure (no I/O): takes the decoded JSON object, returns the response object. The loop frames it.

    Args:
        backend: The JVM-touching backend.
        obj: The decoded JSON-RPC request object.

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
        result = dispatch(backend, method, params)
    except WorkerError as exc:
        return build_error(request_id, exc.code, exc.safe_message)
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
    """The minimal stream-socket surface the serve loop needs (recv/sendall)."""

    def recv(self, bufsize: int) -> bytes:
        """Receive up to ``bufsize`` bytes."""
        ...

    def sendall(self, data: bytes) -> None:
        """Send all of ``data``."""
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


def serve_connection(conn: _Conn, backend: GhidraBackend, *, max_frame_bytes: int) -> None:
    """Serve requests on one accepted connection until shutdown/EOF/protocol error.

    The server is the worker's sole client (one connection per session). On a framing/protocol
    violation or EOF the loop returns; the worker then exits (the server treats a closed socket as
    worker-unavailable and evicts — rpc-protocol.md §6).

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
        response = handle_request(backend, obj)
        try:
            frame = rpc_framing.encode_frame(response, max_frame_bytes=max_frame_bytes)
            conn.sendall(frame)
        except (FramingError, OSError):
            return
        if is_shutdown(obj):
            return
