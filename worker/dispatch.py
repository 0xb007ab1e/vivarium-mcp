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
        # call-graph adjacency extraction (v1.1 — ADR-007; worker-only graph extraction, ADR-001)
        "call_graph",
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


def build_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response with a safe slug.

    Args:
        request_id: The originating request id (may be ``None`` for unparseable requests).
        code: JSON-RPC numeric error code.
        message: Safe, boundary-crossing message (no host detail).

    Returns:
        A JSON-RPC error response dict.
    """
    slug = _SLUG_BY_CODE.get(code, "internal-error")
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message, "data": {"type": slug}},
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
    except Exception:
        return build_error(request_id, CODE_INTERNAL, "internal worker error")
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
