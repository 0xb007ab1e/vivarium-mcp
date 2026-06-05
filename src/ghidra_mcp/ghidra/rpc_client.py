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
"""

from __future__ import annotations

import socket
import uuid
from collections.abc import Callable
from typing import Any, Protocol

from ghidra_mcp.core.errors import ErrorType
from ghidra_mcp.ghidra import _errors, rpc_framing
from ghidra_mcp.ghidra.rpc_framing import (
    FramingError,
    RpcCallError,
    RpcProtocolError,
)
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
        connect_timeout_s: float = 30.0,
    ) -> None:
        """Initialize the adapter with injected runtime collaborators.

        Args:
            launcher: Callable that spawns a hardened worker bound to a session + socket path.
            socket_dir: Directory under which per-session UDS files live (``<dir>/<sid>.sock``).
            tool_timeout_s: Default per-tool-call wall-clock deadline.
            analysis_timeout_s: Per-analysis wall-clock deadline (kills worker on expiry).
            max_response_bytes: Hard frame cap; a declared length above this kills the worker.
            connect_timeout_s: How long to wait for the worker to bind/accept on its socket.
        """
        self._launcher = launcher
        self._socket_dir = socket_dir
        self._tool_timeout_s = tool_timeout_s
        self._analysis_timeout_s = analysis_timeout_s
        self._max_response_bytes = max_response_bytes
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
        try:
            sess.worker.kill()
        except Exception:
            pass

    def import_binary(self, session_id: str, args: s.SessionImportIn) -> s.SessionInfo:
        """Import the (size-checked) binary into the session's worker.

        Args:
            session_id: The session.
            args: Import arguments (size/digest already enforced server-side before this call).

        Returns:
            Updated :class:`SessionInfo`.
        """
        result = self._call(
            session_id,
            "import_binary",
            {"source_ref": args.source_ref, "expected_sha256": args.expected_sha256},
            timeout_s=self._tool_timeout_s,
        )
        return s.SessionInfo.model_validate(result)

    def analyze(self, session_id: str, args: s.SessionAnalyzeIn) -> s.SessionInfo:
        """Run Ghidra auto-analysis, bounded by the analysis timeout (kills worker on expiry).

        Args:
            session_id: The session.
            args: Analysis arguments (optional timeout override, already clamped by the server).

        Returns:
            Updated :class:`SessionInfo`.
        """
        deadline = float(args.timeout_seconds) if args.timeout_seconds else self._analysis_timeout_s
        result = self._call(
            session_id,
            "analyze",
            {"timeout_seconds": args.timeout_seconds},
            timeout_s=deadline,
        )
        return s.SessionInfo.model_validate(result)

    # --- read-only tool operations ----------------------------------------------------------
    def decompile_function(self, sid: str, a: s.DecompileFunctionIn) -> s.DecompiledFunction:
        """Decompile one function."""
        return s.DecompiledFunction.model_validate(
            self._tool_call(sid, "decompile_function", {"function": a.function})
        )

    def disassemble(self, sid: str, a: s.DisassembleIn) -> s.DisassembleOut:
        """Disassemble a bounded range or function."""
        return s.DisassembleOut.model_validate(
            self._tool_call(
                sid,
                "disassemble",
                {"start": a.start, "function": a.function, "max_instructions": a.max_instructions},
            )
        )

    def list_functions(self, sid: str, a: s.ListFunctionsIn) -> s.FunctionListOut:
        """List functions (paginated/bounded)."""
        return s.FunctionListOut.model_validate(
            self._tool_call(
                sid,
                "list_functions",
                {"offset": a.offset, "limit": a.limit, "name_contains": a.name_contains},
            )
        )

    def get_function(self, sid: str, a: s.GetFunctionIn) -> s.FunctionDetail:
        """Get one function's detail."""
        return s.FunctionDetail.model_validate(
            self._tool_call(sid, "get_function", {"function": a.function})
        )

    def xrefs_to(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References TO a target."""
        return s.XrefsOut.model_validate(self._tool_call(sid, "xrefs_to", _xrefs_params(a)))

    def xrefs_from(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References FROM a target."""
        return s.XrefsOut.model_validate(self._tool_call(sid, "xrefs_from", _xrefs_params(a)))

    def list_strings(self, sid: str, a: s.ListStringsIn) -> s.StringListOut:
        """List defined strings (paginated/bounded)."""
        return s.StringListOut.model_validate(
            self._tool_call(
                sid,
                "list_strings",
                {"offset": a.offset, "limit": a.limit, "min_length": a.min_length},
            )
        )

    def list_symbols(self, sid: str, a: s.ListSymbolsIn) -> s.SymbolListOut:
        """List symbols (paginated/bounded)."""
        return s.SymbolListOut.model_validate(
            self._tool_call(
                sid,
                "list_symbols",
                {"offset": a.offset, "limit": a.limit, "name_contains": a.name_contains},
            )
        )

    def get_symbol(self, sid: str, a: s.GetSymbolIn) -> s.Symbol:
        """Resolve one symbol."""
        return s.Symbol.model_validate(
            self._tool_call(sid, "get_symbol", {"identifier": a.identifier})
        )

    def list_data(self, sid: str, a: s.ListDataIn) -> s.DataListOut:
        """List defined data (paginated/bounded)."""
        return s.DataListOut.model_validate(
            self._tool_call(sid, "list_data", {"offset": a.offset, "limit": a.limit})
        )

    def get_data_type(self, sid: str, a: s.GetDataTypeIn) -> s.DataType:
        """Resolve one data type."""
        return s.DataType.model_validate(self._tool_call(sid, "get_data_type", {"name": a.name}))

    def get_comments(self, sid: str, a: s.GetCommentsIn) -> s.CommentListOut:
        """Read comments (paginated/bounded)."""
        return s.CommentListOut.model_validate(
            self._tool_call(
                sid,
                "get_comments",
                {"offset": a.offset, "limit": a.limit, "address": a.address},
            )
        )

    def memory_map(self, sid: str, a: s.MemoryMapIn) -> s.MemoryMapOut:
        """List memory blocks/segments."""
        return s.MemoryMapOut.model_validate(self._tool_call(sid, "memory_map", {}))

    def read_bytes(self, sid: str, a: s.ReadBytesIn) -> s.ReadBytesOut:
        """Bounded raw byte read."""
        return s.ReadBytesOut.model_validate(
            self._tool_call(sid, "read_bytes", {"address": a.address, "length": a.length})
        )

    def search_bytes(self, sid: str, a: s.SearchBytesIn) -> s.SearchBytesOut:
        """Bounded byte-pattern search."""
        return s.SearchBytesOut.model_validate(
            self._tool_call(
                sid,
                "search_bytes",
                {"pattern_hex": a.pattern_hex, "offset": a.offset, "limit": a.limit},
            )
        )

    def search_strings(self, sid: str, a: s.SearchStringsIn) -> s.SearchStringsOut:
        """Bounded defined-string search."""
        return s.SearchStringsOut.model_validate(
            self._tool_call(
                sid,
                "search_strings",
                {"query": a.query, "offset": a.offset, "limit": a.limit},
            )
        )

    def program_metadata(self, sid: str, a: s.ProgramMetadataIn) -> s.ProgramMetadata:
        """High-level program metadata."""
        return s.ProgramMetadata.model_validate(self._tool_call(sid, "program_metadata", {}))

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
            self.kill_worker(session_id)
            raise _errors.make_error(
                ErrorType.TIMEOUT, "operation exceeded its time limit"
            ) from exc
        except (FramingError, RpcProtocolError) as exc:
            # Hostile/buggy worker: protocol/framing violation → kill + evict.
            self.kill_worker(session_id)
            raise _errors.make_error(
                ErrorType.WORKER_UNAVAILABLE, "worker protocol violation"
            ) from exc
        except (ConnectionError, EOFError, OSError) as exc:
            # Crash / closed socket mid-call → kill + evict.
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
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._connect_timeout_s)
        sock.connect(sess.socket_path)
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
            try:
                sess.sock.close()
            except OSError:
                pass
            sess.sock = None

    def _socket_path(self, session_id: str) -> str:
        """Compute the per-session UDS path (``<socket_dir>/<sid>.sock``).

        Args:
            session_id: The opaque session id (CSPRNG-generated; safe as a filename component).

        Returns:
            The socket path string.
        """
        return f"{self._socket_dir.rstrip('/')}/{session_id}.sock"


def _xrefs_params(a: s.XrefsIn) -> dict[str, Any]:
    """Build the params dict for ``xrefs_to`` / ``xrefs_from``.

    Args:
        a: The xrefs input model.

    Returns:
        The RPC params dict.
    """
    return {"target": a.target, "offset": a.offset, "limit": a.limit}
