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
import socket
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from ghidra_mcp.core.envelope import DataOrigin, Untrusted, wrap
from ghidra_mcp.core.errors import ErrorType
from ghidra_mcp.ghidra import _errors, rpc_framing
from ghidra_mcp.ghidra.rpc_framing import (
    FramingError,
    RpcCallError,
    RpcProtocolError,
)
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
        return s.SessionInfo.model_validate(result)

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
        return s.SessionInfo.model_validate(result)

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
        return s.XrefsOut.model_validate(self._tool_call(sid, "xrefs_to", _xrefs_params(a)))

    def xrefs_from(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        """References FROM a target (addresses/ref-types are server-safe — no wrap needed)."""
        return s.XrefsOut.model_validate(self._tool_call(sid, "xrefs_from", _xrefs_params(a)))

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
            with contextlib.suppress(OSError):
                sess.sock.close()
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


def _build_decompiled(r: dict[str, Any]) -> s.DecompiledFunction:
    """Build :class:`DecompiledFunction`: name=BINARY; c_code/signature=GHIDRA."""
    return s.DecompiledFunction(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        c_code=_w(r["c_code"], DataOrigin.GHIDRA),
        signature=_w(r["signature"], DataOrigin.GHIDRA),
    )


def _build_instruction(r: dict[str, Any]) -> s.Instruction:
    """Build one :class:`Instruction`: mnemonic/operands=GHIDRA; bytes_hex=BINARY (hex)."""
    return s.Instruction(
        address=str(r["address"]),
        mnemonic=_w(r["mnemonic"], DataOrigin.GHIDRA),
        operands=_w(r["operands"], DataOrigin.GHIDRA),
        bytes_hex=_w(r["bytes_hex"], DataOrigin.BINARY, encoding="hex"),
    )


def _build_disassemble(r: dict[str, Any]) -> s.DisassembleOut:
    """Build :class:`DisassembleOut` from a plain result."""
    return s.DisassembleOut(
        instructions=[_build_instruction(i) for i in r.get("instructions", [])],
        truncated=bool(r.get("truncated", False)),
    )


def _build_function_summary(r: dict[str, Any]) -> s.FunctionSummary:
    """Build one :class:`FunctionSummary`: name=BINARY; size is safe."""
    return s.FunctionSummary(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        size=int(r["size"]),
    )


def _build_function_list(r: dict[str, Any]) -> s.FunctionListOut:
    """Build :class:`FunctionListOut` from a plain result."""
    return s.FunctionListOut(
        functions=[_build_function_summary(f) for f in r.get("functions", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


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


def _build_defined_string(r: dict[str, Any]) -> s.DefinedString:
    """Build one :class:`DefinedString`: value=BINARY (extracted, utf-8-replace)."""
    return s.DefinedString(
        address=str(r["address"]),
        value=_w(r["value"], DataOrigin.BINARY, encoding="utf-8-replace"),
        length=int(r["length"]),
    )


def _build_string_list(r: dict[str, Any]) -> s.StringListOut:
    """Build :class:`StringListOut` from a plain result."""
    return s.StringListOut(
        strings=[_build_defined_string(x) for x in r.get("strings", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


def _build_symbol(r: dict[str, Any]) -> s.Symbol:
    """Build one :class:`Symbol`: name/namespace=BINARY (extracted); kind is safe."""
    return s.Symbol(
        address=str(r["address"]),
        name=_w(r["name"], DataOrigin.BINARY),
        kind=str(r["kind"]),
        namespace=_w_opt(r.get("namespace"), DataOrigin.BINARY),
    )


def _build_symbol_list(r: dict[str, Any]) -> s.SymbolListOut:
    """Build :class:`SymbolListOut` from a plain result."""
    return s.SymbolListOut(
        symbols=[_build_symbol(x) for x in r.get("symbols", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


def _build_defined_data(r: dict[str, Any]) -> s.DefinedData:
    """Build one :class:`DefinedData`: data_type=GHIDRA (resolved); value_repr=BINARY."""
    return s.DefinedData(
        address=str(r["address"]),
        data_type=_w(r["data_type"], DataOrigin.GHIDRA),
        value_repr=_w(r["value_repr"], DataOrigin.BINARY),
        length=int(r["length"]),
    )


def _build_data_list(r: dict[str, Any]) -> s.DataListOut:
    """Build :class:`DataListOut` from a plain result."""
    return s.DataListOut(
        data=[_build_defined_data(x) for x in r.get("data", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


def _build_data_type(r: dict[str, Any]) -> s.DataType:
    """Build :class:`DataType`: name/definition=GHIDRA (resolved over hostile input)."""
    return s.DataType(
        name=_w(r["name"], DataOrigin.GHIDRA),
        kind=str(r["kind"]),
        size=int(r["size"]),
        definition=_w(r["definition"], DataOrigin.GHIDRA),
    )


def _build_comment(r: dict[str, Any]) -> s.Comment:
    """Build one :class:`Comment`: text=BINARY (extracted; planted-comment injection vector)."""
    return s.Comment(
        address=str(r["address"]),
        comment_type=str(r["comment_type"]),
        text=_w(r["text"], DataOrigin.BINARY),
    )


def _build_comment_list(r: dict[str, Any]) -> s.CommentListOut:
    """Build :class:`CommentListOut` from a plain result."""
    return s.CommentListOut(
        comments=[_build_comment(x) for x in r.get("comments", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


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


def _build_memory_map(r: dict[str, Any]) -> s.MemoryMapOut:
    """Build :class:`MemoryMapOut` from a plain result."""
    return s.MemoryMapOut(blocks=[_build_memory_block(b) for b in r.get("blocks", [])])


def _build_read_bytes(r: dict[str, Any]) -> s.ReadBytesOut:
    """Build :class:`ReadBytesOut`: data=BINARY (raw bytes, hex-encoded)."""
    return s.ReadBytesOut(
        address=str(r["address"]),
        data=_w(r["data"], DataOrigin.BINARY, encoding="hex"),
        length=int(r["length"]),
        truncated=bool(r.get("truncated", False)),
    )


def _build_byte_match(r: dict[str, Any]) -> s.ByteMatch:
    """Build one :class:`ByteMatch`: context_hex=BINARY (raw bytes, hex-encoded)."""
    return s.ByteMatch(
        address=str(r["address"]),
        context_hex=_w(r["context_hex"], DataOrigin.BINARY, encoding="hex"),
    )


def _build_search_bytes(r: dict[str, Any]) -> s.SearchBytesOut:
    """Build :class:`SearchBytesOut` from a plain result."""
    return s.SearchBytesOut(
        matches=[_build_byte_match(m) for m in r.get("matches", [])],
        total=int(r["total"]),
        truncated=bool(r.get("truncated", False)),
    )


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
