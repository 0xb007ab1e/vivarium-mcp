"""Unit tests for the worker RPC adapter, framing codec, and JVM-free worker dispatch (WS2).

These cover trust boundary 2 (server ↔ worker) without a real Ghidra worker: a real connected UDS
pair (``socket.socketpair``) plays the worker, and a fake :class:`worker.dispatch.GhidraBackend`
exercises the dispatch/framing path. Assertions:

- length-prefixed JSON-RPC round-trip (encode → decode → parse);
- oversized declared frame → ``FramingError`` and adapter kills the worker;
- per-call timeout → adapter SIGKILLs the worker, ``timeout`` envelope;
- worker crash / closed socket mid-call → ``worker-unavailable`` + kill;
- worker JSON-RPC error response → mapped to the public error type (worker NOT killed);
- worker method allow-list + safe-error mapping in the dispatcher.

No real worker, no Ghidra, no network.
"""

from __future__ import annotations

import socket
import threading

import pytest
from worker import dispatch

from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.ghidra import rpc_framing
from ghidra_mcp.ghidra.rpc_client import RpcGhidraAdapter
from ghidra_mcp.tools import schemas as s

_CAP = 4 * 1024 * 1024


class _FakeWorker:
    """A fake worker process handle that records whether it was killed."""

    def __init__(self) -> None:
        """Initialize a live, un-killed fake worker."""
        self.killed = 0
        self._alive = True

    def kill(self) -> None:
        """Record a kill and mark dead."""
        self.killed += 1
        self._alive = False

    def is_alive(self) -> bool:
        """Whether the fake worker is still alive."""
        return self._alive


class _ConnectedAdapter(RpcGhidraAdapter):
    """Adapter whose ``_ensure_connected`` returns a pre-wired socket (a socketpair end)."""

    def __init__(self, *, server_sock: socket.socket, **kw: object) -> None:
        """Initialize with the server-side end of a connected socket pair.

        Args:
            server_sock: The socket the adapter should use as if connected to the worker.
            **kw: Forwarded to :class:`RpcGhidraAdapter`.
        """
        super().__init__(**kw)  # type: ignore[arg-type]
        self._wired = server_sock

    def _ensure_connected(self, sess: object) -> socket.socket:  # type: ignore[override]
        """Return the pre-wired socket instead of dialing a real UDS.

        Args:
            sess: The per-session state (unused).

        Returns:
            The pre-wired socket.
        """
        sess.sock = self._wired  # type: ignore[attr-defined]
        return self._wired


def _make_adapter(server_sock: socket.socket, worker: _FakeWorker) -> _ConnectedAdapter:
    """Build an adapter wired to ``server_sock`` with a fake worker registered for ``sid="s"``.

    Args:
        server_sock: The adapter's end of the connected pair.
        worker: The fake worker handle to register.

    Returns:
        A ready adapter with a live session ``"s"``.
    """
    adapter = _ConnectedAdapter(
        server_sock=server_sock,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/ghidra-mcp-test",
        tool_timeout_s=0.5,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    adapter.start_worker("s")
    return adapter


# --- framing codec ----------------------------------------------------------------------------
def test_framing_round_trip() -> None:
    req = rpc_framing.build_request("id1", "ping", {})
    frame = rpc_framing.encode_frame(req, max_frame_bytes=_CAP)
    assert len(frame) >= rpc_framing.LENGTH_PREFIX_BYTES
    prefix, body = frame[:4], frame[4:]
    n = rpc_framing.decode_length_prefix(prefix, max_frame_bytes=_CAP)
    assert n == len(body)
    obj = rpc_framing.decode_body(body)
    assert obj["method"] == "ping" and obj["id"] == "id1"


def test_decode_length_prefix_rejects_oversized() -> None:
    import struct

    prefix = struct.pack(">I", _CAP + 1)
    with pytest.raises(rpc_framing.FramingError):
        rpc_framing.decode_length_prefix(prefix, max_frame_bytes=_CAP)


def test_decode_length_prefix_rejects_short_prefix() -> None:
    with pytest.raises(rpc_framing.FramingError):
        rpc_framing.decode_length_prefix(b"\x00\x00", max_frame_bytes=_CAP)


def test_encode_frame_rejects_oversized_body() -> None:
    with pytest.raises(rpc_framing.FramingError):
        rpc_framing.encode_frame({"x": "y" * 100}, max_frame_bytes=4)


def test_decode_body_rejects_malformed_json() -> None:
    with pytest.raises(rpc_framing.RpcProtocolError):
        rpc_framing.decode_body(b"{not json")


def test_decode_body_rejects_non_object() -> None:
    with pytest.raises(rpc_framing.RpcProtocolError):
        rpc_framing.decode_body(b"[1,2,3]")


def test_parse_response_id_mismatch() -> None:
    obj = {"jsonrpc": "2.0", "id": "other", "result": {}}
    with pytest.raises(rpc_framing.RpcProtocolError):
        rpc_framing.parse_response(obj, expected_id="mine")


def test_parse_response_both_result_and_error() -> None:
    obj = {"jsonrpc": "2.0", "id": "x", "result": {}, "error": {"code": -1, "message": "m"}}
    with pytest.raises(rpc_framing.RpcProtocolError):
        rpc_framing.parse_response(obj, expected_id="x")


def test_parse_response_error_carries_slug() -> None:
    obj = {
        "jsonrpc": "2.0",
        "id": "x",
        "error": {"code": -32004, "message": "nope", "data": {"type": "not-found"}},
    }
    with pytest.raises(rpc_framing.RpcCallError) as ei:
        rpc_framing.parse_response(obj, expected_id="x")
    assert ei.value.error.type_slug == "not-found"


# --- adapter call semantics -------------------------------------------------------------------
def _serve_one(worker_sock: socket.socket, response: dict[str, object]) -> None:
    """Read one framed request and reply with ``response`` (echoing the request id)."""
    obj = dispatch.read_frame(worker_sock, max_frame_bytes=_CAP)
    response = {**response, "id": obj["id"]}
    worker_sock.sendall(rpc_framing.encode_frame(response, max_frame_bytes=_CAP))


def test_call_success_round_trip() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    result = {
        "session_id": "s",
        "state": "ready",
        "created_at": 1,
        "expires_at": 2,
        "binary_sha256": None,
    }
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    info = adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", timeout_seconds=1))
    t.join(timeout=2)
    assert info.state == "ready"
    assert worker.killed == 0  # success never kills
    wrk.close()


def test_worker_error_response_maps_and_does_not_kill() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    err = {
        "jsonrpc": "2.0",
        "error": {"code": -32004, "message": "no fn", "data": {"type": "not-found"}},
    }
    t = threading.Thread(target=_serve_one, args=(wrk, err), daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.NOT_FOUND
    assert worker.killed == 0  # a healthy worker returning a method error is NOT killed
    wrk.close()


def test_timeout_kills_worker() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    # No thread answers → the recv times out (tool_timeout_s=0.5).
    with pytest.raises(GhidraMcpError) as ei:
        adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    assert ei.value.envelope.type is ErrorType.TIMEOUT
    assert ei.value.envelope.retryable is True
    assert worker.killed == 1  # SIGKILL on deadline expiry (no graceful wait)
    wrk.close()


def test_oversized_declared_frame_kills_worker() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    # Small-but-usable cap: requests fit, but the worker declares a far-larger inbound frame.
    cap = 1024
    adapter = _ConnectedAdapter(
        server_sock=srv,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/x",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=cap,
    )
    adapter.start_worker("s")

    def _serve_oversized() -> None:
        import struct

        dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        # Declare a body far above the adapter's cap; the adapter must reject BEFORE allocating.
        wrk.sendall(struct.pack(">I", cap + 1_000_000) + b"{")

    t = threading.Thread(target=_serve_oversized, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.read_bytes("s", s.ReadBytesIn(session_id="s", address="0x1000", length=16))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1
    wrk.close()


def test_worker_crash_mid_call_is_unavailable_and_kills() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _crash() -> None:
        dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        wrk.close()  # close mid-call → EOF on the adapter's read

    t = threading.Thread(target=_crash, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.list_functions("s", s.ListFunctionsIn(session_id="s"))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1


def test_call_without_worker_is_unavailable() -> None:
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/tmp/x",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    with pytest.raises(GhidraMcpError) as ei:
        adapter.memory_map("ghost", s.MemoryMapIn(session_id="ghost"))
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_kill_worker_is_idempotent() -> None:
    worker = _FakeWorker()
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/x",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    adapter.start_worker("s")
    adapter.start_worker("s")  # idempotent spawn
    adapter.kill_worker("s")
    adapter.kill_worker("s")  # idempotent kill (no error, no double-kill of a dropped session)
    assert worker.killed == 1


def test_socket_path_uses_session_id() -> None:
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/run/ghidra-mcp/",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    assert adapter._socket_path("abc") == "/run/ghidra-mcp/abc.sock"


# --- worker dispatcher (JVM-free) -------------------------------------------------------------
class _FakeBackend:
    """A fake :class:`worker.dispatch.GhidraBackend` recording calls and returning canned dicts."""

    def __init__(self) -> None:
        """Initialize with no recorded calls."""
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __getattr__(self, name: str):
        """Return a handler that records the call and echoes the method name."""

        def handler(params: dict[str, object]) -> dict[str, object]:
            self.calls.append((name, params))
            return {"method": name}

        return handler


def test_dispatch_ping_and_shutdown_bypass_backend() -> None:
    be = _FakeBackend()
    assert dispatch.dispatch(be, "ping", {}) == {"ok": True}
    assert dispatch.dispatch(be, "shutdown", {}) == {"ok": True}
    assert be.calls == []  # neither touched the backend


def test_handle_request_unknown_method() -> None:
    resp = dispatch.handle_request(_FakeBackend(), {"jsonrpc": "2.0", "id": "1", "method": "nope"})
    assert (
        resp["error"]["data"]["type"] == "internal-error"
        or resp["error"]["code"] == dispatch.CODE_METHOD_NOT_FOUND
    )


def test_handle_request_bad_envelope() -> None:
    resp = dispatch.handle_request(_FakeBackend(), {"id": "1", "method": "ping"})
    assert resp["error"]["code"] == dispatch.CODE_INVALID_REQUEST


def test_handle_request_non_dict_params() -> None:
    resp = dispatch.handle_request(
        _FakeBackend(), {"jsonrpc": "2.0", "id": "1", "method": "ping", "params": [1]}
    )
    assert resp["error"]["code"] == dispatch.CODE_INVALID_PARAMS


def test_handle_request_backend_worker_error_maps_slug() -> None:
    class _Boom:
        def list_strings(self, params: dict[str, object]) -> dict[str, object]:
            raise dispatch.WorkerError(dispatch.CODE_NOT_FOUND, "missing")

    resp = dispatch.handle_request(
        _Boom(), {"jsonrpc": "2.0", "id": "1", "method": "list_strings", "params": {}}
    )
    assert resp["error"]["data"]["type"] == "not-found"


def test_handle_request_unexpected_exception_is_internal_only() -> None:
    class _Boom:
        def memory_map(self, params: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("/secret/host/path leaked")  # must NOT cross the boundary

    resp = dispatch.handle_request(
        _Boom(), {"jsonrpc": "2.0", "id": "1", "method": "memory_map", "params": {}}
    )
    assert resp["error"]["code"] == dispatch.CODE_INTERNAL
    assert "secret" not in resp["error"]["message"]  # no host detail leaked


def test_handle_request_success() -> None:
    be = _FakeBackend()
    resp = dispatch.handle_request(
        be, {"jsonrpc": "2.0", "id": "9", "method": "program_metadata", "params": {}}
    )
    assert resp["result"] == {"method": "program_metadata"}
    assert resp["id"] == "9"


def test_serve_connection_round_trip_then_shutdown() -> None:
    a, b = socket.socketpair(socket.AF_UNIX)
    be = _FakeBackend()
    server_thread = threading.Thread(
        target=dispatch.serve_connection,
        args=(a,),
        kwargs={"backend": be, "max_frame_bytes": _CAP},
        daemon=True,
    )
    server_thread.start()
    # client: send a list_functions request, read the reply, then shutdown.
    b.sendall(
        rpc_framing.encode_frame(
            rpc_framing.build_request("r1", "list_functions", {"offset": 0}),
            max_frame_bytes=_CAP,
        )
    )
    reply = dispatch.read_frame(b, max_frame_bytes=_CAP)
    assert rpc_framing.parse_response(reply, expected_id="r1") == {"method": "list_functions"}
    b.sendall(
        rpc_framing.encode_frame(
            rpc_framing.build_request("r2", "shutdown", {}), max_frame_bytes=_CAP
        )
    )
    dispatch.read_frame(b, max_frame_bytes=_CAP)  # shutdown ack
    server_thread.join(timeout=2)
    assert not server_thread.is_alive()
    a.close()
    b.close()


def test_serve_connection_protocol_violation_closes() -> None:
    a, b = socket.socketpair(socket.AF_UNIX)
    be = _FakeBackend()
    server_thread = threading.Thread(
        target=dispatch.serve_connection,
        args=(a,),
        kwargs={"backend": be, "max_frame_bytes": 8},
        daemon=True,
    )
    server_thread.start()
    import struct

    b.sendall(struct.pack(">I", 1_000_000) + b"x")  # declared length over the 8-byte cap
    server_thread.join(timeout=2)
    assert not server_thread.is_alive()  # loop returned on FramingError
    a.close()
    b.close()
