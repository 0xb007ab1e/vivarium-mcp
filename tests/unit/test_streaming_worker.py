"""Unit tests for the ADR-040/ADR-041 worker side (dispatch routing + chunk emitter + cancel poll).

Hermetic, JVM-free: the JVM-touching ``_gh_decompile_stream`` edge is NOT exercised here (it is
``# pragma: no cover`` and validated under live-regression). These cover the parts that are pure /
fake-able:

- **Allow-list:** ``start_decompile_stream`` is in the frozen ``RPC_METHODS`` and the superseded
  ``cancel_stream`` request method is NOT (ADR-041).
- **Dispatch routing:** ``start_decompile_stream`` is threaded the socket-bound chunk emitter AND
  the ``$/cancel`` poll (keyword-only) exactly like opted-in ``analyze`` is threaded the progress
  emitter; other methods never receive either.
- **The chunk emitter** (``_make_chunk_emitter``): emits a valid ``$/chunk`` frame; unlike the
  progress emitter it does NOT coalesce or swallow (every chunk delivered, errors propagate so the
  stream fails honestly).
- **The cancel poll** (``_make_cancel_poll``, ADR-041): a non-blocking poll over a real
  ``socketpair`` — returns ``False`` when nothing is readable, ``True`` (and latches) on a
  ``$/cancel`` for the in-flight id, ``False`` (no-op) for an unknown id, and raises a protocol
  violation on a non-``$/cancel``/malformed frame.
- **Loop stop:** a fake decompile edge that consults ``is_cancelled()`` between functions proves
  production stops at the next boundary once the poll reports cancelled, while an unknown-id cancel
  lets the stream complete.
- **Backend ``start_decompile_stream``:** param shaping (``functions`` vs window) with the JVM edge
  stubbed, and that ``poll_cancel`` is threaded down as ``is_cancelled``.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from typing import Any

import pytest
from worker import dispatch as wd

from vivarium.ghidra import rpc_framing as f
from vivarium.ghidra._jvm_bridge import PyGhidraBackend

_CAP = 4 * 1024 * 1024
_RID = "req-stream-1"


def _send_frame(sock: socket.socket, obj: dict[str, Any]) -> None:
    """Frame and send one JSON-RPC object on ``sock`` (test-side worker→server or server→worker)."""
    sock.sendall(f.encode_frame(obj, max_frame_bytes=_CAP))


def _send_raw_frame(sock: socket.socket, body: bytes) -> None:
    """Send a length-prefixed raw body (for malformed/oversized frame abuse paths)."""
    sock.sendall(struct.pack(">I", len(body)) + body)


# --- allow-list --------------------------------------------------------------------------------
def test_start_decompile_stream_in_allow_list() -> None:
    assert "start_decompile_stream" in wd.RPC_METHODS


def test_cancel_stream_method_removed_from_allow_list() -> None:
    """ADR-041 supersedes the cancel_stream REQUEST method with the $/cancel notification."""
    assert "cancel_stream" not in wd.RPC_METHODS


# --- dispatch routing of the chunk emitter + cancel poll ---------------------------------------
class _RecordingBackend:
    """Backend fake recording what ``start_decompile_stream`` got (emit_chunk + poll_cancel)."""

    def __init__(self) -> None:
        self.stream_emit: list[bool] = []
        self.stream_poll: list[bool] = []

    def start_decompile_stream(
        self, params: dict[str, Any], *, emit_chunk: Any = None, poll_cancel: Any = None
    ) -> dict[str, Any]:
        self.stream_emit.append(emit_chunk is not None)
        self.stream_poll.append(poll_cancel is not None)
        return {"total": 0, "truncated": False, "done": True}

    def __getattr__(self, name: str) -> Any:
        def _handler(params: dict[str, Any]) -> dict[str, Any]:
            return {"method": name}

        return _handler


def test_dispatch_threads_chunk_emitter_and_poll_into_start_decompile_stream() -> None:
    be = _RecordingBackend()

    def _emitter(seq: int, kind: str, payload: dict[str, Any]) -> None:
        return None

    def _poll() -> bool:
        return False

    wd.dispatch(be, "start_decompile_stream", {"limit": 3}, emit_chunk=_emitter, poll_cancel=_poll)
    wd.dispatch(be, "start_decompile_stream", {"limit": 3})  # neither built
    assert be.stream_emit == [True, False]
    assert be.stream_poll == [True, False]


def test_dispatch_non_stream_method_never_uses_chunk_emitter_or_poll() -> None:
    be = _RecordingBackend()
    called: list[tuple[int, str, dict[str, Any]]] = []
    polled: list[bool] = []

    def _record_emit(s: int, k: str, p: dict[str, Any]) -> None:
        called.append((s, k, p))

    def _record_poll() -> bool:
        polled.append(True)
        return False

    out = wd.dispatch(be, "list_functions", {}, emit_chunk=_record_emit, poll_cancel=_record_poll)
    assert out == {"method": "list_functions"}
    assert called == []
    assert polled == []


# --- the chunk emitter (_make_chunk_emitter) ---------------------------------------------------
class _RecordingConn:
    """A ``_Conn`` fake recording every frame sent (the worker's session socket)."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, _n: int) -> bytes:  # part of the _Conn protocol; unused by the emitter
        return b""

    def fileno(self) -> int:  # part of the _Conn protocol; unused by the emitter
        return -1


class _RaisingConn:
    """A ``_Conn`` fake whose ``sendall`` always raises ``OSError`` (transient socket error)."""

    def sendall(self, data: bytes) -> None:
        raise OSError("broken pipe")

    def recv(self, _n: int) -> bytes:  # part of the _Conn protocol; unused by the emitter
        return b""

    def fileno(self) -> int:  # part of the _Conn protocol; unused by the emitter
        return -1


def test_make_chunk_emitter_sends_a_valid_chunk_frame() -> None:
    conn = _RecordingConn()
    emit = wd._make_chunk_emitter(conn, _RID, max_frame_bytes=_CAP)
    payload = {"address": "0x401000", "name": "FUN_00401000", "c_code": "x", "signature": "y"}
    emit(0, "function", payload)
    assert len(conn.sent) == 1
    obj = json.loads(conn.sent[0][4:])  # strip the 4-byte length prefix
    assert f.is_chunk_notification(obj)
    assert obj["params"] == {"id": _RID, "seq": 0, "kind": "function", "payload": payload}


def test_make_chunk_emitter_does_not_coalesce_back_to_back() -> None:
    """Every chunk is delivered — no progress-style coalescing (ADR-040 D5: never shed)."""
    conn = _RecordingConn()
    emit = wd._make_chunk_emitter(conn, _RID, max_frame_bytes=_CAP)
    for i in range(5):
        emit(i, "function", {})
    assert len(conn.sent) == 5  # all five, none dropped


def test_make_chunk_emitter_raises_on_bad_kind() -> None:
    """An out-of-vocab kind is a coding mistake → build_chunk raises (NOT swallowed)."""
    conn = _RecordingConn()
    emit = wd._make_chunk_emitter(conn, _RID, max_frame_bytes=_CAP)
    with pytest.raises(ValueError, match="kind"):
        emit(0, "evil", {})


def test_make_chunk_emitter_propagates_send_error() -> None:
    """Unlike progress, a send failure PROPAGATES so the stream fails honestly (not silently)."""
    emit = wd._make_chunk_emitter(_RaisingConn(), _RID, max_frame_bytes=_CAP)
    with pytest.raises(OSError, match="broken pipe"):
        emit(0, "function", {})


# --- backend start_decompile_stream (JVM edge stubbed) -----------------------------------------
def test_backend_start_decompile_stream_windowed_params(monkeypatch: pytest.MonkeyPatch) -> None:
    be = PyGhidraBackend()
    seen: dict[str, Any] = {}

    def _fake_edge(
        names: list[str] | None,
        offset: int,
        limit: int,
        *,
        emit_chunk: Any,
        is_cancelled: Any,
    ) -> dict[str, Any]:
        seen.update({"names": names, "offset": offset, "limit": limit})
        return {"total": 0, "truncated": False, "done": True}

    monkeypatch.setattr(be, "_gh_decompile_stream", _fake_edge)
    out = be.start_decompile_stream({"offset": 5, "limit": 9}, emit_chunk=lambda s, k, p: None)
    assert out == {"total": 0, "truncated": False, "done": True}
    assert seen == {"names": None, "offset": 5, "limit": 9}


def test_backend_start_decompile_stream_explicit_functions(monkeypatch: pytest.MonkeyPatch) -> None:
    be = PyGhidraBackend()
    seen: dict[str, Any] = {}

    def _fake_edge(
        names: list[str] | None, offset: int, limit: int, *, emit_chunk: Any, is_cancelled: Any
    ) -> dict[str, Any]:
        seen["names"] = names
        return {"total": 2, "truncated": False, "done": True}

    monkeypatch.setattr(be, "_gh_decompile_stream", _fake_edge)
    be.start_decompile_stream({"functions": ["main", "0x401000"]}, emit_chunk=None)
    assert seen["names"] == ["main", "0x401000"]


def test_backend_start_decompile_stream_clamps_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """A huge requested limit is clamped to the result-count cap before the JVM edge (CWE-400)."""
    be = PyGhidraBackend()
    seen: dict[str, Any] = {}

    def _fake_edge(
        names: list[str] | None, offset: int, limit: int, *, emit_chunk: Any, is_cancelled: Any
    ) -> dict[str, Any]:
        seen["limit"] = limit
        return {"total": 0, "truncated": False, "done": True}

    monkeypatch.setattr(be, "_gh_decompile_stream", _fake_edge)
    be.start_decompile_stream({"limit": 10**9}, emit_chunk=None)
    assert seen["limit"] == 10_000  # _MAX_RESULT_COUNT


def test_backend_threads_poll_cancel_as_is_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    """The dispatch-supplied ``poll_cancel`` IS what the edge sees as ``is_cancelled`` (ADR-041)."""
    be = PyGhidraBackend()
    captured: dict[str, Any] = {}
    calls = {"n": 0}

    def _poll() -> bool:
        calls["n"] += 1
        return calls["n"] >= 2  # False the first time, True after

    def _fake_edge(
        names: list[str] | None, offset: int, limit: int, *, emit_chunk: Any, is_cancelled: Any
    ) -> dict[str, Any]:
        captured["first"] = is_cancelled()
        captured["second"] = is_cancelled()
        return {"total": 0, "truncated": False, "done": True}

    monkeypatch.setattr(be, "_gh_decompile_stream", _fake_edge)
    be.start_decompile_stream({"limit": 1}, emit_chunk=None, poll_cancel=_poll)
    assert captured == {"first": False, "second": True}  # the very poll passed is the predicate


def test_backend_no_poll_never_cancels(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no ``poll_cancel`` (fake path) the edge sees a constant-False predicate."""
    be = PyGhidraBackend()
    captured: dict[str, Any] = {}

    def _fake_edge(
        names: list[str] | None, offset: int, limit: int, *, emit_chunk: Any, is_cancelled: Any
    ) -> dict[str, Any]:
        captured["c1"] = is_cancelled()
        captured["c2"] = is_cancelled()
        return {"total": 0, "truncated": False, "done": True}

    monkeypatch.setattr(be, "_gh_decompile_stream", _fake_edge)
    be.start_decompile_stream({"limit": 1}, emit_chunk=None)  # no poll_cancel
    assert captured == {"c1": False, "c2": False}


def test_backend_no_longer_has_cancel_stream_method() -> None:
    """The superseded ``cancel_stream`` backend method + per-stream flag are gone (ADR-041)."""
    be = PyGhidraBackend()
    assert not hasattr(be, "cancel_stream")
    assert not hasattr(be, "_stream_cancelled")


# --- the cancel poll (_make_cancel_poll, ADR-041) ----------------------------------------------
# A real ``socket.socketpair`` plays the session connection: ``conn`` is the worker end the poll
# reads from (recv/sendall/fileno all satisfy the _Conn protocol directly); ``peer`` is the server
# end the test writes server→worker control frames to. select() reports the worker end readable iff
# the server has written something — exercising the real non-blocking path.


def test_cancel_poll_false_when_nothing_readable() -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)
        # Nothing written on the peer end → select sees the worker end not-readable → no cancel.
        assert poll() is False
        assert poll() is False  # still nothing — repeatedly safe
    finally:
        conn.close()
        peer.close()


def test_cancel_poll_true_and_latches_on_matching_cancel() -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        _send_frame(peer, f.build_cancel(_RID))
        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)
        assert poll() is True
        # Latched: a second call returns True WITHOUT reading the socket again (no frame pending).
        assert poll() is True
    finally:
        conn.close()
        peer.close()


def test_cancel_poll_noop_for_unknown_id() -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        _send_frame(peer, f.build_cancel("some-other-stream"))
        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)
        # A $/cancel for an unknown/other stream id is a safe no-op (ADR-041 D6).
        assert poll() is False
        # And it consumed exactly that one frame: with nothing else pending, still False.
        assert poll() is False
    finally:
        conn.close()
        peer.close()


def test_cancel_poll_rejects_non_cancel_frame_on_stream_socket() -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        # A $/chunk (or any non-$/cancel) frame arriving server→worker mid-stream is a §6 violation.
        _send_frame(peer, f.build_chunk(_RID, 0, "function", {}))
        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)
        with pytest.raises(f.RpcProtocolError):
            poll()
    finally:
        conn.close()
        peer.close()


def test_cancel_poll_rejects_a_request_frame_on_stream_socket() -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        # The former cancel_stream REQUEST shape (a method WITH a top-level id) is now rejected:
        # only the $/cancel notification is valid on the stream socket (ADR-041 supersession).
        _send_frame(peer, {"jsonrpc": "2.0", "id": "x", "method": "cancel_stream", "params": {}})
        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)
        with pytest.raises(f.RpcProtocolError):
            poll()
    finally:
        conn.close()
        peer.close()


def test_cancel_poll_rejects_malformed_json_frame() -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        _send_raw_frame(peer, b"{not valid json")
        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)
        with pytest.raises(f.RpcProtocolError):
            poll()
    finally:
        conn.close()
        peer.close()


def test_cancel_poll_raises_on_select_error_for_closed_conn() -> None:
    """A closed/invalid descriptor at select() is a transport failure → FramingError (evict)."""

    class _BadFdConn:
        def sendall(self, data: bytes) -> None: ...

        def recv(self, _n: int) -> bytes:
            return b""

        def fileno(self) -> int:
            return -1  # an invalid fd → select raises ValueError

    poll = wd._make_cancel_poll(_BadFdConn(), _RID, max_frame_bytes=_CAP)
    with pytest.raises(f.FramingError):
        poll()


def test_cancel_poll_rejects_oversized_frame() -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        # Declare a frame far above the (tiny) cap → decode_length_prefix raises FramingError
        # BEFORE any body is allocated (CWE-400 bound). Just the 4-byte prefix is enough to trip it.
        peer.sendall(struct.pack(">I", 999_999))
        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=1024)
        with pytest.raises(f.FramingError):
            poll()
    finally:
        conn.close()
        peer.close()


# --- the decompile loop stops at the next boundary once cancelled (the wiring contract) --------
# A fake edge faithfully mirrors the real ``_gh_decompile_stream`` loop shape: it checks
# ``is_cancelled()`` BEFORE each function and emits one chunk per produced function. Driving it via
# the backend (with a real socketpair-backed poll) proves a $/cancel stops production promptly,
# while an unknown-id cancel lets the bounded set complete. (The real edge is JVM-only / no-cover.)


def _loop_mimic_edge(
    n_functions: int,
) -> Any:
    """Build a fake ``_gh_decompile_stream`` that emits ``n_functions`` chunks, cancel-aware."""

    def _edge(
        names: list[str] | None,
        offset: int,
        limit: int,
        *,
        emit_chunk: Any,
        is_cancelled: Any,
    ) -> dict[str, Any]:
        seq = 0
        for _ in range(n_functions):
            if is_cancelled():
                return {"total": seq, "truncated": False, "done": True}
            if emit_chunk is not None:
                emit_chunk(seq, "function", {"address": f"0x{seq:08x}"})
            seq += 1
        return {"total": seq, "truncated": False, "done": True}

    return _edge


def test_loop_stops_at_next_boundary_on_matching_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        be = PyGhidraBackend()
        monkeypatch.setattr(be, "_gh_decompile_stream", _loop_mimic_edge(64))
        emitted: list[int] = []
        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)

        def _emit(seq: int, kind: str, payload: dict[str, Any]) -> None:
            emitted.append(seq)
            if seq == 0:
                # The client cancels after the first chunk: the server sends $/cancel server→worker.
                _send_frame(peer, f.build_cancel(_RID))

        out = be.start_decompile_stream({"limit": 64}, emit_chunk=_emit, poll_cancel=poll)
        # Production stopped at the NEXT boundary after the cancel landed — far fewer than 64.
        assert out["done"] is True
        assert out["total"] == len(emitted)
        assert len(emitted) < 64
        # Stopped within ~a function or two of the cancel (granularity = one function, ADR-041 D3).
        assert len(emitted) <= 2
    finally:
        conn.close()
        peer.close()


def test_loop_completes_on_unknown_id_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        be = PyGhidraBackend()
        monkeypatch.setattr(be, "_gh_decompile_stream", _loop_mimic_edge(5))
        emitted: list[int] = []

        def _emit(seq: int, kind: str, payload: dict[str, Any]) -> None:
            emitted.append(seq)
            if seq == 0:
                _send_frame(peer, f.build_cancel("not-this-stream"))  # a no-op cancel

        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)
        out = be.start_decompile_stream({"limit": 5}, emit_chunk=_emit, poll_cancel=poll)
        # An unknown-id cancel is ignored → the full bounded set completes.
        assert emitted == [0, 1, 2, 3, 4]
        assert out == {"total": 5, "truncated": False, "done": True}
    finally:
        conn.close()
        peer.close()


def test_loop_aborts_on_bad_control_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bad control frame mid-stream propagates out of the streaming call (→ kill + evict)."""
    conn, peer = socket.socketpair(socket.AF_UNIX)
    try:
        be = PyGhidraBackend()
        monkeypatch.setattr(be, "_gh_decompile_stream", _loop_mimic_edge(10))

        def _emit(seq: int, kind: str, payload: dict[str, Any]) -> None:
            if seq == 0:
                _send_frame(peer, f.build_chunk(_RID, 0, "function", {}))  # illegal server→worker

        poll = wd._make_cancel_poll(conn, _RID, max_frame_bytes=_CAP)
        with pytest.raises(f.RpcProtocolError):
            be.start_decompile_stream({"limit": 10}, emit_chunk=_emit, poll_cancel=poll)
    finally:
        conn.close()
        peer.close()


# --- handle_request maps a poll protocol violation to a propagating raise (kill + evict) --------
def test_handle_request_reraises_poll_protocol_violation(monkeypatch: pytest.MonkeyPatch) -> None:
    """A FramingError/RpcProtocolError from the poll escapes handle_request (NOT internal-error)."""
    be = PyGhidraBackend()

    def _edge(
        names: list[str] | None, offset: int, limit: int, *, emit_chunk: Any, is_cancelled: Any
    ) -> dict[str, Any]:
        is_cancelled()  # the poll raises here
        return {"total": 0, "truncated": False, "done": True}

    monkeypatch.setattr(be, "_gh_decompile_stream", _edge)

    def _bad_poll() -> bool:
        raise f.RpcProtocolError("bad control frame on the stream socket")

    req = {"jsonrpc": "2.0", "id": _RID, "method": "start_decompile_stream", "params": {"limit": 1}}
    with pytest.raises(f.RpcProtocolError):
        wd.handle_request(be, req, emit_chunk=lambda s, k, p: None, poll_cancel=_bad_poll)


def test_handle_request_normal_method_error_still_becomes_response() -> None:
    """A normal method-level error is STILL an error response (the re-raise is poll-specific)."""

    class _FailingBackend:
        def list_functions(self, params: dict[str, Any]) -> dict[str, Any]:
            raise wd.WorkerError(wd.CODE_NOT_FOUND, "nope")

        def __getattr__(self, name: str) -> Any:
            return lambda params: {"ok": True}

    req = {"jsonrpc": "2.0", "id": _RID, "method": "list_functions", "params": {}}
    resp = wd.handle_request(_FailingBackend(), req)
    assert resp["error"]["code"] == wd.CODE_NOT_FOUND


# --- serve_connection wires the poll into the streaming loop (the full worker loop) ------------
class _CancelAwareBackend:
    """A backend whose ``start_decompile_stream`` consults ``poll_cancel`` between functions.

    Stands in for the JVM edge so ``serve_connection``'s ADR-041 wiring (it builds the poll and
    threads it) is exercised end to end over a real socketpair, without a JVM.
    """

    def __init__(self, n_functions: int, *, gate: threading.Event | None = None) -> None:
        self.n_functions = n_functions
        #: Optional barrier: when set, the producer BLOCKS after emitting the first chunk until the
        #: test releases it. This makes the mid-stream control-frame tests deterministic — the test
        #: injects its $/cancel (or bad frame) into the socket and only THEN releases the producer,
        #: so the next between-functions poll is guaranteed to observe it (no scheduler race; the
        #: 3.14 scheduler exposed the prior race where the fast producer emitted all chunks first).
        self._gate = gate

    def start_decompile_stream(
        self, params: dict[str, Any], *, emit_chunk: Any = None, poll_cancel: Any = None
    ) -> dict[str, Any]:
        seq = 0
        for _ in range(self.n_functions):
            if poll_cancel is not None and poll_cancel():
                return {"total": seq, "truncated": False, "done": True}
            if emit_chunk is not None:
                emit_chunk(seq, "function", {"address": f"0x{seq:08x}"})
            seq += 1
            # Block after the first chunk until the test has injected its mid-stream control frame.
            if self._gate is not None and seq == 1:
                self._gate.wait(timeout=5.0)
        return {"total": seq, "truncated": False, "done": True}

    def __getattr__(self, name: str) -> Any:
        return lambda params: {"method": name}


def test_serve_connection_stops_stream_on_cancel_notification() -> None:
    """The full loop: a $/cancel sent server→worker mid-stream stops production early (ADR-041)."""
    a, b = socket.socketpair(socket.AF_UNIX)
    gate = threading.Event()
    be = _CancelAwareBackend(64, gate=gate)
    server = threading.Thread(
        target=wd.serve_connection,
        args=(a,),
        kwargs={"backend": be, "max_frame_bytes": _CAP},
        daemon=True,
    )
    server.start()
    try:
        # Start the stream, read the first chunk, then send the $/cancel — the worker loop's poll
        # picks it up at the next boundary and ends the stream early with a terminal summary. The
        # producer is gated after the first chunk so the $/cancel is in the socket before its next
        # poll (deterministic — no scheduler race).
        _send_frame(b, f.build_request("rid-stream", "start_decompile_stream", {"limit": 64}))
        first = wd.read_frame(b, max_frame_bytes=_CAP)
        assert f.is_chunk_notification(first)
        _send_frame(b, f.build_cancel("rid-stream"))
        gate.set()  # release the producer; its next between-functions poll observes the $/cancel
        # Drain frames until the terminal response; count the chunks that came through.
        chunks = 1
        while True:
            frame = wd.read_frame(b, max_frame_bytes=_CAP)
            if f.is_chunk_notification(frame):
                chunks += 1
                continue
            result = f.parse_response(frame, expected_id="rid-stream")
            break
        assert result["done"] is True
        assert result["total"] == chunks
        assert chunks < 64  # the cancel stopped it well before the full set
        # The loop is still alive for the next request (a clean stream end does not close it).
        _send_frame(b, f.build_request("r-shut", "shutdown", {}))
        wd.read_frame(b, max_frame_bytes=_CAP)
        server.join(timeout=2)
        assert not server.is_alive()
    finally:
        a.close()
        b.close()


def test_serve_connection_kills_on_bad_control_frame_mid_stream() -> None:
    """A non-$/cancel frame server→worker mid-stream → the loop returns (kill + evict, ADR-041)."""
    a, b = socket.socketpair(socket.AF_UNIX)
    gate = threading.Event()
    be = _CancelAwareBackend(64, gate=gate)
    server = threading.Thread(
        target=wd.serve_connection,
        args=(a,),
        kwargs={"backend": be, "max_frame_bytes": _CAP},
        daemon=True,
    )
    server.start()
    try:
        _send_frame(b, f.build_request("rid-stream", "start_decompile_stream", {"limit": 64}))
        first = wd.read_frame(b, max_frame_bytes=_CAP)
        assert f.is_chunk_notification(first)
        # An illegal server→worker frame on the stream socket (a request, not a $/cancel) → §6
        # protocol violation: the loop returns and the worker exits (the server evicts it). The
        # producer is gated after the first chunk so the bad frame is in the socket before its next
        # poll observes it mid-stream (deterministic — no scheduler race).
        _send_frame(b, f.build_request("evil", "ping", {}))
        gate.set()  # release the producer; its next between-functions poll hits the illegal frame
        server.join(timeout=2)
        assert not server.is_alive()  # the loop returned on the protocol violation
    finally:
        a.close()
        b.close()
