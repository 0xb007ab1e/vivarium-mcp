"""Unit tests for the streaming methods on the RPC adapter (ADR-040 — server-side delegation).

Hermetic: the worker is played by a ``socket.socketpair`` (no real JVM/Ghidra/container). These
cover the adapter's thin delegation to the injected
:class:`~vivarium.jobs.streaming.StreamingJobManager`, the fail-closed guard when streaming is not
wired, and the **real** worker-streaming producer (increment 2b): a scripted sequence of ``$/chunk``
frames + a terminal response is driven over the fake socket and the iterator is asserted to yield
the functions in ``seq`` order, enforce the gap-free invariant, raise on a protocol violation, and
surface a terminal worker error as the producer raising. The job machinery itself is covered in
``test_streaming_jobs``; the framing codec in ``test_streaming_framing``.
"""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from tests.conftest import FrozenClock
from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra import rpc_framing as f
from vivarium.ghidra.rpc_client import RpcGhidraAdapter
from vivarium.jobs.streaming import (
    DecompileStreamIn,
    FetchJobResultsIn,
    JobHandleIn,
    JobState,
    StreamingJobManager,
    StreamTerminal,
)
from vivarium.security.limits import Limits
from vivarium.tools import schemas as s

_SID = "sess-X"
_CALLER = "local"
_CAP = 4 * 1024 * 1024


def _fn(i: int) -> s.DecompiledFunction:
    """A synthetic decompiled function (binary-derived fields wrapped)."""
    addr = 0x00401000 + i * 0x10
    return s.DecompiledFunction(
        address=f"0x{addr:08x}",
        name=Untrusted(value=f"FUN_{addr:08x}", origin=DataOrigin.GHIDRA),
        c_code=Untrusted(value="int f(void){return 0;}", origin=DataOrigin.GHIDRA),
        signature=Untrusted(value="int f(void)", origin=DataOrigin.GHIDRA),
    )


def _producer(n: int) -> Iterator[s.DecompiledFunction]:
    for i in range(n):
        yield _fn(i)


def _adapter(stream_jobs: StreamingJobManager | None) -> RpcGhidraAdapter:
    """Build an adapter with a no-op launcher (no socket I/O) and the given stream manager."""
    return RpcGhidraAdapter(
        launcher=lambda _sid, _path: _DummyWorker(),
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only; no real socket bound
        tool_timeout_s=0.5,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
        stream_jobs=stream_jobs,
    )


class _DummyWorker:
    """A worker handle that is never actually contacted (streaming source is not wired).

    Satisfies the ``WorkerProcess`` protocol (``kill``/``is_alive``/``exit_diagnosis``) so the
    typed launcher signature is honored under ``mypy --strict``.
    """

    def kill(self) -> None:
        """No-op kill."""

    def is_alive(self) -> bool:
        """Report the worker as alive (it is never actually spawned/contacted here)."""
        return True

    def exit_diagnosis(self) -> str:
        """No exit to classify in these tests."""
        return "unknown"


# --- a fake-socket harness for the real worker-streaming producer (increment 2b) -------------


class _FakeWorker:
    """A fake worker process handle that records kills (mirrors test_analyze_progress harness)."""

    def __init__(self) -> None:
        """Initialize a live, un-killed fake worker."""
        self.killed = 0

    def kill(self) -> None:
        """Record a kill."""
        self.killed += 1

    def is_alive(self) -> bool:
        """Whether the fake worker is alive (always True until killed)."""
        return self.killed == 0

    def exit_diagnosis(self) -> str:
        """Return a generic crash diagnosis (no OOM)."""
        return "other"


class _ConnectedAdapter(RpcGhidraAdapter):
    """Adapter whose ``_ensure_connected`` returns a pre-wired socketpair end."""

    def __init__(self, *, server_sock: socket.socket, **kw: object) -> None:
        """Initialize with the server-side end of a connected socket pair.

        Args:
            server_sock: The socket the adapter uses as if connected to the worker.
            **kw: Forwarded to :class:`RpcGhidraAdapter`.
        """
        super().__init__(**kw)  # type: ignore[arg-type]
        self._wired = server_sock

    def _ensure_connected(self, sess: object, *, deadline: float = 0.0) -> socket.socket:
        """Return the pre-wired socket instead of dialing a real UDS.

        Args:
            sess: The per-session state (unused).

        Returns:
            The pre-wired socket.
        """
        sess.sock = self._wired  # type: ignore[attr-defined]
        return self._wired


def _make_adapter(
    server_sock: socket.socket,
    worker: _FakeWorker,
    *,
    analysis_timeout_s: float = 2.0,
) -> _ConnectedAdapter:
    """Build an adapter wired to ``server_sock`` with a live session ``_SID``."""
    adapter = _ConnectedAdapter(
        server_sock=server_sock,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=2.0,
        analysis_timeout_s=analysis_timeout_s,
        max_response_bytes=_CAP,
    )
    adapter.start_worker(_SID)
    return adapter


def _send_frame(sock: socket.socket, obj: dict[str, Any]) -> None:
    """Frame and send one JSON-RPC object on ``sock``."""
    sock.sendall(f.encode_frame(obj, max_frame_bytes=_CAP))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly ``n`` bytes (test-side helper)."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("socket closed mid-frame in test harness")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_request(wrk: socket.socket) -> dict[str, Any]:
    """Read exactly one framed JSON-RPC request from the worker end of the pair."""
    prefix = _recv_exact(wrk, f.LENGTH_PREFIX_BYTES)
    (n,) = struct.unpack(">I", prefix)
    body = _recv_exact(wrk, n) if n else b""
    obj: dict[str, Any] = f.decode_body(body)
    return obj


def _chunk_payload(i: int) -> dict[str, Any]:
    """A plain (un-enveloped) per-function chunk payload as the worker would emit it."""
    addr = 0x00401000 + i * 0x10
    return {
        "address": f"0x{addr:08x}",
        "name": f"FUN_{addr:08x}",
        "c_code": "int f(void){return 0;}",
        "signature": "int f(void)",
    }


def _scripted_worker(
    wrk: socket.socket,
    *,
    chunks: int,
    total: int | None = None,
    truncated: bool = False,
) -> Callable[[], None]:
    """Build a worker thread body emitting ``chunks`` $/chunk frames then a terminal response."""

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        for i in range(chunks):
            _send_frame(wrk, f.build_chunk(rid, i, "function", _chunk_payload(i)))
        result = {"total": chunks if total is None else total, "truncated": truncated, "done": True}
        _send_frame(wrk, {"jsonrpc": "2.0", "id": rid, "result": result})

    return _serve


# --- real worker stream source: drives the iterator over a fake socket -----------------------


def test_decompile_stream_yields_chunks_in_seq_order() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    t = threading.Thread(target=_scripted_worker(wrk, chunks=3), daemon=True)
    t.start()

    terminal = StreamTerminal()
    produced = list(
        adapter.decompile_stream(
            _SID, DecompileStreamIn(session_id=_SID, limit=3), terminal=terminal
        )
    )
    t.join(timeout=3)

    assert [fn.address for fn in produced] == [f"0x{0x00401000 + i * 0x10:08x}" for i in range(3)]
    # Per-chunk untrusted envelope (ADR-005 D9): every binary-derived field is wrapped.
    for fn in produced:
        assert isinstance(fn.name, Untrusted)
        assert isinstance(fn.c_code, Untrusted)
        assert isinstance(fn.signature, Untrusted)
    assert terminal.total == 3
    assert terminal.truncated is False
    assert worker.killed == 0  # a clean chunk+response stream never kills
    wrk.close()


def test_decompile_stream_sends_start_rpc_with_params() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    seen: dict[str, Any] = {}

    def _serve() -> None:
        req = _read_request(wrk)
        seen.update(req)
        _send_frame(wrk, {"jsonrpc": "2.0", "id": req["id"], "result": {"total": 0, "done": True}})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    list(
        adapter.decompile_stream(
            _SID,
            DecompileStreamIn(session_id=_SID, offset=2, limit=7, functions=["main", "0x401000"]),
        )
    )
    t.join(timeout=3)
    assert seen["method"] == "start_decompile_stream"
    # functions-filtering is forwarded for real (increment 2b), plus the window bounds.
    assert seen["params"] == {"offset": 2, "limit": 7, "functions": ["main", "0x401000"]}
    wrk.close()


def test_decompile_stream_records_truncated_from_terminal() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    t = threading.Thread(
        target=_scripted_worker(wrk, chunks=2, total=2, truncated=True), daemon=True
    )
    t.start()
    terminal = StreamTerminal()
    produced = list(
        adapter.decompile_stream(
            _SID, DecompileStreamIn(session_id=_SID, limit=2), terminal=terminal
        )
    )
    t.join(timeout=3)
    assert len(produced) == 2
    assert terminal.truncated is True  # honest over-cap bound surfaced (ADR-040 D8)
    wrk.close()


def test_decompile_stream_skips_progress_frames() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        _send_frame(wrk, f.build_progress(rid, 10, "analyzing"))  # interleaved progress
        _send_frame(wrk, f.build_chunk(rid, 0, "function", _chunk_payload(0)))
        _send_frame(wrk, f.build_progress(rid, 90, "finalizing"))
        _send_frame(wrk, f.build_chunk(rid, 1, "function", _chunk_payload(1)))
        _send_frame(wrk, {"jsonrpc": "2.0", "id": rid, "result": {"total": 2, "done": True}})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    produced = list(adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=2)))
    t.join(timeout=3)
    # Progress is relayed to the log, NOT yielded as a result: exactly the 2 chunks come through.
    assert len(produced) == 2
    assert worker.killed == 0
    wrk.close()


def test_decompile_stream_raises_and_kills_on_non_gap_free_seq() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        _send_frame(wrk, f.build_chunk(rid, 0, "function", _chunk_payload(0)))
        # A gap: seq jumps 0 -> 2 (skipping 1) → protocol violation → kill + worker-unavailable.
        _send_frame(wrk, f.build_chunk(rid, 2, "function", _chunk_payload(2)))

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=3))
    assert next(it).address == f"0x{0x00401000:08x}"  # seq 0 is fine
    with pytest.raises(GhidraMcpError) as ei:
        next(it)  # the gapped seq 2 trips the invariant
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1
    wrk.close()


def test_decompile_stream_raises_on_out_of_vocab_kind() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        bad = {
            "jsonrpc": "2.0",
            "method": "$/chunk",
            "params": {"id": rid, "seq": 0, "kind": "evil", "payload": {}},
        }
        _send_frame(wrk, bad)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=1))
    with pytest.raises(GhidraMcpError) as ei:
        next(it)
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1
    wrk.close()


def test_decompile_stream_surfaces_terminal_worker_error_as_raise() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        _send_frame(wrk, f.build_chunk(rid, 0, "function", _chunk_payload(0)))
        # A worker method-level error AFTER one chunk → producer raises (job → terminal error),
        # NOT an ambiguous early done. A method error does NOT kill the (healthy) worker.
        _send_frame(
            wrk,
            {
                "jsonrpc": "2.0",
                "id": rid,
                "error": {
                    "code": -32010,
                    "message": "decompile failed",
                    "data": {"type": "analysis-failed"},
                },
            },
        )

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=2))
    assert next(it).address == f"0x{0x00401000:08x}"  # the one chunk arrives first
    with pytest.raises(GhidraMcpError) as ei:
        next(it)
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.ANALYSIS_FAILED
    assert worker.killed == 0  # a method-level error does not kill a healthy worker
    wrk.close()


def test_decompile_stream_raises_worker_unavailable_with_no_session() -> None:
    # No worker registered for the session → fail closed before any frame is sent.
    adapter = _adapter(StreamingJobManager(authorize=lambda _s, _c: None))
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=1))
    with pytest.raises(GhidraMcpError) as ei:
        next(it)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_decompile_stream_times_out_and_kills(monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that emits a chunk then goes silent hits the un-extended deadline → kill+TIMEOUT."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker, analysis_timeout_s=5.0)
    # Inject a monotonic clock: deadline base = 0, then the loop's remaining-time check is already
    # past the budget, so the read-loop raises TimeoutError without waiting wall-clock.
    clock = iter([0.0, 0.0, 100.0, 100.0, 100.0])
    monkeypatch.setattr("vivarium.ghidra.rpc_client.time.monotonic", lambda: next(clock))

    def _serve() -> None:
        import contextlib

        with contextlib.suppress(OSError):
            req = _read_request(wrk)
            _send_frame(wrk, f.build_chunk(req["id"], 0, "function", _chunk_payload(0)))
        # then go silent — the deadline must fire regardless.

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=3))
    with pytest.raises(GhidraMcpError) as ei:
        list(it)
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.TIMEOUT
    assert worker.killed == 1
    wrk.close()


def test_decompile_stream_transport_close_is_worker_unavailable() -> None:
    """The worker closing the socket mid-stream (EOF) → kill + worker-unavailable (a crash)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()  # exit_diagnosis() == "other" → generic crash, not OOM
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        _read_request(wrk)
        wrk.close()  # close before sending any frame → EOF on the adapter's first read

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=1))
    with pytest.raises(GhidraMcpError) as ei:
        next(it)
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1


def test_decompile_stream_oom_close_is_resource_exhausted() -> None:
    """An OOM-diagnosed mid-stream worker death → kill + resource-exhausted (ADR-023 / F1)."""

    class _OomWorker(_FakeWorker):
        def exit_diagnosis(self) -> str:
            return "oom"

    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _OomWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        _read_request(wrk)
        wrk.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=1))
    with pytest.raises(GhidraMcpError) as ei:
        next(it)
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.RESOURCE_EXHAUSTED
    assert worker.killed == 1


# --- streaming-not-enabled guard (no manager injected) ---------------------------------------


def test_streaming_methods_fail_closed_when_not_enabled() -> None:
    adapter = _adapter(None)  # streaming not wired
    calls: list[Callable[[], object]] = [
        lambda: adapter.start_decompile_stream(
            _SID, DecompileStreamIn(session_id=_SID, limit=5), caller=_CALLER
        ),
        lambda: adapter.fetch_job_results(
            _SID, FetchJobResultsIn(session_id=_SID, job_id="j"), caller=_CALLER
        ),
        lambda: adapter.job_status(_SID, JobHandleIn(session_id=_SID, job_id="j"), caller=_CALLER),
        lambda: adapter.cancel_job(_SID, JobHandleIn(session_id=_SID, job_id="j"), caller=_CALLER),
    ]
    for call in calls:
        with pytest.raises(GhidraMcpError) as ei:
            call()
        assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


# --- delegation to a wired manager (job pre-seeded directly) ----------------------------------


def test_fetch_status_cancel_delegate_to_the_manager() -> None:
    clock = FrozenClock()
    mgr = StreamingJobManager(
        authorize=lambda _s, _c: None,
        limits=Limits(max_stream_buffer_chunks=2),
        clock=clock.monotonic,
    )
    adapter = _adapter(mgr)
    # Seed a job via the manager (bypassing the worker source) with a synthetic producer.
    job_id = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_CALLER)

    status = adapter.job_status(_SID, JobHandleIn(session_id=_SID, job_id=job_id), caller=_CALLER)
    assert status.state in {JobState.RUNNING, JobState.PAUSED}
    assert status.session_id == _SID

    res = adapter.fetch_job_results(
        _SID, FetchJobResultsIn(session_id=_SID, job_id=job_id, limit=2), caller=_CALLER
    )
    assert [c.seq for c in res.chunks] == [0, 1]
    assert res.cursor == 2

    cancelled = adapter.cancel_job(
        _SID, JobHandleIn(session_id=_SID, job_id=job_id), caller=_CALLER
    )
    assert cancelled.state is JobState.CANCELLED


def test_adapter_fetch_propagates_bola_denial() -> None:
    # An authorizer that rejects any caller → the adapter surfaces the BOLA-safe SESSION_INVALID.
    from vivarium.ghidra import _errors

    def deny(_sid: str, _caller: str) -> None:
        raise _errors.session_invalid()

    mgr = StreamingJobManager(authorize=deny)
    adapter = _adapter(mgr)
    with pytest.raises(GhidraMcpError) as ei:
        adapter.job_status(_SID, JobHandleIn(session_id=_SID, job_id="any"), caller="mallory")
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


def test_cancel_job_best_effort_worker_signal_never_fails_the_cancel() -> None:
    # cancel_job's server-side state change is authoritative; a best-effort $/cancel send must
    # never make the cancel raise. With a wired manager + a registered (socketpair) worker, the
    # cancel returns the terminal status even though no one reads the $/cancel frame.
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    # A tiny buffer so the (larger) producer pauses non-terminal: the job is still cancelable.
    mgr = StreamingJobManager(
        authorize=lambda _s, _c: None, limits=Limits(max_stream_buffer_chunks=2)
    )
    adapter = _ConnectedAdapter(
        server_sock=srv,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
        stream_jobs=mgr,
    )
    adapter.start_worker(_SID)
    # Force a connected socket so cancel_job's best-effort $/cancel has somewhere to write, and an
    # in-flight stream id to target (set as the streaming generator would).
    adapter._ensure_connected(adapter._sessions[_SID])
    adapter._sessions[_SID].active_stream_id = "stream-1"
    job_id = mgr.start_job(_SID, producer=_producer(50), total=50, caller=_CALLER)
    cancelled = adapter.cancel_job(
        _SID, JobHandleIn(session_id=_SID, job_id=job_id), caller=_CALLER
    )
    assert cancelled.state is JobState.CANCELLED
    wrk.close()
    srv.close()


def test_cancel_job_sends_a_well_formed_cancel_for_the_active_stream_id() -> None:
    """cancel_job emits a $/cancel notification targeting the in-flight stream id (ADR-041)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    mgr = StreamingJobManager(
        authorize=lambda _s, _c: None, limits=Limits(max_stream_buffer_chunks=2)
    )
    adapter = _ConnectedAdapter(
        server_sock=srv,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
        stream_jobs=mgr,
    )
    adapter.start_worker(_SID)
    adapter._ensure_connected(adapter._sessions[_SID])
    adapter._sessions[_SID].active_stream_id = "rid-42"
    job_id = mgr.start_job(_SID, producer=_producer(50), total=50, caller=_CALLER)

    adapter.cancel_job(_SID, JobHandleIn(session_id=_SID, job_id=job_id), caller=_CALLER)

    # The worker end should now have exactly one framed $/cancel targeting the active stream id.
    wrk.settimeout(2.0)
    frame = _read_request(wrk)
    assert f.is_cancel_notification(frame)
    cancel = f.parse_cancel(frame, expected_id="rid-42")
    assert cancel.request_id == "rid-42"
    wrk.close()
    srv.close()


def test_cancel_job_sends_nothing_when_no_active_stream() -> None:
    """With no in-flight stream id, cancel_job sends NO $/cancel (nothing to target — a no-op)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    mgr = StreamingJobManager(
        authorize=lambda _s, _c: None, limits=Limits(max_stream_buffer_chunks=2)
    )
    adapter = _ConnectedAdapter(
        server_sock=srv,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
        stream_jobs=mgr,
    )
    adapter.start_worker(_SID)
    adapter._ensure_connected(adapter._sessions[_SID])
    # active_stream_id stays None (its default) — the stream already finished / never produced.
    job_id = mgr.start_job(_SID, producer=_producer(50), total=50, caller=_CALLER)

    cancelled = adapter.cancel_job(
        _SID, JobHandleIn(session_id=_SID, job_id=job_id), caller=_CALLER
    )
    assert cancelled.state is JobState.CANCELLED
    # Nothing was written server→worker: a non-blocking recv on the worker end sees no data.
    wrk.setblocking(False)
    with pytest.raises(BlockingIOError):
        wrk.recv(64)
    wrk.close()
    srv.close()


def test_decompile_stream_sets_and_clears_active_stream_id() -> None:
    """The streaming generator tracks the in-flight id so cancel_job can target it (ADR-041)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    seen: dict[str, Any] = {}

    def _serve() -> None:
        req = _read_request(wrk)
        seen["id"] = req["id"]
        _send_frame(wrk, f.build_chunk(req["id"], 0, "function", _chunk_payload(0)))
        _send_frame(wrk, {"jsonrpc": "2.0", "id": req["id"], "result": {"total": 1, "done": True}})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=1))
    # First next() sends the RPC + records the active id, then yields the first chunk.
    first = next(it)
    assert first.address == f"0x{0x00401000:08x}"
    assert adapter._sessions[_SID].active_stream_id == seen["id"]
    # Drain to completion → the finally clears the active id.
    list(it)
    t.join(timeout=3)
    assert adapter._sessions[_SID].active_stream_id is None
    wrk.close()


def test_decompile_stream_raises_and_kills_on_chunk_flood(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """More than ``_MAX_STREAM_CHUNKS`` ``$/chunk`` frames is a hostile-worker DoS → kill.

    Mirrors the progress-flood cap test: a flood of chunk frames trips the per-call cap, which the
    universal kill handler maps to ``WORKER_UNAVAILABLE`` + SIGKILL. The cap is shrunk via
    monkeypatch so the test stays fast/hermetic (the behavior under test is the bound, not the
    literal 10_000). The seqs are gap-free so the FLOOD check trips first (not the seq invariant).
    """
    monkeypatch.setattr("vivarium.ghidra.rpc_client._MAX_STREAM_CHUNKS", 3)
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        # Emit cap+1 = 4 gap-free chunks; the 4th trips the flood cap (count 4 > 3) pre-yield.
        for i in range(4):
            _send_frame(wrk, f.build_chunk(rid, i, "function", _chunk_payload(i)))

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    it = adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=100))
    # The first cap (=3) chunks stream fine (seq 0,1,2 → their addresses).
    assert [next(it).address for _ in range(3)] == [
        f"0x{0x00401000 + i * 0x10:08x}" for i in range(3)
    ]
    with pytest.raises(GhidraMcpError) as ei:
        next(it)  # the 4th chunk trips the per-call flood cap
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1
    wrk.close()
