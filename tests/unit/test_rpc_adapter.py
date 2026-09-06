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
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from worker import dispatch

from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra import rpc_framing
from vivarium.ghidra.rpc_client import RpcGhidraAdapter
from vivarium.security.limits import DEFAULT_WORKER_MEM_MIB, Limits
from vivarium.tools import schemas as s

_CAP = 4 * 1024 * 1024


class _FakeWorker:
    """A fake worker process handle that records whether it was killed.

    ``diagnosis`` is the value :meth:`exit_diagnosis` returns (ADR-023 / F1) — default ``"other"``
    (a generic crash → ``worker-unavailable``); set ``"oom"`` to simulate a memory-cap OOM.
    """

    def __init__(self, diagnosis: str = "other") -> None:
        """Initialize a live, un-killed fake worker.

        Args:
            diagnosis: The value :meth:`exit_diagnosis` returns.
        """
        self.killed = 0
        self._alive = True
        self._diagnosis = diagnosis

    def kill(self) -> None:
        """Record a kill and mark dead."""
        self.killed += 1
        self._alive = False

    def is_alive(self) -> bool:
        """Whether the fake worker is still alive."""
        return self._alive

    def exit_diagnosis(self) -> str:
        """Return the canned exit diagnosis (ADR-023 / F1)."""
        return self._diagnosis


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

    def _ensure_connected(self, sess: object, *, deadline: float = 0.0) -> socket.socket:
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
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path; no real socket bound
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


def test_call_holds_session_lock_across_the_io_transaction() -> None:
    """gap N1: ``_call`` holds the per-session lock across send→read so a concurrent same-session
    caller cannot use the one UDS mid-transaction (the HTTP threadpool makes this reachable).

    A worker thread reads the request, then pauses *before* replying; while the adapter call is
    blocked in the read, a DIFFERENT thread must not be able to acquire ``sess.lock``. After the
    call completes the lock is fully released.
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    sess = adapter._sessions["s"]  # white-box: assert the per-session lock is held mid-call
    entered = threading.Event()
    proceed = threading.Event()
    result = {
        "session_id": "s",
        "state": "ready",
        "created_at": 1,
        "expires_at": 2,
        "binary_sha256": None,
    }

    def _paused_worker() -> None:
        obj = dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        entered.set()  # the adapter has sent + is now blocked reading the response (lock held)
        proceed.wait(3)
        resp = {"jsonrpc": "2.0", "result": result, "id": obj["id"]}
        wrk.sendall(rpc_framing.encode_frame(resp, max_frame_bytes=_CAP))

    out: list[s.SessionInfo] = []

    def _caller() -> None:
        out.append(adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", timeout_seconds=3)))

    wt = threading.Thread(target=_paused_worker, daemon=True)
    ct = threading.Thread(target=_caller, daemon=True)
    wt.start()
    ct.start()
    assert entered.wait(3), "worker never received the request"
    # Mid-transaction: the call thread holds the per-session lock → another thread cannot take it.
    assert sess.lock.acquire(blocking=False) is False
    proceed.set()
    ct.join(timeout=4)
    wt.join(timeout=4)
    assert out and out[0].state == "ready"
    # Released on completion → now acquirable.
    assert sess.lock.acquire(blocking=False) is True
    sess.lock.release()
    wrk.close()


def test_call_refuses_while_a_stream_owns_the_session() -> None:
    """gap N1: while a stream owns the socket (``active_stream_id`` set), a plain call refuses fast
    (retryable ``worker-unavailable``) instead of reading the stream's chunks off the socket. The
    streamer's reader holds no lock, so this flag — not a held lock — is the exclusion mechanism.
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    adapter._sessions["s"].active_stream_id = "stream-abc"  # simulate an in-flight stream
    with pytest.raises(GhidraMcpError) as ei:
        adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 0  # refusing a busy session is not a worker fault — never kill
    # The lock was acquired for the check and released in the finally → still free afterwards.
    assert adapter._sessions["s"].lock.acquire(blocking=False) is True
    adapter._sessions["s"].lock.release()
    wrk.close()


def test_oversized_declared_frame_kills_worker() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    # Small-but-usable cap: requests fit, but the worker declares a far-larger inbound frame.
    cap = 1024
    adapter = _ConnectedAdapter(
        server_sock=srv,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/x",  # noqa: S108  # test-only path; no real socket bound
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


def test_resource_exhausted_factory_envelope() -> None:
    """``_errors.resource_exhausted`` builds a 503, non-retryable, safe envelope (ADR-023)."""
    from vivarium.ghidra import _errors

    err = _errors.resource_exhausted(correlation_id="cid-1")
    env = err.envelope
    assert env.type is ErrorType.RESOURCE_EXHAUSTED
    assert env.title == "Worker out of resources"
    assert env.status == 503
    assert env.retryable is False
    assert env.correlation_id == "cid-1"
    # No-arg form: generic safe hint (no cap), still leak-free.
    assert "Traceback" not in env.detail and "/" not in env.detail
    assert "memory" in env.detail


def test_resource_exhausted_detail_includes_cap_and_knob() -> None:
    """With ``mem_mib`` the detail names the configured cap + the env knob (ADR-037 §3 sizing hint),
    and still leaks no host path / binary content."""
    from vivarium.ghidra import _errors

    env = _errors.resource_exhausted(4096, correlation_id="cid-2").envelope
    assert env.type is ErrorType.RESOURCE_EXHAUSTED
    assert "4096 MiB" in env.detail
    assert "VIVARIUM_WORKER_MEM_MIB" in env.detail
    assert "(currently 4096)" in env.detail
    # Disclosure safety unchanged: no traceback / host path / binary content.
    assert "Traceback" not in env.detail and "/" not in env.detail


def test_resource_exhausted_via_make_error_maps() -> None:
    """The generic factory also resolves RESOURCE_EXHAUSTED → 503 / non-retryable / titled."""
    from vivarium.ghidra import _errors

    env = _errors.make_error(ErrorType.RESOURCE_EXHAUSTED, "detail").envelope
    assert env.status == 503
    assert env.retryable is False
    assert env.title == "Worker out of resources"


def test_worker_method_error_from_method_not_found_is_actionable() -> None:
    """``-32601`` (worker lacks the verb) → an honest NOT_FOUND, never the opaque INTERNAL 500.

    Regression for #329/#330: a worker image predating a tool emits ``-32601`` with NO matching
    slug (older ``_SLUG_BY_CODE``), so a slug-only mapping fell through to ``internal-error`` → 500.
    Keying off the numeric code fixes it regardless of worker image. Detail stays leak-free and
    points at the real cause (rebuild/repin the worker image).
    """
    from vivarium.ghidra import _errors

    # slug=None models the old-worker fallback (no slug for -32601); slug present must not matter.
    for slug in (None, "internal-error"):
        env = _errors.worker_method_error_from(-32601, slug, correlation_id="cid").envelope
        assert env.type is ErrorType.NOT_FOUND
        assert env.status == 404
        assert env.correlation_id == "cid"
        assert "not supported" in env.detail and "worker image" in env.detail
        # Disclosure safety: no traceback / host path / binary content.
        assert "Traceback" not in env.detail and "/" not in env.detail


def test_worker_method_error_from_invalid_request_maps_validation() -> None:
    """``-32600`` (invalid request envelope) → VALIDATION (400)."""
    from vivarium.ghidra import _errors

    env = _errors.worker_method_error_from(-32600, None).envelope
    assert env.type is ErrorType.VALIDATION
    assert env.status == 400


def test_worker_method_error_from_defers_to_slug_for_other_codes() -> None:
    """Every non-protocol code keeps the existing slug-based mapping (unchanged behaviour)."""
    from vivarium.ghidra import _errors

    assert (
        _errors.worker_method_error_from(-32004, "not-found").envelope.type is ErrorType.NOT_FOUND
    )
    assert (
        _errors.worker_method_error_from(-32010, "analysis-failed").envelope.type
        is ErrorType.ANALYSIS_FAILED
    )
    # Unknown slug on a non-protocol code still fails closed to INTERNAL.
    assert _errors.worker_method_error_from(-32603, "bogus").envelope.type is ErrorType.INTERNAL


def test_map_worker_slug_handles_new_protocol_slugs() -> None:
    """A newer worker emitting proper protocol slugs also maps correctly (defense in depth)."""
    from vivarium.ghidra import _errors

    assert _errors.map_worker_slug("method-not-found") is ErrorType.NOT_FOUND
    assert _errors.map_worker_slug("invalid-request") is ErrorType.VALIDATION


def test_dispatch_build_error_gives_method_not_found_slug() -> None:
    """The worker now emits an honest ``method-not-found`` slug for ``-32601`` (was fallback)."""
    frame = dispatch.build_error("rid", dispatch.CODE_METHOD_NOT_FOUND, "unknown method")
    assert frame["error"]["data"]["type"] == "method-not-found"
    assert frame["error"]["code"] == dispatch.CODE_METHOD_NOT_FOUND


def test_oom_worker_death_maps_to_resource_exhausted(tmp_path: Path) -> None:
    """A transport failure on an OOM-killed worker → distinct, non-retryable resource-exhausted."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker(diagnosis="oom")
    adapter = _make_adapter(srv, worker)

    def _crash() -> None:
        dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        wrk.close()  # close mid-call → EOF on the adapter's read

    t = threading.Thread(target=_crash, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.list_functions("s", s.ListFunctionsIn(session_id="s"))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.RESOURCE_EXHAUSTED
    assert ei.value.envelope.status == 503
    assert ei.value.envelope.retryable is False
    # Detail is the safe, actionable hint carrying the configured cap + knob (ADR-037 §3) — no
    # binary content / host path.
    detail = ei.value.envelope.detail
    assert "memory" in detail
    assert "VIVARIUM_WORKER_MEM_MIB" in detail
    assert f"{DEFAULT_WORKER_MEM_MIB} MiB" in detail
    assert "Traceback" not in detail and "/" not in detail
    assert worker.killed == 1


def test_non_oom_worker_death_stays_unavailable(tmp_path: Path) -> None:
    """A generic crash (diagnosis 'other') stays worker-unavailable (retryable)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker(diagnosis="other")
    adapter = _make_adapter(srv, worker)

    def _crash() -> None:
        dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        wrk.close()

    t = threading.Thread(target=_crash, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.list_functions("s", s.ListFunctionsIn(session_id="s"))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1


def test_unknown_diagnosis_fails_closed_to_unavailable(tmp_path: Path) -> None:
    """An 'unknown' diagnosis (engine query unparseable) fails closed to worker-unavailable."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker(diagnosis="unknown")
    adapter = _make_adapter(srv, worker)

    def _crash() -> None:
        dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        wrk.close()

    t = threading.Thread(target=_crash, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.list_functions("s", s.ListFunctionsIn(session_id="s"))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_diagnosis_exception_fails_closed_to_unavailable(tmp_path: Path) -> None:
    """If the diagnosis query itself raises, classification fails closed to worker-unavailable."""

    class _RaisingWorker(_FakeWorker):
        def exit_diagnosis(self) -> str:
            raise RuntimeError("engine flaked")

    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _RaisingWorker()
    adapter = _make_adapter(srv, worker)

    def _crash() -> None:
        dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        wrk.close()

    t = threading.Thread(target=_crash, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.list_functions("s", s.ListFunctionsIn(session_id="s"))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_call_without_worker_is_unavailable() -> None:
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/tmp/x",  # noqa: S108  # test-only path; no real socket bound
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
        socket_dir="/tmp/x",  # noqa: S108  # test-only path; no real socket bound
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
        socket_dir="/run/vivarium/",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    assert adapter._socket_path("abc") == "/run/vivarium/abc/abc.sock"


# --- #9: untrusted-data wrap chokepoint (ADR-005) ---------------------------------------------
def _run_with_result(method: str, args: object, result: dict[str, object]) -> object:
    """Drive ``adapter.<method>("s", args)`` against a fake worker returning ``result``.

    Args:
        method: The adapter method name to call.
        args: The input model to pass.
        result: The PLAIN (un-wrapped) result dict the fake worker replies with.

    Returns:
        The adapter's typed, wrapped output model.
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    try:
        out = getattr(adapter, method)("s", args)
    finally:
        t.join(timeout=2)
        wrk.close()
    assert worker.killed == 0  # a successful wrap never kills the worker
    return out


def test_decompile_wraps_name_binary_code_ghidra() -> None:
    """Decompiler output is GHIDRA-origin; the symbol name is BINARY-origin — both untrusted."""
    out = _run_with_result(
        "decompile_function",
        s.DecompileFunctionIn(session_id="s", function="main"),
        {
            "address": "0x1000",
            "name": "main",
            "c_code": "int main(){return 0;}",
            "signature": "int main(void)",
        },
    )
    assert isinstance(out, s.DecompiledFunction)
    assert isinstance(out.name, Untrusted) and out.name.origin is DataOrigin.BINARY
    assert out.c_code.origin is DataOrigin.GHIDRA
    assert out.signature.origin is DataOrigin.GHIDRA
    assert out.c_code.value == "int main(){return 0;}"
    assert out.address == "0x1000"  # server-normalized address stays bare (safe)


def test_decompile_normalizes_bidi_injection_in_code() -> None:
    """A Trojan-Source bidi override in decompiled C is neutralized + annotated when wrapped."""
    out = _run_with_result(
        "decompile_function",
        s.DecompileFunctionIn(session_id="s", function="f"),
        {"address": "0x1", "name": "f", "c_code": "a‮b", "signature": "void f()"},
    )
    assert isinstance(out, s.DecompiledFunction)
    assert "‮" not in out.c_code.value  # neutralized to an inert <U+202E> token
    assert "<U+202E>" in out.c_code.value
    assert out.c_code.notes  # the bidi class is annotated for the client


def test_strings_wrap_binary_with_utf8_replace_encoding() -> None:
    out = _run_with_result(
        "list_strings",
        s.ListStringsIn(session_id="s"),
        {
            "strings": [{"address": "0x2000", "value": "hello", "length": 5}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.StringListOut)
    item = out.strings[0]
    assert item.value.origin is DataOrigin.BINARY
    assert item.value.encoding == "utf-8-replace"
    assert item.value.value == "hello"


def test_read_bytes_wraps_hex_binary() -> None:
    out = _run_with_result(
        "read_bytes",
        s.ReadBytesIn(session_id="s", address="0x3000", length=4),
        {"address": "0x3000", "data": "deadbeef", "length": 4, "truncated": False},
    )
    assert isinstance(out, s.ReadBytesOut)
    assert out.data.origin is DataOrigin.BINARY
    assert out.data.encoding == "hex"


def test_search_bytes_wraps_context_hex_binary() -> None:
    out = _run_with_result(
        "search_bytes",
        s.SearchBytesIn(session_id="s", pattern_hex="90"),
        {"matches": [{"address": "0x10", "context_hex": "9090"}], "total": 1, "truncated": False},
    )
    assert isinstance(out, s.SearchBytesOut)
    assert out.matches[0].context_hex.origin is DataOrigin.BINARY
    assert out.matches[0].context_hex.encoding == "hex"


def test_disassemble_wraps_mnemonic_ghidra_bytes_binary() -> None:
    out = _run_with_result(
        "disassemble",
        s.DisassembleIn(session_id="s", start="0x40"),
        {
            "instructions": [
                {"address": "0x40", "mnemonic": "MOV", "operands": "EAX, 1", "bytes_hex": "b801"}
            ],
            "truncated": True,
        },
    )
    assert isinstance(out, s.DisassembleOut)
    insn = out.instructions[0]
    assert insn.mnemonic.origin is DataOrigin.GHIDRA
    assert insn.operands.origin is DataOrigin.GHIDRA
    assert insn.bytes_hex.origin is DataOrigin.BINARY and insn.bytes_hex.encoding == "hex"
    assert out.truncated is True


def test_function_list_wraps_name_binary() -> None:
    out = _run_with_result(
        "list_functions",
        s.ListFunctionsIn(session_id="s"),
        {
            "functions": [{"address": "0x1", "name": "f", "size": 10}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.FunctionListOut)
    assert out.functions[0].name.origin is DataOrigin.BINARY
    assert out.functions[0].size == 10


def test_get_function_wraps_optional_calling_convention() -> None:
    out = _run_with_result(
        "get_function",
        s.GetFunctionIn(session_id="s", function="f"),
        {
            "address": "0x1",
            "name": "f",
            "signature": "void f()",
            "size": 4,
            "is_thunk": False,
            "calling_convention": "__cdecl",
        },
    )
    assert isinstance(out, s.FunctionDetail)
    assert out.name.origin is DataOrigin.BINARY
    assert out.signature.origin is DataOrigin.GHIDRA
    assert out.calling_convention is not None
    assert out.calling_convention.origin is DataOrigin.GHIDRA


def test_get_function_optional_calling_convention_absent_is_none() -> None:
    out = _run_with_result(
        "get_function",
        s.GetFunctionIn(session_id="s", function="f"),
        {"address": "0x1", "name": "f", "signature": "void f()", "size": 4, "is_thunk": True},
    )
    assert isinstance(out, s.FunctionDetail)
    assert out.calling_convention is None  # optional GHIDRA field passes None through unwrapped


def test_symbol_list_wraps_name_and_namespace_binary() -> None:
    out = _run_with_result(
        "list_symbols",
        s.ListSymbolsIn(session_id="s"),
        {
            "symbols": [
                {"address": "0x1", "name": "sym", "kind": "LABEL", "namespace": "ns"},
                {"address": "0x2", "name": "sym2", "kind": "IMPORT"},
            ],
            "total": 2,
            "truncated": False,
        },
    )
    assert isinstance(out, s.SymbolListOut)
    assert out.symbols[0].name.origin is DataOrigin.BINARY
    assert out.symbols[0].namespace is not None
    assert out.symbols[0].namespace.origin is DataOrigin.BINARY
    assert out.symbols[1].namespace is None  # optional absent → None


def test_get_symbol_wraps_single() -> None:
    out = _run_with_result(
        "get_symbol",
        s.GetSymbolIn(session_id="s", identifier="sym"),
        {"address": "0x1", "name": "sym", "kind": "FUNCTION", "namespace": None},
    )
    assert isinstance(out, s.Symbol)
    assert out.name.origin is DataOrigin.BINARY


def test_data_list_wraps_type_ghidra_value_binary() -> None:
    out = _run_with_result(
        "list_data",
        s.ListDataIn(session_id="s"),
        {
            "data": [
                {"address": "0x1", "data_type": "char[4]", "value_repr": '"abc"', "length": 4}
            ],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.DataListOut)
    assert out.data[0].data_type.origin is DataOrigin.GHIDRA
    assert out.data[0].value_repr.origin is DataOrigin.BINARY


def test_get_data_type_wraps_ghidra() -> None:
    out = _run_with_result(
        "get_data_type",
        s.GetDataTypeIn(session_id="s", name="my_struct"),
        {"name": "my_struct", "kind": "struct", "size": 8, "definition": "struct {int a;}"},
    )
    assert isinstance(out, s.DataType)
    assert out.name.origin is DataOrigin.GHIDRA
    assert out.definition.origin is DataOrigin.GHIDRA


def test_comments_wrap_text_binary() -> None:
    out = _run_with_result(
        "get_comments",
        s.GetCommentsIn(session_id="s"),
        {
            "comments": [{"address": "0x1", "comment_type": "EOL", "text": "planted"}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.CommentListOut)
    assert out.comments[0].text.origin is DataOrigin.BINARY


def test_memory_map_wraps_block_name_binary() -> None:
    out = _run_with_result(
        "memory_map",
        s.MemoryMapIn(session_id="s"),
        {
            "blocks": [
                {
                    "name": ".text",
                    "start": "0x1000",
                    "end": "0x2000",
                    "size": 4096,
                    "permissions": "r-x",
                    "initialized": True,
                }
            ]
        },
    )
    assert isinstance(out, s.MemoryMapOut)
    assert out.blocks[0].name.origin is DataOrigin.BINARY
    assert out.blocks[0].permissions == "r-x"  # derived flags stay bare


def test_xrefs_have_no_untrusted_fields() -> None:
    out = _run_with_result(
        "xrefs_to",
        s.XrefsIn(session_id="s", target="0x1"),
        {
            "xrefs": [{"from_address": "0x1", "to_address": "0x2", "ref_type": "CALL"}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.XrefsOut)
    assert out.xrefs[0].ref_type == "CALL"  # all-safe; no wrap needed


def test_xrefs_from_round_trip() -> None:
    out = _run_with_result(
        "xrefs_from",
        s.XrefsIn(session_id="s", target="0x1"),
        {
            "xrefs": [{"from_address": "0x1", "to_address": "0x3", "ref_type": "DATA"}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.XrefsOut)
    assert out.xrefs[0].ref_type == "DATA"


def test_search_strings_wraps_like_list_strings() -> None:
    out = _run_with_result(
        "search_strings",
        s.SearchStringsIn(session_id="s", query="pw"),
        {
            "strings": [{"address": "0x9", "value": "password", "length": 8}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.SearchStringsOut)
    assert out.strings[0].value.origin is DataOrigin.BINARY
    assert out.strings[0].value.encoding == "utf-8-replace"


def test_program_metadata_wraps_compiler_binary_rest_bare() -> None:
    out = _run_with_result(
        "program_metadata",
        s.ProgramMetadataIn(session_id="s"),
        {
            "sha256": "a" * 64,
            "size_bytes": 100,
            "format": "ELF",
            "architecture": "x86:LE:64",
            "endianness": "little",
            "compiler": "gcc",
            "entry_point": "0x1040",
            "function_count": 3,
            "analysis_complete": True,
        },
    )
    assert isinstance(out, s.ProgramMetadata)
    assert out.compiler is not None and out.compiler.origin is DataOrigin.BINARY
    assert out.format == "ELF"  # Ghidra-classified, safe
    assert out.entry_point == "0x1040"


def test_program_metadata_optional_fields_none() -> None:
    out = _run_with_result(
        "program_metadata",
        s.ProgramMetadataIn(session_id="s"),
        {
            "sha256": "a" * 64,
            "size_bytes": 100,
            "format": "ELF",
            "architecture": "x86:LE:64",
            "endianness": "little",
            "compiler": None,
            "entry_point": None,
            "function_count": 0,
            "analysis_complete": False,
        },
    )
    assert isinstance(out, s.ProgramMetadata)
    assert out.compiler is None
    assert out.entry_point is None


# --- #9: pre-Ghidra binary-size cap in import_binary ------------------------------------------
def _import_adapter(
    server_sock: socket.socket,
    worker: _FakeWorker,
    *,
    limits: Limits,
    resolver: Callable[[str], int],
) -> _ConnectedAdapter:
    """Build an adapter with injected ``limits`` + ``source_resolver`` for import tests."""
    adapter = _ConnectedAdapter(
        server_sock=server_sock,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
        limits=limits,
        source_resolver=resolver,
    )
    adapter.start_worker("s")
    return adapter


def test_import_rejects_oversize_binary_before_worker() -> None:
    """An over-cap binary is rejected pre-Ghidra: no RPC is sent and the worker is never fed."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    limits = Limits(max_binary_bytes=1024)
    adapter = _import_adapter(srv, worker, limits=limits, resolver=lambda ref: 1025)
    with pytest.raises(GhidraMcpError) as ei:
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="big"))
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED
    assert worker.killed == 0  # pre-flight rejection: worker untouched
    srv.close()
    wrk.close()


def test_import_unresolvable_source_is_validation_error() -> None:
    """A ``source_ref`` the resolver cannot stat fails closed as VALIDATION (no leak, no worker)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()

    def _boom(ref: str) -> int:
        raise FileNotFoundError("/secret/host/path")  # detail must NOT cross the boundary

    adapter = _import_adapter(srv, worker, limits=Limits(), resolver=_boom)
    with pytest.raises(GhidraMcpError) as ei:
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="missing"))
    assert ei.value.envelope.type is ErrorType.VALIDATION
    assert "secret" not in ei.value.envelope.detail
    srv.close()
    wrk.close()


def test_import_resolver_valueerror_is_validation_error() -> None:
    """A confined resolver rejecting a ref via ``ValueError`` also fails closed as VALIDATION.

    The default resolver only ever raises ``OSError`` (stat), but a deploy-supplied allow-list/
    path-confinement resolver signals a rejected ``source_ref`` (e.g. outside its root) by raising
    ``ValueError``. That must map to the SAME fail-closed ``VALIDATION`` with a fixed, content-free
    detail — never the resolver's own message (master §5).
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()

    def _reject(ref: str) -> int:
        raise ValueError("path /etc/shadow escapes allow-list root /srv/inputs")

    adapter = _import_adapter(srv, worker, limits=Limits(), resolver=_reject)
    with pytest.raises(GhidraMcpError) as ei:
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="../../etc/shadow"))
    assert ei.value.envelope.type is ErrorType.VALIDATION
    assert "shadow" not in ei.value.envelope.detail  # resolver message never crosses the boundary
    assert "allow-list" not in ei.value.envelope.detail
    assert worker.killed == 0  # rejected pre-Ghidra; worker untouched
    srv.close()
    wrk.close()


def test_import_resolver_unexpected_error_propagates_unmasked() -> None:
    """A non-resolution error (wiring/programmer bug) propagates — it is NOT masked as VALIDATION.

    Broadening the resolver catch to ``(OSError, ValueError)`` must NOT swallow other exceptions:
    a ``TypeError`` (e.g. a mis-wired resolver) is a programmer error and must fail fast, not be
    laundered into an input-validation error (``topic-error-handling``: fail fast on bugs).
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()

    def _misbehaving(ref: str) -> int:
        raise TypeError("resolver wired with the wrong argument shape")

    adapter = _import_adapter(srv, worker, limits=Limits(), resolver=_misbehaving)
    with pytest.raises(TypeError):
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="ok"))
    assert worker.killed == 0
    srv.close()
    wrk.close()


def test_import_within_cap_feeds_worker() -> None:
    """A within-cap binary passes the check and the import RPC reaches the worker."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    limits = Limits(max_binary_bytes=4096)
    adapter = _import_adapter(srv, worker, limits=limits, resolver=lambda ref: 4096)
    result = {
        "session_id": "s",
        "state": "importing",
        "created_at": 1,
        "expires_at": 2,
        "binary_sha256": "b" * 64,
    }
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    info = adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="ok"))
    t.join(timeout=2)
    assert info.state == "importing"
    # Item 2 (ADR-018): the server-resolved input size is overlaid onto the worker's reply, even
    # though the worker reply carried no ``binary_size`` (it does not report it).
    assert info.binary_size == 4096
    assert worker.killed == 0
    wrk.close()


def test_import_overlays_resolved_size_over_any_worker_reported_size() -> None:
    """Item 2 (ADR-018): the server-resolved size is authoritative over a worker-claimed one.

    The adapter computes the size from the confined resolver pre-Ghidra (ADR-001) and overlays it;
    a (hostile/buggy) worker cannot dictate the recorded provenance.
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _import_adapter(
        srv, worker, limits=Limits(max_binary_bytes=1 << 20), resolver=lambda ref: 1234
    )
    result = {
        "session_id": "s",
        "state": "importing",
        "created_at": 1,
        "expires_at": 2,
        "binary_sha256": "b" * 64,
        "binary_size": 999_999,  # worker-forged size — MUST be discarded for the resolved value
    }
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    info = adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="ok"))
    t.join(timeout=2)
    assert info.binary_size == 1234  # the server-resolved size, not the worker's claim
    wrk.close()


def _serve_import_ok(wrk: socket.socket) -> threading.Thread:
    """Start a daemon thread that answers one import_binary RPC with a minimal SessionInfo."""
    result = {
        "session_id": "s",
        "state": "importing",
        "created_at": 1,
        "expires_at": 2,
        "binary_sha256": "b" * 64,
    }
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    return t


def test_preflight_oversized_warns_and_proceeds(caplog: pytest.LogCaptureFixture) -> None:
    """An input above the OOM-plausible threshold logs a warn (size + mem only) and PROCEEDS."""
    import logging

    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    # Within the hard binary cap, but above plausible_max_bytes(64 MiB) = 128 MiB.
    size = 200 * 1024 * 1024
    adapter = _ConnectedAdapter(
        server_sock=srv,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
        limits=Limits(max_binary_bytes=1024 * 1024 * 1024),
        source_resolver=lambda ref: size,
        worker_mem_mib=64,
    )
    adapter.start_worker("s")
    t = _serve_import_ok(wrk)
    with caplog.at_level(logging.WARNING):
        info = adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="big-ok"))
    t.join(timeout=2)
    # Proceeded (not a reject): the RPC reached the worker and returned.
    assert info.state == "importing"
    assert worker.killed == 0
    rec = next(r for r in caplog.records if r.message == "worker.preflight_oversized")
    # The log carries ONLY size + configured memory (no content/path — master §5 redaction).
    assert rec.size_bytes == size  # type: ignore[attr-defined]
    assert rec.worker_mem_mib == 64  # type: ignore[attr-defined]
    wrk.close()


def test_preflight_not_emitted_for_normal_input(caplog: pytest.LogCaptureFixture) -> None:
    """An input within the plausible threshold emits NO oversized pre-flight log."""
    import logging

    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _ConnectedAdapter(
        server_sock=srv,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
        limits=Limits(),
        source_resolver=lambda ref: 1024,  # tiny — well under the threshold
        worker_mem_mib=4096,
    )
    adapter.start_worker("s")
    t = _serve_import_ok(wrk)
    with caplog.at_level(logging.WARNING):
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="ok"))
    t.join(timeout=2)
    assert not any(r.message == "worker.preflight_oversized" for r in caplog.records)
    wrk.close()


# --- pre-flight mode (ADR-029 C) --------------------------------------------------------------
def _preflight_adapter(
    server_sock: socket.socket,
    worker: _FakeWorker,
    *,
    size: int,
    mode: str,
) -> _ConnectedAdapter:
    """Build a connected adapter with a given pre-flight ``mode`` + a fixed resolved input size.

    Memory is pinned at 64 MiB so the plausibility threshold is a known 128 MiB; the hard binary cap
    is set to 1 GiB so it never fires before the pre-flight under test.
    """
    adapter = _ConnectedAdapter(
        server_sock=server_sock,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
        limits=Limits(max_binary_bytes=1024 * 1024 * 1024),
        source_resolver=lambda ref: size,
        worker_mem_mib=64,
        preflight_mode=mode,
    )
    adapter.start_worker("s")
    return adapter


def test_preflight_reject_over_threshold_fails_closed_before_worker(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``reject`` mode raises ``resource-exhausted`` (503, non-retryable); never feeds the worker.

    The error detail (and any log) must carry NO content/path sentinel — only size + memory may be
    logged (master §5 redaction).
    """
    import logging

    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    size = 200 * 1024 * 1024  # above plausible_max_bytes(64 MiB) = 128 MiB
    adapter = _preflight_adapter(srv, worker, size=size, mode="reject")
    sentinel = "/secret/host/binary-name"
    with (
        caplog.at_level(logging.WARNING),
        pytest.raises(GhidraMcpError) as ei,
    ):
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref=sentinel))
    env = ei.value.envelope
    assert env.type is ErrorType.RESOURCE_EXHAUSTED
    assert env.status == 503
    assert env.retryable is False
    # The reject is pre-Ghidra: no RPC was sent, the worker was never contacted.
    assert worker.killed == 0
    # Redaction: neither the detail nor any log record leaks the source ref / content.
    assert sentinel not in env.detail
    assert all(sentinel not in str(getattr(r, "msg", "")) for r in caplog.records)
    assert all(sentinel not in str(getattr(r, "args", "")) for r in caplog.records)
    srv.close()
    wrk.close()


def test_preflight_warn_mode_logs_and_proceeds() -> None:
    """``warn`` mode (the default) proceeds: the import RPC reaches the worker."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    size = 200 * 1024 * 1024
    adapter = _preflight_adapter(srv, worker, size=size, mode="warn")
    t = _serve_import_ok(wrk)
    info = adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="big-ok"))
    t.join(timeout=2)
    assert info.state == "importing"
    assert worker.killed == 0
    wrk.close()


def test_preflight_off_mode_skips_check_and_proceeds() -> None:
    """``off`` mode skips the plausibility check entirely: an oversized input still proceeds."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    size = 200 * 1024 * 1024  # over threshold, but off → no warn, no reject
    adapter = _preflight_adapter(srv, worker, size=size, mode="off")
    t = _serve_import_ok(wrk)
    info = adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="big-ok"))
    t.join(timeout=2)
    assert info.state == "importing"
    assert worker.killed == 0
    wrk.close()


def test_preflight_under_threshold_untouched_in_every_mode() -> None:
    """An under-threshold input proceeds untouched regardless of mode (warn/reject/off)."""
    for mode in ("warn", "reject", "off"):
        srv, wrk = socket.socketpair(socket.AF_UNIX)
        worker = _FakeWorker()
        adapter = _preflight_adapter(srv, worker, size=1024, mode=mode)  # tiny — under 128 MiB
        t = _serve_import_ok(wrk)
        info = adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="ok"))
        t.join(timeout=2)
        assert info.state == "importing", mode
        assert worker.killed == 0, mode
        wrk.close()


def test_preflight_unknown_mode_falls_back_to_warn(caplog: pytest.LogCaptureFixture) -> None:
    """A bad mode reaching the adapter degrades to ``warn`` (fail safe — never silently ``off``)."""
    import logging

    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    size = 200 * 1024 * 1024
    adapter = _preflight_adapter(srv, worker, size=size, mode="bogus")
    t = _serve_import_ok(wrk)
    with caplog.at_level(logging.WARNING):
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="big-ok"))
    t.join(timeout=2)
    # Degraded to warn: it logged the heads-up and proceeded (did not reject, did not skip).
    assert any(r.message == "worker.preflight_oversized" for r in caplog.records)
    assert worker.killed == 0
    wrk.close()


# --- analyze param-shaping (ADR-029 B; pure helper) -------------------------------------------
def test_analyze_params_default_is_no_op() -> None:
    """The default profile yields the PRE-ADR-029 param shape — no ``profile`` key (no-op)."""
    from vivarium.ghidra.rpc_client import _analyze_params

    assert _analyze_params(123, "default") == {"timeout_seconds": 123}
    assert "profile" not in _analyze_params(None, "default")


@pytest.mark.parametrize("profile", ["light", "deep"])
def test_analyze_params_non_default_adds_profile(profile: str) -> None:
    """A non-default profile adds the explicit ``profile`` key alongside the timeout."""
    from vivarium.ghidra.rpc_client import _analyze_params

    assert _analyze_params(None, profile) == {"timeout_seconds": None, "profile": profile}


def test_analyze_threads_profile_into_rpc() -> None:
    """``analyze`` sends the profile in the RPC params for a non-default profile (ADR-029 B)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    seen: dict[str, object] = {}

    def _serve() -> None:
        obj = dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        seen.update(obj["params"])
        result = {
            "session_id": "s",
            "state": "ready",
            "created_at": 1,
            "expires_at": 2,
            "binary_sha256": None,
        }
        wrk.sendall(
            rpc_framing.encode_frame(
                {"jsonrpc": "2.0", "id": obj["id"], "result": result}, max_frame_bytes=_CAP
            )
        )

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", profile="light"))
    t.join(timeout=2)
    assert seen.get("profile") == "light"
    srv.close()
    wrk.close()


def test_analyze_default_profile_omits_profile_in_rpc() -> None:
    """The default profile sends NO ``profile`` key — the worker takes the unchanged path."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    seen: dict[str, object] = {}

    def _serve() -> None:
        obj = dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        seen.update(obj["params"])
        result = {
            "session_id": "s",
            "state": "ready",
            "created_at": 1,
            "expires_at": 2,
            "binary_sha256": None,
        }
        wrk.sendall(
            rpc_framing.encode_frame(
                {"jsonrpc": "2.0", "id": obj["id"], "result": result}, max_frame_bytes=_CAP
            )
        )

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    adapter.analyze("s", s.SessionAnalyzeIn(session_id="s"))
    t.join(timeout=2)
    assert "profile" not in seen
    assert seen == {"timeout_seconds": None}
    srv.close()
    wrk.close()


def test_default_source_resolver_stats_a_real_file(tmp_path: Path) -> None:
    """The built-in resolver returns the on-disk size (used when no confined resolver is wired)."""
    from vivarium.ghidra.rpc_client import _default_source_size

    f = tmp_path / "blob.bin"
    f.write_bytes(b"abcd")
    assert _default_source_size(str(f)) == 4


def test_ensure_connected_dials_real_uds(tmp_path: Path) -> None:
    """The real ``_ensure_connected`` connects to the per-session UDS and round-trips a call.

    Uses a genuinely bound listening UDS (no socketpair, no subclass override) so the adapter's
    own connect path is exercised — then a within-process 'worker' thread accepts and replies.
    """
    sock_dir = str(tmp_path)
    worker = _FakeWorker()
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: worker,
        socket_dir=sock_dir,
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
    )
    adapter.start_worker("s")
    sock_path = adapter._socket_path("s")
    Path(sock_path).parent.mkdir(parents=True, exist_ok=True)  # per-session subdir (ADR-009)

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(1)

    _resp = {
        "jsonrpc": "2.0",
        "result": {"address": "0x1", "name": "main", "c_code": "x", "signature": "void main()"},
    }

    def _serve() -> None:
        conn, _ = listener.accept()
        try:
            _serve_one(conn, dict(_resp))  # first call: fresh connect
            _serve_one(conn, dict(_resp))  # second call: reuses the cached socket
        finally:
            conn.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    out1 = adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    # Second call on the same session reuses the cached socket (covers the cached-socket branch).
    out2 = adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    t.join(timeout=3)
    assert out1.name.value == "main"
    assert out2.name.value == "main"
    assert worker.killed == 0
    adapter.kill_worker("s")  # closes the connected socket
    listener.close()


def test_ensure_connected_retries_until_worker_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The connect retries past the worker-bind race (ENOENT/ECONNREFUSED), not one-shot.

    The spawn (`podman run --detach`) returns before the worker binds its UDS; a single connect
    would lose the race and fail closed as worker-unavailable. Here connect fails twice (not bound
    yet) then succeeds — the adapter must keep trying within the connect budget.
    """
    from vivarium.ghidra import rpc_client as rc

    # String targets (not rc.time/rc.socket attribute access) so --strict mypy doesn't flag the
    # imported modules as non-reexported attributes; monkeypatch resolves them on the module.
    monkeypatch.setattr("vivarium.ghidra.rpc_client.time.sleep", lambda *_: None)
    attempts = {"n": 0}

    class _FlakySock:
        def settimeout(self, *_: object) -> None: ...

        def connect(self, path: str) -> None:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise FileNotFoundError(path)  # socket not bound yet

        def close(self) -> None: ...

    monkeypatch.setattr("vivarium.ghidra.rpc_client.socket.socket", lambda *a, **k: _FlakySock())
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/run/x",
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
        connect_timeout_s=5.0,
    )
    sess = rc._Session(_FakeWorker(), "/run/x/s/s.sock")
    # Q4: a far-future call deadline → the connect budget is bounded by connect_timeout_s (5s), so
    # the three fast (no-op-sleep) retries succeed exactly as before.
    got = adapter._ensure_connected(sess, deadline=time.monotonic() + 100.0)
    assert attempts["n"] == 3
    assert got is sess.sock


def test_ensure_connected_gives_up_after_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that never binds within the budget makes connect raise (→ worker-unavailable).

    Controlled 3-tick monotonic clock so the first attempt runs (remaining>0), gets
    ``ConnectionRefusedError`` (bound-but-not-accepting), and the post-attempt budget check sees the
    budget elapsed → re-raises it (NOT the loop-top ``ConnectionError``). Ticks: connect_deadline
    computation, loop-top remaining, post-attempt give-up check.
    """
    from vivarium.ghidra import rpc_client as rc

    monkeypatch.setattr("vivarium.ghidra.rpc_client.time.sleep", lambda *_: None)
    clock = iter([0.0, 0.0, 100.0])  # min()+budget, loop-top remaining, then past the budget
    monkeypatch.setattr("vivarium.ghidra.rpc_client.time.monotonic", lambda: next(clock))

    class _DeadSock:
        def settimeout(self, *_: object) -> None: ...

        def connect(self, path: str) -> None:
            raise ConnectionRefusedError(path)  # bound but never accepting

        def close(self) -> None: ...

    monkeypatch.setattr("vivarium.ghidra.rpc_client.socket.socket", lambda *a, **k: _DeadSock())
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/run/x",
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
        connect_timeout_s=5.0,
    )
    sess = rc._Session(_FakeWorker(), "/run/x/s/s.sock")
    # A far-future literal deadline (no monotonic() call) so the connect_timeout_s budget expires
    # first → the caught ConnectionRefusedError is re-raised (worker-unavailable), not the top one.
    with pytest.raises(ConnectionRefusedError):
        adapter._ensure_connected(sess, deadline=1000.0)


def test_ensure_connected_fails_closed_when_call_deadline_already_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """gap round-4 Q4: if the per-call deadline is already spent on entry (e.g. the lock acquire ate
    the budget), connect makes NO socket attempt and fails closed → worker-unavailable.

    A past deadline makes ``connect_deadline`` already elapsed, so the loop-top guard raises before
    any ``socket()`` — proving connect can't run (under sess.lock) once the call budget is gone.
    """
    from vivarium.ghidra import rpc_client as rc

    clock = iter([10.0, 10.0])  # connect_deadline computation, then loop-top remaining (<= 0)
    monkeypatch.setattr("vivarium.ghidra.rpc_client.time.monotonic", lambda: next(clock))
    # No socket() should ever be constructed; make it explode if the guard fails to short-circuit.
    monkeypatch.setattr(
        "vivarium.ghidra.rpc_client.socket.socket",
        lambda *a, **k: pytest.fail("connect attempted despite an elapsed call deadline"),
    )
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/run/x",
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
        connect_timeout_s=5.0,
    )
    sess = rc._Session(_FakeWorker(), "/run/x/s/s.sock")
    with pytest.raises(ConnectionError):  # OSError family → mapped to worker-unavailable by _call
        adapter._ensure_connected(sess, deadline=0.0)  # already in the past


def test_socket_path_fits_af_unix_limit_with_real_session_id() -> None:
    """The per-session UDS path stays under the AF_UNIX limit with a 256-bit id + default dir.

    Regression: using the full 43-char session id for BOTH the dir and the filename overflowed
    AF_UNIX (~107 bytes) at the default /run/vivarium (108). The dir is now a short id prefix;
    the filename keeps the full id (in-container contract unchanged).
    """
    import secrets as _secrets

    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/run/vivarium",  # the production default
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
    )
    sid = _secrets.token_urlsafe(32)  # 43 chars — the real session-id width
    path = adapter._socket_path(sid)
    assert len(path) < 108, f"AF_UNIX path too long: {len(path)}"
    parent, _, name = path.rpartition("/")
    assert parent.rpartition("/")[2] == sid[:16]  # dir = short prefix
    assert name == f"{sid}.sock"  # filename keeps the full id


# --- worker dispatcher (JVM-free) -------------------------------------------------------------
class _FakeBackend:
    """A fake :class:`worker.dispatch.GhidraBackend` recording calls and returning canned dicts."""

    def __init__(self) -> None:
        """Initialize with no recorded calls."""
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __getattr__(self, name: str) -> Callable[[dict[str, object]], dict[str, object]]:
        """Return a handler that records the call and echoes the method name."""

        def handler(params: dict[str, object]) -> dict[str, object]:
            self.calls.append((name, params))
            return {"method": name}

        return handler

    def analyze(
        self,
        params: dict[str, Any],
        *,
        emit_progress: Callable[[int | None, str], None] | None = None,
    ) -> dict[str, Any]:
        """Explicit ``analyze`` matching the ``GhidraBackend`` protocol (ADR-030 emit_progress kw).

        The catch-all ``__getattr__`` cannot satisfy the protocol's keyword-only ``emit_progress``
        signature, so ``analyze`` is declared explicitly. Records the call (with whether progress
        was requested) and echoes, like every other faked method.
        """
        self.calls.append(("analyze", {**params, "_emit_progress": emit_progress is not None}))
        return {"method": "analyze"}

    def start_decompile_stream(
        self,
        params: dict[str, Any],
        *,
        emit_chunk: Callable[[int, str, dict[str, Any]], None] | None = None,
        poll_cancel: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        """Explicit ``start_decompile_stream`` matching the protocol's keyword-only collaborators.

        Like ``analyze``, the catch-all ``__getattr__`` cannot express the keyword-only emitter /
        cancel poll, so this is declared explicitly. Records the call (with whether a chunk emitter
        and a cancel poll were supplied) and returns a canned terminal summary.
        """
        self.calls.append(
            (
                "start_decompile_stream",
                {
                    **params,
                    "_emit_chunk": emit_chunk is not None,
                    "_poll_cancel": poll_cancel is not None,
                },
            )
        )
        return {"total": 0, "truncated": False, "done": True}


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
        cast("dispatch.GhidraBackend", _Boom()),
        {"jsonrpc": "2.0", "id": "1", "method": "list_strings", "params": {}},
    )
    assert resp["error"]["data"]["type"] == "not-found"


def test_handle_request_unexpected_exception_is_internal_only() -> None:
    class _Boom:
        def memory_map(self, params: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("/secret/host/path leaked")  # must NOT cross the boundary

    resp = dispatch.handle_request(
        cast("dispatch.GhidraBackend", _Boom()),
        {"jsonrpc": "2.0", "id": "1", "method": "memory_map", "params": {}},
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


# --- ADR-024 PR-1: redacted worker-error detail (worker→server only) --------------------------
def test_handle_request_unexpected_exception_carries_redacted_detail() -> None:
    """An unexpected worker exception → generic message + redacted class-name detail only."""

    class _Boom:
        def memory_map(self, params: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("SECRET /host/path 0xdeadbeef decompiled body")

    resp = dispatch.handle_request(
        cast("dispatch.GhidraBackend", _Boom()),
        {"jsonrpc": "2.0", "id": "1", "method": "memory_map", "params": {}},
    )
    assert resp["error"]["code"] == dispatch.CODE_INTERNAL
    assert resp["error"]["message"] == "internal worker error"  # client-facing message unchanged
    detail = resp["error"]["data"]["detail"]
    # The redacted detail is the class name + fixed template — NOT the raw exception text.
    assert detail == "RuntimeError: unhandled worker exception"
    assert "SECRET" not in detail  # binary-derived / host text must never be forwarded
    assert "0xdeadbeef" not in detail
    assert "/host/path" not in detail


def test_handle_request_detail_uses_exception_class_name() -> None:
    """The detail names *which* exception class fired (diagnosability) without its message."""

    class _NpeError(Exception):
        """Stand-in for a JVM NullPointerException whose str() echoes a value."""

    class _Boom:
        def exports(self, params: dict[str, object]) -> dict[str, object]:
            raise _NpeError("at Symbol.getAddress(null) — SENTINEL_VALUE")

    resp = dispatch.handle_request(
        cast("dispatch.GhidraBackend", _Boom()),
        {"jsonrpc": "2.0", "id": "7", "method": "exports", "params": {}},
    )
    assert resp["error"]["data"]["detail"] == "_NpeError: unhandled worker exception"
    assert "SENTINEL_VALUE" not in resp["error"]["data"]["detail"]


def test_build_error_without_detail_omits_data_detail() -> None:
    """A mapped WorkerError (no detail) carries the slug only — no ``data.detail`` key."""
    resp = dispatch.build_error("id", dispatch.CODE_NOT_FOUND, "missing")
    assert resp["error"]["data"] == {"type": "not-found"}
    assert "detail" not in resp["error"]["data"]


def test_worker_error_detail_threads_to_data_detail_log_only() -> None:
    """A ``WorkerError`` carrying a ``detail`` surfaces it in log-only ``data.detail`` (ADR-035).

    The analyzer-option guard raises ``WorkerError(CODE_INTERNAL, <template>, detail=<missing>)``.
    The client-facing ``message`` stays generic; the redacted, log-only ``data.detail`` carries the
    diagnostic (which option drifted) — so a red ADR-028 nightly is actionable.
    """

    class _Boom:
        def memory_map(self, params: dict[str, object]) -> dict[str, object]:
            raise dispatch.WorkerError(
                dispatch.CODE_INTERNAL,
                "analyzer profile references option(s) not available in this Ghidra build",
                detail="analyzer profile option(s) absent in this Ghidra build: ['Bogus Analyzer']",
            )

    resp = dispatch.handle_request(
        cast("dispatch.GhidraBackend", _Boom()),
        {"jsonrpc": "2.0", "id": "9", "method": "memory_map", "params": {}},
    )
    assert resp["error"]["code"] == dispatch.CODE_INTERNAL
    assert resp["error"]["data"]["type"] == "internal-error"
    # Generic client-facing message (no diagnostic leaks to the client envelope message).
    assert resp["error"]["message"] == (
        "analyzer profile references option(s) not available in this Ghidra build"
    )
    # The missing-option diagnostic rides ONLY in the log-only data.detail.
    assert "Bogus Analyzer" in resp["error"]["data"]["detail"]


def test_worker_error_defaults_to_no_detail() -> None:
    """A plain ``WorkerError`` (no ``detail``) still omits ``data.detail`` (backward compat)."""

    class _Boom:
        def memory_map(self, params: dict[str, object]) -> dict[str, object]:
            raise dispatch.WorkerError(dispatch.CODE_NOT_FOUND, "missing")

    resp = dispatch.handle_request(
        cast("dispatch.GhidraBackend", _Boom()),
        {"jsonrpc": "2.0", "id": "10", "method": "memory_map", "params": {}},
    )
    assert resp["error"]["data"] == {"type": "not-found"}
    assert "detail" not in resp["error"]["data"]


def test_parse_error_reads_optional_detail() -> None:
    """The framing parser threads the optional ``data.detail`` into the RpcError (capped)."""
    err = {
        "code": -32603,
        "message": "internal worker error",
        "data": {"type": "internal-error", "detail": "RuntimeError: unhandled worker exception"},
    }
    parsed = rpc_framing._parse_error(err)
    assert parsed.type_slug == "internal-error"
    assert parsed.detail == "RuntimeError: unhandled worker exception"


def test_parse_error_detail_is_capped_and_string_only() -> None:
    """A non-string or oversized worker ``data.detail`` is ignored / bounded (fail closed)."""
    too_long = {
        "code": -32603,
        "message": "m",
        "data": {"type": "internal-error", "detail": "z" * 9999},
    }
    assert len(rpc_framing._parse_error(too_long).detail or "") == rpc_framing._MAX_DETAIL_CHARS
    non_str = {"code": -32603, "message": "m", "data": {"type": "internal-error", "detail": 123}}
    assert rpc_framing._parse_error(non_str).detail is None


def test_call_method_error_logs_redacted_detail_and_does_not_change_envelope(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A worker method error logs slug+detail via SAFE keys; client envelope is unchanged."""
    import logging

    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    err = {
        "jsonrpc": "2.0",
        "error": {
            "code": -32603,
            "message": "internal worker error",
            "data": {
                "type": "internal-error",
                "detail": "NullPointerException: unhandled worker exception",
            },
        },
    }
    t = threading.Thread(target=_serve_one, args=(wrk, err), daemon=True)
    t.start()
    with caplog.at_level(logging.WARNING), pytest.raises(GhidraMcpError) as ei:
        adapter.list_exports("s", s.ListExportsIn(session_id="s"))
    t.join(timeout=2)

    # Client envelope: mapped to INTERNAL, generic message — detail is NOT on it.
    assert ei.value.envelope.type is ErrorType.INTERNAL
    assert "NullPointerException" not in ei.value.envelope.detail
    assert worker.killed == 0  # a healthy worker returning a method error is NOT killed

    rec = next(r for r in caplog.records if r.message == "worker.method_error")
    # Safe extra keys carry the diagnostic for server-side logs.
    assert rec.slug == "internal-error"  # type: ignore[attr-defined]
    assert rec.detail == "NullPointerException: unhandled worker exception"  # type: ignore[attr-defined]
    assert rec.method == "exports"  # type: ignore[attr-defined]  # RPC name (list_exports→"exports")
    wrk.close()


def test_worker_message_is_not_forwarded_to_client_detail(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """gap round-4 Q8: a worker method-error's free-form message never reaches the client envelope.

    The worker is a hostile fault domain (TB2/TB3); its ``message`` bypasses the untrusted-data
    envelope normalization, so it is NOT placed on ``ErrorEnvelope.detail`` (a fixed per-type detail
    is used) — it is captured log-only for diagnosis, like ``data.detail`` already is.
    """
    import logging

    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    # bidi override (U+202E) + BEL (U+0007) + over the 512-char cap; chr() so the source
    # carries no raw ambiguous/invisible char (RUF001).
    bidi, bel = chr(0x202E), chr(0x07)
    hostile = "PWN" + bidi + "inject" + bel + "x" * 600
    err = {
        "jsonrpc": "2.0",
        "error": {"code": -32004, "message": hostile, "data": {"type": "not-found"}},
    }
    t = threading.Thread(target=_serve_one, args=(wrk, err), daemon=True)
    t.start()
    with caplog.at_level(logging.WARNING), pytest.raises(GhidraMcpError) as ei:
        adapter.get_function("s", s.GetFunctionIn(session_id="s", function="main"))
    t.join(timeout=2)

    env = ei.value.envelope
    assert env.type is ErrorType.NOT_FOUND
    # The untrusted worker message is NOT on the client envelope — a FIXED safe detail is used.
    assert "PWN" not in env.detail and bidi not in env.detail and bel not in env.detail
    assert env.detail == "the requested item was not found in the program"
    # It IS captured server-side (log-only, non-reserved key) for diagnosis.
    rec = next(r for r in caplog.records if r.message == "worker.method_error")
    assert "PWN" in rec.worker_message  # type: ignore[attr-defined]
    wrk.close()


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
