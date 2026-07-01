"""Unit tests for the mutation (write) RPC adapter methods (ADR-012) — TB2/TB4.

Mirrors ``test_rpc_adapter.py``: a real connected UDS pair (``socket.socketpair``) plays the worker
and a fake worker handle records kills. No real Ghidra, no JVM, no network. Asserts, for each of the
four write adapter methods (``rename_function`` / ``rename_symbol`` / ``set_comment`` / ``undo``):

- a success result round-trips into the typed ``*Out`` with ``old_name`` Untrusted-wrapped
  (binary-derived → ADR-005) and ``applied`` / ``kind`` / ``new_name`` bare (server/validated/safe);
- a worker JSON-RPC error result (``not-found`` / ``analysis-failed``) maps to the right
  ``ErrorType`` WITHOUT killing the (healthy) worker;
- a structurally-malformed / missing-key worker result fails closed as ``WORKER_UNAVAILABLE`` (the
  ``_fail_closed`` builders), never surfacing the raw shaping error.
"""

from __future__ import annotations

import socket
import threading
from typing import cast

import pytest
from worker import dispatch

from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra import rpc_framing
from vivarium.ghidra.rpc_client import RpcGhidraAdapter
from vivarium.tools import schemas as s

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
    """Adapter whose ``_ensure_connected`` returns a pre-wired socketpair end."""

    def __init__(self, *, server_sock: socket.socket, **kw: object) -> None:
        """Initialize with the server-side end of a connected socket pair.

        Args:
            server_sock: The socket the adapter should use as if connected to the worker.
            **kw: Forwarded to :class:`RpcGhidraAdapter`.
        """
        super().__init__(**kw)  # type: ignore[arg-type]
        self._wired = server_sock

    def _ensure_connected(self, sess: object, *, deadline: float = 0.0) -> socket.socket:
        """Return the pre-wired socket instead of dialing a real UDS."""
        sess.sock = self._wired  # type: ignore[attr-defined]
        return self._wired


def _make_adapter(server_sock: socket.socket, worker: _FakeWorker) -> _ConnectedAdapter:
    """Build an adapter wired to ``server_sock`` with a fake worker registered for ``sid="s"``."""
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


def _serve_one(worker_sock: socket.socket, response: dict[str, object]) -> None:
    """Read one framed request and reply with ``response`` (echoing the request id)."""
    obj = dispatch.read_frame(worker_sock, max_frame_bytes=_CAP)
    response = {**response, "id": obj["id"]}
    worker_sock.sendall(rpc_framing.encode_frame(response, max_frame_bytes=_CAP))


def _run(method: str, args: object, result: dict[str, object]) -> tuple[object, _FakeWorker]:
    """Drive ``adapter.<method>("s", args)`` against a fake worker returning a SUCCESS ``result``.

    Args:
        method: The adapter method name to call.
        args: The input model to pass.
        result: The PLAIN (un-wrapped) success result dict the fake worker replies with.

    Returns:
        ``(typed_output, worker)`` — the wrapped output model and the fake worker handle.
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
    return out, worker


def _run_error(
    method: str, args: object, slug: str, code: int
) -> tuple[GhidraMcpError, _FakeWorker]:
    """Drive ``adapter.<method>`` against a worker replying with a JSON-RPC error.

    Args:
        method: The adapter method name.
        args: The input model.
        slug: The worker error ``data.type`` slug (e.g. ``"not-found"``).
        code: The JSON-RPC error code.

    Returns:
        ``(raised_error, worker)``.
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    err = {"jsonrpc": "2.0", "error": {"code": code, "message": "x", "data": {"type": slug}}}
    t = threading.Thread(target=_serve_one, args=(wrk, err), daemon=True)
    t.start()
    try:
        with pytest.raises(GhidraMcpError) as ei:
            getattr(adapter, method)("s", args)
    finally:
        t.join(timeout=2)
        wrk.close()
    return ei.value, worker


# --- rename_function ------------------------------------------------------------------------
def test_rename_function_success_round_trip() -> None:
    out, worker = _run(
        "rename_function",
        s.RenameFunctionIn(session_id="s", function="FUN_00401000", new_name="decrypt"),
        {
            "address": "0x401000",
            "old_name": "FUN_00401000",
            "new_name": "decrypt",
            "applied": True,
        },
    )
    assert isinstance(out, s.RenameResult)
    assert out.address == "0x401000"  # server-normalized, bare
    assert isinstance(out.old_name, Untrusted)
    assert out.old_name.origin is DataOrigin.BINARY  # prior name is binary-derived
    assert out.old_name.value == "FUN_00401000"
    assert out.new_name == "decrypt"  # the validated name we set — bare (safe)
    assert out.applied is True
    assert worker.killed == 0  # a successful write never kills the worker


def test_rename_function_wraps_old_name_with_injection_neutralized() -> None:
    """A hostile prior name (bidi camouflage) is neutralized when wrapped out (ADR-005)."""
    out, _ = _run(
        "rename_function",
        s.RenameFunctionIn(session_id="s", function="f", new_name="clean"),
        {"address": "0x1", "old_name": "evil‮name", "new_name": "clean", "applied": True},
    )
    out = cast(s.RenameResult, out)
    assert "‮" not in out.old_name.value
    assert "<U+202E>" in out.old_name.value
    assert out.old_name.notes  # the neutralized class is annotated for the client


def test_rename_function_not_found_maps_and_does_not_kill() -> None:
    err, worker = _run_error(
        "rename_function",
        s.RenameFunctionIn(session_id="s", function="missing", new_name="x"),
        slug="not-found",
        code=-32004,
    )
    assert err.envelope.type is ErrorType.NOT_FOUND
    assert worker.killed == 0  # a healthy worker returning a method error is NOT killed


def test_rename_function_rolled_back_write_is_analysis_failed() -> None:
    """A worker write that failed + rolled back surfaces as ``analysis-failed`` (ADR-012 §5)."""
    err, worker = _run_error(
        "rename_function",
        s.RenameFunctionIn(session_id="s", function="f", new_name="x"),
        slug="analysis-failed",
        code=-32010,
    )
    assert err.envelope.type is ErrorType.ANALYSIS_FAILED
    assert worker.killed == 0


def test_rename_function_malformed_result_fails_closed() -> None:
    """A missing required key in the worker result maps to WORKER_UNAVAILABLE (fail closed)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    # Missing ``applied`` / ``new_name`` keys → builder KeyError → _fail_closed maps it.
    bad = {"jsonrpc": "2.0", "result": {"address": "0x1"}}
    t = threading.Thread(target=_serve_one, args=(wrk, bad), daemon=True)
    t.start()
    try:
        with pytest.raises(GhidraMcpError) as ei:
            adapter.rename_function(
                "s", s.RenameFunctionIn(session_id="s", function="f", new_name="x")
            )
    finally:
        t.join(timeout=2)
        wrk.close()
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


# --- rename_symbol --------------------------------------------------------------------------
def test_rename_symbol_success_round_trip_includes_kind() -> None:
    out, worker = _run(
        "rename_symbol",
        s.RenameSymbolIn(session_id="s", identifier="DAT_00402000", new_name="g_key"),
        {
            "address": "0x402000",
            "old_name": "DAT_00402000",
            "new_name": "g_key",
            "applied": True,
            "kind": "LABEL",
        },
    )
    assert isinstance(out, s.RenameSymbolResult)
    assert out.old_name.origin is DataOrigin.BINARY
    assert out.new_name == "g_key"
    assert out.kind == "LABEL"  # closed-vocabulary, bare
    assert out.applied is True
    assert worker.killed == 0


def test_rename_symbol_not_found_maps_and_does_not_kill() -> None:
    err, worker = _run_error(
        "rename_symbol",
        s.RenameSymbolIn(session_id="s", identifier="missing", new_name="x"),
        slug="not-found",
        code=-32004,
    )
    assert err.envelope.type is ErrorType.NOT_FOUND
    assert worker.killed == 0


def test_rename_symbol_malformed_result_fails_closed() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    bad = {"jsonrpc": "2.0", "result": {"address": "0x1", "old_name": "x", "new_name": "y"}}
    t = threading.Thread(target=_serve_one, args=(wrk, bad), daemon=True)
    t.start()
    try:
        with pytest.raises(GhidraMcpError) as ei:
            adapter.rename_symbol(
                "s", s.RenameSymbolIn(session_id="s", identifier="d", new_name="y")
            )
    finally:
        t.join(timeout=2)
        wrk.close()
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


# --- set_comment ----------------------------------------------------------------------------
def test_set_comment_success_round_trip_no_untrusted_fields() -> None:
    out, worker = _run(
        "set_comment",
        s.SetCommentIn(session_id="s", address="0x403000", comment_type="EOL", text="note"),
        {"address": "0x403000", "comment_type": "EOL", "applied": True},
    )
    assert isinstance(out, s.SetCommentResult)
    # All fields server/closed-vocabulary — no Untrusted field on a set_comment result.
    assert out.address == "0x403000"
    assert out.comment_type == "EOL"
    assert out.applied is True
    assert worker.killed == 0


def test_set_comment_rolled_back_is_analysis_failed() -> None:
    err, worker = _run_error(
        "set_comment",
        s.SetCommentIn(session_id="s", address="0x403000", comment_type="EOL", text="x"),
        slug="analysis-failed",
        code=-32010,
    )
    assert err.envelope.type is ErrorType.ANALYSIS_FAILED
    assert worker.killed == 0


def test_set_comment_malformed_result_fails_closed() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    bad = {"jsonrpc": "2.0", "result": {"address": "0x1"}}  # missing comment_type/applied
    t = threading.Thread(target=_serve_one, args=(wrk, bad), daemon=True)
    t.start()
    try:
        with pytest.raises(GhidraMcpError) as ei:
            adapter.set_comment(
                "s", s.SetCommentIn(session_id="s", address="0x1", comment_type="EOL", text="x")
            )
    finally:
        t.join(timeout=2)
        wrk.close()
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


# --- undo -----------------------------------------------------------------------------------
def test_undo_success_round_trip() -> None:
    out, worker = _run(
        "undo",
        s.SessionUndoIn(session_id="s"),
        {"undone": True},
    )
    assert isinstance(out, s.SessionUndoOut)
    assert out.session_id == "s"  # server-known id, not taken from the worker
    assert out.undone is True
    assert worker.killed == 0


def test_undo_nothing_to_undo_is_false() -> None:
    out, _ = _run("undo", s.SessionUndoIn(session_id="s"), {"undone": False})
    out = cast(s.SessionUndoOut, out)
    assert out.undone is False


def test_undo_malformed_result_fails_closed() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    bad = {"jsonrpc": "2.0", "result": {}}  # missing ``undone``
    t = threading.Thread(target=_serve_one, args=(wrk, bad), daemon=True)
    t.start()
    try:
        with pytest.raises(GhidraMcpError) as ei:
            adapter.undo("s", s.SessionUndoIn(session_id="s"))
    finally:
        t.join(timeout=2)
        wrk.close()
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
