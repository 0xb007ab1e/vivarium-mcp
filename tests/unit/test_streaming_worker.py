"""Unit tests for the ADR-040 Phase 2 worker side (dispatch routing + chunk emitter + backend).

Hermetic, JVM-free: the JVM-touching ``_gh_decompile_stream`` edge is NOT exercised here (it is
``# pragma: no cover`` and validated under live-regression). These cover the parts that are pure /
fake-able:

- **Allow-list:** ``start_decompile_stream`` / ``cancel_stream`` are in the frozen ``RPC_METHODS``.
- **Dispatch routing:** ``start_decompile_stream`` is threaded the socket-bound chunk emitter
  (keyword-only) exactly like opted-in ``analyze`` is threaded the progress emitter; other methods
  never receive it.
- **The chunk emitter** (``_make_chunk_emitter``): emits a valid ``$/chunk`` frame; unlike the
  progress emitter it does NOT coalesce or swallow (every chunk delivered, errors propagate so the
  stream fails honestly).
- **Backend ``start_decompile_stream``/``cancel_stream``:** param shaping (``functions`` vs window)
  and the per-stream cancel flag, with the JVM edge stubbed.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from worker import dispatch as wd

from vivarium.ghidra import rpc_framing as f
from vivarium.ghidra._jvm_bridge import PyGhidraBackend

_CAP = 4 * 1024 * 1024
_RID = "req-stream-1"


# --- allow-list --------------------------------------------------------------------------------
def test_streaming_methods_in_allow_list() -> None:
    assert "start_decompile_stream" in wd.RPC_METHODS
    assert "cancel_stream" in wd.RPC_METHODS


# --- dispatch routing of the chunk emitter -----------------------------------------------------
class _RecordingBackend:
    """Backend fake recording whether ``start_decompile_stream`` received an ``emit_chunk``."""

    def __init__(self) -> None:
        self.stream_emit: list[bool] = []

    def start_decompile_stream(
        self, params: dict[str, Any], *, emit_chunk: Any = None
    ) -> dict[str, Any]:
        self.stream_emit.append(emit_chunk is not None)
        return {"total": 0, "truncated": False, "done": True}

    def cancel_stream(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"cancelled": True}

    def __getattr__(self, name: str) -> Any:
        def _handler(params: dict[str, Any]) -> dict[str, Any]:
            return {"method": name}

        return _handler


def test_dispatch_threads_chunk_emitter_into_start_decompile_stream() -> None:
    be = _RecordingBackend()

    def _emitter(seq: int, kind: str, payload: dict[str, Any]) -> None:
        return None

    wd.dispatch(be, "start_decompile_stream", {"limit": 3}, emit_chunk=_emitter)
    wd.dispatch(be, "start_decompile_stream", {"limit": 3}, emit_chunk=None)  # no emitter built
    assert be.stream_emit == [True, False]


def test_dispatch_non_stream_method_never_uses_chunk_emitter() -> None:
    be = _RecordingBackend()
    called: list[tuple[int, str, dict[str, Any]]] = []
    out = wd.dispatch(be, "list_functions", {}, emit_chunk=lambda s, k, p: called.append((s, k, p)))
    assert out == {"method": "list_functions"}
    assert called == []


def test_dispatch_cancel_stream_routes_to_backend() -> None:
    be = _RecordingBackend()
    out = wd.dispatch(be, "cancel_stream", {})
    assert out == {"cancelled": True}


# --- the chunk emitter (_make_chunk_emitter) ---------------------------------------------------
class _RecordingConn:
    """A ``_Conn`` fake recording every frame sent (the worker's session socket)."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, _n: int) -> bytes:  # part of the _Conn protocol; unused by the emitter
        return b""


class _RaisingConn:
    """A ``_Conn`` fake whose ``sendall`` always raises ``OSError`` (transient socket error)."""

    def sendall(self, data: bytes) -> None:
        raise OSError("broken pipe")

    def recv(self, _n: int) -> bytes:  # part of the _Conn protocol; unused by the emitter
        return b""


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


# --- backend start_decompile_stream / cancel_stream (JVM edge stubbed) -------------------------
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


def test_backend_start_resets_cancel_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh start clears any prior cancel flag and passes a live predicate to the edge."""
    be = PyGhidraBackend()
    be._stream_cancelled = True  # a stale cancel from a prior stream
    captured: dict[str, Any] = {}

    def _fake_edge(
        names: list[str] | None, offset: int, limit: int, *, emit_chunk: Any, is_cancelled: Any
    ) -> dict[str, Any]:
        captured["before"] = is_cancelled()
        return {"total": 0, "truncated": False, "done": True}

    monkeypatch.setattr(be, "_gh_decompile_stream", _fake_edge)
    be.start_decompile_stream({"limit": 1}, emit_chunk=None)
    assert captured["before"] is False  # the start reset the stale flag


def test_backend_cancel_stream_sets_flag() -> None:
    be = PyGhidraBackend()
    # Read the flag into locals before/after the mutating call so mypy does not narrow the
    # attribute to a literal across the mutation (a known mypy literal-narrowing trap).
    before = be._stream_cancelled
    out = be.cancel_stream({})
    after = be._stream_cancelled
    assert before is False
    assert out == {"cancelled": True}
    assert after is True
    # Idempotent: a second cancel is still cancelled.
    out2 = be.cancel_stream({})
    assert out2 == {"cancelled": True}
    assert be._stream_cancelled is True
