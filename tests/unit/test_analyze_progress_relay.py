"""ADR-030 Phase 2 — the MCP client relay (registry + server-shell wiring).

Phase 1 (``test_analyze_progress.py``) proved the worker→server ``$/progress`` stream and the
adapter-side relay callback. This module proves the SERVER half — the localized async
``session_analyze`` binding (``registry._bind_analyze``):

- the synthesized signature injects an MCP ``Context`` (FastMCP detects + EXCLUDES it from the
  input schema), so the client surface is unchanged;
- ``_progress_token`` reads the client's ``progressToken`` and fails closed to ``None``;
- **no token** → the handler runs inline with NO client relay (``on_progress is None``) — the
  pre-Phase-2 path, byte-for-byte;
- **token present** → the blocking analysis is offloaded to a worker thread and each worker
  progress frame is bridged back onto the loop via ``Context.report_progress`` (the real
  ``anyio.to_thread`` ↔ ``anyio.from_thread`` round-trip, exercised here without a JVM);
- the async error boundary maps a failure to a safe envelope.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Literal, cast

import anyio
from mcp.server.fastmcp.tools.base import Tool

from vivarium.config import Config
from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.ghidra.port import GhidraPort, OnProgress
from vivarium.security.limits import Limits
from vivarium.server.app import _with_error_boundary
from vivarium.sessions.manager import SessionManager
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

_SID = "S" * 43  # a schema-valid opaque session id
_PROGRESS_ID = "tok"  # opaque client progressToken (a request id, not a credential)
_PROGRESS_ID2 = "tok-123"


# --- minimal fakes (self-contained; the registry only needs these few methods) -----------------
class _FakeSessions:
    """In-memory stand-in exposing only the session-manager surface ``_bind_analyze`` touches."""

    def __init__(self) -> None:
        self.events: list[str] = []
        # ADR-029 B: the recorded effective analysis profile (echoed back via authorize).
        self.profile: Literal["default", "light", "deep"] | None = None

    def set_evict_callback(self, on_evict: object) -> None:
        """Composition seam (ADR-040) — build_app binds the streaming discard hook here; no-op."""

    def begin_call(self, session_id: str, *, caller: str | None = None) -> None:
        self.events.append(f"begin:{session_id}")

    def end_call(self, session_id: str, *, caller: str | None = None) -> None:
        self.events.append(f"end:{session_id}")

    def record_analysis_profile(
        self,
        session_id: str,
        profile: Literal["default", "light", "deep"],
        *,
        caller: str = "local",
    ) -> None:
        """Echo the effective analysis profile on the session (ADR-029 B)."""
        self.events.append(f"record_profile:{session_id}:{profile}")
        self.profile = profile

    def authorize(self, session_id: str, *, caller: str = "local") -> s.SessionInfo:
        self.events.append(f"authorize:{session_id}")
        return s.SessionInfo(
            session_id=session_id,
            state="ready",
            created_at=0,
            expires_at=10,
            binary_sha256=None,
            analysis_profile=self.profile,
        )


class _FakePort:
    """Port whose ``analyze`` drives the wired ``on_progress`` with a fixed frame script."""

    def __init__(self, frames: list[tuple[int | None, str]] | None = None) -> None:
        self.frames = frames or []
        self.on_progress_seen: OnProgress | None | object = "unset"

    def attach_stream_jobs(self, manager: object) -> None:
        """No-op streaming-job injection (ADR-040 composition-root wiring seam)."""
        return None

    def analyze(
        self,
        session_id: str,
        args: s.SessionAnalyzeIn,
        *,
        on_progress: OnProgress | None = None,
    ) -> s.SessionInfo:
        self.on_progress_seen = on_progress
        if on_progress is not None:
            for pct, phase in self.frames:
                on_progress(pct, phase)
        return s.SessionInfo(
            session_id=session_id,
            state="ready",
            created_at=999,  # worker-forged lifecycle; the manager overlay must win
            expires_at=1,
            binary_sha256="b" * 64,
        )


class _Meta:
    def __init__(self, token: object | None) -> None:
        self.progressToken = token  # mirrors the MCP field name (intentional mixedCase)


class _ReqCtx:
    def __init__(self, meta: _Meta | None) -> None:
        self.meta = meta


class _FakeContext:
    """Minimal MCP Context double: a request context + an async ``report_progress`` recorder."""

    def __init__(self, *, progress_token: object | None) -> None:
        self._rc = _ReqCtx(_Meta(progress_token) if progress_token is not None else None)
        self.reported: list[tuple[float, float | None, str | None]] = []

    @property
    def request_context(self) -> _ReqCtx:
        return self._rc

    async def report_progress(
        self, progress: float, total: float | None = None, message: str | None = None
    ) -> None:
        self.reported.append((progress, total, message))


def _config() -> Config:
    return Config(
        log_level="INFO",
        log_format="json",
        session_ttl_s=3600,
        session_idle_s=900,
        limits=Limits(),
        worker_image="x",
        worker_runtime="runsc",
        worker_uid=65532,
        worker_gid=65532,
        rpc_socket_dir="/run/x",
        import_root="/work/imports",
    )


def _ctx(port: _FakePort, sessions: _FakeSessions) -> reg.ToolContext:
    return reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, sessions),
        port=cast(GhidraPort, port),
    )


# --- _progress_token ----------------------------------------------------------------------------
def test_progress_token_none_when_context_is_none() -> None:
    assert reg._progress_token(None) is None


def test_progress_token_returns_client_token() -> None:
    assert (
        reg._progress_token(cast(Any, _FakeContext(progress_token=_PROGRESS_ID2))) == _PROGRESS_ID2
    )


def test_progress_token_none_when_no_meta() -> None:
    assert reg._progress_token(cast(Any, _FakeContext(progress_token=None))) is None


def test_progress_token_fails_closed_when_request_context_raises() -> None:
    class _Boom:
        @property
        def request_context(self) -> Any:
            raise ValueError("outside a request")

    assert reg._progress_token(cast(Any, _Boom())) is None


# --- synthesized signature + FastMCP Context detection ------------------------------------------
def test_signature_appends_context_param_only_when_requested() -> None:
    without = reg._signature_from_model(s.SessionAnalyzeIn)
    with_ctx = reg._signature_from_model(s.SessionAnalyzeIn, with_context=True)
    assert "context" not in without.parameters
    assert "context" in with_ctx.parameters
    # Bare class annotation (no generic args) so FastMCP's issubclass(...) detection matches.
    from mcp.server.fastmcp import Context

    assert with_ctx.parameters["context"].annotation is Context


def test_fastmcp_detects_context_and_excludes_it_from_the_input_schema() -> None:
    handler = reg._bind_analyze(_ctx(_FakePort(), _FakeSessions()))
    tool = Tool.from_function(handler, name="session_analyze")
    # FastMCP found the injected param...
    assert tool.context_kwarg == "context"
    # ...and it is NOT part of the client-facing input schema, but the model fields are.
    props = tool.parameters["properties"]
    assert "context" not in props
    assert "session_id" in props


# --- no-token path: byte-for-byte pre-Phase-2 (no client relay) ---------------------------------
def test_no_token_runs_inline_without_relay() -> None:
    port = _FakePort(frames=[(50, "analyzing")])
    sessions = _FakeSessions()
    handler = reg._bind_analyze(_ctx(port, sessions))

    # context=None ⇒ no token ⇒ inline path; on_progress must be None at the port.
    info = anyio.run(functools.partial(handler, context=None, session_id=_SID))

    assert port.on_progress_seen is None
    # Manager lifecycle overlay still wins over the worker-forged fields.
    assert info.session_id == _SID
    assert info.state == "ready"
    assert info.binary_sha256 == "b" * 64
    # ADR-029 B: the effective profile (default here) is echoed on the returned info.
    assert info.analysis_profile == "default"
    # Order: in-flight begin → authorize → record-profile (post-analyze) → in-flight end.
    assert sessions.events == [
        f"begin:{_SID}",
        f"authorize:{_SID}",
        f"record_profile:{_SID}:default",
        f"end:{_SID}",
    ]


def test_context_without_token_takes_the_inline_path() -> None:
    port = _FakePort(frames=[(10, "analyzing")])
    handler = reg._bind_analyze(_ctx(port, _FakeSessions()))
    ctx_obj = _FakeContext(progress_token=None)

    anyio.run(functools.partial(handler, context=cast(Any, ctx_obj), session_id=_SID))

    assert port.on_progress_seen is None
    assert ctx_obj.reported == []  # nothing relayed to the client


# --- token path: offload + bridge each frame to Context.report_progress -------------------------
def test_token_path_relays_each_frame_to_the_client() -> None:
    port = _FakePort(frames=[(0, "importing"), (50, "analyzing"), (100, "finalizing")])
    handler = reg._bind_analyze(_ctx(port, _FakeSessions()))
    ctx_obj = _FakeContext(progress_token=_PROGRESS_ID)

    info = anyio.run(functools.partial(handler, context=cast(Any, ctx_obj), session_id=_SID))

    assert info.state == "ready"
    assert port.on_progress_seen is not None  # a relay WAS wired
    # Each frame became a report_progress(percent, total=100, message=phase) — safe fields only.
    assert ctx_obj.reported == [
        (0.0, 100.0, "importing"),
        (50.0, 100.0, "analyzing"),
        (100.0, 100.0, "finalizing"),
    ]


def test_token_path_skips_frames_with_no_percent_estimate() -> None:
    port = _FakePort(frames=[(None, "analyzing"), (42, "analyzing")])
    handler = reg._bind_analyze(_ctx(port, _FakeSessions()))
    ctx_obj = _FakeContext(progress_token=_PROGRESS_ID)

    anyio.run(functools.partial(handler, context=cast(Any, ctx_obj), session_id=_SID))

    # The None-percent frame cannot be a numeric notification → skipped; the real one rides through.
    assert ctx_obj.reported == [(42.0, 100.0, "analyzing")]


def test_token_path_runs_begin_and_end_call_around_the_offload() -> None:
    port = _FakePort(frames=[(5, "analyzing")])
    sessions = _FakeSessions()
    handler = reg._bind_analyze(_ctx(port, sessions))
    ctx_obj = _FakeContext(progress_token=_PROGRESS_ID)

    anyio.run(functools.partial(handler, context=cast(Any, ctx_obj), session_id=_SID))

    assert sessions.events[0] == f"begin:{_SID}"
    assert sessions.events[-1] == f"end:{_SID}"


# --- async error boundary -----------------------------------------------------------------------
def test_async_error_boundary_maps_handler_failure_to_envelope() -> None:
    async def _boom(**_kwargs: Any) -> Any:
        raise GhidraMcpError(
            ErrorEnvelope(
                type=ErrorType.WORKER_UNAVAILABLE, title="x", detail="worker died", status=503
            )
        )

    guarded = _with_error_boundary("session_analyze", _boom)
    result = anyio.run(functools.partial(guarded, session_id=_SID))

    assert result.type == ErrorType.WORKER_UNAVAILABLE
    assert result.correlation_id is not None


def test_async_error_boundary_maps_unexpected_exception_to_internal() -> None:
    async def _kaboom(**_kwargs: Any) -> Any:
        raise RuntimeError("leaky internal detail")

    guarded = _with_error_boundary("session_analyze", _kaboom)
    result = anyio.run(functools.partial(guarded, session_id=_SID))

    assert result.type == ErrorType.INTERNAL
    assert "leaky internal detail" not in result.detail  # internals never leak (master §5)


def test_error_boundary_preserves_async_handler_as_coroutine() -> None:
    handler = reg._bind_analyze(_ctx(_FakePort(), _FakeSessions()))
    guarded = _with_error_boundary("session_analyze", handler)
    assert inspect.iscoroutinefunction(guarded)
    # Signature (and thus the injected Context param) survives the wrap.
    assert "context" in inspect.signature(guarded).parameters


# --- end-to-end through the REAL FastMCP runtime (no JVM): a client progressToken yields ---------
# notifications/progress. This is the Phase-2 live-verification, frozen as a regression test — it
# proves FastMCP injects our synthesized-signature Context AND that report_progress reaches the
# client, the two seams unit tests with a fake Context cannot cover.
def test_end_to_end_client_receives_progress_notifications() -> None:
    """A real in-memory MCP client passing a progress callback receives each relayed frame."""
    from mcp.shared.memory import create_connected_server_and_client_session as _connect

    from vivarium.server.app import build_app

    port = _FakePort(frames=[(0, "importing"), (60, "analyzing"), (100, "finalizing")])
    app = build_app(
        _config(),
        session_manager=cast(SessionManager, _FakeSessions()),
        port=cast(GhidraPort, port),
    )
    received: list[tuple[float, float | None, str | None]] = []

    async def _drive() -> None:
        async def _on_progress(progress: float, total: float | None, message: str | None) -> None:
            received.append((progress, total, message))

        async with _connect(app) as client:
            await client.initialize()
            await client.call_tool(
                "session_analyze", {"session_id": _SID}, progress_callback=_on_progress
            )

    anyio.run(_drive)

    # The client's progress_callback auto-registers a progressToken; FastMCP injected our Context
    # and each worker frame surfaced as a notifications/progress (percent + closed-vocab phase).
    assert received == [
        (0.0, 100.0, "importing"),
        (60.0, 100.0, "analyzing"),
        (100.0, 100.0, "finalizing"),
    ]


def test_end_to_end_without_progress_callback_emits_nothing_extra() -> None:
    """No client progress callback ⇒ no progressToken ⇒ the inline path; the call still succeeds."""
    from mcp.shared.memory import create_connected_server_and_client_session as _connect

    from vivarium.server.app import build_app

    port = _FakePort(frames=[(50, "analyzing")])
    app = build_app(
        _config(),
        session_manager=cast(SessionManager, _FakeSessions()),
        port=cast(GhidraPort, port),
    )

    async def _drive() -> Any:
        async with _connect(app) as client:
            await client.initialize()
            return await client.call_tool("session_analyze", {"session_id": _SID})

    result = anyio.run(_drive)
    assert result.isError is False
    # No token was sent, so the adapter was never asked to relay (inline, pre-Phase-2 path).
    assert port.on_progress_seen is None
