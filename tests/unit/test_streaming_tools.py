"""Unit tests for the four streaming-extraction tool handlers (ADR-040 increment 3).

Exercises the TOOL layer (`vivarium.tools.registry` handlers) for ``start_decompile_stream`` /
``fetch_job_results`` / ``job_status`` / ``cancel_job`` over the hermetic :class:`FakeGhidraPort`
streaming source, wired exactly as the composition root would: the fake port's job manager carries
the REAL :class:`~vivarium.sessions.manager.SessionManager` ownership authorizer (so BOLA is real),
the clock is injected, and the synthetic per-function stream is deterministic.

Covered (the project bar): input validation (frozen, forbid-extra, ``limit`` bounds), BOLA (a
foreign caller gets the BOLA-safe ``SESSION_INVALID`` envelope), cap enforcement before delegation,
correct delegation + typed client-facing ``*Out`` mapping, the per-chunk ``Untrusted`` envelope in
``fetch_job_results`` output, the one-active-job and terminal-error paths surfaced through the tool
layer, and the ``job_status`` shape (no binary-derived content).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest
from pydantic import ValidationError as PydanticValidationError

from tests.conftest import FakeGhidraPort, FrozenClock
from vivarium.config import Config
from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra import _errors as _err
from vivarium.ghidra.port import GhidraPort
from vivarium.jobs.streaming import StreamingJobManager
from vivarium.security.limits import Limits
from vivarium.server.auth import Principal
from vivarium.sessions.manager import SessionManager
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

_OWNER = "local"  # the static stdio principal id == SessionManager default owner
_OTHER = "mallory"


def _config() -> Config:
    """A minimal valid stdio config for building tool contexts."""
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


def _wire(
    *,
    stream_count: int = 5,
    stream_fail_after: int | None = None,
    limits: Limits | None = None,
    resolve_principal: Callable[[], Principal] | None = None,
) -> tuple[reg.ToolContext, SessionManager, FakeGhidraPort]:
    """Build a tool context with a real session manager + fake port wired like the composition root.

    The fake port's streaming-job manager authorizes through the REAL session manager (true BOLA);
    the injected clock keeps elapsed/ETA deterministic.
    """
    clock = FrozenClock()
    sessions = SessionManager(clock=clock.monotonic, wall_clock=clock.time)
    port = FakeGhidraPort()
    port.stream_count = stream_count
    port.stream_fail_after = stream_fail_after
    jobs = StreamingJobManager(
        authorize=lambda sid, caller: sessions.authorize(sid, caller=caller),
        limits=limits if limits is not None else Limits(),
        clock=clock.monotonic,
    )
    sessions._on_evict = jobs.discard_session
    port.attach_stream_jobs(jobs)
    ctx = reg.ToolContext(
        config=_config(),
        sessions=sessions,
        port=cast(GhidraPort, port),
        resolve_principal=resolve_principal,
    )
    return ctx, sessions, port


def _handlers(ctx: reg.ToolContext) -> dict[str, Callable[..., Any]]:
    """Build the flat-keyword bound handler map for the catalog."""
    return reg.build_handlers(ctx)


def _new_session(sessions: SessionManager, *, owner: str = _OWNER) -> str:
    """Open a session owned by ``owner`` and return its id."""
    return sessions.create(owner=owner).session_id


# --- registration / allow-list -----------------------------------------------------------------
def test_streaming_tools_are_registered() -> None:
    ctx, _sessions, _port = _wire()
    handlers = _handlers(ctx)
    for name in ("start_decompile_stream", "fetch_job_results", "job_status", "cancel_job"):
        assert name in handlers
        assert name in reg.TIER1_TOOL_NAMES


# --- input validation (frozen, forbid-extra, bounds) -------------------------------------------
def test_fetch_limit_default_is_32_and_max_is_256() -> None:
    assert s.FetchJobResultsIn(session_id="s", job="j").limit == 32
    assert s.FetchJobResultsIn(session_id="s", job="j", limit=256).limit == 256
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError (> max)
        s.FetchJobResultsIn(session_id="s", job="j", limit=257)
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError (< 1)
        s.FetchJobResultsIn(session_id="s", job="j", limit=0)


def test_start_stream_rejects_unknown_fields() -> None:
    with pytest.raises(Exception):  # noqa: B017 - extra="forbid"
        s.StartDecompileStreamIn(session_id="s", bogus=1)  # type: ignore[call-arg]


def test_start_stream_rejects_oversized_function_name() -> None:
    with pytest.raises(Exception):  # noqa: B017 - model_validator length bound
        s.StartDecompileStreamIn(session_id="s", functions=["a" * 5000])


def test_start_stream_rejects_empty_function_name() -> None:
    with pytest.raises(Exception):  # noqa: B017 - model_validator length bound
        s.StartDecompileStreamIn(session_id="s", functions=[""])


def test_start_stream_rejects_empty_function_list() -> None:
    # An explicit-but-empty list is ambiguous ("stream nothing") — fail closed (omit to stream all).
    with pytest.raises(Exception):  # noqa: B017 - model_validator non-empty bound
        s.StartDecompileStreamIn(session_id="s", functions=[])


# --- BOLA (foreign caller → SESSION_INVALID, BOLA-safe) ----------------------------------------
def test_start_stream_foreign_caller_is_denied() -> None:
    ctx, sessions, _port = _wire(resolve_principal=lambda: Principal(id=_OTHER))
    sid = _new_session(sessions, owner=_OWNER)  # owned by "local", not mallory
    handlers = _handlers(ctx)
    with pytest.raises(GhidraMcpError) as ei:
        handlers["start_decompile_stream"](session_id=sid)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


def test_fetch_foreign_caller_is_denied() -> None:
    # Owner starts a job; a foreign principal then tries to fetch it.
    owner_ctx, sessions, _port = _wire(stream_count=3)
    sid = _new_session(sessions, owner=_OWNER)
    job = _handlers(owner_ctx)["start_decompile_stream"](session_id=sid).job
    foreign_ctx = reg.ToolContext(
        config=_config(),
        sessions=sessions,
        port=owner_ctx.port,
        resolve_principal=lambda: Principal(id=_OTHER),
    )
    with pytest.raises(GhidraMcpError) as ei:
        _handlers(foreign_ctx)["fetch_job_results"](session_id=sid, job=job)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


def test_status_and_cancel_foreign_caller_denied() -> None:
    owner_ctx, sessions, _port = _wire(stream_count=3)
    sid = _new_session(sessions, owner=_OWNER)
    job = _handlers(owner_ctx)["start_decompile_stream"](session_id=sid).job
    foreign_ctx = reg.ToolContext(
        config=_config(),
        sessions=sessions,
        port=owner_ctx.port,
        resolve_principal=lambda: Principal(id=_OTHER),
    )
    for tool in ("job_status", "cancel_job"):
        with pytest.raises(GhidraMcpError) as ei:
            _handlers(foreign_ctx)[tool](session_id=sid, job=job)
        assert ei.value.envelope.type is ErrorType.SESSION_INVALID


def test_unknown_session_is_rejected() -> None:
    ctx, _sessions, _port = _wire()
    handlers = _handlers(ctx)
    with pytest.raises(GhidraMcpError) as ei:
        handlers["start_decompile_stream"](session_id="nope")
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


# --- delegation + typed output -----------------------------------------------------------------
def test_start_stream_returns_job_start_out() -> None:
    ctx, sessions, _port = _wire(stream_count=4)
    sid = _new_session(sessions)
    out = _handlers(ctx)["start_decompile_stream"](session_id=sid)
    assert isinstance(out, s.JobStartOut)
    assert out.job  # opaque handle present
    assert out.state in {"running", "paused", "done"}
    assert out.total_estimate == 4


def test_start_stream_with_explicit_functions_bounds_the_total() -> None:
    # An explicit function set bounds the produced-chunk count to its length (the count cap enforced
    # before delegation). The fake source produces min(stream_count, requested) chunks.
    ctx, sessions, _port = _wire(stream_count=10)
    sid = _new_session(sessions)
    out = _handlers(ctx)["start_decompile_stream"](
        session_id=sid, functions=["main", "0x401000", "helper"]
    )
    assert isinstance(out, s.JobStartOut)
    assert out.total_estimate == 3  # bounded to the named set, not the 10 available


def test_fetch_returns_ordered_chunks_with_untrusted_envelope() -> None:
    ctx, sessions, _port = _wire(stream_count=3)
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    job = handlers["start_decompile_stream"](session_id=sid).job
    out = handlers["fetch_job_results"](session_id=sid, job=job, limit=2)
    assert isinstance(out, s.JobResultsOut)
    assert [c.seq for c in out.chunks] == [0, 1]
    assert out.next_cursor == 2
    assert out.truncated is False
    # Per-chunk untrusted envelope (ADR-005 / ADR-040 D9): binary-derived fields are wrapped.
    chunk = out.chunks[0]
    assert isinstance(chunk.name, Untrusted)
    assert isinstance(chunk.code, Untrusted)
    assert isinstance(chunk.signature, Untrusted)
    assert chunk.code.origin in {DataOrigin.GHIDRA, DataOrigin.BINARY}
    # ``address`` is a server-normalized scalar (bare, not wrapped).
    assert isinstance(chunk.address, str)


def test_full_stream_drains_in_order_and_terminates_done() -> None:
    ctx, sessions, _port = _wire(stream_count=5)
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    job = handlers["start_decompile_stream"](session_id=sid).job
    seen: list[int] = []
    while True:
        out = handlers["fetch_job_results"](session_id=sid, job=job, limit=2)
        seen.extend(c.seq for c in out.chunks)
        if out.done and not out.chunks:
            break
    assert seen == [0, 1, 2, 3, 4]


def test_fetch_limit_is_capped_before_delegation() -> None:
    # The fetch limit (max 256) is enforced by the frozen pydantic schema — i.e. BEFORE the handler
    # authorizes or delegates to the port (the raw handler reconstructs+validates the *In model;
    # the server's error boundary later turns this ValidationError into a VALIDATION envelope).
    ctx, sessions, _port = _wire(stream_count=3)
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    job = handlers["start_decompile_stream"](session_id=sid).job
    with pytest.raises(PydanticValidationError):
        handlers["fetch_job_results"](session_id=sid, job=job, limit=999)


# --- one-active-job cap (LIMIT_EXCEEDED) --------------------------------------------------------
def test_second_active_stream_is_rejected_limit_exceeded() -> None:
    ctx, sessions, _port = _wire(stream_count=3, limits=Limits(max_stream_buffer_chunks=2))
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    handlers["start_decompile_stream"](session_id=sid)  # first job (running/paused)
    with pytest.raises(GhidraMcpError) as ei:
        handlers["start_decompile_stream"](session_id=sid)
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED


# --- terminal-error path surfaced through the tool layer ---------------------------------------
def test_terminal_error_surfaces_done_then_status_error() -> None:
    ctx, sessions, _port = _wire(stream_count=5, stream_fail_after=2)
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    job = handlers["start_decompile_stream"](session_id=sid).job
    seen: list[int] = []
    done = False
    for _ in range(10):
        out = handlers["fetch_job_results"](session_id=sid, job=job, limit=2)
        seen.extend(c.seq for c in out.chunks)
        if out.done:
            done = True
            break
    assert done
    # Two chunks were produced before the producer raised → honest terminal error.
    assert seen == [0, 1]
    status = handlers["job_status"](session_id=sid, job=job)
    assert status.state == "error"
    assert status.done is True


# --- job_status shape (server counters only, NO binary content) --------------------------------
def test_job_status_has_no_binary_content() -> None:
    ctx, sessions, _port = _wire(stream_count=4)
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    job = handlers["start_decompile_stream"](session_id=sid).job
    status = handlers["job_status"](session_id=sid, job=job)
    assert isinstance(status, s.JobStatusOut)
    # Every field is a server scalar/label — assert none is an Untrusted envelope (master §5).
    for value in status.model_dump().values():
        assert not isinstance(value, Untrusted)
    assert status.state in {"running", "paused", "done", "error", "cancelled"}
    assert status.phase == status.state
    assert status.buffered >= 0
    assert status.started_at >= 0.0


def test_job_status_reports_total_when_known() -> None:
    ctx, sessions, _port = _wire(stream_count=6)
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    job = handlers["start_decompile_stream"](session_id=sid).job
    status = handlers["job_status"](session_id=sid, job=job)
    assert status.total == 6


# --- cancel (idempotent terminal ack) ----------------------------------------------------------
def test_cancel_marks_job_cancelled_idempotently() -> None:
    ctx, sessions, _port = _wire(stream_count=5, limits=Limits(max_stream_buffer_chunks=2))
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    job = handlers["start_decompile_stream"](session_id=sid).job
    out = handlers["cancel_job"](session_id=sid, job=job)
    assert isinstance(out, s.CancelJobOut)
    assert out.cancelled is True
    # Idempotent: cancelling an already-terminal job is a no-op that still reports cancelled=True
    # (the job record stays bound to its session until the session is evicted — ADR-040 cancel is
    # idempotent; the lifetime discard is on eviction, not on cancel).
    again = handlers["cancel_job"](session_id=sid, job=job)
    assert again.cancelled is True


def test_cancel_frees_the_slot_for_a_new_stream() -> None:
    ctx, sessions, _port = _wire(stream_count=3, limits=Limits(max_stream_buffer_chunks=2))
    sid = _new_session(sessions)
    handlers = _handlers(ctx)
    job1 = handlers["start_decompile_stream"](session_id=sid).job
    handlers["cancel_job"](session_id=sid, job=job1)
    # A new stream may start now that the active slot is freed.
    job2 = handlers["start_decompile_stream"](session_id=sid).job
    assert job2 != job1


# --- worker-unavailable fail-closed (streaming not wired against a real worker) ----------------
class _NoStreamPort(FakeGhidraPort):
    """A port whose stream-start fails closed ``worker-unavailable`` (the increment-2b real path).

    The worker incremental emit is a later increment; against a real worker the start RPC fails
    closed rather than silently producing nothing. This double models that path at the tool layer so
    the handler is shown to surface the safe envelope unchanged.
    """

    def start_decompile_stream(self, sid: str, a: Any, *, caller: str) -> str:
        """Fail closed: worker streaming is not available (increment 2b)."""
        raise _err.make_error(ErrorType.WORKER_UNAVAILABLE, "streaming off")


def test_start_stream_fails_closed_when_worker_unavailable() -> None:
    clock = FrozenClock()
    sessions = SessionManager(clock=clock.monotonic, wall_clock=clock.time)
    ctx = reg.ToolContext(
        config=_config(), sessions=sessions, port=cast(GhidraPort, _NoStreamPort())
    )
    sid = _new_session(sessions)
    with pytest.raises(GhidraMcpError) as ei:
        _handlers(ctx)["start_decompile_stream"](session_id=sid)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
