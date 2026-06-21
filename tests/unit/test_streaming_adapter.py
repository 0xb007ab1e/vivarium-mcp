"""Unit tests for the streaming methods on the RPC adapter (ADR-040 — server-side delegation).

Hermetic: no real worker / socket. These cover the adapter's thin delegation to the injected
:class:`~vivarium.jobs.streaming.StreamingJobManager`, the fail-closed guard when streaming is not
wired, and the (this-increment) ``worker-unavailable`` raised by the not-yet-wired worker stream
source. The job machinery itself is covered in ``test_streaming_jobs``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from tests.conftest import FrozenClock
from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra.rpc_client import RpcGhidraAdapter
from vivarium.jobs.streaming import (
    DecompileStreamIn,
    FetchJobResultsIn,
    JobHandleIn,
    JobState,
    StreamingJobManager,
)
from vivarium.security.limits import Limits
from vivarium.tools import schemas as s

_SID = "sess-X"
_CALLER = "local"


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
        max_response_bytes=4 * 1024 * 1024,
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


# --- worker stream source: not wired this increment ------------------------------------------


def test_decompile_stream_fails_closed_this_increment() -> None:
    adapter = _adapter(StreamingJobManager(authorize=lambda _s, _c: None))
    # Not wired this increment: the worker stream source fails closed with worker-unavailable
    # (raised eagerly — it is not a lazy generator, so no chunk is ever produced).
    with pytest.raises(GhidraMcpError) as ei:
        adapter.decompile_stream(_SID, DecompileStreamIn(session_id=_SID, limit=5))
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_start_decompile_stream_surfaces_unwired_worker() -> None:
    # The producer source raises before the job is created → worker-unavailable propagates.
    adapter = _adapter(StreamingJobManager(authorize=lambda _s, _c: None))
    with pytest.raises(GhidraMcpError) as ei:
        adapter.start_decompile_stream(
            _SID, DecompileStreamIn(session_id=_SID, limit=5), caller=_CALLER
        )
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


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
    # Seed a job via the manager (bypassing the unwired worker source) with a synthetic producer.
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
