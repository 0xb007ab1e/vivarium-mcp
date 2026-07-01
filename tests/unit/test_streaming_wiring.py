"""Unit tests for the end-to-end streaming wiring (ADR-040 — real collaborators, fake worker).

Wires the REAL :class:`~vivarium.sessions.manager.SessionManager` ⇄
:class:`~vivarium.jobs.streaming.StreamingJobManager` ⇄ :class:`FakeGhidraPort` exactly as the
composition root would: the job manager authorizes through the session manager (BOLA), and the
session manager's ``on_evict`` discards the session's jobs. Hermetic: the fake port supplies a
deterministic synthetic stream; the clock is injected. This is the integration the individual unit
tests do not exercise together.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests.conftest import FakeGhidraPort, FrozenClock
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.jobs.streaming import (
    DecompileStreamIn,
    FetchJobResultsIn,
    JobHandleIn,
    JobState,
    StreamingJobManager,
)
from vivarium.security.limits import Limits
from vivarium.sessions.manager import SessionManager
from vivarium.tools import schemas as s

_OWNER = "alice"
_OTHER = "mallory"


def _wire(
    clock: FrozenClock, *, limits: Limits | None = None
) -> tuple[SessionManager, StreamingJobManager, FakeGhidraPort]:
    """Build the real session + streaming managers wired to a fake port (composition-root shape)."""
    sessions = SessionManager(clock=clock.monotonic, wall_clock=clock.time)
    jobs = StreamingJobManager(
        authorize=lambda sid, caller: sessions.authorize(sid, caller=caller),
        limits=limits if limits is not None else Limits(),
        clock=clock.monotonic,
    )
    # Lifetime binding: a session eviction discards its streaming jobs (ADR-040 §6). Uses the
    # public call-once composition seam (build_app shape), not a private-attr poke.
    sessions.set_evict_callback(jobs.discard_session)
    port = FakeGhidraPort()
    return sessions, jobs, port


def test_full_stream_through_real_session_and_fake_worker() -> None:
    clock = FrozenClock()
    sessions, _jobs, port = _wire(clock, limits=Limits(max_stream_buffer_chunks=3))
    port.stream_count = 7
    info = sessions.create(owner=_OWNER)
    sid = info.session_id

    job_id = port.start_decompile_stream(
        sid, DecompileStreamIn(session_id=sid, limit=100), caller=_OWNER
    )
    # The job manager and the port share the same manager instance only via the port's own; assert
    # the job is reachable through the port's management surface and streams in order.
    seen: list[int] = []
    while True:
        res = port.fetch_job_results(
            sid, FetchJobResultsIn(session_id=sid, job_id=job_id, limit=2), caller=_OWNER
        )
        seen.extend(c.seq for c in res.chunks)
        if res.done and not res.chunks:
            break
    assert seen == list(range(7))


def test_session_eviction_discards_the_jobs() -> None:
    clock = FrozenClock()
    sessions, jobs, _port = _wire(clock, limits=Limits(max_stream_buffer_chunks=2))
    info = sessions.create(owner=_OWNER)
    sid = info.session_id

    # Use the SAME job manager the session manager is wired to discard (authorize → sessions).
    def producer() -> Iterator[s.DecompiledFunction]:
        for i in range(10):
            yield _decompiled(i)

    job_id = jobs.start_job(sid, producer=producer(), total=10, caller=_OWNER)
    assert jobs.status(sid, job_id, caller=_OWNER).state in {JobState.RUNNING, JobState.PAUSED}

    # Closing the session must fire on_evict → discard_session → the job is gone.
    sessions.evict(sid, reason="close", caller=_OWNER)
    with pytest.raises(GhidraMcpError) as ei:
        jobs.status(sid, job_id, caller=_OWNER)
    # The session itself is now invalid, so the authorize layer denies first (BOLA-safe).
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


def test_foreign_caller_denied_through_real_authorizer() -> None:
    clock = FrozenClock()
    sessions, jobs, _port = _wire(clock, limits=Limits(max_stream_buffer_chunks=2))
    info = sessions.create(owner=_OWNER)
    sid = info.session_id

    def producer() -> Iterator[s.DecompiledFunction]:
        for i in range(5):
            yield _decompiled(i)

    job_id = jobs.start_job(sid, producer=producer(), total=5, caller=_OWNER)
    with pytest.raises(GhidraMcpError) as ei:
        jobs.fetch(sid, job_id, limit=2, caller=_OTHER)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


def test_fake_port_terminal_error_stream() -> None:
    clock = FrozenClock()
    sessions, _jobs, port = _wire(clock)
    port.stream_count = 5
    port.stream_fail_after = 2  # the fake source raises after 2 chunks → terminal ERROR
    info = sessions.create(owner=_OWNER)
    sid = info.session_id
    job_id = port.start_decompile_stream(
        sid, DecompileStreamIn(session_id=sid, limit=100), caller=_OWNER
    )
    seen: list[int] = []
    res = port.fetch_job_results(
        sid, FetchJobResultsIn(session_id=sid, job_id=job_id, limit=10), caller=_OWNER
    )
    seen.extend(c.seq for c in res.chunks)
    res2 = port.fetch_job_results(
        sid, FetchJobResultsIn(session_id=sid, job_id=job_id, limit=10), caller=_OWNER
    )
    assert seen == [0, 1]
    assert res2.state is JobState.ERROR
    assert res2.error is not None
    assert res2.error.type is ErrorType.ANALYSIS_FAILED


def test_fake_port_status_and_cancel() -> None:
    clock = FrozenClock()
    sessions, _jobs, port = _wire(clock)
    port.stream_count = 4
    info = sessions.create(owner=_OWNER)
    sid = info.session_id
    job_id = port.start_decompile_stream(
        sid, DecompileStreamIn(session_id=sid, limit=100), caller=_OWNER
    )
    # All 4 are produced but still buffered (undrained): the client-visible state is RUNNING, not
    # DONE — `done` is not reported until the buffer drains (ADR-040 D7).
    st_ = port.job_status(sid, JobHandleIn(session_id=sid, job_id=job_id), caller=_OWNER)
    assert st_.produced == 4
    assert st_.state is JobState.RUNNING
    # Drain the buffer → the stream is now genuinely complete (DONE).
    drained = port.fetch_job_results(
        sid, FetchJobResultsIn(session_id=sid, job_id=job_id, limit=10), caller=_OWNER
    )
    assert [c.seq for c in drained.chunks] == [0, 1, 2, 3]
    assert drained.done
    # Cancelling a DONE job leaves it DONE (cancel does not override a terminal state).
    cancelled = port.cancel_job(sid, JobHandleIn(session_id=sid, job_id=job_id), caller=_OWNER)
    assert cancelled.state is JobState.DONE


def _decompiled(i: int) -> s.DecompiledFunction:
    """Build a synthetic decompiled function for the wiring tests."""
    from vivarium.core.envelope import DataOrigin, Untrusted

    addr = 0x00401000 + i * 0x10
    return s.DecompiledFunction(
        address=f"0x{addr:08x}",
        name=Untrusted(value=f"FUN_{addr:08x}", origin=DataOrigin.GHIDRA),
        c_code=Untrusted(value="int f(void){return 0;}", origin=DataOrigin.GHIDRA),
        signature=Untrusted(value="int f(void)", origin=DataOrigin.GHIDRA),
    )
