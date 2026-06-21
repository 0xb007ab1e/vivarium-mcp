"""Unit tests for the streaming-job machinery (ADR-040 — server-side core).

Hermetic and deterministic (master §4, topic-testing): no real worker, no wall-clock, no
randomness in assertions — the producer is a synthetic in-memory iterator and time is the injected
:class:`FrozenClock`. Covers the ADR-040 §6 invariants:

- ordering: ``seq`` monotonic + gap-free; cursor = next-seq;
- cursor resume + client-dedupe semantics;
- buffer bound + backpressure (producer PAUSES when full, RESUMES on drain; no drop/reorder);
- terminal-error path (explicit ``error`` end, never an ambiguous early ``done``);
- one-active-job-per-session cap;
- BOLA (a foreign caller / a job not bound to the authorized session is denied);
- per-chunk untrusted envelope present;
- ``job_status`` counters + injected-clock ETA.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from pydantic import ValidationError as PydanticValidationError

from tests.conftest import FrozenClock
from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra import _errors
from vivarium.jobs.streaming import (
    DecompileStreamIn,
    JobState,
    SessionAuthorizer,
    StreamingJobManager,
)
from vivarium.security.limits import Limits
from vivarium.tools import schemas as s

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

_SID = "sess-A"
_OWNER = "alice"


def _fn(i: int) -> s.DecompiledFunction:
    """Build a deterministic synthetic decompiled function (binary-derived fields wrapped)."""
    addr = 0x00401000 + i * 0x10
    return s.DecompiledFunction(
        address=f"0x{addr:08x}",
        name=Untrusted(value=f"FUN_{addr:08x}", origin=DataOrigin.GHIDRA),
        c_code=Untrusted(
            value=f"int FUN_{addr:08x}(void) {{ return {i}; }}", origin=DataOrigin.GHIDRA
        ),
        signature=Untrusted(value=f"int FUN_{addr:08x}(void)", origin=DataOrigin.GHIDRA),
    )


def _producer(n: int) -> Iterator[s.DecompiledFunction]:
    """A finite synthetic producer yielding ``n`` functions then stopping (→ DONE)."""
    for i in range(n):
        yield _fn(i)


def _failing_producer(ok: int) -> Iterator[s.DecompiledFunction]:
    """Yield ``ok`` functions then raise a safe ANALYSIS_FAILED (→ terminal ERROR)."""
    for i in range(ok):
        yield _fn(i)
    raise _errors.make_error(ErrorType.ANALYSIS_FAILED, "synthetic mid-stream failure")


@pytest.mark.critical
def test_done_reported_only_after_buffer_fully_drained() -> None:
    """``done`` must not be reported while buffered chunks remain (ADR-040 D7 regression).

    Regression for the bug the live worker surfaced (#134 follow-up): a producer that fills the
    buffer then exhausts leaves a tail buffered, so a ``limit``-capped final batch reported
    ``done`` while chunks were still buffered — a client trusting ``done`` (and breaking) orphaned
    the tail, and a cursor re-fetch then delivered un-seen chunks. The producer here (10) is larger
    than BOTH the buffer cap (3) and the fetch limit (2), the exact shape the real worker hit.
    """
    mgr = _manager(limits=Limits(max_stream_buffer_chunks=3))
    job_id = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)

    seen: list[int] = []
    reported_done = False
    for _pull in range(100):
        res = mgr.fetch(_SID, job_id, limit=2, caller=_OWNER)
        seen.extend(c.seq for c in res.chunks)
        if res.done:
            reported_done = True
            break

    assert reported_done, "stream never reported done"
    # If `done` had fired early (with a tail still buffered), the break would have left chunks
    # unseen — so an exactly-once gap-free 0..9 proves `done` waited for the buffer to drain.
    assert seen == list(range(10)), f"chunks not delivered exactly once gap-free: {seen}"
    # A re-fetch after `done` yields nothing — the buffer was truly empty at the done point.
    replay = mgr.fetch(_SID, job_id, limit=2, caller=_OWNER)
    assert [c.seq for c in replay.chunks] == [], "a fetch after done delivered orphaned chunks"


def _accept_all(_sid: str, _caller: str) -> None:
    """A permissive authorizer (no session table) for non-BOLA tests."""


def _manager(
    *,
    authorize: SessionAuthorizer = _accept_all,
    limits: Limits | None = None,
    clock: FrozenClock | None = None,
) -> StreamingJobManager:
    """Build a manager with an injected authorizer/limits/clock (deterministic)."""
    clk = clock if clock is not None else FrozenClock()
    return StreamingJobManager(
        authorize=authorize,
        limits=limits if limits is not None else Limits(),
        clock=clk.monotonic,
    )


# ---------------------------------------------------------------------------------------------
# Ordering: monotonic, gap-free seq; cursor = next-seq
# ---------------------------------------------------------------------------------------------


@pytest.mark.critical
def test_seq_is_monotonic_gap_free_across_the_whole_stream() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(5), total=5, caller=_OWNER)
    collected: list[int] = []
    while True:
        res = mgr.fetch(_SID, job_id, limit=2, caller=_OWNER)
        collected.extend(c.seq for c in res.chunks)
        # Every returned chunk's seq must equal its position (gap-free, monotonic from 0).
        if res.done and not res.chunks:
            break
    assert collected == [0, 1, 2, 3, 4]


@pytest.mark.critical
def test_cursor_advances_to_next_seq() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(3), total=3, caller=_OWNER)
    res = mgr.fetch(_SID, job_id, limit=2, caller=_OWNER)
    assert [c.seq for c in res.chunks] == [0, 1]
    assert res.cursor == 2  # next-expected seq
    res2 = mgr.fetch(_SID, job_id, limit=2, caller=_OWNER)
    assert [c.seq for c in res2.chunks] == [2]
    assert res2.cursor == 3
    assert res2.done is True
    assert res2.state is JobState.DONE


def test_chunks_are_never_reordered_under_partial_fetches() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(6), total=6, caller=_OWNER)
    order: list[int] = []
    for _ in range(6):
        res = mgr.fetch(_SID, job_id, limit=1, caller=_OWNER)
        order.extend(c.seq for c in res.chunks)
    assert order == sorted(order) == [0, 1, 2, 3, 4, 5]


# ---------------------------------------------------------------------------------------------
# Cursor resume + client-dedupe semantics
# ---------------------------------------------------------------------------------------------


def test_resume_cursor_at_or_behind_server_is_accepted() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(3), total=3, caller=_OWNER)
    mgr.fetch(_SID, job_id, limit=2, caller=_OWNER)  # cursor now 2
    # Re-fetch acknowledging an earlier cursor (idempotent client-dedupe signal): accepted.
    res = mgr.fetch(_SID, job_id, cursor=1, limit=2, caller=_OWNER)
    assert [c.seq for c in res.chunks] == [2]  # server is authoritative on what remains


@pytest.mark.critical
def test_resume_cursor_ahead_of_server_is_rejected() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(3), total=3, caller=_OWNER)
    # The client claims to have consumed seq 5 before the server delivered it → fail closed.
    with pytest.raises(GhidraMcpError) as ei:
        mgr.fetch(_SID, job_id, cursor=5, limit=2, caller=_OWNER)
    assert ei.value.envelope.type is ErrorType.VALIDATION


# ---------------------------------------------------------------------------------------------
# Buffer bound + backpressure (pause when full, resume on drain; no drop/reorder)
# ---------------------------------------------------------------------------------------------


@pytest.mark.critical
def test_producer_pauses_when_chunk_count_bound_is_reached() -> None:
    limits = Limits(max_stream_buffer_chunks=3)
    mgr = _manager(limits=limits)
    # 10 available, but the buffer only holds 3 → after start the job is PAUSED (backpressure).
    job_id = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    status = mgr.status(_SID, job_id, caller=_OWNER)
    assert status.state is JobState.PAUSED
    assert status.buffered == 3
    assert status.produced == 3  # nothing produced beyond the buffer bound


@pytest.mark.critical
def test_backpressure_resumes_on_drain_with_no_drop_or_reorder() -> None:
    limits = Limits(max_stream_buffer_chunks=3)
    mgr = _manager(limits=limits)
    job_id = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    seen: list[int] = []
    while True:
        res = mgr.fetch(_SID, job_id, limit=2, caller=_OWNER)
        seen.extend(c.seq for c in res.chunks)
        if res.done and not res.chunks:
            break
    # Every function arrives exactly once, in order — backpressure paused, never dropped/reordered.
    assert seen == list(range(10))


def test_byte_bound_pauses_before_count_bound_for_large_chunks() -> None:
    # A tiny byte cap trips before the (large) count cap: a single chunk exceeds it.
    limits = Limits(max_stream_buffer_chunks=1000, max_stream_buffer_bytes=1)
    mgr = _manager(limits=limits)
    job_id = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    status = mgr.status(_SID, job_id, caller=_OWNER)
    # The first chunk alone exceeds the 1-byte cap, so exactly one is buffered then it pauses.
    assert status.buffered == 1
    assert status.state is JobState.PAUSED


# ---------------------------------------------------------------------------------------------
# Terminal-error path (explicit error end, never an ambiguous early done)
# ---------------------------------------------------------------------------------------------


@pytest.mark.critical
def test_producer_error_terminates_with_explicit_error_not_done() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_failing_producer(2), total=None, caller=_OWNER)
    # Drain the two good chunks, then the next fetch surfaces the terminal error (not done).
    seen: list[int] = []
    res = mgr.fetch(_SID, job_id, limit=5, caller=_OWNER)
    seen.extend(c.seq for c in res.chunks)
    res2 = mgr.fetch(_SID, job_id, limit=5, caller=_OWNER)
    assert seen == [0, 1]
    assert res2.state is JobState.ERROR
    assert res2.done is True
    assert res2.error is not None
    assert res2.error.type is ErrorType.ANALYSIS_FAILED


def test_unexpected_producer_fault_fails_closed_to_internal() -> None:
    def boom() -> Iterator[s.DecompiledFunction]:
        yield _fn(0)
        raise RuntimeError("not an envelope")  # a non-GhidraMcpError fault

    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=boom(), total=None, caller=_OWNER)
    mgr.fetch(_SID, job_id, limit=5, caller=_OWNER)  # drains seq 0
    res = mgr.fetch(_SID, job_id, limit=5, caller=_OWNER)
    assert res.state is JobState.ERROR
    assert res.error is not None
    assert res.error.type is ErrorType.INTERNAL
    # Leak-free: the generic detail must not echo the raw exception text.
    assert "not an envelope" not in res.error.detail


# ---------------------------------------------------------------------------------------------
# One active job per session
# ---------------------------------------------------------------------------------------------


@pytest.mark.critical
def test_second_active_job_on_same_session_is_rejected() -> None:
    # A small buffer keeps the first job non-terminal (PAUSED) so it is genuinely "active".
    mgr = _manager(limits=Limits(max_stream_buffer_chunks=2))
    mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED


def test_new_job_allowed_after_previous_completes() -> None:
    mgr = _manager()
    j1 = mgr.start_job(_SID, producer=_producer(1), total=1, caller=_OWNER)
    # Drain j1 to completion (DONE) — the active slot clears for the next stream.
    mgr.fetch(_SID, j1, limit=5, caller=_OWNER)
    assert mgr.status(_SID, j1, caller=_OWNER).state is JobState.DONE
    j2 = mgr.start_job(_SID, producer=_producer(1), total=1, caller=_OWNER)
    assert j2 != j1


def test_new_job_allowed_after_cancel() -> None:
    mgr = _manager(limits=Limits(max_stream_buffer_chunks=2))
    j1 = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    mgr.cancel(_SID, j1, caller=_OWNER)
    j2 = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    assert j2 != j1


def test_two_sessions_each_get_their_own_active_job() -> None:
    mgr = _manager()
    j1 = mgr.start_job("sess-1", producer=_producer(3), total=3, caller=_OWNER)
    j2 = mgr.start_job("sess-2", producer=_producer(3), total=3, caller=_OWNER)
    assert j1 != j2
    assert mgr.status("sess-1", j1, caller=_OWNER).session_id == "sess-1"
    assert mgr.status("sess-2", j2, caller=_OWNER).session_id == "sess-2"


# ---------------------------------------------------------------------------------------------
# BOLA: foreign caller denied; job not bound to the authorized session denied
# ---------------------------------------------------------------------------------------------


def _owner_only_authorizer(owned_sid: str, owner: str) -> Callable[[str, str], None]:
    """An authorizer that mimics SessionManager: only ``owner`` may authorize ``owned_sid``."""

    def authorize(sid: str, caller: str) -> None:
        if sid != owned_sid or caller != owner:
            # BOLA-safe: the SAME error for unknown / foreign (no existence oracle).
            raise _errors.session_invalid()

    return authorize


@pytest.mark.critical
def test_foreign_caller_cannot_fetch_another_principals_job() -> None:
    authorize = _owner_only_authorizer(_SID, _OWNER)
    mgr = _manager(authorize=authorize)
    job_id = mgr.start_job(_SID, producer=_producer(5), total=5, caller=_OWNER)
    # A different principal naming the same session id is denied the BOLA-safe SESSION_INVALID.
    with pytest.raises(GhidraMcpError) as ei:
        mgr.fetch(_SID, job_id, limit=2, caller="mallory")
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_foreign_caller_cannot_status_or_cancel_another_principals_job() -> None:
    authorize = _owner_only_authorizer(_SID, _OWNER)
    mgr = _manager(authorize=authorize)
    job_id = mgr.start_job(_SID, producer=_producer(5), total=5, caller=_OWNER)
    ops: list[Callable[[], object]] = [
        lambda: mgr.status(_SID, job_id, caller="mallory"),
        lambda: mgr.cancel(_SID, job_id, caller="mallory"),
    ]
    for op in ops:
        with pytest.raises(GhidraMcpError) as ei:
            op()
        assert ei.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_job_handle_from_another_session_is_session_invalid() -> None:
    # Two sessions owned by the same principal: a job started under sess-1 must not be reachable
    # by naming sess-2 (the handle is bound to its session — no cross-session reach).
    def authorize(sid: str, caller: str) -> None:
        if sid not in {"sess-1", "sess-2"} or caller != _OWNER:
            raise _errors.session_invalid()

    mgr = _manager(authorize=authorize)
    j1 = mgr.start_job("sess-1", producer=_producer(3), total=3, caller=_OWNER)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.fetch("sess-2", j1, limit=2, caller=_OWNER)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


@pytest.mark.critical
def test_start_job_authorizes_session_before_allocation() -> None:
    authorize = _owner_only_authorizer(_SID, _OWNER)
    mgr = _manager(authorize=authorize)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.start_job(_SID, producer=_producer(3), total=3, caller="mallory")
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


def test_unknown_job_id_is_session_invalid() -> None:
    mgr = _manager()
    with pytest.raises(GhidraMcpError) as ei:
        mgr.status(_SID, "no-such-job", caller=_OWNER)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


# ---------------------------------------------------------------------------------------------
# Per-chunk untrusted envelope present
# ---------------------------------------------------------------------------------------------


@pytest.mark.critical
def test_every_chunk_carries_the_untrusted_envelope() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(4), total=4, caller=_OWNER)
    res = mgr.fetch(_SID, job_id, limit=10, caller=_OWNER)
    assert res.chunks
    for chunk in res.chunks:
        fn = chunk.function
        for fld in (fn.name, fn.c_code, fn.signature):
            assert isinstance(fld, Untrusted)
            assert fld.origin in (DataOrigin.GHIDRA, DataOrigin.BINARY)
        # The server-normalized address is a bare scalar (not wrapped) — safe.
        assert isinstance(fn.address, str)


# ---------------------------------------------------------------------------------------------
# Status counters + injected-clock ETA (no wall-clock)
# ---------------------------------------------------------------------------------------------


def test_status_carries_no_binary_content_fields() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(3), total=3, caller=_OWNER)
    status = mgr.status(_SID, job_id, caller=_OWNER)
    # Status is server-authored: only scalars/labels — assert the model has no Untrusted field.
    dumped = status.model_dump()
    for value in dumped.values():
        assert not isinstance(value, Untrusted)


def test_eta_uses_injected_clock_and_extrapolates() -> None:
    clock = FrozenClock()
    limits = Limits(max_stream_buffer_chunks=2)  # so produced stays < total (paused)
    mgr = _manager(limits=limits, clock=clock)
    job_id = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    # Advance the injected clock: 2 produced in 4s → 0.5/s; 8 remaining → eta 16s.
    clock.advance(4)
    status = mgr.status(_SID, job_id, caller=_OWNER)
    assert status.produced == 2
    assert status.total == 10
    assert status.elapsed_seconds == pytest.approx(4.0)
    assert status.eta_seconds == pytest.approx(16.0)


def test_eta_is_none_when_total_unknown() -> None:
    clock = FrozenClock()
    mgr = _manager(clock=clock)
    job_id = mgr.start_job(_SID, producer=_producer(3), total=None, caller=_OWNER)
    clock.advance(2)
    status = mgr.status(_SID, job_id, caller=_OWNER)
    assert status.total is None
    assert status.eta_seconds is None


def test_eta_is_none_before_any_production() -> None:
    clock = FrozenClock()
    # An empty stream produces nothing; eta is indeterminate (and it terminates DONE).
    mgr = _manager(clock=clock)
    job_id = mgr.start_job(_SID, producer=_producer(0), total=5, caller=_OWNER)
    clock.advance(3)
    status = mgr.status(_SID, job_id, caller=_OWNER)
    assert status.produced == 0
    assert status.eta_seconds is None
    assert status.state is JobState.DONE  # exhausted immediately


def test_eta_is_none_when_terminal() -> None:
    clock = FrozenClock()
    mgr = _manager(clock=clock)
    job_id = mgr.start_job(_SID, producer=_producer(2), total=2, caller=_OWNER)
    mgr.fetch(_SID, job_id, limit=5, caller=_OWNER)  # → DONE
    clock.advance(5)
    status = mgr.status(_SID, job_id, caller=_OWNER)
    assert status.state is JobState.DONE
    assert status.eta_seconds is None


# ---------------------------------------------------------------------------------------------
# Cancel + lifetime (discard_session)
# ---------------------------------------------------------------------------------------------


@pytest.mark.critical
def test_cancel_marks_cancelled_and_drops_buffer() -> None:
    # Small buffer → the job is PAUSED with buffered chunks when cancelled (genuine mid-stream).
    mgr = _manager(limits=Limits(max_stream_buffer_chunks=3))
    job_id = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    assert mgr.status(_SID, job_id, caller=_OWNER).buffered == 3
    status = mgr.cancel(_SID, job_id, caller=_OWNER)
    assert status.state is JobState.CANCELLED
    assert status.buffered == 0
    # A subsequent fetch returns no chunks and the terminal cancelled state (idempotent).
    res = mgr.fetch(_SID, job_id, limit=5, caller=_OWNER)
    assert res.chunks == []
    assert res.state is JobState.CANCELLED
    assert res.done is True


def test_cancel_is_idempotent_on_a_done_job() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(1), total=1, caller=_OWNER)
    mgr.fetch(_SID, job_id, limit=5, caller=_OWNER)  # → DONE
    status = mgr.cancel(_SID, job_id, caller=_OWNER)
    assert status.state is JobState.DONE  # a done job stays done; cancel does not override


@pytest.mark.critical
def test_discard_session_ends_all_its_jobs() -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(10), total=10, caller=_OWNER)
    mgr.discard_session(_SID)
    # The job is gone: any access is SESSION_INVALID (bound to a now-discarded session).
    with pytest.raises(GhidraMcpError) as ei:
        mgr.status(_SID, job_id, caller=_OWNER)
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID
    # And the session's active slot is freed (a new stream may start).
    new_id = mgr.start_job(_SID, producer=_producer(3), total=3, caller=_OWNER)
    assert new_id != job_id


def test_discard_session_is_a_noop_for_unknown_session() -> None:
    mgr = _manager()
    mgr.discard_session("never-existed")  # must not raise


def test_discard_session_only_affects_the_named_session() -> None:
    mgr = _manager(limits=Limits(max_stream_buffer_chunks=2))
    j1 = mgr.start_job("sess-1", producer=_producer(10), total=10, caller=_OWNER)
    j2 = mgr.start_job("sess-2", producer=_producer(10), total=10, caller=_OWNER)
    mgr.discard_session("sess-1")
    with pytest.raises(GhidraMcpError):
        mgr.status("sess-1", j1, caller=_OWNER)
    # sess-2's job is untouched (still actively buffering, non-terminal).
    assert mgr.status("sess-2", j2, caller=_OWNER).state in {JobState.RUNNING, JobState.PAUSED}


# ---------------------------------------------------------------------------------------------
# Fetch limit validation (DoS bound on a single pull)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("bad_limit", [0, -1, 10_000])
def test_fetch_limit_out_of_range_is_rejected(bad_limit: int) -> None:
    mgr = _manager()
    job_id = mgr.start_job(_SID, producer=_producer(3), total=3, caller=_OWNER)
    with pytest.raises(GhidraMcpError) as ei:
        mgr.fetch(_SID, job_id, limit=bad_limit, caller=_OWNER)
    assert ei.value.envelope.type is ErrorType.VALIDATION


# ---------------------------------------------------------------------------------------------
# Request-model schema bounds (frozen / extra-forbid / caps)
# ---------------------------------------------------------------------------------------------


def test_decompile_stream_in_rejects_extra_fields() -> None:
    with pytest.raises(PydanticValidationError):  # extra="forbid"
        DecompileStreamIn(session_id="s", limit=10, bogus=1)  # type: ignore[call-arg]


def test_decompile_stream_in_caps_limit() -> None:
    with pytest.raises(PydanticValidationError):
        DecompileStreamIn(session_id="s", limit=10_001)
