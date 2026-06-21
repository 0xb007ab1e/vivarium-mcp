"""Streaming-job model + manager — server-side core (ADR-040; hermetic, JVM-free).

Implements the pull-based "job plus cursor" streaming machinery (design A2,
`docs/design/streaming-partial-results-and-progress.md` §4). The contract this builds to (the
design doc §6 "Security and contract impact" — invariants that MUST hold):

- **Untrusted envelope per chunk.** Every chunk's binary-derived fields stay wrapped in the
  ADR-005 :class:`~vivarium.core.envelope.Untrusted` envelope exactly as a full result would.
  Server-authored status (:class:`StreamJobStatus`) carries NO binary content — only counts,
  state, durations.
- **Bounds + backpressure.** The buffer of un-fetched chunks is bounded by BOTH a chunk count and
  a total byte size (from :class:`~vivarium.security.limits.Limits`). When either bound is reached
  the producer **pauses** (the job enters ``paused``); it never drops or reorders a chunk and never
  grows unbounded (topic-reliability; std-owasp-llm LLM04 is a cost/resource concern). The pause
  lifts when the client drains the buffer by fetching.
- **Ordering, resume, idempotency.** Chunks carry a monotonic, **gap-free** ``seq`` starting at 0;
  the cursor is the next expected ``seq``. A client resumes/dedupes by cursor — a re-fetch from an
  already-consumed cursor is honored (at-least-once in spirit; the client dedupes).
- **Fail closed and honest.** On a producer error mid-stream the job terminates with an explicit
  terminal error (``error`` state + an :class:`~vivarium.core.errors.ErrorEnvelope`), never an
  ambiguous early ``done``.
- **One active job per session.** Starting a second streaming job on a session whose job is still
  running/paused fails with ``LIMIT_EXCEEDED``. A job lifetime is bounded by its session: on
  session eviction the job is discarded (the manager exposes :meth:`discard_session`).
- **Authorization (BOLA).** Fetch / status / cancel authorize through an injected
  session-ownership check (the :class:`~vivarium.sessions.manager.SessionManager` chokepoint) AND
  bind the job to its creating session: a job handle is meaningless without its owning session, and
  one principal cannot pull another principal's job (ADR-017 / std-owasp-api API1).

This module is the **functional core** of streaming (topic-architecture-patterns): it performs no
I/O and no JVM work. Production is driven by a *producer* iterator the caller (the adapter) supplies
— for this increment a fake streaming producer; later the worker's incremental decompile RPC. The
clock is **injected** so elapsed/ETA are deterministic (topic-numeric-correctness; no wall-clock).
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.ghidra import _errors
from vivarium.logging import get_logger
from vivarium.security.limits import Limits
from vivarium.tools import schemas as s

_LOG = get_logger(__name__)

#: Random bytes in a job id (256 bits — unguessable like the session id; BOLA defense-in-depth, on
#: top of the owning-session ownership check). URL-safe base64 (~43 chars), safe as a log field.
_JOB_ID_BYTES = 32

#: Hard cap on a single :meth:`StreamingJobManager.fetch` batch (chunks) — bounds one pull's
#: response size independently of the buffer cap (DoS — CWE-400). A client may request fewer.
_MAX_FETCH_BATCH = 256
#: Default fetch batch when the caller does not specify one.
_DEFAULT_FETCH_BATCH = 64


class JobState(StrEnum):
    """Lifecycle state of a streaming job (the closed status vocabulary — ADR-040 §6).

    Transitions are monotone toward a terminal state; ``running`` ⇄ ``paused`` is the only
    reversible pair (backpressure). ``done``/``error``/``cancelled`` are terminal — no chunk is
    produced after a terminal state.
    """

    RUNNING = "running"
    """Producing; the buffer has room (chunks may be appended on the next pump)."""

    PAUSED = "paused"
    """Backpressure: the buffer is full (count OR bytes); the producer is held until a fetch drains
    it. Non-terminal — fetching lifts the pause back to ``running``."""

    DONE = "done"
    """The producer signalled completion (exhausted) and all chunks have been produced. Terminal."""

    ERROR = "error"
    """The producer raised mid-stream; the job carries a terminal :class:`ErrorEnvelope`. Terminal —
    an explicit, honest end (never indistinguishable from ``done``)."""

    CANCELLED = "cancelled"
    """The client explicitly cancelled the job (freed the worker early). Terminal."""


_TERMINAL_STATES: frozenset[JobState] = frozenset(
    {JobState.DONE, JobState.ERROR, JobState.CANCELLED}
)


@dataclass
class StreamTerminal:
    """Mutable holder for a stream's worker-reported terminal summary (ADR-040 D8).

    The producer is an ``Iterator[DecompiledFunction]`` — it cannot itself *return* the job-level
    ``{total, truncated}`` the worker reports in its terminal response. The adapter passes ONE of
    these to both the producer (which fills it on clean completion) and the job (which reads it),
    decoupling the per-function stream from the job-level honesty flag. ``truncated`` is ``True``
    iff the requested function set exceeded the decompile total cap and was honestly bounded (never
    silently cut). Default-safe: ``truncated`` starts ``False`` (no over-cap until the worker says
    so), ``total`` ``None`` (unknown until the terminal response lands).

    Attributes:
        total: Worker-reported count of functions actually streamed (``None`` until completion).
        truncated: Whether the requested set exceeded the cap (honest bound).
    """

    total: int | None = None
    truncated: bool = False


#: Bounds for the streaming request models (mirror ``tools.schemas`` conventions). Kept literal
#: here so this provisional surface is self-contained (see the module-level note: the client-facing
#: tool schemas are frozen-contract additions for a LATER increment — these are server-side shapes).
_MAX_LIMIT = 10_000


class DecompileStreamIn(s._SessionScopedIn):  # reuse the frozen session-scoped base
    """Arguments to start a streaming bulk-decompile job (server-side shape — ADR-040, provisional).

    Session-scoped like every tool input (BOLA — the session manager authorizes ``session_id``).
    Bounds the number of functions the stream will cover so a job cannot enumerate an unbounded set
    (DoS — the total caps the produced chunk count). This is the SERVER-SIDE start shape consumed by
    the adapter; the client-facing ``start_decompile_stream`` tool schema is a frozen-contract
    addition for a later increment and is intentionally NOT defined here.

    Attributes:
        offset: Zero-based start index into the program's function list (used only when
            ``functions`` is omitted — the windowed path).
        limit: Maximum functions to stream (the job's total upper bound; capped at ``_MAX_LIMIT``).
        functions: Optional explicit set of function entry addresses (hex) OR names to decompile.
            When given, the worker decompiles exactly those (the list IS the bound) and ignores the
            window; when omitted, the ``[offset, offset+limit)`` window of the program is streamed.
            Each identifier is a bounded, untrusted string (the client schema length-caps the list).
    """

    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=_MAX_LIMIT)
    functions: list[str] | None = Field(default=None, max_length=_MAX_LIMIT)


class FetchJobResultsIn(s._SessionScopedIn):  # reuse the frozen session-scoped base
    """Arguments to pull the next batch from a streaming job (server-side shape — ADR-040).

    Attributes:
        job_id: The opaque job handle returned by the stream start.
        cursor: Optional client resume cursor (next ``seq`` the client expects); validated against
            the server's authoritative cursor.
        limit: Max chunks to return this pull (bounded by the manager's fetch cap).
    """

    job_id: str = Field(min_length=1, max_length=64)
    cursor: int | None = Field(default=None, ge=0)
    limit: int = Field(default=_DEFAULT_FETCH_BATCH, ge=1, le=_MAX_FETCH_BATCH)


class JobHandleIn(s._SessionScopedIn):  # reuse the frozen session-scoped base
    """Arguments naming a streaming job for status/cancel (server-side shape — ADR-040).

    Attributes:
        job_id: The opaque job handle.
    """

    job_id: str = Field(min_length=1, max_length=64)


class StreamChunk(BaseModel):
    """One streamed partial result — a single decompiled function (ADR-040; binary-derived).

    Frozen and extra-forbidding like every contract model. The ``function`` payload's binary-derived
    fields are already :class:`~vivarium.core.envelope.Untrusted`-wrapped (the per-chunk envelope
    rule — design §6); ``seq`` is a server-assigned, gap-free monotonic index (the cursor unit).

    Attributes:
        seq: Server-assigned sequence number, starting at 0, monotonic and gap-free across the
            whole stream. The client resumes/dedupes by it; the next-expected ``seq`` is the cursor.
        function: The decompiled function for this chunk. Its ``name``/``c_code``/``signature`` are
            untrusted (ADR-005) — inert data, never instructions.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Field(ge=0)
    function: s.DecompiledFunction


class StreamFetchResult(BaseModel):
    """Result of one pull from a streaming job (ADR-040 ``fetch_job_results`` shape).

    Frozen/extra-forbid. Carries the next bounded batch of chunks plus the resume cursor and the
    job's current state; on a terminal ``error`` the ``error`` envelope is set (honest end).

    Attributes:
        job_id: The opaque job handle these chunks belong to.
        chunks: The next bounded, ordered batch (possibly empty when nothing new is buffered yet).
        cursor: The next-expected ``seq`` — the resume point for the following fetch.
        state: The job's state AFTER this fetch (``running``/``paused``/``done``/``error``/
            ``cancelled``).
        done: Convenience flag — ``True`` iff ``state`` is terminal (no more chunks will arrive).
        truncated: ``True`` iff the worker reported the requested function set exceeded the
            decompile total cap and was honestly bounded (ADR-040 D8; never silently cut). ``False``
            until the worker's terminal summary lands.
        error: The terminal error envelope when ``state`` is ``error`` (else ``None``) — explicit,
            never a silent early stop.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    job_id: str
    chunks: list[StreamChunk]
    cursor: int = Field(ge=0)
    state: JobState
    done: bool
    truncated: bool = False
    error: ErrorEnvelope | None = None


class StreamJobStatus(BaseModel):
    """Server-authored streaming-job status — NO binary content (ADR-040 ``job_status`` shape).

    Every field is a server-computed scalar/label; nothing here is binary-derived (no function
    name, decompiled text, or path — design §6: "progress messages contain no binary-derived
    content"). ETA is computed from the **injected** clock so it is deterministic in tests.

    Attributes:
        job_id: The opaque job handle.
        session_id: The owning session id (the job is bound to it — BOLA).
        state: Current :class:`JobState`.
        produced: Count of chunks produced so far (seq assigned).
        total: Total expected chunks when known up front (else ``None`` — indeterminate).
        buffered: Count of produced-but-not-yet-fetched chunks currently held in the buffer.
        cursor: The next-expected ``seq`` the client should fetch from.
        elapsed_seconds: Wall-clock-free elapsed time since job start (injected monotonic clock).
        eta_seconds: Rough estimate of seconds remaining (``None`` when indeterminate — unknown
            total, no progress yet, or a terminal state). A best-effort linear extrapolation.
        truncated: ``True`` iff the worker reported the requested function set exceeded the
            decompile total cap and was honestly bounded (ADR-040 D8). ``False`` until completion.
        error: The terminal error envelope when ``state`` is ``error`` (else ``None``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    job_id: str
    session_id: str
    state: JobState
    produced: int = Field(ge=0)
    total: int | None = Field(default=None, ge=0)
    buffered: int = Field(ge=0)
    cursor: int = Field(ge=0)
    elapsed_seconds: float = Field(ge=0.0)
    eta_seconds: float | None = Field(default=None, ge=0.0)
    truncated: bool = False
    error: ErrorEnvelope | None = None


def _chunk_size_bytes(chunk: StreamChunk) -> int:
    """Estimate a chunk's buffered byte footprint for the byte-bound backpressure check.

    Uses the length of the untrusted text fields (the dominant, attacker-influenced payload). A
    cheap, deterministic upper-ish bound — exactness is not required, only that a few large chunks
    trip the byte cap before the count cap (so the buffer cannot grow unbounded in bytes). Pure.

    Args:
        chunk: The chunk to size.

    Returns:
        A non-negative byte estimate of the chunk's binary-derived payload.
    """
    fn = chunk.function
    return len(fn.name.value) + len(fn.c_code.value) + len(fn.signature.value) + len(fn.address)


class _StreamingJob:
    """Internal per-job state: bounded buffer, gap-free seq, backpressure, terminal-error (ADR-040).

    Not part of the public surface; the manager owns instances and exposes them only through the
    frozen result/status models. All mutation is serialized by the manager's lock (the manager holds
    it across each operation), so this class assumes single-threaded access per call.
    """

    __slots__ = (
        "_buffer",
        "_clock",
        "_error",
        "_max_buffer_bytes",
        "_max_buffer_chunks",
        "_next_seq",
        "_producer",
        "_started_mono",
        "_state",
        "_terminal",
        "_total",
        "buffered_bytes",
        "cursor",
        "job_id",
        "owner",
        "session_id",
    )

    def __init__(
        self,
        *,
        job_id: str,
        session_id: str,
        owner: str,
        producer: Iterator[s.DecompiledFunction],
        total: int | None,
        limits: Limits,
        clock: Callable[[], float],
        terminal: StreamTerminal | None = None,
    ) -> None:
        """Initialize a fresh streaming job in the ``running`` state.

        Args:
            job_id: Opaque CSPRNG job handle.
            session_id: The owning session id (lifetime + BOLA binding).
            owner: The creating principal id (defense-in-depth ownership tag; the authoritative
                BOLA check is the session-ownership authorizer).
            producer: An iterator yielding per-function results; raising mid-iteration becomes a
                terminal error, exhaustion becomes ``done``.
            total: Total expected chunk count when known up front, else ``None``.
            limits: Active resource limits (buffer caps).
            clock: Injected monotonic clock for elapsed/ETA (deterministic in tests).
            terminal: Optional holder the producer fills with the worker's terminal
                ``{total, truncated}`` on clean completion; the job reads ``truncated`` from it for
                honest reporting (ADR-040 D8). ``None`` for the synthetic/in-memory producer (no
                worker terminal summary — ``truncated`` stays ``False``).
        """
        self.job_id = job_id
        self.session_id = session_id
        self.owner = owner
        self._producer = producer
        self._total = total
        self._terminal = terminal if terminal is not None else StreamTerminal()
        self._max_buffer_chunks = limits.max_stream_buffer_chunks
        self._max_buffer_bytes = limits.max_stream_buffer_bytes
        self._clock = clock
        self._started_mono = clock()
        self._buffer: deque[StreamChunk] = deque()
        self.buffered_bytes = 0
        self._next_seq = 0
        self.cursor = 0
        self._state = JobState.RUNNING
        self._error: ErrorEnvelope | None = None

    @property
    def state(self) -> JobState:
        """The job's current lifecycle state."""
        return self._state

    @property
    def is_terminal(self) -> bool:
        """Whether the job has reached a terminal state (no more chunks will be produced).

        This is the INTERNAL terminal flag (producer exhausted/errored/cancelled). It does NOT
        imply the client has seen everything — buffered chunks may still be undelivered. For what
        the client should observe, use :attr:`effective_state` / :attr:`effective_done`.
        """
        return self._state in _TERMINAL_STATES

    @property
    def effective_state(self) -> JobState:
        """The state as the CLIENT should observe it (ADR-040 D7: ``done`` is authoritative).

        A producer that has finished (``done``) or raised (``error``) is still reported as
        ``running`` while buffered chunks remain undelivered, so the client's ``done`` does not flip
        until the stream is genuinely complete (the buffer is drained). Otherwise a ``limit``-capped
        final batch would report ``done`` with a tail still buffered, and the client — trusting
        ``done`` — would orphan those chunks. ``cancelled`` drops the buffer, so it reports at once.
        """
        if self._buffer and self._state in (JobState.DONE, JobState.ERROR):
            return JobState.RUNNING
        return self._state

    @property
    def effective_done(self) -> bool:
        """Whether the client should consider the stream complete: terminal AND buffer drained."""
        return self.effective_state in _TERMINAL_STATES

    @property
    def error(self) -> ErrorEnvelope | None:
        """The terminal error envelope when the job is in ``error`` state, else ``None``."""
        return self._error

    @property
    def truncated(self) -> bool:
        """Whether the worker honestly bounded an over-cap requested set (ADR-040 D8).

        Read from the shared terminal holder the producer fills on clean completion; ``False`` until
        the worker's terminal summary lands (and for the synthetic in-memory producer).
        """
        return self._terminal.truncated

    def _buffer_full(self) -> bool:
        """Whether the buffer has hit either backpressure bound (count OR bytes)."""
        return (
            len(self._buffer) >= self._max_buffer_chunks
            or self.buffered_bytes >= self._max_buffer_bytes
        )

    def pump(self) -> None:
        """Advance the producer to refill the buffer, applying backpressure as a pause.

        Pulls from the producer ONLY while the buffer has room: when a bound is reached the job
        enters ``paused`` and the producer is left un-advanced (no chunk dropped or reordered —
        backpressure is a pause, design §6). Producer exhaustion → ``done``; a producer exception →
        a terminal ``error`` (honest end). A no-op once terminal. Each appended chunk gets the next
        gap-free ``seq``.
        """
        if self.is_terminal:
            return
        while not self._buffer_full():
            try:
                fn = next(self._producer)
            except StopIteration:
                self._state = JobState.DONE
                return
            except GhidraMcpError as exc:
                # Honest terminal error: surface the producer's safe envelope, never an ambiguous
                # early ``done`` (design §6 fail-closed-and-honest).
                self._state = JobState.ERROR
                self._error = exc.envelope
                _LOG.warning(
                    "stream.job.error",
                    extra={
                        "event": "stream_job_error",
                        "job_id": self.job_id,
                        "session_id": self.session_id,
                        "produced": self._next_seq,
                        "error_type": exc.envelope.type.value,
                    },
                )
                return
            except Exception:
                # An unexpected (non-envelope) producer fault: fail closed to a generic, leak-free
                # terminal error — never expose internals, never end ambiguously
                # (topic-error-handling).
                self._state = JobState.ERROR
                self._error = ErrorEnvelope(
                    type=ErrorType.INTERNAL,
                    title="Internal error",
                    detail="the streaming producer failed unexpectedly",
                    status=500,
                    retryable=False,
                )
                _LOG.error(
                    "stream.job.producer_fault",
                    extra={
                        "event": "stream_job_producer_fault",
                        "job_id": self.job_id,
                        "session_id": self.session_id,
                        "produced": self._next_seq,
                    },
                )
                return
            chunk = StreamChunk(seq=self._next_seq, function=fn)
            self._next_seq += 1
            self._buffer.append(chunk)
            self.buffered_bytes += _chunk_size_bytes(chunk)
        # The loop exits ONLY because the buffer filled (exhaustion/error ``return`` inside the loop
        # before reaching here), so the job is necessarily non-terminal: pause (backpressure) — the
        # pause is lifted back to ``running`` on the next drain (fetch).
        self._state = JobState.PAUSED

    def drain(self, max_chunks: int) -> list[StreamChunk]:
        """Remove and return up to ``max_chunks`` buffered chunks in order, advancing the cursor.

        Pops from the front of the buffer (lowest ``seq`` first — never reorders), advances the
        cursor to the next-expected ``seq``, and frees the corresponding buffered bytes. Lifts a
        ``paused`` job back to ``running`` (the drain made room) so the next :meth:`pump` resumes
        producing. Does not itself pump — the manager pumps after draining.

        Args:
            max_chunks: Maximum chunks to return this fetch (already bounded by the manager).

        Returns:
            The ordered batch of chunks removed from the buffer (possibly empty).
        """
        out: list[StreamChunk] = []
        while self._buffer and len(out) < max_chunks:
            chunk = self._buffer.popleft()
            self.buffered_bytes -= _chunk_size_bytes(chunk)
            self.cursor = chunk.seq + 1
            out.append(chunk)
        # Draining freed room: a paused job can resume producing (running). Terminal states stick.
        if self._state is JobState.PAUSED:
            self._state = JobState.RUNNING
        return out

    def cancel(self) -> None:
        """Mark the job cancelled and drop any buffered chunks (free the worker early — design §6).

        Idempotent: cancelling a terminal job is a no-op (a ``done`` job stays ``done``; a
        re-cancel stays ``cancelled``). Discarding the buffer is a confidentiality + resource win
        (no un-fetched binary-derived chunks linger).
        """
        if self.is_terminal:
            return
        self._state = JobState.CANCELLED
        self._buffer.clear()
        self.buffered_bytes = 0

    def status(self) -> StreamJobStatus:
        """Snapshot the server-authored status (no binary content), with an injected-clock ETA.

        Returns:
            A :class:`StreamJobStatus` — counts, state, elapsed, and a best-effort ETA. ETA is a
            linear extrapolation from elapsed and produced-vs-total; it is ``None`` when the total
            is unknown, nothing has been produced, or the job is terminal.
        """
        elapsed = max(0.0, self._clock() - self._started_mono)
        eta: float | None = None
        if (
            not self.is_terminal
            and self._total is not None
            and self._next_seq > 0
            and self._next_seq < self._total
            and elapsed > 0.0
        ):
            rate = self._next_seq / elapsed  # chunks per second so far
            remaining = self._total - self._next_seq
            eta = remaining / rate
        effective = self.effective_state
        return StreamJobStatus(
            job_id=self.job_id,
            session_id=self.session_id,
            state=effective,
            produced=self._next_seq,
            total=self._total,
            buffered=len(self._buffer),
            cursor=self.cursor,
            elapsed_seconds=elapsed,
            eta_seconds=eta,
            truncated=self._terminal.truncated,
            # Surface the terminal error only once the pre-error buffered chunks have drained
            # (design §6: the terminal error comes AFTER the already-buffered chunks).
            error=self._error if effective is JobState.ERROR else None,
        )


#: Signature of the session-ownership authorizer the manager calls before every job operation. It
#: MUST raise ``SESSION_INVALID`` (BOLA-safe) for an unknown/expired/evicted/foreign session — i.e.
#: the existing :meth:`SessionManager.authorize` bound with the caller. Returning normally means the
#: caller owns a live session; the manager then matches the job's ``session_id`` to it. The return
#: value is **ignored** (the authorizer is called for its raise-or-not side effect), so the type is
#: ``object`` — the real :meth:`SessionManager.authorize` returns a ``SessionInfo`` and conforms.
type SessionAuthorizer = Callable[[str, str], object]


class StreamingJobManager:
    """Owns streaming jobs across sessions: one active job per session, BOLA-bound (ADR-040).

    Constructed once (composition root). The session-ownership authorizer is injected (dependency
    inversion) so this core has no import-time dependency on the concrete session manager — it is
    handed a callable that performs the BOLA-safe authorize for ``(session_id, caller)``.

    Thread-safety: a re-entrant lock serializes all table + per-job mutation (a periodic reaper and
    request threads must not corrupt state — topic-concurrency). No I/O is performed under the lock;
    the producer is advanced under it but the producer for this increment is a pure in-memory
    iterator (the real worker-streaming adapter will pump off-lock in a later increment).
    """

    def __init__(
        self,
        *,
        authorize: SessionAuthorizer,
        limits: Limits | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the manager with an injected ownership authorizer and limits.

        Args:
            authorize: BOLA-safe ``(session_id, caller) -> None`` ownership check; raises
                ``SESSION_INVALID`` for any unknown/expired/evicted/foreign session. Typically
                ``lambda sid, caller: session_manager.authorize(sid, caller=caller)``.
            limits: Active resource limits (buffer caps); defaults to :class:`Limits` defaults.
            clock: Injected monotonic clock (deterministic ETA/elapsed in tests).
        """
        self._authorize = authorize
        self._limits = limits if limits is not None else Limits()
        self._clock = clock
        self._jobs: dict[str, _StreamingJob] = {}
        #: session_id -> its single active (non-terminal) job_id (one-active-per-session cap).
        self._active_by_session: dict[str, str] = {}
        self._lock = threading.RLock()

    def start_job(
        self,
        session_id: str,
        *,
        producer: Iterator[s.DecompiledFunction],
        total: int | None = None,
        caller: str = "local",
        terminal: StreamTerminal | None = None,
    ) -> str:
        """Start a streaming job for a caller-owned session; return its opaque handle (ADR-040).

        Authorizes the session (BOLA chokepoint) BEFORE creating anything, then enforces the
        one-active-job-per-session cap: a session whose existing job is still ``running``/``paused``
        cannot start a second (``LIMIT_EXCEEDED`` — a terminal job is cleared first so a finished
        stream does not block the next). The new job starts in ``running`` and is pumped once so the
        first batch is buffered (subject to backpressure).

        Args:
            session_id: The owning, caller-owned session id.
            producer: An iterator of per-function results (the worker-streaming source; a fake in
                this increment). Exhaustion → ``done``; an exception → terminal ``error``.
            total: Total expected chunks when known up front (drives ETA/total reporting).
            caller: The authenticated, server-derived calling-principal id (ADR-017).
            terminal: Optional shared holder the producer fills with the worker's terminal
                ``{total, truncated}`` (ADR-040 D8); read by the job for honest ``truncated``.

        Returns:
            The opaque CSPRNG job id.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) for a bad/foreign session, or
                ``LIMIT_EXCEEDED`` when the session already has an active streaming job.
        """
        with self._lock:
            # BOLA: prove the caller owns a live session before anything is allocated.
            self._authorize(session_id, caller)
            existing = self._active_by_session.get(session_id)
            if existing is not None:
                job = self._jobs.get(existing)
                if job is not None and not job.is_terminal:
                    raise _errors.make_error(
                        ErrorType.LIMIT_EXCEEDED,
                        "session already has an active streaming job",
                    )
                # The recorded job is gone or terminal: clear the slot so a new stream can start.
                self._active_by_session.pop(session_id, None)
            job_id = secrets.token_urlsafe(_JOB_ID_BYTES)
            job = _StreamingJob(
                job_id=job_id,
                session_id=session_id,
                owner=caller,
                producer=producer,
                total=total,
                limits=self._limits,
                clock=self._clock,
                terminal=terminal,
            )
            self._jobs[job_id] = job
            self._active_by_session[session_id] = job_id
            job.pump()
            _LOG.info(
                "stream.job.start",
                extra={
                    "event": "stream_job_started",
                    "job_id": job_id,
                    "session_id": session_id,
                    "principal_id": caller,
                    "total": total,
                },
            )
            return job_id

    def fetch(
        self,
        session_id: str,
        job_id: str,
        *,
        cursor: int | None = None,
        limit: int = _DEFAULT_FETCH_BATCH,
        caller: str = "local",
    ) -> StreamFetchResult:
        """Pull the next bounded batch of chunks from a caller-owned job (ADR-040 fetch).

        Authorizes the owning session (BOLA) and verifies the job belongs to THAT session before
        returning anything — a job handle is meaningless without its session, and a foreign caller
        is denied the BOLA-safe ``SESSION_INVALID`` at the session check (it can never even learn
        the job exists). Drains up to ``limit`` buffered chunks in ``seq`` order (advancing the
        cursor), then pumps the producer to refill (lifting any backpressure pause). The returned
        ``cursor`` is the resume point for the next fetch.

        ``cursor`` is accepted for client-driven resume/dedupe semantics: chunks are delivered
        exactly once from the server buffer (popped on drain), and the client dedupes by ``seq``
        against its own progress; supplying a cursor that does not match the server's next cursor is
        a client-side bookkeeping signal only (the server is the authority on what remains buffered)
        and is rejected as a validation error if it runs *ahead* of the server (a client claiming to
        have consumed chunks the server never produced — fail closed).

        Args:
            session_id: The owning session id.
            job_id: The opaque job handle.
            cursor: Optional client resume cursor; when supplied it must not exceed the server's
                current cursor (it may be <= for an idempotent re-fetch acknowledgement).
            limit: Max chunks to return this pull (bounded to ``_MAX_FETCH_BATCH``).
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            A :class:`StreamFetchResult` with the batch, the next cursor, the post-fetch state, and
            (on a terminal error) the error envelope.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) for a bad/foreign session or a job that
                is not owned by it; ``VALIDATION`` for a non-positive/oversized ``limit`` or a
                cursor ahead of the server.
        """
        if limit < 1 or limit > _MAX_FETCH_BATCH:
            raise _errors.make_error(
                ErrorType.VALIDATION,
                f"fetch limit must be between 1 and {_MAX_FETCH_BATCH}",
            )
        with self._lock:
            job = self._authorized_job(session_id, job_id, caller=caller)
            if cursor is not None and cursor > job.cursor:
                # The client claims to have consumed beyond what the server has delivered — a
                # bookkeeping impossibility; fail closed rather than silently skipping chunks.
                raise _errors.make_error(
                    ErrorType.VALIDATION,
                    "resume cursor is ahead of the stream",
                )
            chunks = job.drain(limit)
            job.pump()
            effective = job.effective_state
            return StreamFetchResult(
                job_id=job.job_id,
                chunks=chunks,
                cursor=job.cursor,
                # Report terminal (state/done) only when the buffer is drained — a producer that
                # finished/errored with chunks still buffered stays `running`, so the client does
                # not trust an early `done` and orphan the buffered tail (ADR-040 D7).
                state=effective,
                done=job.effective_done,
                truncated=job.truncated,
                # Surface the terminal error only once the pre-error buffered chunks have drained.
                error=job.error if effective is JobState.ERROR else None,
            )

    def status(self, session_id: str, job_id: str, *, caller: str = "local") -> StreamJobStatus:
        """Return a caller-owned job's server-authored status (no binary content — ADR-040).

        Authorizes the owning session (BOLA) and verifies job ownership, then snapshots counts /
        state / elapsed / ETA from the injected clock. Status NEVER carries binary-derived content.

        Args:
            session_id: The owning session id.
            job_id: The opaque job handle.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            The :class:`StreamJobStatus` snapshot.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) for a bad/foreign session or a job not
                owned by it.
        """
        with self._lock:
            job = self._authorized_job(session_id, job_id, caller=caller)
            return job.status()

    def cancel(self, session_id: str, job_id: str, *, caller: str = "local") -> StreamJobStatus:
        """Cancel a caller-owned job (free the worker early); return its terminal status (ADR-040).

        Authorizes the owning session (BOLA) and verifies ownership, marks the job ``cancelled``,
        discards its buffer, and clears the session's active-job slot so a new stream may start.
        Idempotent (cancelling a terminal job returns its existing terminal status).

        Args:
            session_id: The owning session id.
            job_id: The opaque job handle.
            caller: The authenticated, server-derived calling-principal id (ADR-017).

        Returns:
            The job's :class:`StreamJobStatus` after cancellation (terminal).

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) for a bad/foreign session or a job not
                owned by it.
        """
        with self._lock:
            job = self._authorized_job(session_id, job_id, caller=caller)
            job.cancel()
            self._active_by_session.pop(session_id, None)
            _LOG.info(
                "stream.job.cancel",
                extra={
                    "event": "stream_job_cancelled",
                    "job_id": job_id,
                    "session_id": session_id,
                    "principal_id": caller,
                },
            )
            return job.status()

    def discard_session(self, session_id: str) -> None:
        """Drop every job bound to ``session_id`` (called on session eviction — lifetime bound).

        A job lives inside its session's lifetime (design §6 / ADR-002): when the session is evicted
        (TTL/idle/close/poison/timeout) its jobs end and their buffers are discarded so no
        binary-derived chunk outlives the session. Internal/system path (not principal-scoped) — the
        session manager has already authorized the eviction. Idempotent.

        Args:
            session_id: The evicted session's id.
        """
        with self._lock:
            self._active_by_session.pop(session_id, None)
            doomed = [jid for jid, job in self._jobs.items() if job.session_id == session_id]
            for jid in doomed:
                job = self._jobs.pop(jid)
                job.cancel()
            if doomed:
                _LOG.info(
                    "stream.job.discard_session",
                    extra={
                        "event": "stream_jobs_discarded",
                        "session_id": session_id,
                        "count": len(doomed),
                    },
                )

    def _authorized_job(self, session_id: str, job_id: str, *, caller: str) -> _StreamingJob:
        """Authorize the session (BOLA) and return the job IFF it belongs to that session.

        The single ownership chokepoint for fetch/status/cancel (complete mediation — every
        job-scoped path runs the same check). A foreign caller is denied at the session authorize
        with the BOLA-safe ``SESSION_INVALID`` (no oracle that the job exists); a job whose
        ``session_id`` does not match the (now-owned) session is likewise ``SESSION_INVALID`` — one
        owner cannot reach another session's job even by guessing the handle. Caller holds the lock.

        Args:
            session_id: The session the client claims owns the job.
            job_id: The opaque job handle.
            caller: The authenticated, server-derived calling-principal id.

        Returns:
            The owned :class:`_StreamingJob`.

        Raises:
            GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) for a bad/foreign session, an unknown
                job, or a job not bound to the authorized session.
        """
        # 1) Session ownership (raises SESSION_INVALID for unknown/expired/evicted/foreign).
        self._authorize(session_id, caller)
        # 2) Job must exist AND be bound to THIS owned session — same BOLA-safe error otherwise so a
        #    handle from another session is indistinguishable from a nonexistent one (no oracle).
        job = self._jobs.get(job_id)
        if job is None or job.session_id != session_id:
            raise _errors.session_invalid()
        return job
