"""Error envelope (RFC 9457-style Problem Details) — FROZEN CONTRACT (WS0).

Every tool failure and protocol error surfaces as an :class:`ErrorEnvelope`. The shape is a
deliberately small, stable, machine-readable problem document modeled on RFC 9457 (Problem
Details for HTTP APIs), adapted to the MCP tool context.

Security (std-owasp-proactive #10, topic-error-handling): the envelope **never** leaks internals
— no stack traces, file paths, JVM detail, dependency versions, or raw binary content. The
``detail`` field is a safe, human-readable summary; full diagnostics are logged server-side under
a correlation id only.

See ``docs/contracts/error-envelope.md`` for the canonical specification.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ErrorType(StrEnum):
    """Stable machine-readable error categories (the RFC 9457 ``type`` slug, last path segment).

    These slugs are part of the frozen contract — clients may branch on them. Add new members for
    new categories; never repurpose an existing slug.
    """

    VALIDATION = "validation-error"
    """Tool arguments failed boundary validation (trust boundary 1)."""

    NOT_FOUND = "not-found"
    """A requested object (function, symbol, session, address) does not exist."""

    SESSION_INVALID = "session-invalid"
    """Session id is unknown, expired, or evicted (also the BOLA-safe response — never reveal
    whether another session exists)."""

    FORBIDDEN = "forbidden"
    """The caller is authenticated and owns the target, but lacks permission for THIS operation
    (ADR-036): a missing OAuth capability (ADR-033 scope→tool authZ) or absent write/structural
    consent (ADR-012). Distinct from ``validation-error`` ("your request was malformed") and from
    ``session-invalid`` ("you may not even know this exists" — BOLA-safe). NEVER used for
    ownership/cross-caller denial (that stays ``session-invalid`` so 403 cannot become an
    existence oracle). 403, not retryable."""

    LIMIT_EXCEEDED = "limit-exceeded"
    """A size/count/time bound was exceeded (DoS control — PLAN §3 F7)."""

    TIMEOUT = "timeout"
    """A per-tool or per-analysis wall-clock timeout elapsed; the worker may have been killed."""

    WORKER_UNAVAILABLE = "worker-unavailable"
    """The Ghidra worker could not be reached, crashed, or was evicted mid-call."""

    RESOURCE_EXHAUSTED = "resource-exhausted"
    """The worker exceeded its memory cap (OOM-killed) or exited unexpectedly from resource
    pressure (ADR-023 / F1). Distinct from ``worker-unavailable`` so a client can surface a precise
    'increase worker memory or reduce input size' hint. Not retryable (the same input would OOM
    again)."""

    ANALYSIS_FAILED = "analysis-failed"
    """Ghidra could not analyze the input (e.g. unrecognized/corrupt format) — not a server bug."""

    INTERNAL = "internal-error"
    """Unexpected server-side fault. Detail is generic; diagnostics are logged, not returned."""


class ErrorEnvelope(BaseModel):
    """An RFC 9457-style problem document returned on any failure — FROZEN CONTRACT.

    Attributes:
        type: Stable machine-readable category (:class:`ErrorType`).
        title: Short, human-readable summary of the error category (stable per ``type``).
        detail: Safe, specific explanation for this occurrence. MUST NOT contain stack traces,
            paths, secrets, or binary-derived content.
        status: Optional numeric code mirroring HTTP semantics for client convenience (e.g.
            400 validation, 404 not-found, 413 limit-exceeded, 408/504 timeout, 503 worker).
        correlation_id: Opaque id tying this error to redacted server-side logs for support.
        retryable: Whether the client may retry the same call (transient vs terminal —
            topic-error-handling / topic-event-driven). Defaults to ``False`` (fail closed).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: ErrorType
    title: str = Field(min_length=1, max_length=120)
    detail: str = Field(min_length=1, max_length=2048)
    status: int | None = Field(default=None, ge=400, le=599)
    correlation_id: str | None = Field(default=None, max_length=64)
    retryable: bool = False


class GhidraMcpError(Exception):
    """Base exception carrying a safe :class:`ErrorEnvelope` for boundary translation.

    Internal code raises subclasses of this; the server shell catches it at the tool boundary and
    returns ``envelope`` to the client. Anything *not* a ``GhidraMcpError`` is mapped to a generic
    ``INTERNAL`` envelope (never leaked) — fail closed.

    Note:
        STUB (WS1/WS4) — concrete subclasses (ValidationError, SessionInvalidError,
        LimitExceededError, TimeoutError, WorkerUnavailableError, AnalysisFailedError) are defined
        as the layers that raise them are implemented.
    """

    def __init__(self, envelope: ErrorEnvelope) -> None:
        """Initialize with the safe, client-facing error envelope.

        Args:
            envelope: The redacted problem document to return to the client.
        """
        super().__init__(envelope.detail)
        self.envelope = envelope
