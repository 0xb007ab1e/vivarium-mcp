"""Safe error-envelope factories for the worker adapter and session manager (server-side).

Thin helpers that build a :class:`vivarium.core.errors.GhidraMcpError` carrying a redacted
:class:`vivarium.core.errors.ErrorEnvelope` for each failure mode WS2 raises. Centralizing
construction here keeps the envelope shapes consistent and ensures ``detail`` is always a fixed,
safe string (no host paths, JVM detail, or binary content — error-envelope.md disclosure rules).

JVM-free: importable from ``sessions`` and ``ghidra.rpc_client`` without violating ADR-001.
"""

from __future__ import annotations

from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError

# JSON-RPC protocol error codes we special-case (rpc-protocol.md §5). ``-32601`` (method-not-found)
# is emitted by the worker for a verb its build does not implement — e.g. when the running worker
# image predates a tool added to the server. It carries NO matching slug in the worker's
# ``_SLUG_BY_CODE`` (older builds), so a slug-only mapping would fall through to ``INTERNAL`` (an
# opaque 500). We therefore key off the numeric CODE, which every worker preserves, to surface an
# honest, actionable error regardless of the worker image version.
_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INVALID_REQUEST = -32600

# Map the worker's JSON-RPC ``data.type`` slug → public ErrorType (rpc-protocol.md §5).
_WORKER_SLUG_TO_TYPE: dict[str, ErrorType] = {
    "invalid-params": ErrorType.VALIDATION,
    "not-found": ErrorType.NOT_FOUND,
    "limit-exceeded": ErrorType.LIMIT_EXCEEDED,
    "analysis-failed": ErrorType.ANALYSIS_FAILED,
    "internal-error": ErrorType.INTERNAL,
    # Present so a NEWER worker that emits proper slugs for the protocol codes maps correctly even
    # if the numeric-code fast-path below is ever bypassed (defense in depth).
    "method-not-found": ErrorType.NOT_FOUND,
    "invalid-request": ErrorType.VALIDATION,
}

_STATUS: dict[ErrorType, int] = {
    ErrorType.VALIDATION: 400,
    ErrorType.NOT_FOUND: 404,
    ErrorType.SESSION_INVALID: 404,
    ErrorType.FORBIDDEN: 403,
    ErrorType.LIMIT_EXCEEDED: 413,
    ErrorType.TIMEOUT: 504,
    ErrorType.WORKER_UNAVAILABLE: 503,
    ErrorType.RESOURCE_EXHAUSTED: 503,
    ErrorType.ANALYSIS_FAILED: 422,
    ErrorType.INTERNAL: 500,
}

_TITLE: dict[ErrorType, str] = {
    ErrorType.VALIDATION: "Invalid arguments",
    ErrorType.NOT_FOUND: "Not found",
    ErrorType.SESSION_INVALID: "Invalid session",
    ErrorType.FORBIDDEN: "Forbidden",
    ErrorType.LIMIT_EXCEEDED: "Limit exceeded",
    ErrorType.TIMEOUT: "Operation timed out",
    ErrorType.WORKER_UNAVAILABLE: "Worker unavailable",
    ErrorType.RESOURCE_EXHAUSTED: "Worker out of resources",
    ErrorType.ANALYSIS_FAILED: "Analysis failed",
    ErrorType.INTERNAL: "Internal error",
}

# Retryable per the error-envelope contract. RESOURCE_EXHAUSTED is deliberately NOT retryable: the
# same input against the same memory cap would OOM again (ADR-023 D2) — the operator must increase
# worker memory or the client must reduce the input.
_RETRYABLE: dict[ErrorType, bool] = {
    ErrorType.LIMIT_EXCEEDED: True,
    ErrorType.TIMEOUT: True,
    ErrorType.WORKER_UNAVAILABLE: True,
}


def make_error(
    error_type: ErrorType,
    detail: str,
    *,
    correlation_id: str | None = None,
) -> GhidraMcpError:
    """Build a :class:`GhidraMcpError` with a safe, fully-populated envelope.

    Args:
        error_type: The public error category.
        detail: A safe, specific summary (caller MUST NOT pass host paths, stack traces, or
            binary-derived content).
        correlation_id: Optional id tying the error to redacted server-side logs.

    Returns:
        A ready-to-raise :class:`GhidraMcpError`.
    """
    envelope = ErrorEnvelope(
        type=error_type,
        title=_TITLE[error_type],
        detail=detail,
        status=_STATUS[error_type],
        correlation_id=correlation_id,
        retryable=_RETRYABLE.get(error_type, False),
    )
    return GhidraMcpError(envelope)


#: Fixed, safe client-facing detail for a worker JSON-RPC **method** error, by mapped type. The
#: worker's own free-form ``message`` is NEVER placed on the client envelope (gap round-4 Q8): it is
#: binary-adjacent, untrusted text from a potentially-hostile worker (TB2/TB3) and bypasses the
#: untrusted-data envelope's bidi/control normalization. These canned strings are used instead; the
#: worker message is logged (log-only), like ``data.detail`` already is.
_WORKER_METHOD_DETAIL: dict[ErrorType, str] = {
    ErrorType.VALIDATION: "the worker rejected the request arguments",
    ErrorType.NOT_FOUND: "the requested item was not found in the program",
    ErrorType.LIMIT_EXCEEDED: "the request exceeded a worker limit",
    ErrorType.ANALYSIS_FAILED: "the worker could not analyze the program",
    ErrorType.INTERNAL: "the worker reported an internal error",
}


def worker_method_error(
    error_type: ErrorType, *, correlation_id: str | None = None
) -> GhidraMcpError:
    """Build a client error for a worker JSON-RPC **method** error with a FIXED, safe detail.

    The worker's free-form ``message`` is deliberately NOT forwarded to the client (gap round-4 Q8):
    it is untrusted worker output (TB2/TB3) that would otherwise reach ``ErrorEnvelope.detail``
    un-normalized. A fixed per-type detail is used; the caller logs the worker's message separately
    (log-only). Falls back to a generic detail for any unmapped type (fail closed).

    Args:
        error_type: The public error category (from :func:`map_worker_slug`).
        correlation_id: Optional id tying the error to redacted server-side logs.

    Returns:
        A ready-to-raise :class:`GhidraMcpError` whose detail is a fixed safe string.
    """
    detail = _WORKER_METHOD_DETAIL.get(error_type, "the worker reported an error")
    return make_error(error_type, detail, correlation_id=correlation_id)


def worker_method_error_from(
    code: int, slug: str | None, *, correlation_id: str | None = None
) -> GhidraMcpError:
    """Build a client error for a worker JSON-RPC **method** error, honest about method-not-found.

    Keys off the numeric JSON-RPC ``code`` first: ``-32601`` (method-not-found) becomes an
    actionable ``NOT_FOUND`` — the worker does not implement this verb (commonly a worker image
    that predates the tool) — rather than the opaque ``INTERNAL`` a slug-only mapping produced
    (older workers emit no slug for ``-32601``, so it fell through to ``internal-error`` → 500).
    ``-32600`` (invalid-request) maps to ``VALIDATION``. Every other code defers to the existing
    slug mapping (:func:`map_worker_slug` + :func:`worker_method_error`), unchanged.

    Args:
        code: The worker's numeric JSON-RPC error code (from the decoded ``RpcError``).
        slug: The worker's ``data.type`` slug, or ``None``.
        correlation_id: Optional id tying the error to redacted server-side logs.

    Returns:
        A ready-to-raise :class:`GhidraMcpError` with a fixed, safe detail.
    """
    if code == _JSONRPC_METHOD_NOT_FOUND:
        return make_error(
            ErrorType.NOT_FOUND,
            "operation not supported by the running worker "
            "(the worker image may predate this tool — rebuild or re-pin the worker image)",
            correlation_id=correlation_id,
        )
    if code == _JSONRPC_INVALID_REQUEST:
        return make_error(
            ErrorType.VALIDATION,
            _WORKER_METHOD_DETAIL[ErrorType.VALIDATION],
            correlation_id=correlation_id,
        )
    return worker_method_error(map_worker_slug(slug), correlation_id=correlation_id)


def session_invalid(correlation_id: str | None = None) -> GhidraMcpError:
    """Build the BOLA-safe ``session-invalid`` error.

    The detail is identical regardless of whether the id is unknown, expired, evicted, or belongs
    to another caller — it never reveals that another session exists (error-envelope.md).

    Args:
        correlation_id: Optional id tying the error to redacted server-side logs.

    Returns:
        A ``SESSION_INVALID`` :class:`GhidraMcpError`.
    """
    return make_error(
        ErrorType.SESSION_INVALID,
        "session is unknown, expired, or no longer available",
        correlation_id=correlation_id,
    )


def resource_exhausted(
    mem_mib: int | None = None, correlation_id: str | None = None
) -> GhidraMcpError:
    """Build the ``resource-exhausted`` error for a worker OOM/resource-pressure exit (ADR-023/037).

    The detail is a safe, actionable hint (no host paths, binary content, or engine internals —
    error-envelope.md disclosure rules); 503, not retryable (the same input against the same memory
    cap would OOM again — the operator must raise the cap or the client shrink input).

    When ``mem_mib`` is supplied (ADR-037 §3 sizing hint) the detail names the current configured
    worker memory and the env knob to raise, so the operator knows the baseline to grow from. The
    value is a server-computed integer only — no host path or binary-derived content leaks.

    Args:
        mem_mib: The resolved worker memory cap (MiB) to surface as the sizing hint; ``None`` falls
            back to the generic message (e.g. when the cap is not known at the call site).
        correlation_id: Optional id tying the error to redacted server-side logs.

    Returns:
        A ``RESOURCE_EXHAUSTED`` :class:`GhidraMcpError`.
    """
    if mem_mib is not None:
        detail = (
            f"worker exhausted its memory limit ({mem_mib} MiB); increase "
            f"VIVARIUM_WORKER_MEM_MIB (currently {mem_mib}) or reduce input size"
        )
    else:
        detail = "worker exhausted its memory limit; increase worker memory or reduce input size"
    return make_error(
        ErrorType.RESOURCE_EXHAUSTED,
        detail,
        correlation_id=correlation_id,
    )


def map_worker_slug(slug: str | None) -> ErrorType:
    """Map a worker JSON-RPC ``data.type`` slug to a public :class:`ErrorType`.

    Unknown/missing slugs fail closed to ``INTERNAL`` (never leak an unrecognized worker fault as
    something more specific).

    Args:
        slug: The worker-supplied error slug, or ``None``.

    Returns:
        The corresponding public :class:`ErrorType`.
    """
    if slug is None:
        return ErrorType.INTERNAL
    return _WORKER_SLUG_TO_TYPE.get(slug, ErrorType.INTERNAL)
