"""Safe error-envelope factories for the worker adapter and session manager (server-side).

Thin helpers that build a :class:`ghidra_mcp.core.errors.GhidraMcpError` carrying a redacted
:class:`ghidra_mcp.core.errors.ErrorEnvelope` for each failure mode WS2 raises. Centralizing
construction here keeps the envelope shapes consistent and ensures ``detail`` is always a fixed,
safe string (no host paths, JVM detail, or binary content — error-envelope.md disclosure rules).

JVM-free: importable from ``sessions`` and ``ghidra.rpc_client`` without violating ADR-001.
"""

from __future__ import annotations

from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError

# Map the worker's JSON-RPC ``data.type`` slug → public ErrorType (rpc-protocol.md §5).
_WORKER_SLUG_TO_TYPE: dict[str, ErrorType] = {
    "invalid-params": ErrorType.VALIDATION,
    "not-found": ErrorType.NOT_FOUND,
    "limit-exceeded": ErrorType.LIMIT_EXCEEDED,
    "analysis-failed": ErrorType.ANALYSIS_FAILED,
    "internal-error": ErrorType.INTERNAL,
}

_STATUS: dict[ErrorType, int] = {
    ErrorType.VALIDATION: 400,
    ErrorType.NOT_FOUND: 404,
    ErrorType.SESSION_INVALID: 404,
    ErrorType.LIMIT_EXCEEDED: 413,
    ErrorType.TIMEOUT: 504,
    ErrorType.WORKER_UNAVAILABLE: 503,
    ErrorType.ANALYSIS_FAILED: 422,
    ErrorType.INTERNAL: 500,
}

_TITLE: dict[ErrorType, str] = {
    ErrorType.VALIDATION: "Invalid arguments",
    ErrorType.NOT_FOUND: "Not found",
    ErrorType.SESSION_INVALID: "Invalid session",
    ErrorType.LIMIT_EXCEEDED: "Limit exceeded",
    ErrorType.TIMEOUT: "Operation timed out",
    ErrorType.WORKER_UNAVAILABLE: "Worker unavailable",
    ErrorType.ANALYSIS_FAILED: "Analysis failed",
    ErrorType.INTERNAL: "Internal error",
}

# Retryable per the error-envelope contract.
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
