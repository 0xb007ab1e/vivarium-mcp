"""Contract tests for the RFC 9457-style error envelope (FROZEN — WS0).

These lock the error-envelope shape so WS1+ build against a stable contract and so no future
change silently leaks internals or drops a field. Critical path (envelope) → 100% target.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError


@pytest.mark.critical
def test_error_type_slugs_are_stable() -> None:
    # Clients may branch on these slugs; assert the frozen values explicitly.
    # (.value: ErrorType is a str-enum; compare the serialized slug so mypy --strict doesn't
    # flag the enum-member-vs-str-literal comparison as non-overlapping.)
    assert ErrorType.VALIDATION.value == "validation-error"
    assert ErrorType.NOT_FOUND.value == "not-found"
    assert ErrorType.SESSION_INVALID.value == "session-invalid"
    assert ErrorType.LIMIT_EXCEEDED.value == "limit-exceeded"
    assert ErrorType.TIMEOUT.value == "timeout"
    assert ErrorType.WORKER_UNAVAILABLE.value == "worker-unavailable"
    assert ErrorType.RESOURCE_EXHAUSTED.value == "resource-exhausted"
    assert ErrorType.ANALYSIS_FAILED.value == "analysis-failed"
    assert ErrorType.INTERNAL.value == "internal-error"


@pytest.mark.critical
def test_minimal_envelope_defaults_fail_closed() -> None:
    env = ErrorEnvelope(type=ErrorType.INTERNAL, title="Internal error", detail="Something failed.")
    # Defaults: no status, no correlation id, NOT retryable (fail closed).
    assert env.status is None
    assert env.correlation_id is None
    assert env.retryable is False


@pytest.mark.critical
def test_envelope_is_frozen_and_forbids_extra_fields() -> None:
    env = ErrorEnvelope(type=ErrorType.TIMEOUT, title="Timeout", detail="Deadline elapsed.")
    with pytest.raises(ValidationError):
        env.detail = "mutated"  # frozen
    with pytest.raises(ValidationError):
        ErrorEnvelope(  # extra field rejected
            type=ErrorType.TIMEOUT,
            title="Timeout",
            detail="x",
            stacktrace="LEAK",  # type: ignore[call-arg]
        )


@pytest.mark.critical
@pytest.mark.parametrize("bad_status", [399, 600])
def test_status_bounds_enforced(bad_status: int) -> None:
    with pytest.raises(ValidationError):
        ErrorEnvelope(type=ErrorType.VALIDATION, title="t", detail="d", status=bad_status)


@pytest.mark.critical
def test_detail_and_title_length_bounds() -> None:
    with pytest.raises(ValidationError):
        ErrorEnvelope(type=ErrorType.VALIDATION, title="", detail="d")  # title too short
    with pytest.raises(ValidationError):
        ErrorEnvelope(type=ErrorType.VALIDATION, title="t", detail="x" * 2049)  # detail too long


@pytest.mark.critical
def test_exception_carries_envelope() -> None:
    env = ErrorEnvelope(
        type=ErrorType.SESSION_INVALID, title="Invalid session", detail="Unknown session."
    )
    exc = GhidraMcpError(env)
    assert exc.envelope is env
    assert str(exc) == "Unknown session."
