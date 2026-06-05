"""Resource limits enforced BEFORE the Ghidra worker — critical path (100% target).

These caps are the first line of DoS defense (PLAN §3 F7): the binary size cap is checked before a
single byte reaches Ghidra; response/result caps bound output; wall-clock timeouts bound time and
trigger a worker kill. Values default from configuration (``config``) with conservative built-in
fallbacks, and are clamped to safe ranges (a client/env can only make a limit *stricter* within
bounds, never unboundedly larger).

WS0 freezes the interface + default constants; WS4 implements enforcement; WS5 covers it to 100%
including boundary and overflow cases.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError

# Conservative built-in defaults (overridable via config within clamps). Mirrors .env.example.
DEFAULT_MAX_BINARY_BYTES = 128 * 1024 * 1024  # 128 MiB
DEFAULT_ANALYSIS_TIMEOUT_S = 600
DEFAULT_TOOL_TIMEOUT_S = 60
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024  # 4 MiB
DEFAULT_MAX_SESSIONS = 4

# Hard clamps — config can never exceed these (defense against misconfig widening the surface).
HARD_MAX_BINARY_BYTES = 1024 * 1024 * 1024  # 1 GiB absolute ceiling
HARD_MAX_ANALYSIS_TIMEOUT_S = 3600
HARD_MAX_SESSIONS = 32

# Per-field hard ceiling used for clamping. A resolved override is the MIN of the requested value
# and its ceiling: a caller may only make a limit *stricter*, never wider than the safe bound
# (defense against misconfig/an attacker-influenced env widening the attack surface — fail closed).
# Fields without an explicit higher ceiling clamp to their own built-in default (cannot be raised).
_HARD_CEILINGS: dict[str, int] = {
    "max_binary_bytes": HARD_MAX_BINARY_BYTES,
    "analysis_timeout_s": HARD_MAX_ANALYSIS_TIMEOUT_S,
    "tool_timeout_s": HARD_MAX_ANALYSIS_TIMEOUT_S,
    "max_response_bytes": DEFAULT_MAX_RESPONSE_BYTES,
    "max_sessions": HARD_MAX_SESSIONS,
}


@dataclass(frozen=True, slots=True)
class Limits:
    """Resolved, validated resource limits for a server instance.

    Attributes:
        max_binary_bytes: Hard cap on imported binary size (checked before Ghidra).
        analysis_timeout_s: Per-analysis wall-clock; on expiry the worker is killed.
        tool_timeout_s: Per-tool-call wall-clock.
        max_response_bytes: Cap on a single tool response payload.
        max_sessions: Worker-pool concurrency cap (backpressure above this).
    """

    max_binary_bytes: int = DEFAULT_MAX_BINARY_BYTES
    analysis_timeout_s: int = DEFAULT_ANALYSIS_TIMEOUT_S
    tool_timeout_s: int = DEFAULT_TOOL_TIMEOUT_S
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    max_sessions: int = DEFAULT_MAX_SESSIONS


def _validation_error(detail: str) -> GhidraMcpError:
    """Build a fail-closed ``VALIDATION`` error for an invalid limit override.

    Args:
        detail: Safe, specific message (no internals — names/values of config keys only).

    Returns:
        A :class:`GhidraMcpError` carrying a ``validation-error`` envelope (status 400).
    """
    return GhidraMcpError(
        ErrorEnvelope(
            type=ErrorType.VALIDATION,
            title="Invalid limit configuration",
            detail=detail,
            status=400,
            retryable=False,
        )
    )


def resolve_limits(overrides: dict[str, int] | None = None) -> Limits:
    """Resolve limits from defaults + overrides, clamped to safe ranges (fail closed).

    Each known override is validated as a positive ``int`` and then clamped to ``[1, ceiling]``,
    where ``ceiling`` is the field's hard bound (:data:`_HARD_CEILINGS`). A caller can therefore
    only make a limit **stricter** than the safe default — never widen it past the ceiling, even
    via a misconfigured or attacker-influenced environment (defense against surface widening).
    Unknown keys and non-positive / non-``int`` (incl. ``bool``) values fail closed with a
    ``VALIDATION`` error rather than being silently ignored.

    Args:
        overrides: Optional mapping of limit name → value (typically from validated config).

    Returns:
        A validated, clamped :class:`Limits`.

    Raises:
        GhidraMcpError: ``VALIDATION`` if an override key is unknown or its value is not a positive
            integer.
    """
    if not overrides:
        return Limits()

    known = {f.name for f in fields(Limits)}
    resolved: dict[str, int] = {}
    for key, value in overrides.items():
        if key not in known:
            raise _validation_error(f"unknown limit '{key}'")
        # Reject bool explicitly (``bool`` is an ``int`` subclass) and any non-positive value.
        if isinstance(value, bool) or not isinstance(value, int):
            raise _validation_error(f"limit '{key}' must be a positive integer")
        if value < 1:
            raise _validation_error(f"limit '{key}' must be >= 1")
        ceiling = _HARD_CEILINGS.get(key, getattr(Limits(), key))
        # Clamp DOWNWARD only: never allow a value above the hard ceiling (fail closed on widening).
        resolved[key] = min(value, ceiling)

    return Limits(**resolved)


def check_binary_size(size_bytes: int, limits: Limits) -> None:
    """Reject an over-cap binary BEFORE it reaches the worker.

    This is the first DoS line for TB3 (PLAN §3 F7): enforced on the server, before a single byte
    is handed to Ghidra. Fails closed on a negative size (which would otherwise pass a naive
    ``>`` comparison — guards against an integer/sign bug upstream).

    Args:
        size_bytes: Size of the candidate input, in bytes.
        limits: Active limits.

    Raises:
        GhidraMcpError: ``VALIDATION`` if ``size_bytes`` is not a non-negative integer;
            ``LIMIT_EXCEEDED`` if ``size_bytes`` exceeds ``limits.max_binary_bytes``.
    """
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int):
        raise _validation_error("binary size must be a non-negative integer")
    if size_bytes < 0:
        raise _validation_error("binary size must be a non-negative integer")
    if size_bytes > limits.max_binary_bytes:
        raise GhidraMcpError(
            ErrorEnvelope(
                type=ErrorType.LIMIT_EXCEEDED,
                title="Binary too large",
                # Safe: reports the cap and the rejected size only — no path/host/internals.
                detail=(
                    f"input size {size_bytes} bytes exceeds the maximum "
                    f"{limits.max_binary_bytes} bytes"
                ),
                status=413,
                retryable=False,
            )
        )
