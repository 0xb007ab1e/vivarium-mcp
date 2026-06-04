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

from dataclasses import dataclass

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


def resolve_limits(overrides: dict[str, int] | None = None) -> Limits:
    """Resolve limits from defaults + overrides, clamped to safe ranges (fail closed).

    Args:
        overrides: Optional mapping of limit name → value (typically from validated config).

    Returns:
        A validated, clamped :class:`Limits`.

    Raises:
        GhidraMcpError: ``VALIDATION`` if an override is non-positive or otherwise invalid.

    Note:
        STUB (WS4). Clamp each value to ``[1, HARD_MAX_*]``; never allow a wider-than-hard limit.
    """
    raise NotImplementedError("WS4: implement limit resolution with clamping")


def check_binary_size(size_bytes: int, limits: Limits) -> None:
    """Reject an over-cap binary BEFORE it reaches the worker.

    Args:
        size_bytes: Size of the candidate input.
        limits: Active limits.

    Raises:
        GhidraMcpError: ``LIMIT_EXCEEDED`` if ``size_bytes`` exceeds ``limits.max_binary_bytes``.

    Note:
        STUB (WS4). Also where zip-bomb/decompression-ratio checks attach if archive inputs are
        ever supported (currently raw binaries only).
    """
    raise NotImplementedError("WS4: implement pre-worker size enforcement")
