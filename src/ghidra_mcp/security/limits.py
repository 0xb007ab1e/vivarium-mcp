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

# Worker container resource bounds (ADR-023 / F1). Integer-MiB memory/tmpfs + whole-CPU + pid caps
# the launcher renders to engine spelling at argv build. Defaults mirror the previously-hardcoded
# launcher values (4g mem, 2 cpus, 512 pids, 2g scratch tmpfs, 4g project tmpfs); the env can only
# *tune* them, never widen past the hard ceiling (clamped DOWN — same fail-closed pattern as the
# limits above; CWE-400 DoS bound preserved, now operator-tunable).
DEFAULT_WORKER_MEM_MIB = 4096
DEFAULT_WORKER_CPUS = 2
DEFAULT_WORKER_PIDS = 512
DEFAULT_WORKER_TMPFS_SCRATCH_MIB = 2048
DEFAULT_WORKER_TMPFS_PROJECT_MIB = 4096

# Per-field hard ceilings — the env may tune a worker bound below or above its default but never
# above the ceiling (clamped DOWN to the ceiling — fail closed on widening the DoS surface).
HARD_MAX_WORKER_MEM_MIB = 32768  # 32 GiB
HARD_MAX_WORKER_CPUS = 16
HARD_MAX_WORKER_PIDS = 4096
HARD_MAX_WORKER_TMPFS_SCRATCH_MIB = 16384  # 16 GiB
HARD_MAX_WORKER_TMPFS_PROJECT_MIB = 32768  # 32 GiB

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
    "max_sessions_per_owner": HARD_MAX_SESSIONS,
}

# Per-field hard ceiling for worker-resource overrides (ADR-023 / F1). Same clamp-down semantics as
# ``_HARD_CEILINGS``: an override is the MIN of the requested value and its ceiling — the env may
# tune a bound (below OR above its default) but never past the safe ceiling (fail closed).
_WORKER_HARD_CEILINGS: dict[str, int] = {
    "mem_mib": HARD_MAX_WORKER_MEM_MIB,
    "cpus": HARD_MAX_WORKER_CPUS,
    "pids": HARD_MAX_WORKER_PIDS,
    "tmpfs_scratch_mib": HARD_MAX_WORKER_TMPFS_SCRATCH_MIB,
    "tmpfs_project_mib": HARD_MAX_WORKER_TMPFS_PROJECT_MIB,
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
        max_sessions_per_owner: Optional per-principal session cap (multi-principal
            noisy-neighbor fairness — ADR-017); ``None`` = off (the global ``max_sessions``
            still bounds total exhaustion). Set below ``max_sessions`` for multi-principal.
    """

    max_binary_bytes: int = DEFAULT_MAX_BINARY_BYTES
    analysis_timeout_s: int = DEFAULT_ANALYSIS_TIMEOUT_S
    tool_timeout_s: int = DEFAULT_TOOL_TIMEOUT_S
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    max_sessions: int = DEFAULT_MAX_SESSIONS
    max_sessions_per_owner: int | None = None


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


@dataclass(frozen=True, slots=True)
class WorkerResources:
    """Resolved, validated worker-container resource bounds (ADR-023 / F1 — DoS caps, CWE-400).

    All values are plain integers in their natural unit (whole MiB / whole CPUs / pid count); the
    launcher renders them to the container engine's spelling at argv build (``f"{mib}m"`` /
    ``str(cpus)``). Defaults mirror the previously-hardcoded launcher values and are clamped to the
    hard ceilings, so a misconfigured/attacker-influenced env can tune the bound but never widen it
    past the safe ceiling (fail closed).

    Attributes:
        mem_mib: Container memory cap, MiB (``--memory``; ``--memory-swap`` is pinned EQUAL → no
            swap, ADR-004).
        cpus: Whole-CPU quota (``--cpus``).
        pids: Process/thread cap (``--pids-limit``) — bounds fork bombs.
        tmpfs_scratch_mib: Size of the scratch tmpfs (``/tmp/ghidra``), MiB.
        tmpfs_project_mib: Size of the per-session project-store tmpfs (``/work/project``), MiB.
    """

    mem_mib: int = DEFAULT_WORKER_MEM_MIB
    cpus: int = DEFAULT_WORKER_CPUS
    pids: int = DEFAULT_WORKER_PIDS
    tmpfs_scratch_mib: int = DEFAULT_WORKER_TMPFS_SCRATCH_MIB
    tmpfs_project_mib: int = DEFAULT_WORKER_TMPFS_PROJECT_MIB


def resolve_worker_resources(overrides: dict[str, int] | None = None) -> WorkerResources:
    """Resolve worker resource bounds from defaults + overrides, clamped to ceilings (fail closed).

    Mirrors :func:`resolve_limits`: each known override is validated as a positive ``int`` and then
    clamped to ``[1, ceiling]`` (:data:`_WORKER_HARD_CEILINGS`). A value below the default is
    honored verbatim (an operator may run a smaller worker); a value above the ceiling is clamped
    DOWN to the ceiling (never widen the DoS surface past the safe bound). Unknown keys and
    non-positive / non-``int`` (incl. ``bool``) values fail closed with a ``VALIDATION`` error.

    Args:
        overrides: Optional mapping of resource name → value (typically from validated config).

    Returns:
        A validated, clamped :class:`WorkerResources`.

    Raises:
        GhidraMcpError: ``VALIDATION`` if an override key is unknown or its value is not a positive
            integer.
    """
    if not overrides:
        return WorkerResources()

    known = {f.name for f in fields(WorkerResources)}
    resolved: dict[str, int] = {}
    for key, value in overrides.items():
        if key not in known:
            raise _validation_error(f"unknown worker resource '{key}'")
        # Reject bool explicitly (``bool`` is an ``int`` subclass) and any non-positive value.
        if isinstance(value, bool) or not isinstance(value, int):
            raise _validation_error(f"worker resource '{key}' must be a positive integer")
        if value < 1:
            raise _validation_error(f"worker resource '{key}' must be >= 1")
        # Clamp DOWNWARD only: never allow a value above the hard ceiling (fail closed on widening).
        resolved[key] = min(value, _WORKER_HARD_CEILINGS[key])

    return WorkerResources(**resolved)


def plausible_max_bytes(mem_mib: int, ratio: float = 2.0) -> int:
    """Plausible upper bound (bytes) on an input size for a worker with ``mem_mib`` of memory.

    Pure threshold for the warn-only pre-flight (ADR-023 D3): an input larger than ``ratio`` times
    worker memory is very likely to OOM-kill the worker, so the server emits a heads-up log (size +
    configured memory only — never content) and still proceeds. This is advisory, NOT a reject
    gate; the hard binary-size cap (:func:`check_binary_size`) and the worker's own memory cgroup
    remain the enforcing controls.

    Args:
        mem_mib: Configured worker memory in MiB.
        ratio: Multiplier of worker memory above which an input is flagged oversized (default 2.0).

    Returns:
        The threshold in bytes (``mem_mib`` MiB times ``ratio``), as a non-negative integer.
    """
    return int(mem_mib * 1024 * 1024 * ratio)


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
