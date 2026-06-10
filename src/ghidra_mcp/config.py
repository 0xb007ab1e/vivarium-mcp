"""Startup configuration — 12-Factor, validated, fail-closed (WS1).

Config is read from the environment (see ``.env.example``) and validated at startup; the process
refuses to boot on missing/invalid required values (topic-config-environments — fail fast). There
are NO secrets in v1 config. Parsed into a typed, immutable object so the rest of the code depends
on validated values, not raw ``os.environ`` lookups (dependency inversion).

Resource limits are resolved (and clamped) through :func:`ghidra_mcp.security.limits.resolve_limits`
so a misconfigured environment can only make a bound *stricter* within hard ceilings, never wider
(fail closed — security/limits.py owns the clamps).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from ghidra_mcp.security.limits import Limits, resolve_limits

# Environment variable names (12-Factor; documented in .env.example). Centralized so the read set
# is a single, auditable allow-list.
_ENV_LOG_LEVEL = "GHIDRA_MCP_LOG_LEVEL"
_ENV_LOG_FORMAT = "GHIDRA_MCP_LOG_FORMAT"
_ENV_SESSION_TTL = "GHIDRA_MCP_SESSION_TTL_SECONDS"
_ENV_SESSION_IDLE = "GHIDRA_MCP_SESSION_IDLE_SECONDS"
_ENV_MAX_SESSIONS = "GHIDRA_MCP_MAX_SESSIONS"
_ENV_MAX_BINARY_BYTES = "GHIDRA_MCP_MAX_BINARY_BYTES"
_ENV_ANALYSIS_TIMEOUT = "GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS"
_ENV_TOOL_TIMEOUT = "GHIDRA_MCP_TOOL_TIMEOUT_SECONDS"
_ENV_MAX_RESPONSE_BYTES = "GHIDRA_MCP_MAX_RESPONSE_BYTES"
_ENV_WORKER_IMAGE = "GHIDRA_MCP_WORKER_IMAGE"
_ENV_WORKER_RUNTIME = "GHIDRA_MCP_WORKER_RUNTIME"
_ENV_RPC_SOCKET_DIR = "GHIDRA_MCP_RPC_SOCKET_DIR"
_ENV_IMPORT_ROOT = "GHIDRA_MCP_IMPORT_ROOT"

# Secure defaults for non-limit operational knobs (12-Factor: safe-by-default).
_DEFAULT_LOG_LEVEL = "INFO"
_DEFAULT_LOG_FORMAT = "json"
_DEFAULT_SESSION_TTL_S = 3600
_DEFAULT_SESSION_IDLE_S = 900
_DEFAULT_WORKER_RUNTIME = "runsc"
_DEFAULT_RPC_SOCKET_DIR = "/run/ghidra-mcp"
_DEFAULT_IMPORT_ROOT = "/work/imports"

# Allow-lists for enum-like values.
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR"})
_VALID_LOG_FORMATS = frozenset({"json", "text"})

# Cap on string-valued config to bound startup input (worker image refs, socket dirs).
_MAX_CONFIG_STR_LEN = 512


@dataclass(frozen=True, slots=True)
class Config:
    """Validated server configuration.

    Attributes:
        log_level: Logging verbosity (``DEBUG``..``ERROR``). DEBUG never emits binary content.
        log_format: ``"json"`` or ``"text"``.
        session_ttl_s: Absolute session lifetime before eviction.
        session_idle_s: Idle timeout before eviction.
        limits: Resolved resource limits (see :class:`ghidra_mcp.security.limits.Limits`).
        worker_image: Pinned-by-digest worker image reference (ADR-003).
        worker_runtime: Container runtime for the worker (e.g. ``runsc`` for gVisor — ADR-004).
        rpc_socket_dir: Directory for per-session RPC sockets.
        import_root: Host dir (read-only mount) under which importable inputs live; the confined
            ``source_ref`` resolver rejects refs outside it (CWE-22) — ADR-009.
    """

    log_level: str
    log_format: str
    session_ttl_s: int
    session_idle_s: int
    limits: Limits
    worker_image: str
    worker_runtime: str
    rpc_socket_dir: str
    import_root: str


def _startup_error(detail: str) -> GhidraMcpError:
    """Build a fail-closed ``VALIDATION`` error for a bad/missing config value.

    Args:
        detail: A safe, value-free description of the misconfiguration (no secrets/paths echoed).

    Returns:
        A :class:`GhidraMcpError` whose envelope is safe to surface in startup logs.
    """
    return GhidraMcpError(
        ErrorEnvelope(
            type=ErrorType.VALIDATION,
            title="Invalid configuration",
            detail=detail,
            status=500,
            retryable=False,
        )
    )


def _read_int(env: dict[str, str], name: str) -> int | None:
    """Read and parse a non-negative integer env var, or ``None`` if unset/empty.

    Args:
        env: The environment mapping to read from.
        name: The variable name.

    Returns:
        The parsed integer, or ``None`` when the variable is absent or empty.

    Raises:
        GhidraMcpError: ``VALIDATION`` if the value is present but not a valid integer.
    """
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return None
    text = raw.strip()
    # Allow-list digits only (reject signs, underscores, hex, floats — fail closed).
    if not text.isdigit():
        raise _startup_error(f"environment variable {name} must be a non-negative integer")
    return int(text)


def _read_positive_int(env: dict[str, str], name: str, default: int) -> int:
    """Read a strictly positive integer env var, falling back to ``default`` when unset.

    Args:
        env: The environment mapping.
        name: The variable name.
        default: Value used when the variable is absent/empty.

    Returns:
        A strictly positive integer.

    Raises:
        GhidraMcpError: ``VALIDATION`` if present but non-integer or not strictly positive.
    """
    value = _read_int(env, name)
    if value is None:
        return default
    if value < 1:
        raise _startup_error(f"environment variable {name} must be a positive integer")
    return value


def _read_choice(env: dict[str, str], name: str, default: str, allowed: frozenset[str]) -> str:
    """Read an enum-like string env var validated against an allow-list.

    Args:
        env: The environment mapping.
        name: The variable name.
        default: Value used when the variable is absent/empty.
        allowed: The permitted set of values.

    Returns:
        The validated choice.

    Raises:
        GhidraMcpError: ``VALIDATION`` if the value is not in ``allowed``.
    """
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip()
    if value not in allowed:
        raise _startup_error(f"environment variable {name} has an unsupported value")
    return value


def _read_str(env: dict[str, str], name: str, default: str, *, required: bool) -> str:
    """Read a bounded, non-empty string env var.

    Args:
        env: The environment mapping.
        name: The variable name.
        default: Value used when absent/empty and not required.
        required: When ``True``, an absent/empty value is a fatal misconfiguration.

    Returns:
        The validated string.

    Raises:
        GhidraMcpError: ``VALIDATION`` if required-but-missing, too long, or containing control
            characters.
    """
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        if required:
            raise _startup_error(f"environment variable {name} is required")
        return default
    value = raw.strip()
    if len(value) > _MAX_CONFIG_STR_LEN:
        raise _startup_error(f"environment variable {name} is too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise _startup_error(f"environment variable {name} contains control characters")
    return value


def load_config(env: dict[str, str] | None = None) -> Config:
    """Load and validate configuration from the environment; fail closed on error.

    Args:
        env: Optional environment mapping to read from (defaults to :data:`os.environ`). Injected
            for testability (dependency inversion — topic-dependency-injection) so config loading
            stays deterministic and hermetic.

    Returns:
        A validated :class:`Config` with limits resolved and clamped.

    Raises:
        GhidraMcpError: ``VALIDATION`` on any missing required value or invalid/out-of-range value;
            the process must refuse to boot (fail fast).
    """
    src = dict(os.environ) if env is None else env

    log_level = _read_choice(src, _ENV_LOG_LEVEL, _DEFAULT_LOG_LEVEL, _VALID_LOG_LEVELS)
    log_format = _read_choice(src, _ENV_LOG_FORMAT, _DEFAULT_LOG_FORMAT, _VALID_LOG_FORMATS)

    session_ttl_s = _read_positive_int(src, _ENV_SESSION_TTL, _DEFAULT_SESSION_TTL_S)
    session_idle_s = _read_positive_int(src, _ENV_SESSION_IDLE, _DEFAULT_SESSION_IDLE_S)
    if session_idle_s > session_ttl_s:
        raise _startup_error("session idle timeout must not exceed the session TTL")

    # Validate all required/string fields BEFORE resolving limits, so a missing/invalid required
    # value fails fast on its own merits (and config validation is fully exercisable independent of
    # the limits layer).
    worker_image = _read_str(src, _ENV_WORKER_IMAGE, "", required=True)
    worker_runtime = _read_str(src, _ENV_WORKER_RUNTIME, _DEFAULT_WORKER_RUNTIME, required=False)
    rpc_socket_dir = _read_str(src, _ENV_RPC_SOCKET_DIR, _DEFAULT_RPC_SOCKET_DIR, required=False)
    import_root = _read_str(src, _ENV_IMPORT_ROOT, _DEFAULT_IMPORT_ROOT, required=False)

    # Limit overrides: only include keys that were explicitly set (let resolve_limits apply its own
    # defaults + hard clamps for the rest). resolve_limits is fail-closed (WS4).
    overrides: dict[str, int] = {}
    for env_name, limit_key in (
        (_ENV_MAX_SESSIONS, "max_sessions"),
        (_ENV_MAX_BINARY_BYTES, "max_binary_bytes"),
        (_ENV_ANALYSIS_TIMEOUT, "analysis_timeout_s"),
        (_ENV_TOOL_TIMEOUT, "tool_timeout_s"),
        (_ENV_MAX_RESPONSE_BYTES, "max_response_bytes"),
    ):
        value = _read_int(src, env_name)
        if value is not None:
            overrides[limit_key] = value
    limits = resolve_limits(overrides or None)

    return Config(
        log_level=log_level,
        log_format=log_format,
        session_ttl_s=session_ttl_s,
        session_idle_s=session_idle_s,
        limits=limits,
        worker_image=worker_image,
        worker_runtime=worker_runtime,
        rpc_socket_dir=rpc_socket_dir,
        import_root=import_root,
    )
