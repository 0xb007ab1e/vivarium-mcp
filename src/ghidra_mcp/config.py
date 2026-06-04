"""Startup configuration — 12-Factor, validated, fail-closed (stub, WS1).

Config is read from the environment (see ``.env.example``) and validated at startup; the process
refuses to boot on missing/invalid required values (topic-config-environments — fail fast). There
are NO secrets in v1 config. Parsed into a typed, immutable object so the rest of the code depends
on validated values, not raw ``os.environ`` lookups (dependency inversion).
"""

from __future__ import annotations

from dataclasses import dataclass

from ghidra_mcp.security.limits import Limits


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
    """

    log_level: str
    log_format: str
    session_ttl_s: int
    session_idle_s: int
    limits: Limits
    worker_image: str
    worker_runtime: str
    rpc_socket_dir: str


def load_config() -> Config:
    """Load and validate configuration from the environment; fail closed on error.

    Returns:
        A validated :class:`Config`.

    Raises:
        GhidraMcpError: ``VALIDATION`` (or a startup error) on missing/invalid required values.

    Note:
        STUB (WS1). Must reject unknown/invalid values and clamp limits via
        :func:`ghidra_mcp.security.limits.resolve_limits`.
    """
    raise NotImplementedError("WS1: implement env config loading + validation")
