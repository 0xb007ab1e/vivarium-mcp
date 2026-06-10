"""Process entry point for the ghidra-mcp server (stdio transport, v1).

This module is the **imperative shell**'s outermost edge and the **composition root**: it parses no
binary and loads no JVM (ADR-001). It loads + validates configuration (fail closed), configures
redacting structured logging, constructs the Ghidra adapter and the session manager, builds the
FastMCP server with the allow-listed Tier-1 catalog, and serves over **stdio** (the only transport
in v1; HTTP is a gated v1.1 increment — ADR-006), draining all sessions on shutdown.

Collaborator construction is injected via factory callables so the wiring is unit-testable with
fakes (dependency inversion — topic-dependency-injection) and so this module does not hard-depend
on the concrete WS2 constructor signatures while they settle.
"""

from __future__ import annotations

from collections.abc import Callable

from ghidra_mcp.config import Config, load_config
from ghidra_mcp.core.errors import GhidraMcpError
from ghidra_mcp.ghidra.port import GhidraPort
from ghidra_mcp.logging import configure_logging, get_logger
from ghidra_mcp.server.app import build_app, run_stdio
from ghidra_mcp.sessions.manager import SessionManager

_log = get_logger(__name__)

# Factory aliases. The defaults reference the WS2 concrete types lazily (imported inside the
# factory) so this module imports cleanly even while those are stubs, and so tests can pass fakes.
PortFactory = Callable[[Config], GhidraPort]
SessionManagerFactory = Callable[[Config, GhidraPort], SessionManager]


def _default_port_factory(config: Config) -> GhidraPort:
    """Construct the concrete RPC Ghidra adapter (WS2) from validated config.

    Imported lazily so a stub adapter does not break module import; the JVM/PyGhidra never load
    here (ADR-001 — the adapter manages the out-of-process worker).

    Args:
        config: Validated server configuration.

    Returns:
        A :class:`ghidra_mcp.ghidra.port.GhidraPort` implementation.
    """
    from ghidra_mcp.ghidra.launcher import ContainerWorkerLauncher, make_confined_resolver
    from ghidra_mcp.ghidra.rpc_client import RpcGhidraAdapter

    launcher = ContainerWorkerLauncher(
        worker_image=config.worker_image,
        import_root=config.import_root,
        runtime=config.worker_runtime,
        analysis_timeout_s=config.limits.analysis_timeout_s,
    )
    return RpcGhidraAdapter(
        launcher=launcher,
        socket_dir=config.rpc_socket_dir,
        tool_timeout_s=config.limits.tool_timeout_s,
        analysis_timeout_s=config.limits.analysis_timeout_s,
        max_response_bytes=config.limits.max_response_bytes,
        limits=config.limits,
        source_resolver=make_confined_resolver(config.import_root),
    )


def _default_session_manager_factory(config: Config, port: GhidraPort) -> SessionManager:
    """Construct the session manager (WS2), giving it the port + config it needs.

    Args:
        config: Validated server configuration (limits, TTL/idle policy).
        port: The Ghidra adapter the manager uses to spawn/kill workers.

    Returns:
        A constructed :class:`ghidra_mcp.sessions.manager.SessionManager`.
    """
    # SessionManager is constructible with safe defaults today; WS2 finalizes the wiring that
    # injects ``port``/``config`` here at the composition root.
    return SessionManager()


def main(
    *,
    port_factory: PortFactory = _default_port_factory,
    session_manager_factory: SessionManagerFactory = _default_session_manager_factory,
) -> int:
    """Run the ghidra-mcp stdio server.

    Flow: load + validate config (fail closed on bad config), configure redacting structured
    logging, construct the Ghidra adapter and session manager, build the FastMCP server with the
    allow-listed Tier-1 catalog, and run it over stdio with graceful shutdown (drain + kill workers
    + verified store wipe).

    Args:
        port_factory: Builds the Ghidra adapter from config (injected for testing).
        session_manager_factory: Builds the session manager from config + port (injected).

    Returns:
        Process exit code (``0`` on clean shutdown, non-zero on fatal startup/config error).
    """
    # 1. Config first — refuse to boot on bad config (fail fast). Logging is not yet configured,
    #    so use a minimal stderr message via the default logger; the envelope detail is safe.
    try:
        config = load_config()
    except GhidraMcpError as exc:
        # Safe, redacted detail only (no internals). Goes to the default (unconfigured) stderr.
        _log.error("startup.config_invalid", extra={"error_type": exc.envelope.type.value})
        return 2

    # 2. Logging with redaction, per validated config.
    try:
        configure_logging(level=config.log_level, fmt=config.log_format)
    except ValueError:
        _log.error("startup.logging_invalid")
        return 2

    # 3. Construct collaborators (composition root) and serve.
    try:
        port = port_factory(config)
        session_manager = session_manager_factory(config, port)
        app = build_app(config, session_manager=session_manager, port=port)
    except GhidraMcpError as exc:
        _log.error("startup.failed", extra={"error_type": exc.envelope.type.value})
        return 2

    _log.info("startup.serving")
    return run_stdio(app, session_manager=session_manager)


if __name__ == "__main__":
    raise SystemExit(main())
