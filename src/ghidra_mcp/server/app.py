"""FastMCP application factory and stdio runner (stub, WS1).

Builds the MCP server from validated config + injected collaborators (session manager, Ghidra
adapter) at the composition root, registers the Tier-1 tools, and runs the stdio transport with
graceful shutdown.
"""

from __future__ import annotations

from typing import Any


def build_app(config: Any, *, session_manager: Any) -> Any:  # noqa: ANN401 (stub; typed in WS1)
    """Construct and return the configured FastMCP application.

    Args:
        config: Validated :class:`ghidra_mcp.config.Config`.
        session_manager: The constructed session manager (dependency-injected).

    Returns:
        A FastMCP application instance ready to serve.

    Note:
        STUB (WS1). Concrete types replace ``Any`` once the ``mcp`` SDK surface is wired.
    """
    raise NotImplementedError("WS1: build FastMCP app + register Tier-1 tools")


def run_stdio(app: Any) -> int:  # noqa: ANN401 (stub; typed in WS1)
    """Run the MCP server on the stdio transport until shutdown.

    Args:
        app: The FastMCP application from :func:`build_app`.

    Returns:
        Process exit code.

    Note:
        STUB (WS1). Must handle SIGTERM/SIGINT → drain → evict all sessions (kill workers + wipe).
    """
    raise NotImplementedError("WS1: run FastMCP over stdio with graceful shutdown")
