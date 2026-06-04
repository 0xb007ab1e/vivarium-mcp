"""Process entry point for the ghidra-mcp server (stdio transport, v1).

This module is the **imperative shell**'s outermost edge: it parses no binary and loads no JVM
(ADR-001). It wires configuration, logging, the session manager, and the MCP server, then serves
over **stdio** (the only transport in v1; HTTP is a gated v1.1 increment — ADR-006).

WS0 ships a stub; WS1 implements the wiring.
"""

from __future__ import annotations


def main() -> int:
    """Run the ghidra-mcp stdio server.

    Returns:
        Process exit code (``0`` on clean shutdown, non-zero on fatal startup/config error).

    Note:
        STUB (WS1). Intended flow: load + validate config (fail closed on bad config), configure
        structured logging with redaction, construct the session manager and Ghidra adapter,
        build the FastMCP server with the allow-listed Tier-1 tool catalog, and run it on the
        stdio transport with graceful shutdown (drain + kill workers + verified store wipe).
    """
    raise NotImplementedError("WS1: implement stdio server bootstrap")


if __name__ == "__main__":
    raise SystemExit(main())
