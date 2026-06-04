"""Tier-1 tool registry — the explicit allow-list of exposed tools (stub, WS1).

There is no dynamic tool discovery: the catalog is a fixed, reviewed allow-list (PLAN §2). This
module maps each tool name to its handler and its (input, output) schema pair from
:mod:`ghidra_mcp.tools.schemas`, for registration with the FastMCP server in
:mod:`ghidra_mcp.server`.

Each handler (WS1) MUST: validate input via the schema + ``core.validation``, authorize the
session via the session manager (BOLA defense), call the Ghidra adapter under the tool timeout,
wrap binary-derived output in the untrusted-data envelope, and translate failures to the error
envelope. No handler runs Ghidra in-process (ADR-001).
"""

from __future__ import annotations

# The canonical, frozen list of Tier-1 tool names (matches docs/contracts/tool-catalog.md).
# Kept as data so the catalog can be asserted in tests and registered uniformly.
TIER1_TOOL_NAMES: tuple[str, ...] = (
    # session lifecycle
    "session_create",
    "session_import",
    "session_analyze",
    "session_status",
    "session_close",
    # code
    "decompile_function",
    "disassemble",
    "list_functions",
    "get_function",
    # xrefs
    "xrefs_to",
    "xrefs_from",
    # strings / symbols / data / types
    "list_strings",
    "list_symbols",
    "get_symbol",
    "list_data",
    "get_data_type",
    # comments (read-only)
    "get_comments",
    # memory / bytes / search
    "memory_map",
    "read_bytes",
    "search_bytes",
    "search_strings",
    # metadata
    "program_metadata",
)


def register_tools() -> None:
    """Register the Tier-1 tool catalog with the MCP server.

    Note:
        STUB (WS1). Will bind each name in ``TIER1_TOOL_NAMES`` to its handler + schemas and
        register with the FastMCP instance. Registration MUST be exhaustive and match the frozen
        catalog exactly (a test asserts parity).
    """
    raise NotImplementedError("WS1: register the Tier-1 tool catalog with FastMCP")
