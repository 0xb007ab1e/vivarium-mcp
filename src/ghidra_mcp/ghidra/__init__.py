"""Ghidra adapter: the out-of-process boundary (ADR-001).

This package is the ONLY place that knows about the Ghidra worker. It defines the **port**
(:mod:`ghidra_mcp.ghidra.port`) that the session manager and tools depend on, and an **adapter**
(:mod:`ghidra_mcp.ghidra.rpc_client`) that spawns/kills hardened worker containers and speaks the
internal RPC protocol (``docs/contracts/rpc-protocol.md``).

CRITICAL INVARIANT (ADR-001): nothing importable into the MCP server process loads the JVM or
parses a binary. The JVM bridge (:mod:`ghidra_mcp.ghidra._jvm_bridge`) runs ONLY inside the worker
container; it is not imported by the server and is excluded from server coverage.
"""
