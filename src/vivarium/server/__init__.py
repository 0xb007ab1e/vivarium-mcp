"""MCP server shell (imperative shell): FastMCP wiring over stdio (v1).

The server constructs the FastMCP app, registers the allow-listed Tier-1 tool catalog
(:mod:`vivarium.tools.registry`), and serves over **stdio** — the only transport in v1 (HTTP is
a gated v1.1 increment, ADR-006). It is deliberately thin: every tool handler delegates validation
to ``core``, authorization to the session manager, analysis to the Ghidra adapter, and translates
results/failures to the frozen envelopes. No JVM, no binary parsing here (ADR-001).
"""
