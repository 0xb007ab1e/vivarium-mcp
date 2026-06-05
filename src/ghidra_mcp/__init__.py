"""ghidra-mcp: a secure MCP server exposing headless, out-of-process Ghidra as read-only tools.

This package is organized with **ports & adapters** (functional core / imperative shell,
``topic-architecture-patterns``):

- ``core``     — pure, I/O-free domain logic: tool-arg validation and the untrusted-data /
                 error envelopes. The trust-boundary heart; 100% test coverage target.
- ``sessions`` — persistent per-binary session lifecycle (TTL + idle eviction, one worker per
                 session, verified store wipe). Prevents cross-session leakage / BOLA.
- ``security`` — DoS bounds (size/time/count caps) enforced *before* the worker, and
                 injection-defense helpers. Home of WS4 hardening.
- ``server``   — the imperative shell: MCP (FastMCP) wiring over **stdio** in v1; registers tools.
- ``tools``    — the Tier-1 read-only tool implementations (allow-listed catalog).
- ``ghidra``   — the **adapter** to the out-of-process Ghidra worker via internal RPC. The MCP
                 server process NEVER loads the JVM or parses a binary (ADR-001).

WS0 freezes the contracts (``docs/contracts/``) and ships interface stubs only; WS1-WS5 implement
the logic against those frozen contracts.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
