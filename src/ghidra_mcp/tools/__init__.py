"""Tier-1 read-only tool layer: schemas (frozen) and implementations (stubs).

The Tier-1 catalog is an **explicit allow-list** — there is no dynamic/arbitrary tool surface and
no ``runScript`` in v1 (PLAN §2). Each tool has a frozen pydantic input AND output schema in
:mod:`ghidra_mcp.tools.schemas`; implementations (WS1) validate input at the boundary, call the
Ghidra adapter, and return outputs with all binary-derived content wrapped in the untrusted-data
envelope (ADR-005).
"""
