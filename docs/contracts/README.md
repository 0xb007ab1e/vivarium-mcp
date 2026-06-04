# Frozen Contracts (WS0)

These documents are the **frozen contracts** the build workstreams (WS1–WS5) implement against.
Per PLAN §5 / red-team F6, WS0 must freeze these **before** WS1/WS2 fork:

1. [`rpc-protocol.md`](rpc-protocol.md) — server ↔ worker RPC: process boundary, transport,
   framing, timeout/kill semantics, error model. (TB2)
2. [`tool-catalog.md`](tool-catalog.md) — the full Tier-1 read-only tool catalog with each tool's
   input + output schema and bounded args. Pydantic source of truth: `src/ghidra_mcp/tools/schemas.py`.
3. [`untrusted-envelope.md`](untrusted-envelope.md) — the untrusted-data envelope (ADR-005) and the
   client rendering contract. Pydantic source: `src/ghidra_mcp/core/envelope.py`.
4. [`error-envelope.md`](error-envelope.md) — the RFC 9457-style error envelope. Pydantic source:
   `src/ghidra_mcp/core/errors.py`.

> **Change control:** contract changes route through the PM (batch-atomicity mandate) — they are
> NOT edited ad hoc by a feature workstream, because multiple workstreams depend on them. A change
> updates the doc **and** the pydantic source in the same reviewed batch.
