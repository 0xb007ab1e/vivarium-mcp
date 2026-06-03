# ghidra-mcp

A **secure [MCP](https://modelcontextprotocol.io) server** that exposes [Ghidra](https://ghidra-sre.org/)
reverse-engineering capabilities to LLM clients as **tools**. Ghidra runs **isolated, headless, and
out-of-process**, reachable only through the server's internal RPC. **The analyzed binary is treated
as hostile input** — containment of the analyzer is the central security control.

> **Status:** bootstrapping. See [`PLAN.md`](./PLAN.md) for the approved delivery plan, locked
> decisions, architecture, trust boundaries, and workstreams. Architecture, contracts, threat model,
> CI, and the full project skeleton are produced in WS0 (in progress).

## At a glance (v1)
- **Tool scope:** Tier-1 read-only core (decompile, disassemble, functions, xrefs, strings, symbols,
  data types, comments, memory map, bounded read/search, program metadata).
- **Transport:** stdio (HTTP transport + reporting/metrics + mutation tools are planned for v1.1).
- **Sessions:** persistent per-binary, TTL + idle eviction; one isolated worker per session.
- **Runtime:** container-only; Ghidra 11.x + JDK 21 pinned by digest; rootless podman/OCI isolation.

## Documentation
- [`PLAN.md`](./PLAN.md) — delivery plan & decisions
- `docs/` — architecture, ADRs, threat model, runbooks _(populated in WS0)_
- `SECURITY.md` — vulnerability reporting _(populated in WS0)_

## License
[Apache License 2.0](./LICENSE) — aligned with Ghidra's own license. See [`NOTICE`](./NOTICE).
