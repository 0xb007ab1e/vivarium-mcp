# ghidra-mcp

A **secure [MCP](https://modelcontextprotocol.io) server** that exposes [Ghidra](https://ghidra-sre.org/)
reverse-engineering capabilities to LLM clients as **tools**. Ghidra runs **isolated, headless, and
out-of-process**, reachable only through the server's internal RPC. **The analyzed binary is treated
as hostile input** — containment of the analyzer is the central security control.

> **Latest release: [v0.2.1](https://github.com/0xb007ab1e/ghidra-mcp/releases/tag/v0.2.1)** (2026-06-13) —
> the first **write surface** (gated, default-deny annotation + structural mutation tools), the **HTTP
> transport**, a behavioral-equivalence naming eval, and **multi-principal authorization**. See the
> [CHANGELOG](./CHANGELOG.md) for what's new, and [`PLAN.md`](./PLAN.md) for the delivery plan, locked
> decisions, architecture, trust boundaries, and ADRs.

## At a glance (v0.2.1)
- **Tool scope:** 47 tools — Tier-1 read-only core (decompile, disassemble, functions, xrefs, strings,
  symbols, data types, comments, memory map, bounded read/search, program metadata) + Tier-2
  reporting/metrics + semantic-naming + a **gated, default-deny write tier** (annotation + structural
  rename / signature / type-apply / composite-create).
- **Transport:** stdio (default) or **HTTP** (MCP Streamable; secure-by-default exposure, bearer auth
  with mTLS/OAuth-pluggable, multi-principal per-session ownership).
- **Sessions:** persistent per-binary, TTL + idle eviction; one isolated worker per session; **writes
  require explicit per-session consent**.
- **Runtime:** container-only; Ghidra 12.1.2 + JDK 21 pinned by digest; rootless podman/OCI isolation.

## Documentation
- [`PLAN.md`](./PLAN.md) — delivery plan & decisions
- [`CHANGELOG.md`](./CHANGELOG.md) — release history (Keep a Changelog)
- `docs/` — architecture, ADRs (001–017), threat model, contracts, runbooks
- `SECURITY.md` — vulnerability reporting

## License
[Apache License 2.0](./LICENSE) — aligned with Ghidra's own license. See [`NOTICE`](./NOTICE).
