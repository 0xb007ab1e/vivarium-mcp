# ghidra-mcp

A **secure [MCP](https://modelcontextprotocol.io) server** that exposes [Ghidra](https://ghidra-sre.org/)
reverse-engineering capabilities to LLM clients as **tools**. Ghidra runs **isolated, headless, and
out-of-process**, reachable only through the server's internal RPC. **The analyzed binary is treated
as hostile input** — containment of the analyzer is the central security control.

> **Latest release: [v0.7.1](https://github.com/0xb007ab1e/ghidra-mcp/releases/tag/v0.7.1)** (2026-06-18) —
> the **v1.5** increment (v0.7.1 is the signed release; v0.7.0's image build fail-closed on a base
> CVE, now remediated — see the CHANGELOG): a correctness / supply-chain hardening pass — an analyzer-option
> **existence guard** (fail closed on a version-renamed preset option), a dedicated **`forbidden` /
> 403** authorization-denied error type, an on-demand **naming-accuracy scorer** (advisory eval
> tooling), and **hardened, hash-pinned CI** (dev + scanner tool surfaces, run-from-`src/`). Builds
> on the gated default-deny write surface, the HTTP transport, analyzer-depth profiles, and
> multi-principal / OAuth authorization. See the [CHANGELOG](./CHANGELOG.md) for what's new, and
> [`PLAN.md`](./PLAN.md) for the delivery plan, locked decisions, architecture, trust boundaries,
> and ADRs.

## At a glance (v0.7.0)
- **Tool scope:** 51 tools — Tier-1 read-only core (decompile, disassemble, functions, xrefs, strings,
  symbols, data types, comments, memory map, bounded read/search, program metadata) + Tier-2
  reporting/metrics + semantic-naming + a **gated, default-deny write tier** (annotation + structural
  rename / signature / type-apply / composite-create / type-delete / `define_types` batch
  round-trip).
- **Analysis:** configurable worker resources + selectable **analyzer-depth profiles**
  (`default` / `light` / `deep`, fail-closed on an unknown/renamed preset option) and a
  size-vs-memory pre-flight (`warn` / `reject` / `off`) for large binaries; optional **streamed
  `analyze` progress** to the client (token-gated, percent + phase only).
- **Transport:** stdio (default) or **HTTP** (MCP Streamable; secure-by-default exposure, bearer auth,
  **OAuth scope → per-tool read/write authZ** with a dedicated **`forbidden` / 403** denial, opt-in
  **reverse-proxy mTLS**, multi-principal per-session ownership).
- **Sessions:** persistent per-binary, TTL + idle eviction (in-flight-safe); one isolated worker per
  session; **writes require explicit per-session consent**.
- **Runtime:** container-only; Ghidra 12.1.2 + JDK 21 pinned by digest; rootless podman/OCI isolation
  (gVisor/runsc in production). Signed, SBOM'd, provenance-attested release images.
- **Eval (advisory):** on-demand naming-accuracy scorer (`scripts/naming_eval.py`) over debuginfod /
  ELF / JSON ground truth — reads only DWARF metadata, never executes or Ghidra-parses the binary.

## Documentation
- [`PLAN.md`](./PLAN.md) — delivery plan & decisions
- [`CHANGELOG.md`](./CHANGELOG.md) — release history (Keep a Changelog)
- `docs/` — architecture, ADRs (001–036), threat model, contracts, runbooks
- `SECURITY.md` — vulnerability reporting

## License
[Apache License 2.0](./LICENSE) — aligned with Ghidra's own license. See [`NOTICE`](./NOTICE).
