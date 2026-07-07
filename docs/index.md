# Vivarium

**Vivarium is a secure [MCP](https://modelcontextprotocol.io) server that lets an AI assistant use
[Ghidra](https://ghidra-sre.org/) to analyze a program binary** — exposing Ghidra's
reverse-engineering features (decompiling, disassembly, cross-references, strings, type recovery, and
consent-gated edits) as MCP tools a client like Claude can call.

The point is safety. The binary you analyze is treated as hostile input: Ghidra never runs in the
server process, each analysis runs inside a locked-down, throwaway, network-isolated container, and
every byte that comes back from the binary is wrapped and marked as untrusted before it reaches the
model. The name fits — a *vivarium* is a sealed enclosure where you can safely keep and observe a live
specimen; here the specimen is an untrusted binary.

!!! note "This site is the reading view"
    These pages are rendered from the Markdown in the repository's `docs/` directory. Some links point
    to source files or root files (e.g. `README.md`, `src/…`) that live outside the docs tree — those
    resolve on [GitHub](https://github.com/0xb007ab1e/vivarium-mcp), which is the source-linked view.

## Start here

- **[Getting started](getting-started.md)** — install, configure, run, and your first analysis, plus a
  **Reverse-engineering workflows** section (fast triage, deep analysis, bulk streaming, persistence).
- **[FAQ](faq.md)** — quick answers: is it safe on malware, read-vs-write, persistence, accuracy, limits.
- **[Examples](examples/README.md)** — hands-on, copy-pasteable walkthroughs with the actual tool calls:
  [first look](examples/simple-first-look.md),
  [triage an unknown ELF](examples/medium-triage.md),
  [recover & document a cluster](examples/large-annotate-and-recover.md), and a
  [blind analysis of a stripped SQLite binary](examples/blind-analysis-sqlite.md).

## Understand the design

- **[Architecture](architecture.md)** — how the server, worker, and contracts fit together.
- **[Contracts](contracts/README.md)** — the frozen tool catalog, RPC protocol, and data envelopes.
- **[Security → threat model](security/threat-model.md)** — the STRIDE analysis and trust boundaries.
- **[Decision records (ADRs)](adr/README.md)** — the numbered design decisions, indexed by theme.

## Operate it

- **[Observability](observability.md)** — metrics, health probes, and SLOs for HTTP deployments.
- **[Runbooks](runbooks/README.md)** — deploy, rollback, HTTP exposure, incident response, and more.

## Safety model in one breath

- **The binary is untrusted** — everything Ghidra reports is wrapped as untrusted data; never execute,
  evaluate, or render it as code.
- **The analyzer is contained** — the worker runs non-root, read-only root filesystem, no network,
  dropped capabilities, seccomp, resource caps, and (in production) gVisor.
- **Workers are disposable** — one per session, killed and verify-wiped on eviction or timeout.
- **Writes are gated** — nothing changes the analysis until the session owner turns writes on.
- **The supply chain is pinned** — Ghidra, the JDK, and base images are pinned by digest; release
  images are scanned, signed, and published with an SBOM and build provenance.
