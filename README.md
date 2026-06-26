# Vivarium

Vivarium is a secure [MCP](https://modelcontextprotocol.io) server that lets an AI assistant use
[Ghidra](https://ghidra-sre.org/) to analyze a program binary. It exposes Ghidra's reverse-engineering
features (decompiling, disassembly, cross-references, strings, and more) as MCP tools that a client
like Claude can call.

The point of Vivarium is safety. The binary you analyze is treated as hostile input. Ghidra never runs
in the same process as the server. Instead, each analysis runs inside a locked-down, throwaway
container with no network access, and every piece of data that comes back from the binary is wrapped
and marked as untrusted before it reaches the model.

The name fits the design: a vivarium is a sealed enclosure where you can safely keep and observe a live
specimen. Here the specimen is an untrusted binary.

> Current release: **v0.12.0** (2026-06-24). This release makes `identify_functions` work on **ELF**:
> the worker now bundles permissive-source Ghidra **FunctionID databases** (zlib, musl libc, OpenSSL 3.x,
> Boost), so the tool labels Linux library code instead of returning ~0 matches (Phase 1 was MSVC-only).
> Additive — no tool/contract change, catalog stays **56**. See the [CHANGELOG](./CHANGELOG.md) for details. Vivarium is pre-1.0, so the tool
> set and internal contracts may still change before 1.0.

## What it can do

- **Read and explore a binary.** Decompile and disassemble functions, list functions, imports, exports,
  strings, symbols, data types, and comments, follow cross-references, read the memory map, and search
  bytes or strings. Every read tool takes size and count limits so a response cannot grow without bound.
- **Summarize and measure.** Report cyclomatic complexity, code and data coverage, a call-graph summary,
  scan for indicators of compromise and common crypto constants, and produce a whole-program summary.
- **Stream results as they're produced.** Start a bulk decompile as a job and pull partial results by
  cursor while extraction continues — so an LLM can begin reasoning over early functions — and cancel the
  run mid-stream when you have enough.
- **Suggest names.** Helper tools support a client-driven workflow for proposing human-readable function
  names from the decompiled code.
- **Make changes, only with consent.** Renaming functions and symbols, setting comments, applying or
  defining data types, and similar edits are off by default. A session must explicitly enable writes
  before any change is allowed, and edits can be exported and re-imported as a portable annotation file.

There are 56 tools in total. The full list, with the inputs and outputs for each, is in
[`docs/contracts/tool-catalog.md`](./docs/contracts/tool-catalog.md).

## How it works

Vivarium has two parts:

1. **The server** is the process your MCP client talks to. It holds no binary-parsing code and never
   loads Ghidra. It validates every request, enforces limits, and manages sessions.
2. **The worker** is a separate, hardened container that actually runs Ghidra. The server starts one
   worker per session and talks to it over a private local socket. When a session ends or times out,
   the server kills the worker and wipes its scratch storage.

You connect a client over **stdio** (the default) or over **HTTP**. HTTP adds bearer, OAuth, or
reverse-proxy mTLS authentication and is meant for running Vivarium as a shared service.

## Install and run

See **[`docs/getting-started.md`](./docs/getting-started.md)** for a step-by-step setup: prerequisites,
building the two container images, installing the package, running the server, connecting a client, and
a first analysis. The short version:

```
git clone https://github.com/0xb007ab1e/vivarium-mcp.git
cd vivarium-mcp
# build the worker and server images (this downloads Ghidra; see getting-started for the pinned values)
# create a Python 3.12+ virtual environment and install the package
# point the server at the worker image and an import directory, then run: python -m vivarium
```

Vivarium runs on Linux and uses rootless [podman](https://podman.io) to launch worker containers.

## Safety model in plain terms

- **The binary is untrusted.** Everything Ghidra reports about it (decompiled code, strings, names,
  bytes) is wrapped as untrusted data. Do not execute it, evaluate it, or render it as code.
- **The analyzer is contained.** The worker runs as a non-root user, with a read-only root filesystem,
  no network, dropped Linux capabilities, a seccomp profile, and memory and CPU limits. In production it
  also runs under gVisor for an extra isolation boundary.
- **Workers are disposable.** One worker per session, killed and wiped on eviction or timeout.
- **Writes are gated.** No tool can change the analysis until the session owner turns writes on.
- **The supply chain is pinned.** Ghidra, the JDK, and the base images are pinned by digest. Release
  images are scanned, signed, and published with a software bill of materials and build provenance.

The full design rationale is in the decision records under [`docs/adr/`](./docs/adr/) and the
[threat model](./docs/security/threat-model.md).

## Documentation

- [`docs/getting-started.md`](./docs/getting-started.md): set up and run Vivarium from scratch.
- [`docs/faq.md`](./docs/faq.md): quick answers — what it is, is it safe on malware, read-only vs.
  write, persistence, accuracy, limits.
- [`docs/architecture.md`](./docs/architecture.md): how the pieces fit together.
- [`docs/contracts/`](./docs/contracts/): the tool catalog, RPC protocol, and data envelopes.
- [`docs/examples/`](./docs/examples/README.md): tiered, hands-on RE workflows showing the actual tool
  calls — [first look](./docs/examples/simple-first-look.md) (simple),
  [triage an unknown ELF](./docs/examples/medium-triage.md) (medium),
  [recover & document a cluster](./docs/examples/large-annotate-and-recover.md) (large) — plus a
  [blind analysis of a stripped SQLite binary](./docs/examples/blind-analysis-sqlite.md) checked against
  the original source.
- [`docs/runbooks/`](./docs/runbooks/): operational procedures (deploy, rollback, incident response, and
  more), including [HTTP exposure](./docs/runbooks/http-exposure.md).
- [`docs/adr/`](./docs/adr/): the numbered design decisions (ADR-001 through ADR-043).
- [`SECURITY.md`](./SECURITY.md): how to report a vulnerability.
- [`CHANGELOG.md`](./CHANGELOG.md): release history.
- [`PLAN.md`](./PLAN.md): the delivery plan and locked decisions.

## License

[Apache License 2.0](./LICENSE), matching Ghidra's own license. See [`NOTICE`](./NOTICE).
