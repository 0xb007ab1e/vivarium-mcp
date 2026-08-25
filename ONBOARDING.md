# Onboarding — Vivarium

Welcome. This is the fast path to understanding what Vivarium is, the one mental model that explains
every design choice, and how to get running on day one. Deeper material is linked throughout.

## What Vivarium is

Vivarium is a **secure [MCP](https://modelcontextprotocol.io) server that exposes headless
[Ghidra](https://ghidra-sre.org) to LLM clients as read-only reverse-engineering tools**. An agent
can import a binary, decompile functions, list strings/imports/symbols, trace data flow, diff two
builds, emulate p-code, recover structs, scan for secrets/IOCs — **74 Tier-1 tools** in total (58
read-only, 16 consent-gated writes) — without ever running the target or trusting its output blindly.

The core problem it solves: **running an untrusted binary through a powerful analysis engine, and
feeding the results to an LLM, is dangerous** (the binary is hostile; the LLM is impressionable).
Vivarium is built to make that safe.

## The one mental model (read this before the code)

Four load-bearing invariants explain nearly every decision. They are the ADRs to internalize first:

- **[ADR-001](docs/adr/ADR-001-out-of-process-ghidra.md) — the server never touches Ghidra.** The
  MCP server process does **not** load the JVM or parse a binary. All Ghidra work happens in a
  separate **worker** over an internal RPC. In-process PyGhidra is forbidden.
- **[ADR-002](docs/adr/ADR-002-one-worker-per-session.md) — one disposable worker per session.** The
  worker is a throwaway fault domain: **killed on timeout or eviction**, with a verified wipe of its
  store. Nothing persists.
- **[ADR-004](docs/adr/ADR-004-isolation-tier.md) — the worker is locked down.** Non-root, read-only
  root filesystem, all Linux capabilities dropped, **no network**, seccomp, gVisor/runsc, and hard
  memory/CPU/pid/time limits.
- **[ADR-005](docs/adr/ADR-005-untrusted-data-envelope.md) — binary-derived output is untrusted.**
  Every byte that came from or through Ghidra (decompilation, strings, symbols, names, bytes) is
  wrapped in an **untrusted-data envelope**. Clients must never execute, eval, render as markup, or
  follow URLs/paths found inside it.

If a change would violate one of these, it's the wrong change. The full analysis is in the
[threat model](docs/security/threat-model.md).

## Get running (day one)

Prerequisites: **Python 3.12+** and a container runtime (podman/docker) for the worker.

```bash
git clone https://github.com/0xb007ab1e/vivarium-mcp
cd vivarium-mcp
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# fast, hermetic unit suite (no worker needed)
pytest -m "not integration"
```

The default transport is **stdio** (no network, no auth). Point your MCP client at the `vivarium`
entrypoint. For the network transport and its auth modes, see the
[Configuration reference](docs/configuration.md) and the
[HTTP exposure runbook](docs/runbooks/http-exposure.md).

Full install/run details: **[Getting started](docs/getting-started.md)**.

## Where things live

- **[Getting started](docs/getting-started.md)** — install, run, first analysis.
- **[Configuration reference](docs/configuration.md)** — every `VIVARIUM_*` variable, default, source.
- **[Architecture](docs/architecture.md)** — the server ↔ worker split and data flow.
- **[Tool catalog](docs/contracts/tool-catalog.md)** — the 74 tools, their inputs/outputs, and which
  fields are untrusted. (The [RPC protocol](docs/contracts/rpc-protocol.md) and other frozen
  contracts sit alongside it.)
- **[ADRs](docs/adr/README.md)** — the numbered design decisions (ADR-001 … ADR-072).
- **[Threat model](docs/security/threat-model.md)** — STRIDE over the trust boundaries.
- **[Runbooks](docs/runbooks/README.md)** — deploy, rollback, incident response, evict-poisoned-worker,
  secret rotation, supply-chain pinning, and more.
- **[CI/CD gates](docs/ci-cd.md)** — the merge-blocking checks.
- **[Contributing](CONTRIBUTING.md)** — workflow, gates, ADR process. **[Security policy](SECURITY.md)**.

## What to read next by role

- **Contributor** → [CONTRIBUTING.md](CONTRIBUTING.md), then an ADR or two near your area.
- **Operator** → [Configuration reference](docs/configuration.md) +
  [runbooks](docs/runbooks/README.md), especially [http-exposure](docs/runbooks/http-exposure.md).
- **Security reviewer** → [threat model](docs/security/threat-model.md) + the four invariant ADRs above.

> Version note: `v1.8`/`v1.9` you'll see in docs are internal feature-milestone labels; the package
> version is `0.14.0` (pre-1.0, so tools and contracts may still change). The
> [CHANGELOG](CHANGELOG.md) is the release source of truth.
