# vivarium — project rules

> Inherits the master SSDLC ruleset (~/.claude/CLAUDE.md) automatically.
> Single source of truth for delivery is [`PLAN.md`](./PLAN.md) (APPROVED v2). Honor every
> locked decision and ADR (`docs/adr/`). On any conflict, PLAN.md + the ADRs win over defaults.

## Applied rule modules
@~/.claude/rules/lang-python.md
@~/.claude/rules/std-owasp-llm.md          # tools exposed to an LLM; binary-derived output = untrusted (LLM01/02/08)
@~/.claude/rules/std-owasp-proactive.md    # positive secure-coding: validate-all-input, secure DB/IO, fail-closed
@~/.claude/rules/std-cwe.md                # weakness checklist (esp. CWE-20/22/78/190/400/502/918)
@~/.claude/rules/topic-architecture-patterns.md  # ports & adapters: pure core + Ghidra adapter (functional core / imperative shell)
@~/.claude/rules/topic-resource-management.md    # worker/process lifecycle, kill-on-evict, verified store wipe, no leaks
@~/.claude/rules/topic-reliability.md      # timeouts that kill the worker, backpressure, pool caps, graceful shutdown
@~/.claude/rules/topic-container-k8s.md    # worker container hardening (non-root, ro-rootfs, caps dropped, no-net, seccomp)
@~/.claude/rules/topic-logging-observability.md  # structured logs, audit trail, redaction (no binary content / secrets)
@~/.claude/rules/topic-testing.md          # pyramid, abuse/fuzz tests, 100% on critical paths
@~/.claude/rules/std-supplychain.md        # pin Ghidra/JDK + deps by digest, SBOM, signed releases
@~/.claude/rules/workflow-cicd.md          # merge-blocking gates (lint/type/test/SAST/SCA/secret/image scan)
@~/.claude/rules/workflow-threat-model.md  # STRIDE over the 4 trust boundaries (docs/security/threat-model.md)
@~/.claude/rules/workflow-cve-management.md # track CVEs in Ghidra, the JDK, the base image, and Python deps
@~/.claude/rules/workflow-runbooks.md      # operational runbooks incl. evict-poisoned-worker, CVE digest-bump
# --- Activated for the v1.1 HTTP transport increment (network surface; ADR-011 / threat-model TB6) ---
@~/.claude/rules/std-owasp-api.md          # HTTP API surface: authN, rate-limit, CORS, payload caps, BOLA/API1
@~/.claude/rules/std-zero-trust.md         # network-reachable server: per-request authZ, mTLS-capable, default-deny
@~/.claude/rules/topic-authn-authz.md      # bearer baseline + mTLS/OAuth-pluggable; session-ownership bound to principal

> **Import-lean justification (master §6).** v1 is a single stdio process whose dominant risk is
> *running a hostile binary through Ghidra and feeding its output to an LLM*. The set above targets
> exactly that: LLM untrusted-output + agency (`std-owasp-llm`), input validation + CWE classes
> (`std-owasp-proactive`, `std-cwe`), the containment architecture (`topic-architecture-patterns`,
> `topic-resource-management`, `topic-reliability`, `topic-container-k8s`), supply chain for the
> pinned Ghidra/JDK image (`std-supplychain`, `workflow-cve-management`), and the verification +
> ops machinery (`topic-testing`, `workflow-cicd`, `workflow-threat-model`, `workflow-runbooks`).
> **v1.1 HTTP transport (ADR-011 / TB6) activates** `std-owasp-api` + `std-zero-trust` +
> `topic-authn-authz` — the network surface they were deferred for has arrived (separately threat-
> modeled as TB6). Still deliberately **omitted**: `std-privacy` (no personal data — artifacts are
> confidential but not PII by design) and multi-tenant modules (v1.1 HTTP is single-principal). Add
> a module when a real need appears (multi-tenant, persistence), not preemptively.

## Stack
- **Language/runtime:** Python 3.12+ (CPython). Isolated env (`uv`/venv); deps pinned with a
  lockfile **and** hashes (`std-supplychain`).
- **MCP:** official `mcp` SDK (FastMCP) — **stdio transport only** in v1.
- **Validation:** pydantic v2 at every tool boundary (input *and* output schemas).
- **Ghidra worker (separate process/container only):** Ghidra **12.1.2** + **JDK 21**, pinned by
  **digest**; headless / PyGhidra integration lives **inside the worker only**.
- **Server ↔ worker RPC:** internal, local-only (see `docs/contracts/rpc-protocol.md`); the server
  is the worker's sole client.
- **Tooling:** ruff (lint+format, incl. `D` docstrings), mypy `--strict`, pytest + coverage,
  bandit + semgrep (SAST), pip-audit (SCA), gitleaks (secret scan), Trivy (image/IaC scan).

## Project-specific rules
- **ADR-001 (MANDATORY):** the MCP **server process never loads the JVM or parses a binary**.
  In-process PyGhidra is **forbidden**. Ghidra runs only in the out-of-process worker.
- **Data classification:** the **analyzed binary and all derived artifacts (decompilation,
  disassembly, strings, symbols, comments, bytes) are CONFIDENTIAL and of HOSTILE ORIGIN.** Treat
  every byte that came from or through Ghidra as untrusted input on the way out, wrapped in the
  **untrusted-data envelope** (ADR-005) — never auto-execute, eval, render, or follow it.
- **No real malware in CI or the repo** — benign/synthetic fixtures only (master §5). Binary
  samples are git-ignored; tests build their own deterministic synthetic inputs.
- **Read-only v1:** no mutation tools, no `runScript`, no arbitrary script execution path. Tools
  are an explicit allow-listed Tier-1 catalog (`docs/contracts/tool-catalog.md`).
- **Bounded by default:** every tool that returns binary-derived data takes size/count caps and
  enforces them *before* calling the worker; the worker enforces wall-clock + memory limits and is
  **killed on timeout or eviction** (ADR-002), with a **verified project-store wipe**.
- **Logging redaction:** never log binary content, decompiled text, strings, or session secrets;
  log session IDs (opaque), tool name, sizes, durations, and outcomes only.
- **Contracts are frozen (WS0).** RPC protocol, tool schemas, untrusted-data envelope, and error
  envelope under `docs/contracts/` are the contract WS1–WS5 build to; changes route through the PM
  (batch-atomicity mandate), never edited ad hoc by a feature workstream.
- **Gated actions:** first commit, any push/tag, image pulls + dependency installs (pin by digest
  first), and any container run binding host ports/paths are **gated** — surface to the human via
  the PM (`@~/.claude/rules/workflow-gated-actions.md`).
