# Changelog

All notable changes to `ghidra-mcp` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-06-12

First tagged release. A secure [MCP](https://modelcontextprotocol.io) server that exposes
Ghidra reverse-engineering as read-only LLM tools, with Ghidra running **isolated, headless,
and out-of-process**. The analyzed binary is treated as hostile input; containment of the
analyzer is the central security control.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts are frozen for v0.1.0
> but may evolve before 1.0. See `docs/contracts/`.

### Added

**Core server & isolation**
- Out-of-process architecture (ADR-001): the MCP server process **never loads the JVM or
  parses a binary**; Ghidra runs only in a separate hardened worker. In-process PyGhidra is
  forbidden and guarded.
- Hardened worker container (ADR-003/004): **Ghidra 12.1.2 + JDK 21 pinned by digest**,
  rootless OCI, non-root, read-only rootfs, all capabilities dropped, seccomp `RuntimeDefault`,
  **no network/egress**, CPU/memory/pids limits, tmpfs scratch; gVisor (runsc) supported.
- Server ↔ worker over an internal **JSON-RPC 2.0 on a per-session Unix domain socket**; the
  server is the worker's sole client (ADR-009).
- Persistent **per-binary sessions** with TTL + idle eviction; **one worker per session, killed
  on eviction** with a **verified project-store wipe** (ADR-002).
- DoS controls: per-analysis wall-clock timeout that **kills the worker**, max input size
  enforced before Ghidra, worker-pool concurrency cap + backpressure.

**Tier-1 read-only tools** (the frozen `docs/contracts/tool-catalog.md`)
- decompile, disassemble, list/inspect functions, xrefs to/from, strings, symbols/labels,
  data types, comments (read), memory map/segments, bounded read-bytes, bounded search, and
  program metadata. **Read-only** — no mutation tools, no `runScript`.

**Untrusted-data handling**
- All binary-derived output (decompilation, disassembly, strings, symbols, comments, bytes) is
  wrapped in a typed **untrusted-data envelope** (ADR-005): never auto-executed, rendered, or
  followed — mitigating indirect prompt injection (OWASP LLM01/02).

**Semantic naming (v1.1)**
- Leaf-first call-graph **semantic-naming** read-only tools, a client-driven reference loop, a
  sandboxed compile evaluator (TB5: rootless, no-egress, ro-rootfs, caps dropped, kill-on-timeout,
  compile-only), and a tracked **`naming_accuracy`** metric (exact-match + token-set F1 vs DWARF
  ground truth). Validated across cJSON/zlib/lua fixtures (ADR-007/010).

**Tier-2 reporting & metrics (v1.1)**
- Eight read-only tools: cyclomatic complexity, code/data coverage, imports, exports, IOC scan,
  crypto-constant scan (incl. CRC-32), call-graph metrics, and a program-summary report
  (ADR-008).

**HTTP transport (v1.1 — ADR-011 / threat-model TB6)**
- MCP **Streamable HTTP** with a **secure-by-default exposure ladder**: stdio (default) →
  loopback TCP → Unix domain socket → **gated** network TCP. A non-loopback bind **fails closed
  at startup** unless TLS **and** an authenticator are configured.
- Pluggable **`Authenticator`** strategy port: **bearer** token (constant-time compare, generic
  401, token never logged), with mTLS/OAuth as port-ready stubs.
- `std-owasp-api` edge hardening: per-client rate limiting (429, size-bounded LRU bucket map so the
  limiter cannot itself grow memory without bound — CWE-400), request size cap (413), strict CORS
  (no `*`), security headers (nosniff / X-Frame-Options / Referrer-Policy; HSTS on TLS), and a
  consistent error envelope that leaks no internals. The runbook documents that per-client limiting
  degrades to per-proxy behind a reverse proxy (rate-limit at the proxy there).
- BOLA/API1 closed by construction for single-principal (256-bit CSPRNG session-id capability +
  one principal); a per-principal owner check is deferred to a future multi-principal increment.
- Operator runbook: `docs/runbooks/http-exposure.md`.

**Security, supply chain & docs**
- STRIDE threat model over six trust boundaries (TB1–TB6) in `docs/security/threat-model.md`.
- Merge-blocking CI gates: ruff (lint+format), mypy `--strict`, pytest with coverage
  (≥90% line+branch, 100% on critical paths), bandit + semgrep (SAST), pip-audit (SCA), gitleaks
  (secret scan), Trivy (image/IaC scan).
- Supply chain: Ghidra/JDK/base images/CI-actions/Python deps **pinned by digest**; on `v*` tags
  the worker + server images are built, scanned, **SBOM-attested (SLSA provenance + SBOM)**, and
  **cosign-signed** (keyless/OIDC) — see `.github/workflows/worker-image.yml`.
- Abuse/injection test suites (prompt-injection envelope handling, BOLA-safe session errors,
  decompile-bomb/oversized-input bounds, HTTP edge abuse) and a ground-truth e2e against the real
  worker on stripped OSS binaries.

### Security
- This release establishes the project's first network attack surface (HTTP/TB6); it is
  off-by-default and fail-closed. See `docs/security/threat-model.md` and `SECURITY.md` for the
  reporting channel.

[Unreleased]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0xb007ab1e/ghidra-mcp/releases/tag/v0.1.0
