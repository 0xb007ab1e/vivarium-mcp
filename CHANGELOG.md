# Changelog

All notable changes to `ghidra-mcp` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] — 2026-06-13

Patch release: a defense-in-depth hardening of the (gated, client-side) naming-eval differential
runner. No tool/RPC/envelope contract change; no behavior change for normal use.

### Security
- **Bounded-streaming stdout capture in the differential-run sandbox (ADR-016 F1 / CWE-400).** The
  exec runner previously buffered a candidate's entire stdout (`subprocess.run(capture_output=True)`)
  before truncating to `max_stdout_bytes`, so the cap bounded only the *retained* output — a candidate
  flooding stdout could force the host to buffer far more during capture. It now performs a single
  bounded `read(cap)` at the subprocess boundary (`_read_capped`) then kills + reaps the child, so
  **peak host memory during capture is bounded by the cap**; the engine `--timeout` remains the
  wall-clock backstop. Confined to the gated TB5 eval path; the threat-model TB5 mitigation wording is
  corrected to match.

## [0.2.0] — 2026-06-13

The **first write surface.** v0.1.0 was strictly read-only; this release adds an allow-listed,
default-deny **mutation/write** tier (annotation + structural), a behavioral-equivalence naming
metric, and **multi-principal authorization** for the HTTP transport. The tool catalog grows
**35 → 47**. Ghidra still runs **isolated, headless, and out-of-process** (ADR-001 unchanged);
the analyzed binary remains hostile input; the server never loads the JVM or mutates — every
write executes only inside the hardened worker, in one transaction with rollback.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before
> 1.0. **This release is backward-compatible:** all new tools are **additive** (no existing
> tool / RPC method / envelope shape changed), the new write tier and per-owner session cap are
> **opt-in and default-off**, and existing stdio / single-principal users are unaffected (the
> session `owner` defaults to the implicit `local` principal). See `docs/contracts/`.

### Added

**Mutation / write tools — the headline (first write/agency boundary — threat-model TB7)**
- **Default-deny write consent (ADR-012):** a session is read-only until the operator calls the
  explicit, auditable, revocable, per-session, non-transferable **`session_enable_writes`**
  human-in-the-loop gate (OWASP LLM08 least-agency). `session_disable_writes` reverts to
  read-only; **`session_undo`** reverts the last committed mutation transaction. Every write runs
  `authorize → require_write_consent → validate → worker-RPC → audit`; the server **never
  mutates** (ADR-001) — the write executes only in the worker inside **one Ghidra transaction**
  (commit on success, `endTransaction(commit=False)` rollback on any failure — fail closed).
- **Annotation writes (ADR-012):** `rename_function`, `rename_symbol`, `set_comment`.
  Attacker-influenced `new_name` / comment `text` are validated **on the way in** (the
  `validate_write_name` identifier allow-list / bounded `validate_comment_text` normalization —
  stored-injection / data-poisoning defense), and the read path still wraps `Untrusted[...]` +
  normalizes **on the way out** (two-sided defense, ADR-005).
- **Structural writes — Phase A (ADR-013):** `rename_local_variable`, `rename_parameter` via the
  HighFunction path (name-only; the `updateDBVariable` data type is `null` — **no C parser
  surface**). HighSymbol resolution (decompile) happens **before** the transaction opens, so a
  resolution failure is a clean `not-found` with no transaction.
- **Structural writes — Phase B (ADR-014):** `set_function_signature`, `apply_data_type` over a
  **structured / constrained `TypeRef`** (resolved base/named types, bounded pointer-levels and
  array-length, closed-vocabulary calling convention) — **resolved against the program's
  `DataTypeManager`, never parsed from a C string**, so the C-parser injection surface is
  eliminated by construction (LLM07).
- **Structural writes — Phase C (ADR-015):** `define_struct`, `define_union` — composite
  *creation*. The empty composite is pre-registered so self-`named` pointers resolve (true
  self-referential types); a **by-value self-embed (incl. array-of-self) is rejected**, name
  collisions are fail-closed REJECTED, and a 1 MiB size cap + transactional rollback bound the
  rest.
- **Two-level consent for structural writes:** the six structural tools (Phase A/B/C) require, in
  addition to write consent, the **separate `allow_structural` opt-in**
  (`session_enable_writes{allow_structural: true}` → `require_write_consent(structural=True)`).
- **Per-write audit** (intent + outcome: tool, opaque session id, target address, value sizes,
  applied/denied — **never** binary-derived content or the new value verbatim; redacted) on an
  append-only stream; write-consent grant/revoke is itself audited. Mutations are
  **session-scoped + ephemeral** (lost on evict — ADR-002; no persistence).

**Behavioral-equivalence naming metric (ADR-016)**
- Completes ADR-010's deferred **`behavioral_equivalence`** metric with a client-side
  **differential harness** for semantic-naming quality (alongside the existing `naming_accuracy`
  + compile-rate). Evaluation extends the TB5 sandbox (rootless, no-egress, read-only rootfs,
  caps dropped, resource-capped, kill-on-timeout); it **never executes the hostile binary** —
  best-effort C remains a measured metric, not a guarantee.

**Multi-principal authorization for HTTP (ADR-017 — threat-model TB6)**
- **Multi-token bearer:** the single shared bearer token is replaced by a **token → principal-id
  map**, so distinct tokens authenticate distinct principals (constant-time compare, **no
  which-token timing oracle**, generic `401`, tokens never logged; mTLS/OAuth remain pluggable
  port stubs).
- **Enforced per-principal session ownership:** a session is owned by its creating principal; the
  `owner` is server-derived and immutable. Every session-scoped entry point (read / write /
  close) goes through the shared owner check (complete mediation).
- **Operator-configurable per-owner session cap** (`GHIDRA_MCP_MAX_SESSIONS_PER_OWNER`; **default
  off** — the global `max_sessions` backstops) bounds the noisy-neighbor / pool-monopolization
  case in a multi-principal deployment.

**Supply chain & operations**
- **Daily scheduled CVE rescan of `main` (`scheduled-rescan.yml`):** SCA (pip-audit on the
  hash-pinned runtime + dev lockfiles) **and** a digest-pinned image rebuild + Trivy scan, on a
  daily cron, **scan-only** (never builds-to-push / signs / publishes), **fail-closed** on a new
  HIGH/CRITICAL — the failed run is the alert. Surfaces a new CVE in an **unchanged** dependency
  or pinned base between releases (the gap that let CVE-2026-45447 / openssl reach the v0.1.0 tag).

### Changed
- **Tool catalog: 35 → 47** — 22 Tier-1 read-only + 5 semantic-naming + 8 Tier-2 reporting
  (all read-only, unchanged) **+ 12 new write tools** (6 annotation/lifecycle ADR-012, 6
  structural ADR-013/014/015). The exact count is asserted in tests.
- **HTTP BOLA (TB6-I) is now ENFORCED, no longer deferred (ADR-017):** v0.1.0 closed BOLA "by
  construction" for a single principal (256-bit CSPRNG session-id capability); v0.2.0 adds an
  **enforced per-principal owner check** on top — a cross-principal session reference returns the
  **same `SESSION_INVALID`** as unknown/expired/evicted (no oracle). Transparent to existing
  single-principal / stdio users (owner defaults to `local`).

### Security
- **TB7 — write/agency boundary (ADR-012/013/014/015):** mutation raises OWASP LLM08 agency (the
  read-only "no destructive action exists" bound no longer holds inside a write-enabled session).
  Bounded — not prevented — by default-deny consent (human gate), the second `allow_structural`
  gate, allow-list / structured-input validation (no free-form C parsed), one-transaction
  rollback, per-write audit, `session_undo`, and ADR-002 session ephemerality. Worst case is a
  mis-annotated / mis-restructured **disposable** session — never host or durable-data compromise.
- **TB5 — eval boundary extended (ADR-016):** the behavioral-equivalence harness compiles
  attacker-derived C in the existing no-egress / read-only / resource-capped / kill-on-timeout
  sandbox; compile-only, never links or runs the binary.
- **TB6 — enforced ownership + multi-token authn (ADR-017):** closes the deferred BOLA gap;
  forging another principal requires their secret token; identity is server-derived only.

### Notes
- **Pre-1.0 contract posture:** contracts remain frozen per release but may evolve before 1.0;
  this release is additive and backward-compatible (see the version header above).
- **New environment variables (opt-in):**
  - **Multi-token bearer map** — operator supplies a token → principal-id mapping (secret-managed
    credentials, never in source/logs); see `docs/runbooks/http-exposure.md`. HTTP off-loopback
    still requires **TLS + an authenticator** or the server fails closed at startup (unchanged).
  - **`GHIDRA_MCP_MAX_SESSIONS_PER_OWNER`** — per-owner session cap; **default off** (global
    `max_sessions` backstops).
- **Upgrade is transparent for read-only / stdio / single-principal users.** To use writes an
  operator must explicitly call `session_enable_writes` (and `{allow_structural: true}` for the
  6 structural tools). No DB schema or migration (sessions are ephemeral; no persistence).

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

[Unreleased]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/0xb007ab1e/ghidra-mcp/releases/tag/v0.1.0
