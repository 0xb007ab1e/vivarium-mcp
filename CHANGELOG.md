# Changelog

All notable changes to `ghidra-mcp` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — 2026-06-15

Composite-batch type creation + a deeper naming-eval. The tool catalog grows **49 → 50**.
Backward-compatible: the new tool is additive (no existing tool / RPC / envelope contract changed)
and gated; the eval refinement is client-side and additive.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before 1.0.

### Added

**`define_types` — multi-type composite batch (ADR-021 — tools 49 → 50, GATED)**
- Create a **batch of interdependent new composites** (structs/unions) in **one transaction** — a
  field may reference **another new composite in the same batch** (beyond ADR-015's single-composite
  `define_struct`/`define_union`, which remain). Gated by per-session write-consent + `allow_structural`.
- **By-value cycle detector:** an iterative 3-colour DFS over by-value member edges (`pointer_levels
  == 0`, array-of-B included) **rejects** any by-value cycle (self / array-of-self / A↔B / longer) →
  infinite-size types are impossible; **pointer members create no edge**, so **mutually-recursive
  pointer structs are allowed**.
- Assembly **pre-registers all empties** in the batch, resolves + adds each, enforces a batch-total
  size cap, and **rolls back the whole batch** on any failure (no partial/orphan type). Structured
  `TypeRef` only (no C parsed); name-collision (existing or intra-batch dup) fail-closed REJECT.

**Deeper behavioral-equivalence eval (ADR-022 — client-side)**
- `behavioral_equivalence_normalized` — a second naming-eval score reported **alongside** the
  unchanged strict byte-exact `behavioral_equivalence`. A conservative `normalize_output` masks
  volatile tokens (pointers `0x…`, ISO/clock timestamps, labelled PIDs, trailing whitespace) so two
  builds that differ **only** in volatile output are no longer scored as divergent. Invariant
  `normalized >= strict`; over-normalization risks false positives, so **strict stays the primary
  signal** (measured, not guaranteed).
- Seeded, deterministic `generate_fuzz_vectors` broadens behavioral coverage beyond the fixed
  vectors. Still **never runs the analyzed (hostile) binary** — A = trusted-source build vs B =
  recompiled renamed-C, both sandboxed (TB5).

### Changed
- Tool catalog **49 → 50** (`define_types`); all prior tools unchanged.

### Security
- **TB7** extended (ADR-021): the by-value cycle detector + one-transaction rollback-all bound the
  composite-batch write surface; structural consent + owner-scoping unchanged.
- **TB5** extended (ADR-022): normalization is a pure transform on inert captured bytes; fuzz inputs
  are seeded/bounded synthetic; the eval never executes the hostile original.

### Notes
- **Backward-compatible** (additive gated tool + additive client-side metric).
- **Tracked follow-ups:** `define_types` persistence round-trip of mutually-recursive pointer
  composites (ADR-021 §b); memory-state / coverage-guided equivalence (ADR-022 deferred).

## [0.3.1] — 2026-06-15

Patch release: the **mTLS peer-cert bridge** — `auth_mode=mtls` is now end-to-end functional (ADR-020), resolving the v0.3.0 known limitation. No new dependency; no other auth/transport path changed.

### Added
- **mTLS peer-cert bridge — `auth_mode=mtls` now functional (ADR-020).** A custom uvicorn HTTP
  protocol (`MtlsAwareProtocol`, used **only** for `auth_mode=mtls`) injects the **verified** client
  certificate into the ASGI scope, so it reaches the in-app `MtlsAuthenticator` and resolves to its
  cert-derived principal. Completes the ADR-019 increment-A seam: the `[0.3.0]` "Known limitation"
  (the cert never reaching the authenticator → all requests rejected) is resolved. Fail-closed
  preserved (an empty/absent peer cert injects nothing → generic `401`); the cert is read **only**
  from the verified TLS object, never a header (no spoofing). No new dependency; every other
  transport/auth path is unchanged.

### Security
- mTLS is now end-to-end verified by a **real-TLS integration test** (synthetic CA + server/client
  certs; no real secrets): a CA-signed client cert authenticates as its CN principal, and a client
  with no/untrusted cert is rejected at the handshake (ADR-019 abuse case 70 promoted from skip).
- Removed the `auth.mtls_bridge_pending` startup warning (the bridge is now wired).

## [0.3.0] — 2026-06-15

Cross-session **annotation persistence** plus two new pluggable **authentication identity sources**
(mTLS, OAuth) for the HTTP transport. The tool catalog grows **47 → 49**. Backward-compatible: all
new tools are additive (no existing tool / RPC / envelope contract changed), and the new auth modes
are opt-in. Ghidra still runs **isolated, headless, out-of-process** (ADR-001); the analyzed binary
remains hostile input.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before 1.0.

### Added

**Cross-session annotation persistence (ADR-018 — tools 47 → 49)**
- **`session_export_annotations`** — exports a session's `USER_DEFINED` annotations
  (renames / comments / signatures / applied + defined types) as a **versioned, binary-hash-bound,
  structured document**; read-only, owner-scoped, binary-derived strings wrapped `Untrusted`
  (ADR-005), bounded.
- **`session_import_annotations`** — replays such a document into a fresh same-binary session:
  schema-validated → **binary-hash verified** (mismatch fails closed) → write-consent gated
  (+ `allow_structural`) → **every entry re-validated through the live validators and replayed via
  the existing gated write tools** (one transaction each). **Import adds no new write primitive.**
- **Stateless / client-owned:** the server persists nothing (ADR-002 preserved) — export returns the
  document, import takes it; the client owns the artifact + its confidentiality. New trust boundary
  **TB8** (threat-model §12).

**Pluggable authentication identity sources for HTTP (ADR-019)**
- **OAuth (`GHIDRA_MCP_HTTP_AUTH=oauth`) — functional.** JWT access tokens validated locally via
  **JWKS**: a **pinned asymmetric algorithm allow-list** (`alg:none` and HS/RS confusion impossible —
  the token's `alg` is never trusted), `iss` / `aud` / `exp` / `nbf` enforced, `sub` (configurable)
  → principal. JWKS is fetched + cached (no per-request round-trip); failures fail closed, no oracle,
  the token is never logged. Config: `…_OAUTH_ISSUER` / `…_AUDIENCE` / `…_JWKS_URI` /
  `…_PRINCIPAL_CLAIM` / `…_ALGORITHMS` / `…_LEEWAY_SECONDS`.
- **mTLS (`GHIDRA_MCP_HTTP_AUTH=mtls`) — seam shipped (made functional in [Unreleased] / ADR-020).**
  Server-terminated client-cert verification (uvicorn `CERT_REQUIRED` + a configured client-CA
  bundle); the verified cert's configured field (CN / SAN / DN) maps to the principal. Config:
  `…_TLS_CLIENT_CA`, `…_MTLS_PRINCIPAL_FIELD`. (In 0.3.0 the verified cert did not yet reach the
  authenticator — wired by the ADR-020 peer-cert bridge in [Unreleased].)
- Both produce distinct **`Principal`s** that feed the existing per-principal session-ownership
  mechanism (ADR-017) unchanged. Hardens trust boundary **TB6** (threat-model §13).

### Changed
- Tool catalog **47 → 49** (the two persistence tools; all prior tools unchanged).

### Security
- **TB8** (annotation-import) and **TB6** (mTLS/OAuth identity) threat-modeled (STRIDE); 25 new
  abuse-case tests (annotation-import 68–77; mTLS 67–71; OAuth 72–82, renumbered in §13).
- Network principals are now **cryptographically proven** (client cert / JWKS-verified JWT), not just
  shared bearer secrets; all auth modes are fail-closed with no credential oracle and no token/cert
  logging.

### Dependencies
- Promoted **`pyjwt[crypto]`** (MIT) + **`cryptography`** (Apache-2.0 / BSD) to direct dependencies
  for OAuth (already present transitively via `mcp`); pinned + hashed in the lockfile
  (`pyjwt 2.13.0`, `cryptography 48.0.0`); `pip-audit` reports no known vulnerabilities.

### Known limitations
- **`auth_mode=mtls` is not yet end-to-end functional.** *(RESOLVED in [Unreleased] by the ADR-020
  peer-cert bridge — `auth_mode=mtls` is now functional.)* In 0.3.0, uvicorn did not surface the
  verified peer certificate into the request scope, so the transport→scope peer-cert bridge was a
  tracked follow-up; until it landed, an `mtls` endpoint was **fail-closed** (the TLS handshake still
  required a CA-signed client cert, and the authenticator rejected when no cert reached it) and
  startup logged `auth.mtls_bridge_pending`. mTLS startup requires server TLS (refuses a plaintext
  mtls listener).

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

[Unreleased]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/0xb007ab1e/ghidra-mcp/releases/tag/v0.1.0
