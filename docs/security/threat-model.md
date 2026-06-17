# Threat Model — `ghidra-mcp` (v1, stdio)

> Method: STRIDE over a data-flow diagram (`workflow-threat-model`). Scope: v1 (Tier-1 read-only,
> **stdio only**). v1.1 increments are modeled inline as they land: Tier-2 reporting (§9, ADR-008),
> semantic-naming (§8, ADR-007), the naming-eval compiler (TB5, ADR-010), the **HTTP transport
> network boundary (TB6, ADR-011)**, the **annotation-mutation (write) boundary (TB7, §10,
> ADR-012)**, the **structural-mutation Phase A (TB7 structural, §10, ADR-013)**, and the
> **structural-mutation Phase B — signature + data-type apply (TB7 structural Phase B, §10,
> ADR-014)**, and (v1.2) the **annotation-persistence import boundary (TB8, §12, ADR-018)**.
> Source of truth: [`PLAN.md`](../../PLAN.md).
> **Data classification:** the analyzed binary and all derived artifacts are **confidential** and
> of **hostile origin** (master §5).

## 1. Assets

- **A1 — The host / control plane:** the machine and the trusted MCP server process. Compromise =
  worst case.
- **A2 — Confidentiality of analyzed artifacts:** one client's binary + derived data must not leak
  to another session or off-host.
- **A3 — Availability:** the server must stay responsive under hostile/oversized inputs.
- **A4 — Integrity of the LLM interaction:** the LLM must not be hijacked by injected content from
  a binary (indirect prompt injection).

## 2. Trust boundaries & data-flow diagram

The four boundaries are fixed by PLAN §4.

```mermaid
flowchart LR
  client([MCP Client / LLM host]):::ext
  subgraph SRV["ghidra-mcp server process (trusted control plane — NO JVM)"]
    val["Validate + allow-list (core)"]
    sess["Session mgr (authorize / evict)"]
    lim["Limits (size/time/count)"]
    adp["Ghidra adapter (GhidraPort)"]
    env["Untrusted-data + error envelopes"]
  end
  subgraph WK["Ghidra worker container (hardened, NO network)"]
    rpc["RPC server loop"]
    jvm["Ghidra / JVM bridge"]
  end
  bin[("Analyzed binary\nHOSTILE")]:::hostile
  store[("Per-session project store\nconfidential")]:::data

  client -- "tool args  ((TB1))" --> val
  val --> sess --> lim --> adp
  adp == "internal RPC  ((TB2))" ==> rpc
  rpc --> jvm
  jvm -- "load/analyze  ((TB3))" --> bin
  jvm <--> store
  jvm == "results  ((TB4))" ==> adp
  adp --> env -- "wrapped untrusted" --> client

  classDef ext fill:#124,stroke:#48f,color:#fff;
  classDef hostile fill:#511,stroke:#a00,color:#fff;
  classDef data fill:#141,stroke:#4a4,color:#fff;
```

| TB | Crossing | Why it's a boundary | Stance |
|----|----------|---------------------|--------|
| **TB1** | client → server | untrusted tool args | validate + allow-list, fail closed |
| **TB2** | server → worker | process/container line; server is sole client | internal RPC, no external clients, bounded |
| **TB3** | binary → analyzer | **HOSTILE**; primary containment | isolate, no egress, bounded, kill-on-timeout |
| **TB4** | worker → server → LLM | untrusted output (prompt injection) | untrusted-data envelope, never auto-execute |
| **TB5** | naming eval → compiler | **attacker-derived C compiled** (v1.1 eval; ADR-010) | sandbox like TB3: rootless container, no egress, ro-rootfs, caps dropped, resource caps, kill-on-timeout, compile-only (no link/run) |
| **TB6** | network client → server (HTTP) | **first network attack surface** (v1.1; ADR-011/ADR-017) | secure-by-default: stdio default, else loopback; network bind needs TLS+auth (fail closed); **multi-token bearer** auth → distinct principals (mTLS/OAuth-pluggable); rate-limit + size caps + strict CORS; per-request authZ; **BOLA closed by an enforced per-principal owner check** (session owned by its creating principal; foreign id → same `SESSION_INVALID`, no oracle — ADR-017) on top of the CSPRNG session-id capability; operator-configurable per-owner session cap (noisy-neighbor; default off, global cap backstops); same read-only catalog |
| **TB7** | client write-request → program mutation | **first write/agency boundary** — an LLM-exposed tool now *mutates* the per-session analysis (rename/comment) (v1.1 PROPOSED; ADR-012, §10) | **default-deny write consent** per session (human-in-the-loop gate — LLM08); annotation-only minimal set (rename function/symbol, set comment); allow-list write-name validation + comment normalization on the way IN (stored-injection defense); **one Ghidra transaction per write → rollback on failure**; per-write audit (intent+outcome); **session-scoped + ephemeral** (no persistence — wiped on evict, ADR-002); server NEVER mutates (ADR-001 — write executes only in the worker) |
| **TB8** | annotation-import document → server | **NEW write boundary (v1.2; ADR-018)** — a client-supplied, offline-tamperable annotation document is replayed as writes | treat the document as **fully untrusted**: schema-validate + bound (count/size); **binary-hash binding** (reject a doc minted for a different program); **consent-gated** (+ `allow_structural` for structural entries); **every entry re-validated through the live validators + replayed via the existing gated write path** (no new write primitive) in per-entry transactions w/ rollback; owner-scoped (ADR-017); per-entry audited; **server persists nothing** (stateless — ADR-002 preserved); export carries the binary's confidential artifacts off-server to the client (master §5) |

## 3. STRIDE per element / flow

Likelihood × Impact → severity (master §7). "L/M/H".

### TB1 — Client → Server (tool args)
| STRIDE | Threat | L×I | Mitigation (control · module) |
|--------|--------|-----|-------------------------------|
| **S** | Client forges identity | N/A in v1 — local stdio, single trusted host; no auth boundary inside one process | — (HTTP v1.1 adds authn — `topic-authn-authz`) |
| **T** | Malformed/oversized args, mass-assignment via extra fields | M×M=**Med** | pydantic frozen schemas, `extra="forbid"`, `core.validation` allow-list; bounds on every field (`std-owasp-proactive` #5, CWE-20) |
| **R** | Client denies issuing a call | L×L=**Low** | structured audit log: tool name, session id, sizes, outcome (redacted — `topic-logging-observability`) |
| **I** | Error messages leak internals (paths, stack, JVM detail) | M×M=**Med** | RFC 9457 error envelope; generic `detail`, diagnostics logged not returned (`topic-error-handling`) |
| **D** | Flood of calls / huge args exhausts the server | M×M=**Med** | per-tool timeout, payload caps, concurrency cap + backpressure (`topic-reliability`, F7) |
| **E** | Arg drives privileged behavior (e.g. `runScript`, path traversal) | M×H=**High** | **no mutation / no script surface in v1**; tools are a fixed allow-list; path-like args resolved + confined server-side (CWE-22) |

### TB2 — Server → Ghidra worker (internal RPC)
| STRIDE | Threat | L×I | Mitigation |
|--------|--------|-----|------------|
| **S** | A rogue local process talks to the worker | L×H=**Med** | per-session **Unix domain socket** with restrictive perms in a private dir; no TCP; server is the sole client (`docs/contracts/rpc-protocol.md`) |
| **T** | Tampered RPC frames | L×M=**Low** | local-only socket; length-prefixed framing + strict schema validation of every frame; reject malformed |
| **R** | — | — | RPC calls correlated to the tool call in logs |
| **I** | Worker leaks more than requested over RPC | M×M=**Med** | worker returns only the requested, size-capped result; server re-validates + caps |
| **D** | Worker hangs holding the RPC, stalling the server | M×M=**Med** | per-call timeout that **kills the worker**; adapter never blocks unbounded (`topic-reliability`) |
| **E** | Compromised worker pivots to the server via RPC | L×H=**Med** | server treats worker output as **untrusted** (TB4); strict frame schema; no code/paths from worker are executed/trusted |

### TB3 — Binary → Ghidra analyzer (**HOSTILE — primary boundary**)
| STRIDE | Threat | L×I | Mitigation |
|--------|--------|-----|------------|
| **S** | n/a (data, not a principal) | — | — |
| **T** | Malicious binary corrupts analyzer state / poisons results | M×M=**Med** | one worker per session, disposable; **kill + verified-wipe on evict** (ADR-002); poisoned-worker rotation runbook |
| **R** | — | — | per-session worker lifetime logged |
| **I** | Binary exfiltrates data or reads host | M×H=**High** | **no network/egress**; read-only rootfs; dropped caps; gVisor; tmpfs scratch (ADR-004) |
| **D** | **Decompile bomb / pathological input** hangs or OOMs the analyzer | H×M=**High** | wall-clock timeout **kills the worker**; memory/pids/cpu/tmpfs limits; max input size enforced **before** Ghidra; fuzz/abuse tests (F7, WS4). **v1.3 (ADR-023 / F1):** those bounds are now **operator-tunable but CLAMPED to a hard ceiling** — the env can lower OR raise within bounds; an above-ceiling/bool/non-int/`<1` value fails closed (clamp-down / VALIDATION), so **CWE-400 is preserved** (the cap can never be widened past the safe ceiling). On a memory-cap OOM the death is classified server-side (engine metadata: `OOMKilled`/exit 137 — **no binary parsing**, ADR-001) and surfaced as the distinct, non-retryable `resource-exhausted` (clearer signal than `worker-unavailable`); a warn-only pre-flight logs an oversized input (size + configured memory only — **no content/path**) and proceeds. |
| **E** | **Loader/analyzer RCE** (memory-safety/deserialization in Ghidra parsing hostile bytes) | M×H=**High** | out-of-process (ADR-001) + full isolation stack (ADR-004) contains it to a disposable, network-less worker; CVE-track + patch Ghidra/JDK by digest |

> **TB3 delta — v1.3 worker-resource tunability (ADR-023 / F1; no new boundary).** Making the five
> worker bounds (mem/cpus/pids/scratch+project tmpfs) env-configurable does **not** widen TB3: every
> override is clamped DOWN to a hard ceiling and validated fail-closed, so the DoS surface (CWE-400)
> is at most what it was and the `--memory-swap == --memory` (no swap) and all other ADR-004
> hardening flags are unchanged byte-for-byte. The new `resource-exhausted` error detail and the
> `worker.preflight_oversized` / `worker.rpc_failed` logs carry **no binary content and no host
> paths** (size + configured-MiB integers only) — confirmed against the error-envelope disclosure
> rules + master §5 redaction. The OOM classification is a server-side container-engine metadata
> query, never binary parsing (ADR-001 preserved).

> **TB3 delta — v1.4 analyzer profile + pre-flight reject (ADR-029 B/C; no new boundary).** The
> additive `session_analyze` `profile` (`default`/`light`/`deep`) only **reduces or adjusts analysis
> depth** — it adds **no new capability or agency** (the worker still runs Ghidra auto-analysis
> worker-side per ADR-001, still bounded by the kill-on-timeout of ADR-002). `default` is a
> byte-for-byte no-op (the analyze RPC omits the param and the worker touches no options object), so
> the existing analysis path is unchanged when the profile is omitted; `light` is a DoS *mitigation*
> (less time/heap on a huge binary). The pre-flight gains a **reject** mode
> (`GHIDRA_MCP_WORKER_PREFLIGHT=reject`): an input over the OOM-plausible threshold is failed closed
> with the existing non-retryable `resource-exhausted` **before** the worker is contacted — a
> fail-closed resource-DoS guard (strictly stronger than the warn-only default), not a new surface.
> The new `worker.preflight_rejected` log and the reject error carry **no binary content or host
> paths** (size + configured-MiB integers only). The profile→analyzer-option mapping is pure data;
> the JVM option-setting is the worker-only edge.

### TB4 — Worker → Server → LLM (untrusted output)
| STRIDE | Threat | L×I | Mitigation |
|--------|--------|-----|------------|
| **S** | Content impersonates a system/tool instruction to the LLM | H×M=**High** | **untrusted-data envelope** (ADR-005); documented "do not auto-execute/render/follow" contract; injection abuse tests (WS4) |
| **T** | Content rendered as active markup/links by the client | M×M=**Med** | envelope `encoding`/`notes`; WS4 normalization of control/bidi/zero-width chars; inert-text rendering contract |
| **R** | — | — | — |
| **I** | Confidential artifacts over-returned to the wrong caller | M×H=**High** | session-scoped results (BOLA — TB1/sessions); response size caps; no cross-session reuse (ADR-002) |
| **D** | Huge output payload exhausts client/server | M×M=**Med** | `max_response_bytes` + per-tool result caps; pagination on all lists (F7) |
| **E** | **Indirect prompt injection** escalates the agent to take harmful actions | H×H=**Critical** | envelope + never-auto-execute; least agency (`std-owasp-llm` LLM08); the tools are **read-only** (no destructive action exists to trigger); WS4 injection suite |

### Cross-cutting: Per-session project store (confidentiality)
| STRIDE | Threat | L×I | Mitigation |
|--------|--------|-----|------------|
| **I** | **Cross-session leakage** of one binary's store to another | M×H=**High** | one worker/session; per-session store path; **verified wipe on evict** (ADR-002); cross-session isolation abuse test (WS4) |
| **D** | Stores accumulate and exhaust disk | M×M=**Med** | TTL/idle eviction reclaims; concurrency cap bounds live stores; tmpfs option |

### TB5 — Naming eval → compiler (attacker-derived C; v1.1 — ADR-010)
The naming-quality eval measures whether the renamed translation unit compiles; that source is
attacker-derived (from a hostile binary's decompilation, via the namer). Compiling it is a new
hostile boundary, sandboxed like TB3 (`ContainerCompileRunner`). The eval **never links or runs**
the output — compile-only (`-c`) into a throwaway tmpfs.

| STRIDE | Threat | L×I | Mitigation |
|--------|--------|-----|------------|
| **T** | Malicious source corrupts host/toolchain state | L×H=**Med** | compile in a rootless container; read-only rootfs; source mounted **ro**; output only to ephemeral tmpfs; non-root, all caps dropped |
| **I** | `#include`/`#embed`/pragma reads host files or exfiltrates | M×M=**Med** | `--network none` (no egress); read-only rootfs (no host paths mounted but the ro source); diagnostics truncated; sandbox holds no secrets |
| **D** | Compiler bomb (macro/template/`#include` blowup) exhausts CPU/mem/time | M×M=**Med** | memory/cpu/pids caps + **kill-on-timeout** (engine `--timeout`); fail closed → `ok=False` |
| **E** | Compiler/sandbox escape to host | L×H=**Med** | gVisor runtime in prod (ADR-004); `no-new-privileges` + seccomp; caps dropped; pinned + verified compiler image (supply chain) |

### TB6 — Network client → Server over HTTP (v1.1 — ADR-011; multi-principal ADR-017)
HTTP is the first **network** boundary. Default stays stdio; HTTP defaults to loopback; a network
bind is opt-in + gated and **fails closed at startup without TLS + an authenticator**. Mitigations
live in the `server/` shell + the `SessionManager` owner check (the tool/worker layers are unchanged
and already bounded); applies `std-owasp-api` + `std-zero-trust` + `topic-authn-authz` +
`topic-multi-tenancy`. **ADR-017 makes this boundary truly multi-principal:** the single shared bearer
token is replaced by a **token → principal-id map**, and per-principal **session ownership** is
enforced — closing the BOLA gap that ADR-011 §6 deferred (TB6-I).

| STRIDE | Threat | L×I | Mitigation |
|--------|--------|-----|------------|
| **S** | Unauthenticated/forged caller (or forged *principal*) invokes the tool surface | M×H=**High** | **default-deny auth** on every TCP bind: **multi-token bearer** (each token a secret-managed credential mapping to a distinct principal id), constant-time compare with **no which-token timing oracle**, mTLS/OAuth-pluggable; generic `401` (no user/credential oracle). Forging another principal requires their secret token; identity is **server-derived** from the authenticated request only, never client-supplied. Network bind without auth refuses to start |
| **T** | Request tampering / MITM on the wire | M×H=**High** | **TLS required off-loopback** (1.2+, prefer 1.3); plaintext only on loopback/UDS; HSTS + security headers; proxy-terminated TLS supported. Session `owner` is set once at create from the server-derived principal and is **immutable** (no tool rewrites it) |
| **R** | Caller denies issuing a request | L×M=**Low** | structured audit log per request and per **principal+session** event (create / authorize-deny / write-consent — principal id + session id + outcome, redacted; `topic-logging-observability`); append-only stream |
| **I** | Cross-principal/session data disclosure (BOLA) or verbose errors leak internals | M×H=**High** | **TB6-I — ENFORCED (ADR-017), no longer deferred:** every session-scoped entry point goes through the shared `_get_live_locked` owner check (complete mediation); a session whose `owner ≠ caller` is denied the **same `SESSION_INVALID`** as unknown/expired/evicted — **no oracle** distinguishes "exists but not yours" from "does not exist" (D2). Defense in depth on top of the 256-bit CSPRNG session-id capability; per-request authZ server-side; consistent error envelope, no stack traces/internals (`topic-error-handling`); strict CORS (no `*`+creds; default no origins) |
| **D** | Request flood / huge payloads, **or one principal starving others** | M×H=**High** | per-client **rate limit + quota**, **request size caps**, timeouts + backpressure (`topic-reliability`); bounded by ADR-002 one-worker-per-session + eviction; an **operator-configurable per-owner session cap** (`GHIDRA_MCP_MAX_SESSIONS_PER_OWNER`; **default off** — the global `max_sessions` bounds total exhaustion) so a multi-principal deployment can stop one principal monopolizing the pool (noisy-neighbor — `topic-multi-tenancy`); loopback default limits reach |
| **E** | Remote caller escalates via the network edge to actions beyond the read-only catalog, **or acts on another principal's session/worker** | L×H=**Med** | **same frozen read-only catalog** (no new/mutation tools); the network edge does not bypass per-call validation/allow-listing (defense in depth); least privilege. A principal **cannot read or write another's session** (owner-checked read+write) and **cannot gain another's worker** (`ensure_worker` is owner-gated before spawn); write-consent is bound to principal+session (ADR-012) on top of the owner-scoped session. The hostile-binary containment (TB3) is unchanged and unaffected by transport |

## 4. Supply chain (build-time)
| Threat | L×I | Mitigation |
|--------|-----|------------|
| Compromised/typosquatted Python dep | M×H=**High** | pin + hash lockfile; vet new deps; SCA (pip-audit) gate (`std-supplychain`, `workflow-cve-management`) |
| Tag-mutated / poisoned Ghidra/JDK image | M×H=**High** | pin **by digest** (ADR-003); SBOM; gated image pulls; CVE tracking + digest-bump runbook |
| Compromised CI action | L×H=**Med** | pin CI actions **by digest**; least-privilege OIDC; ephemeral runners (`workflow-cicd`) |

## 5. Residual risk & assumptions

- **Prompt injection is not fully preventable** — the envelope + never-auto-execute **limit blast
  radius**; the agent host must honor the rendering contract. Tracked as the top residual risk.
  **Re-rated for TB7 (ADR-012 PROPOSED):** the read-only "no destructive action exists to trigger"
  bound (TB4-E) **no longer holds once mutation lands** — an injection that reaches the client can
  now steer a *write*. The compensating controls are TB7's: default-deny write consent (human gate),
  allow-list write-name validation, per-write audit, transaction rollback, optional `session_undo`,
  and the unchanged ADR-002 ephemerality (a poisoned session is disposable and wiped on evict). The
  worst case shifts from "wrong data shown" to "wrong annotation persisted in a disposable session",
  not host/durable compromise. **Residual:** within a write-enabled session the annotation writes are
  autonomous, so an injection during that window can mis-annotate before the operator notices —
  bounded by reversibility + audit, not prevented.
- **Sandbox escape from gVisor + no-network** is assumed hard but not impossible; defense-in-depth
  (ADR-001/004) and CVE patching are the controls. A confirmed escape → incident response.
- **Out of scope (v1):** remote/network attackers (no HTTP), authn/multi-tenant authz, mutation.
- **v1.1 HTTP (TB6, ADR-011):** the network attacker is now in scope, mitigated by secure-by-default
  exposure (stdio→loopback→gated network) + fail-closed TLS/auth.
- **v1.1 multi-principal authZ (TB6 strengthened, ADR-017):** multiple distinct principals are now in
  scope (multi-token bearer). BOLA is closed by an **enforced per-principal session-owner check**
  (TB6-I no longer deferred): a cross-principal session reference yields the same `SESSION_INVALID`
  (no oracle), and an operator-configurable per-owner session cap (default off; global cap backstops) bounds noisy-neighbor. **Still out of scope:**
  cross-principal session *sharing*/delegation (sessions are single-owner); per-principal rate limits
  beyond the session cap; mTLS/OAuth identity extraction (port stubs until built — same ownership
  mechanism). See §11.
- **v1.1 mutation (TB7, ADR-012):** the annotation write/agency boundary is in scope (see §10),
  mitigated by default-deny write consent + atomic+reversible+audited annotation writes + session
  ephemerality.
- **v1.1 structural mutation Phase A (TB7 structural, ADR-013):** the first **structural** writes —
  `rename_local_variable`/`rename_parameter` via the HighFunction path, gated by the existing
  `allow_structural` opt-in (see §10 "TB7 (structural)"), mitigated by the two-level default-deny
  consent + one-transaction rollback (incl. the §4 commit-time CWE-460 fix) + `session_undo` +
  per-write audit + ADR-002 ephemerality.
- **v1.1 structural mutation Phase B (TB7 structural Phase B, ADR-014 — PROPOSED):** the first
  **type-aware** structural writes — `set_function_signature` + `apply_data_type` over a
  **structured/constrained `TypeRef`** input (resolved/base types, NOT free-form C — ADR-013 §2a,
  ratified), so the C-parser injection surface is **absent by construction** (see §10 "TB7 (structural
  Phase B)"). Same `allow_structural` gate + one-transaction rollback + `session_undo` + audit +
  ephemerality; the live new concerns are the wider re-flow/re-render blast radius (signature → callers)
  and construction-time DoS (bounded params/depth/array-length).
  **Still out of scope:** multi-tenant authZ (single-principal); **Phase C composite-type creation**
  (`define_data_type`/`create_struct` — its own future gated, separately-threat-modeled increment,
  ADR-014 §1) and cross-session **persistence** (ADR-012 §4); `runScript`/arbitrary script execution
  (permanently out of scope — PLAN §2).

## 6. Abuse-case list for WS4 (REQUIRED — acceptance criteria)

These map 1:1 to `tests/security/test_abuse_cases.py` (scaffolded, skipped until WS4). Each uses
**benign/synthetic fixtures only — never real malware** (master §5, PLAN §6). Each must FAIL the
attack (the control holds) and be a deterministic, hermetic test.

1. **Decompile-bomb / analysis hang** — a pathological function/CFG must hit the tool/analysis
   timeout and **kill the worker**; the server stays responsive. (TB3-D)
2. **Oversized binary** — an input above `max_binary_bytes` is **rejected before** any byte reaches
   Ghidra. (TB3-D / limits)
3. **Zip / decompression bomb** — archive/decompression-ratio abuse is rejected by the size/ratio
   guard (if/when archive inputs exist). (TB3-D)
4. **Malformed-loader RCE attempt** — a crafted/corrupt format input crashes only the **contained
   worker**; no host/server impact; worker is evicted + wiped. (TB3-E)
5. **Indirect prompt injection via strings/symbols/comments** — payloads in binary-derived content
   are returned **wrapped in the untrusted-data envelope**, normalized/annotated, never as bare
   instruction text. (TB4-S/E)
6. **Session-ID guessing / BOLA (TB6-I)** — a `session_id` is a 256-bit CSPRNG capability and
   `authorize()` returns the *same* `SESSION_INVALID` for unknown/expired/evicted ids (never
   revealing whether other sessions exist). **As of ADR-017 (multi-principal) the per-principal
   `owner` check is ENFORCED, not deferred:** a session is owned by its creating principal, and any
   session-scoped call by a different principal is denied the *same* `SESSION_INVALID` (no oracle —
   D2), across read/write/close. Exercised by cross-principal abuse cases **61-66** below.
   (TB1/TB4-I/TB6-I)
7. **Worker-pool starvation / resource exhaustion** — exceeding the concurrency cap yields
   **backpressure** (`LIMIT_EXCEEDED`), not exhaustion; timeouts reclaim stuck workers. (TB1-D/TB3-D)
8. **Cross-session project-store leakage** — one session cannot read another's store; eviction
   performs a **verified wipe** (assert the store is gone). (store-I / ADR-002)
9. **Naming-eval compiler abuse** — a malicious decompilation (compiler bomb, `#include`/pragma
   abuse, oversized TU) fed to the eval compiler is **bounded + contained**, not an escape or DoS:
   compile-only in a no-network, read-only, resource-capped, timeout-killed sandbox; failure maps to
   `ok=False`. (TB5 — ADR-010)

## 7. Open items feeding the model (PLAN §9)
- Exact Ghidra 12.1.2 patch version + headless integration (SME) — affects TB3 CVE surface.
- Final RPC mechanism + serialization (recommended in `docs/contracts/rpc-protocol.md`) — affects TB2.
- Project-store location (volume vs tmpfs) + verified-wipe mechanism — affects store-I/D (ADR-002).

## 8. Addendum — v1.1 semantic-naming tools (ADR-007)

The five new tools (`call_graph`, `callees`, `callers`, `analysis_order`, `function_context`) add
surface but introduce **no new trust boundary**: still a single **stdio** process, still
**read-only**, still **output-only** (the tools NEVER mutate the Ghidra DB). They sit on the
existing TB1 (client args), TB3 (hostile binary → analyzer, for graph extraction), and TB4 (untrusted
output → LLM) boundaries. The naming/synthesis intelligence runs on the **client** (no server-side
LLM), so server-side agency risk (LLM08) is unchanged.

New/relevant threats and controls:

| STRIDE | Threat | Control |
|--------|--------|---------|
| **D** | **Graph-bomb** — a hostile binary presents an enormous fan-out call graph (millions of edges) to exhaust memory/time | Node/edge caps enforced at the tool boundary **before** the worker (`max_nodes ≤ 50k`, `max_edges ≤ 200k`); worker stops at the cap and sets `truncated`. (TB3-D / TB4-D, std-owasp-llm LLM04) |
| **D/I** | **String-flood / injection via `referenced_strings`** — a function referencing huge or attacker-crafted string literals to exhaust output or smuggle a prompt-injection payload | `max_strings ≤ 1024` cap enforced at the tool boundary and again in the worker (de-duplicated by target address, `truncated` on clip); every value stays `Untrusted[...]` (`BINARY` origin) and is normalized at the `core.envelope.wrap` chokepoint — client renders inert. (TB3-D / TB4-I, ADR-005) |
| **D** | **Deep recursion / long-chain** — a deeply nested or very long call chain | `max_depth ≤ 256` traversal cap; the **pure ordering core is iterative** (no Python recursion) so it cannot stack-overflow at any size. (TB3-D) |
| **D** | **Cycle abuse** — densely cyclic/mutually-recursive graph to blow up an ordering algorithm | SCC condensation is `O(V+E)` Tarjan (iterative); cycles collapse to one component; deterministic, bounded by node/edge caps. (TB3-D) |
| **I/S** | **Untrusted graph + decompiled C** — node names, comments, and pseudo-C in `function_context` carry indirect-prompt-injection payloads | All binary-derived names + decompiled C stay `Untrusted[...]`, normalized/annotated at the `core.envelope.wrap` chokepoint; client renders inert (TB4 — same control as abuse-case 5, ADR-005). |
| **I** | **Misleading-incomplete graph** — unresolved indirect/virtual calls silently dropped would hide real control flow and mislead naming | Unresolved edges are **surfaced** in `unresolved_callers` / `has_unresolved_calls`, never dropped (honesty; the client knows the inference is incomplete). |
| **T** | **DB tampering via naming** | Out of scope by design — tools are read-only/output-only; no rename/retype/comment-write/`runScript` exists (ADR-007). |

**Residual risk (added to §5).** Synthesized C is **best-effort**: compile-rate and behavioral
equivalence are **measured, not guaranteed** (ADR-007) — a client must not treat recompiled C as a
faithful reproduction. Indirect prompt injection via graph node names / decompiled C in
`function_context` carries the same residual risk as abuse-case 5 (the envelope is defense-in-depth,
not a guarantee).

### Abuse cases for the v1.1 build fan-out (append to §6; benign/synthetic fixtures only)

9. **Graph-bomb** — a synthetic binary/graph with edge count above `max_edges` returns a
   `truncated` graph capped at the limit, not an OOM; the server stays responsive. (TB3-D/TB4-D)
10. **Deep-recursion chain** — a synthetic deep call chain is ordered without recursion/stack
    overflow and respects `max_depth`. (TB3-D)
11. **Cycle / mutual-recursion** — a synthetic cyclic graph condenses to a single recursive
    component; the order is total and deterministic; `is_recursive`/`self_recursive` are set. (TB3-D)
12. **Unresolved-edge surfacing** — a synthetic indirect/virtual call site appears in
    `unresolved_callers` / `has_unresolved_calls`, is never silently dropped. (TB4-I)
13. **Injection via graph node name / decompiled C in `function_context`** — a planted payload in a
    node name or pseudo-C is returned `Untrusted`-wrapped + normalized, never as bare instructions.
    (TB4-S/E — extends abuse-case 5)

## 9. Addendum — v1.1 Tier-2 reporting/metrics tools (ADR-008)

The Tier-2 tools (`cyclomatic_complexity`, `list_imports`, `list_exports`, `coverage`, `ioc_scan`,
`crypto_constant_scan`, `call_graph_metrics`, `program_summary`) add surface but **no new trust
boundary**: still single **stdio**, **read-only**, **output-only** (no Ghidra DB mutation). They sit
on TB1 (client args), TB3 (hostile binary → analyzer, for the 4 new extraction RPCs), and TB4
(untrusted output → LLM). Derivation is JVM-free (pure core — ADR-001); the metrics/scan
intelligence is server-side, not agentic.

New/relevant threats and controls:

| STRIDE | Threat | Control |
|--------|--------|---------|
| **I/S** | **Injection via `ioc_scan` matches** — a planted string (e.g. a "URL"/"domain"/"path" that is actually a prompt-injection payload) is matched and returned | The matched `value` is `Untrusted[...]` (BINARY origin), normalized at the `core.envelope.wrap` chokepoint; surfaced as inert data the client must NOT follow/fetch/execute (TB4 — extends abuse-case 5, ADR-005). |
| **I/S** | **Injection via import/export/crypto-finding names/detail** | All binary-derived names/detail wrapped `Untrusted`; addresses/categories/algorithm labels are server-computed/closed-vocabulary, bare. (TB4) |
| **D** | **Scan-bomb** — a binary with millions of strings / huge data to exhaust the IOC/crypto scan | `ioc_scan` scans a bounded page (`limit`) with per-string length caps before regex (ReDoS-safe, linear patterns); `crypto_constant_scan` runs a bounded set of already-bounded `search_bytes`; both set `truncated`. (TB3-D / CWE-400) |
| **D** | **Metric-bomb** — pathological CFG/call-graph to blow up complexity/metrics | `cyclomatic_complexity` is `O(1)` arithmetic over worker-capped block/edge counts; `call_graph_metrics` inherits the ADR-007 node/edge/depth caps and the iterative (no-recursion) core. (TB3-D) |
| **I** | **Misleading heuristics** — IOC/crypto scans yield false positives/negatives presented as authoritative | Tools are documented + framed as **heuristic triage aids, not authoritative detections** (ADR-008 caveat); findings are leads, not verdicts. `cyclomatic_complexity` returns `incomplete` + raw block/edge counts; `coverage` measures *defined*, not ground truth. |
| **T** | **DB tampering via reporting** | Out of scope by design — Tier-2 is read-only/output-only; no mutation tool exists (ADR-008; mutation tier is a separate gated increment). |

**Residual risk (added to §5).** IOC/crypto scans are heuristic — a client must not treat a hit as
proof or a miss as clean. The same indirect-prompt-injection residual as abuse-case 5 applies to all
binary-derived Tier-2 strings (the envelope is defense-in-depth, not a guarantee).

## 10. TB7 — Client write-request → program mutation (v1.1 — ADR-012, PROPOSED)

The **first write/agency boundary.** Until now every tool was read-only/output-only (§8, §9 record
"no mutation tool exists"). ADR-012's annotation-only write set (`rename_function`, `rename_symbol`,
`set_comment`, gated by the server-side `session_enable_writes`) lets an **LLM-driven client mutate
the per-session program DB**. This is **new agency** (`std-owasp-llm` LLM08) and a new trust boundary
over the **integrity of the analysis the operator relies on** — *not* a host-compromise boundary
(**ADR-001 still holds: the server never loads the JVM or mutates; the write executes only inside the
hardened worker** over the internal RPC). The boundary sits on the existing TB1/TB6 (client args/
network), TB2 (server→worker RPC — gains new write methods, same channel), and TB4 (untrusted
worker output — a write tool's echoed prior name stays `Untrusted[...]`). The hostile-binary
containment (TB3) and worker isolation (ADR-004) are **unchanged and unaffected** by adding writes.

The dominant new risk classes are **E**levation (write = new agency / LLM08), **T**ampering (a
mutation corrupting analysis state, or one session's writes reaching another), **R**epudiation (an
unattributable mutation), and **D** (a write-flood). STRIDE:

| STRIDE | Threat | L×I | Mitigation (control · module) |
|--------|--------|-----|-------------------------------|
| **S** | Caller forges identity to issue writes | N/A stdio (single trusted host); on HTTP same as TB6 (bearer/mTLS authn, generic `401`) — writes add no new identity surface | reuse TB6 authn; write **consent** is bound to the authenticated principal + session (ADR-012 §3) |
| **T** | **Injection-steered malicious write** — indirect prompt injection (TB4) steers the client into a `new_name`/comment carrying markup/path/zero-width/RTL/control chars, **persisted** into the DB and later re-served (stored injection / data poisoning) | **H×M=High** | write payload validated as **untrusted, attacker-influenced** input at the boundary — allow-list **`validate_write_name`** (identifier charset) + bounded `validate_comment_text` normalization on the way **IN**; closed-vocabulary `comment_type`; the **read path still wraps `Untrusted` + normalizes on the way OUT** (ADR-005) — two-sided defense in depth (`std-owasp-proactive` #5, CWE-20, abuse-cases 2/3) |
| **T** | **Partial / corrupting write** — a write that fails mid-operation leaves the program in an inconsistent state | M×M=**Med** | **one Ghidra transaction per mutation**; commit only on success, **`endTransaction(commit=False)` rollback on any exception** → fail closed, surfaced as `analysis-failed`; program unchanged (ADR-012 §4, abuse-case 4) |
| **T** | **Cross-session write contamination** — a write (or write-consent) for session A affects session B's analysis state | M×H=**High** | one worker + one program per session (ADR-002); write consent is **per session**; `authorize()` BOLA chokepoint scopes every call; stores independent and verified-wiped on evict (abuse-cases 5/8) |
| **R** | **Unattributable mutation** — operator/agent denies a write, or a bad annotation can't be traced | M×M=**Med** | **per-write audit log: intent + outcome** (tool, session id (opaque), target address, value sizes, applied/denied — **never** the binary-derived content or the new value verbatim beyond size; redacted — `topic-logging-observability`); append-only stream; the write-consent grant/revoke is itself audited |
| **I** | Write result over-discloses / echoes hostile content as instructions | M×M=**Med** | a write echoes only `address` (server-normalized, safe), `applied`/`kind` (safe), and the prior `old_name` **wrapped `Untrusted[...]`** (ADR-005); session-scoped (BOLA — TB1/TB6); no cross-session reuse |
| **D** | **Write-flood / unbounded consumption** — a burst of writes (LLM04 cost-DoS) exhausts the worker or grows state without bound | M×M=**Med** | each write is **one bounded transaction** (no unbounded growth); same per-tool **timeout that kills the worker**, concurrency cap + backpressure, and (HTTP) per-client rate limit as reads (`topic-reliability`, ADR-011 §5); abuse-case 6 |
| **E** | **Excessive agency** — the LLM autonomously performs destructive writes without human intent; or escalates beyond the annotation set | **H×H=Critical** | **default-deny: sessions are read-only**; mutation requires the explicit, auditable, revocable, per-session, non-transferable `session_enable_writes` **human-in-the-loop consent gate** (LLM08 least-agency); the catalog is a **fixed allow-list of annotation-only writes** (no locals/signatures/types/`runScript` — those are deferred/forbidden); structural writes require a **separate** `allow_structural` opt-in (Phase A renames land in ADR-013 — see TB7 (structural) below; signatures/types stay deferred to Phase B); `session_undo` bounds a mistake (ADR-012 §1/§3/§4, abuse-cases 1/7) |
| **E** | A write bypasses the server to reach the JVM directly | L×H=**Med** | **ADR-001 invariant unchanged** — no JVM/PyGhidra import server-side (the architecture-invariant CI test covers the new write handlers too); the write is a typed worker RPC, not in-process (abuse-case 8) |

**Residual risk (added to §5).** Mutation **raises LLM08 agency**: the read-only "no destructive
action exists" bound (TB4-E) no longer holds — an injection reaching the client can steer a write
*within a write-enabled session*, before the operator notices. Bounded — not prevented — by
default-deny consent (the human gate), allow-list write validation, transaction rollback, per-write
audit, optional `session_undo`, and ADR-002 session ephemerality (a poisoned session is disposable
and wiped on evict; mutations do not persist). The worst case is a mis-annotated **disposable**
session, not host or durable-data compromise.

### Abuse cases for the mutation increment (append to §6; benign/synthetic fixtures only)

These map 1:1 to new cases in `tests/security/test_abuse_cases.py` (ADR-012 §7). Each must FAIL the
attack (the control holds), deterministic + hermetic, synthetic fixtures only (master §5):

14. **Write-without-consent** — a mutation tool on a session lacking `session_enable_writes` is
    denied (read-only default; fail closed). (TB7-E)
15. **Injection-steered malicious name** — a `new_name` with markup/`../path`/zero-width/RTL/control
    chars is rejected by `validate_write_name` (never written to the DB). (TB7-T)
16. **Comment stored-injection** — a `set_comment` `text` carrying a prompt-injection + bidi/
    zero-width payload is normalized/annotated on write and returned `Untrusted`-wrapped on read-back,
    never bare instructions. (TB7-T / TB4 — extends abuse-case 5)
17. **Failed-write atomicity** — a worker write that raises mid-transaction rolls back
    (`commit=False`) and surfaces `analysis-failed`; the program is unchanged. (TB7-T)
18. **Cross-session write isolation** — write consent + a rename on session A does not enable writes
    on, or mutate, session B. (TB7-T / store-I — extends abuse-case 8)
19. **Write-flood / consumption** — a burst of writes is bounded by the per-tool timeout +
    concurrency cap + (HTTP) rate limit; a hung write kills the worker. (TB7-D)
20. **BOLA on the grant** — `session_enable_writes` against an unknown/foreign session id yields the
    same `session-invalid` envelope (no oracle). (TB7-E / BOLA — extends abuse-case 6)
21. **ADR-001 invariant under writes** — the architecture-invariant test still passes: no JVM/
    PyGhidra import on any server-side module, including the new write handlers. (TB7-E)

### TB7 (structural) — Structural mutation increment (v1.1 — ADR-013, PROPOSED)

ADR-013 **Phase A** extends TB7 from annotation writes to the **first structural writes** —
`rename_local_variable` and `rename_parameter` — via Ghidra's HighFunction path
(`DecompInterface` → `HighFunction` → `HighSymbol` → `HighFunctionDBUtil.updateDBVariable`), gated by
the **already-built** `allow_structural` opt-in on `session_enable_writes` (ADR-012 §3 forward hook —
`require_write_consent(structural=True)`). It is **the same trust boundary** (TB7), **not a new one**:
the boundary still sits on TB1/TB6 (client args/network), TB2 (server→worker RPC — gains two new write
methods, same channel), and TB4 (untrusted worker output — echoed `function`/`old_name` stay
`Untrusted[...]`). **ADR-001 still holds: the server never loads the JVM or mutates; the write — and
the decompile to obtain the HighSymbol — execute only in the hardened worker.** The hostile-binary
containment (TB3) and worker isolation (ADR-004) are **unchanged and unaffected**.

What is **new vs the annotation writes** (the crux — ADR-013 §2): structural writes carry **three risk
classes annotations did not** — (a) **type/signature strings parsed by Ghidra's C parser** (highest
injection-into-API surface — *deferred to Phase B*, but the input model is design-decided now as
structured/constrained, NOT free-form C); (b) **stateful HighFunction re-decompile** (the live Phase-A
mechanism — failure-prone, version-sensitive); (c) **larger re-flow/re-render blast radius** (a local
rename re-renders one function; a signature/type change — Phase B — re-flows callers / re-renders
dependent data). The dominant residual classes remain **T** (type-string injection into the C parser
in Phase B; signature/storage re-flow corruption) and **E** (more agency).

| STRIDE | Threat (structural) | L×I | Mitigation (control · module) |
|--------|---------------------|-----|-------------------------------|
| **E** | **Structural agency without intent / escalation beyond the annotation set** — the LLM autonomously performs a structural write (rename a local/param) | **H×H=Critical** | **two-level default-deny**: writes off by default → `session_enable_writes{allow_structural:false}` permits annotations only → **`allow_structural:true` is a SEPARATE, explicit, audited human opt-in** for the structural set; each structural handler calls `require_write_consent(structural=True)` (the existing chokepoint — `manager.py:301-331`); fixed allow-list (only `rename_local_variable`/`rename_parameter` in Phase A; signatures/types/`runScript` deferred/forbidden); `session_undo` reverts in one step (ADR-013 §1/§3) |
| **T** | **Type/signature string injection into Ghidra's C parser** — an injection-steered `DataTypeParser`/`CParser`/`ApplyFunctionSignatureCmd` string causes parser-bomb consumption, unintended type definitions, or smuggled markup in type names | **H×M=High** (Phase B) | **DEFERRED to Phase B** AND **neutralized by design**: Phase B accepts a **structured/constrained signature** (resolved `TypeRef`s + bounded `ParamSpec` list + closed-vocabulary calling convention) assembled from already-resolved `DataType` handles — **no C string is parsed** (`std-owasp-llm` LLM07, ADR-013 §2a). Phase A does **NOT** parse any type string (name-only; `updateDBVariable` data type is `null`) — the C-parser surface is **absent** from this increment by construction. Any future free-form-C path is a narrower opt-in bounded by `validate_type_decl` (length/depth/decl-count, no preprocessor/pragma) parsing under worker kill-on-timeout |
| **T** | **HighFunction re-decompile failure → partial/corrupting write** — the decompile-to-HighSymbol step (stateful, version-sensitive) fails mid-operation | M×M=**Med** | **resolution (decompile → HighSymbol) happens BEFORE `startTransaction`** (read-only) → a resolution failure is a clean `not-found` with no transaction opened; only the `updateDBVariable` DB write is transacted; **one transaction per write, rollback on any exception incl. commit-time (the §4 CWE-460 fix)**; bounded `DecompInterface` timeout + the per-call timeout that **kills the worker** on a hung decompile (ADR-013 §2b/§4, abuse-cases 4/5) |
| **T** | **Larger re-flow/re-render tampering blast radius** — a structural write re-renders more than its target (Phase A: one function; Phase B: callers / dependent data) | M×M=**Med** (Phase A); M×H=**High** (Phase B) | bounded by **one-transaction rollback** + **`session_undo`** (revert the last committed transaction) + **ADR-002 session ephemerality** (worst case is a mis-restructured **disposable** session, wiped on evict — never host/durable compromise); Phase B's wider re-flow is a reason it is deferred to its own threat-modeled increment (ADR-013 §2c) |
| **T** | **Structural stored-injection / data-poisoning** — a malicious local/param `new_name` (markup/path/zero-width/RTL/control) persisted and re-served by `decompile_function`/`function_context` | M×M=**Med** | **reuse `validate_write_name`** (the identifier allow-list — `validation.py:303-337`) on the way IN; the read path re-wraps `Untrusted[...]` + re-normalizes on the way OUT (ADR-005) — same two-sided defense as ADR-012 §7 (abuse-case 3) |
| **R** | **Unattributable structural mutation** | M×M=**Med** | **per-write audit: intent + outcome** (tool, session id (opaque), target sizes/flags, applied/denied — **never** binary-derived content or the new value verbatim; redacted — `topic-logging-observability`); the `allow_structural` grant/revoke is itself audited (same posture as ADR-012 TB7-R) |
| **D** | **Structural-write-flood** — a burst of structural writes (each triggering a decompile) exhausts the worker | M×M=**Med** | each write is **one bounded transaction**; same per-tool **timeout that kills the worker** (covers a hung decompile), concurrency cap + backpressure, and (HTTP) rate limit as reads (`topic-reliability`, ADR-011 §5; abuse-case 7) |
| **E** | A structural write bypasses the server to reach the JVM directly | L×H=**Med** | **ADR-001 invariant unchanged** — no JVM/PyGhidra import server-side (the architecture-invariant CI test covers the new structural handlers); the write + the decompile-for-HighSymbol are a typed worker RPC, not in-process (abuse-case 9) |

**Residual risk (added to §5).** Phase A raises LLM08 agency again: within a session enabled with
`allow_structural`, the structural renames are autonomous, so an injection during that window can
mis-name a local/param (re-rendering one function) before the operator notices — bounded, not
prevented, by the two-level opt-in, transaction rollback (incl. the §4 commit-time fix), per-write
audit, `session_undo`, and ADR-002 ephemerality. **The highest-risk surface — attacker-influenced
type/signature strings parsed by the C parser — is DEFERRED to Phase B and design-decided as
structured/constrained (no free-form C), so it is absent from this increment by construction**
(ADR-013 §2a). The worst case is a mis-restructured **disposable** session, not host or durable-data
compromise. **Still out of scope:** Phase B structural writes (`set_function_signature`,
`define_data_type`, `apply_data_type` — their own gated, separately-threat-modeled increment) and
cross-session persistence (ADR-012 §4); `runScript`/arbitrary script execution (permanently out of
scope — PLAN §2).

### Abuse cases for the structural-mutation increment (append to §6; benign/synthetic fixtures only)

These map 1:1 to new cases in `tests/security/test_abuse_cases.py` (ADR-013 §7). Each must FAIL the
attack (the control holds), deterministic + hermetic, synthetic fixtures only (master §5):

22. **Structural-without-`allow_structural`** — `rename_local_variable`/`rename_parameter` on a session
    enabled with `allow_structural=false` is denied with `VALIDATION` "structural writes not
    permitted" (the `require_write_consent(structural=True)` chokepoint — `manager.py:326-330`).
    (TB7-E / gating)
23. **Structural-without-any-consent** — the same tools on a read-only session (no
    `session_enable_writes`) are denied "session is read-only" (default-deny). (TB7-E)
24. **Injection-steered malicious local/param name** — a `new_name` with markup/`../path`/zero-width/
    RTL/control chars is rejected by `validate_write_name` (never written). (TB7-T — extends case 15)
25. **HighFunction resolution failure → no partial write** — a `variable`/`parameter` that does not
    resolve to a HighSymbol (or a decompile that fails/times out) surfaces `not-found`/
    `analysis-failed` with the program unchanged (resolution is before `startTransaction`). (TB7-T)
26. **Commit-time atomicity (the §4 fix)** — a write that raises in `write()` **or in the commit**
    (`endTransaction(txn, True)`) rolls back and surfaces `analysis-failed`; no dangling transaction,
    no untyped escape (CWE-460). The program is unchanged. (TB7-T — extends case 17)
27. **Cross-session structural isolation** — `allow_structural` + a local rename on session A does not
    enable or mutate session B. (TB7-T / store-I — extends case 18)
28. **Structural-write-flood** — a burst of structural writes (each decompiling) is bounded by the
    per-tool timeout (kills the worker on a hung decompile) + concurrency cap + (HTTP) rate limit.
    (TB7-D — extends case 19)
29. **BOLA on the structural grant** — `session_enable_writes{allow_structural:true}` against an
    unknown/foreign session id yields the same `session-invalid` envelope (no oracle). (TB7-E / BOLA —
    extends case 20)
30. **ADR-001 invariant under structural writes** — the architecture-invariant test still passes: no
    JVM/PyGhidra import on any server-side module, including the new structural handlers (the write +
    the decompile-for-HighSymbol execute only in the worker). (TB7-E — extends case 21)

### TB7 (structural Phase B) — Signature + data-type apply (v1.1 — ADR-014, PROPOSED)

ADR-014 **Phase B** extends TB7 (structural) from the Phase-A name-only renames to the first
**type-aware** structural writes — `set_function_signature` (set a function's prototype) and
`apply_data_type` (lay a resolvable type at an address). It is **the same trust boundary** (TB7),
**not a new one**: same TB1/TB6 (client args/network), TB2 (server→worker RPC — gains two new write
methods, same channel), TB4 (untrusted worker output — echoed `function`/`old_signature`/
`new_signature`/`type_name` stay `Untrusted[...]`). **ADR-001 still holds: the server never loads the
JVM or mutates; the type resolution and the write execute only in the hardened worker.** Hostile-binary
containment (TB3) and worker isolation (ADR-004) are **unchanged**.

What is **new vs the Phase-A renames** (ADR-014 §1/§2): Phase B is where the structural risk class (a)
flagged in ADR-013 §2 — **type/signature strings parsed by Ghidra's C parser** — would have landed,
**and it is eliminated by construction**: ADR-014 honors the human-ratified ADR-013 §2(a) pre-decision
and accepts a **structured/constrained `TypeRef` + bounded `ParamSpec` + closed-vocabulary
calling-convention** input assembled in the worker from **already-resolved `DataType` handles** — **no
client string ever reaches `CParser`/`DataTypeParser`** (`std-owasp-llm` LLM07). The two live new
concerns are therefore **(c)** the **larger re-flow blast radius** — a signature change re-renders
every **caller**'s decompiled view, an applied type re-renders dependent items (ADR-013 §2c) — and the
**construction-time DoS** of unbounded params/pointer-depth/array-length (now in *our* assembly code,
not a parser). Phase B keeps composite-type *creation* (`define_data_type`/`create_struct`) **deferred
to Phase C** (the widest surface + recursive-definition risk).

| STRIDE | Threat (structural Phase B) | L×I | Mitigation (control · module) |
|--------|------------------------------|-----|-------------------------------|
| **E** | **Type-aware structural agency without intent / escalation beyond the rename set** — the LLM autonomously sets a signature or applies a type | **H×H=Critical** | **same two-level default-deny** as Phase A: `session_enable_writes{allow_structural:true}` + each handler calls `require_write_consent(structural=True)` (the existing chokepoint — `manager.py:301-331`, **no new gate**); fixed allow-list (only `set_function_signature`/`apply_data_type` in Phase B; composite-type *creation* deferred to Phase C; `runScript` forbidden); `session_undo` reverts in one step (ADR-014 §1/§4) |
| **T** | **Type/signature C-parser injection** — an injection-steered type/signature string causes parser-bomb consumption, unintended type definitions, or smuggled markup in type names | **N/A — ELIMINATED by construction** | the input is a **structured `TypeRef`/`ParamSpec`/closed-vocab CC** model; the worker assembles typed Java `DataType`/`FunctionDefinitionDataType` objects from already-resolved handles — **`CParser`/`DataTypeParser` are never instantiated on a client value** (ADR-014 §2; abuse-case 31). A `named` `TypeRef` is a bounded identifier *looked up* in the `DataTypeManager`, never parsed; free-form C is the rejected alternative (ADR-013 §2a, ratified) |
| **T** | **Signature/storage re-flow corruption** — `updateFunction` (re-flowing params/storage) or its commit-time re-render of callers fails mid-operation → inconsistent program | M×M=**Med** | **type/function resolution is read-only and BEFORE `startTransaction`** (an unresolvable `TypeRef`/function is a clean `not-found`, no txn opened); **one transaction per write, rollback on any exception incl. commit-time** (the ADR-013 §4 CWE-460 fix — `_jvm_bridge.py:1533-1569` — which already covers the commit-time re-flow a signature change makes *more* likely to raise); bounded per-call timeout **kills the worker** on a hung re-flow (ADR-014 §4, abuse-cases 32/33) |
| **T** | **Larger re-flow/re-render tampering blast radius** — a signature change re-renders every **caller**; an applied type re-renders dependent data/decompilation (wider than a Phase-A one-function rename — ADR-013 §2c) | M×H=**High** | bounded by **one-transaction rollback** + **`session_undo`** (revert the last committed transaction) + **ADR-002 session ephemerality** (worst case is a mis-restructured **disposable** session, wiped on evict — never host/durable compromise); composite-type *creation* (the widest re-render) is deferred to Phase C (ADR-014 §1, abuse-case 36) |
| **T** | **Structural stored-injection / data-poisoning via parameter names** — a malicious `ParamSpec.name` (markup/path/zero-width/RTL/control) persisted and re-served by `function_context`/`decompile_function` | M×M=**Med** | **reuse `validate_write_name`** (the identifier allow-list — `validation.py:303-337`) on every parameter name IN; the read path re-wraps `Untrusted[...]` + re-normalizes OUT (ADR-005) — same two-sided defense as ADR-012/013 §7 (abuse-case 35) |
| **D** | **Construction-time / re-flow consumption** — oversized `parameters`, pointer depth, or array length, or a burst of signature changes each re-flowing callers, exhausts the worker | M×M=**Med** | **bounded at the boundary BEFORE any worker call**: `_MAX_PARAMS` (≈64), `_MAX_POINTER_DEPTH` (≈8), `_MAX_ARRAY_LEN` (≈65536) rejected as `VALIDATION`/`LIMIT_EXCEEDED`; an applied array/type footprint is **map-confined** by the worker before write; each write is one bounded transaction; the per-tool **timeout kills the worker** on a hung re-flow; concurrency cap + (HTTP) rate limit (CWE-400, `topic-reliability`, ADR-014 §2.5/§7, abuse-cases 34/40) |
| **R** | **Unattributable Phase-B mutation** | M×M=**Med** | **per-write audit: intent + outcome** (tool, session id (opaque), target sizes/param-count/flags, applied/denied — **never** binary-derived content or the new signature/type verbatim; redacted — `topic-logging-observability`); same posture as ADR-012/013 TB7-R |
| **E** | A Phase-B write bypasses the server to reach the JVM directly | L×H=**Med** | **ADR-001 invariant unchanged** — no JVM/PyGhidra import server-side (the architecture-invariant CI test covers the new `set_function_signature`/`apply_data_type` handlers); the write **and** the type resolution are a typed worker RPC, not in-process (abuse-case 39) |

**Residual risk (added to §5).** Phase B raises LLM08 agency once more: within an `allow_structural`
session the type-aware writes are autonomous, so an injection during that window can corrupt a
function's prototype (re-rendering its callers) or mis-apply a type before the operator notices —
bounded, not prevented, by the two-level opt-in, transaction rollback (incl. the commit-time fix),
per-write audit, `session_undo`, and ADR-002 ephemerality. **The highest-risk surface that ADR-013 §2
named — attacker-influenced type/signature strings parsed by the C parser — is ABSENT from this
increment by construction** (structured input, not free-form C — ADR-013 §2a, ratified). The worst
case is a mis-restructured **disposable** session, not host or durable-data compromise. **Still out of
scope:** Phase C composite-type *creation* (`define_data_type`/`create_struct` — its own gated,
separately-threat-modeled increment) and cross-session persistence (ADR-012 §4); `runScript`/arbitrary
script execution (permanently out of scope — PLAN §2).

### Abuse cases for the structural Phase-B increment (append to §6; benign/synthetic fixtures only)

These map 1:1 to new cases in `tests/security/test_abuse_cases.py` (ADR-014 §7). Each must FAIL the
attack (the control holds), deterministic + hermetic, synthetic fixtures only (master §5):

31. **Type-ref injection attempt rejected** — a `TypeRef.named` carrying C-declaration syntax / markup
    / `*`-laden text / a struct body (`"struct{int x;}"`, `"int*"`, `"a;b"`) is rejected by
    `validate_type_ref` (not a valid identifier; never parsed) → `VALIDATION`; no type defined/applied.
    (TB7-T — the design-eliminated C-parser surface, proven absent)
32. **Unresolvable-type fail-closed** — a well-formed but **unknown** `named` `TypeRef` surfaces
    `not-found` with the program unchanged (resolution is before `startTransaction`; no partial write).
    (TB7-T / atomicity)
33. **Signature re-flow corruption / commit-time atomicity** — a signature change whose
    `updateFunction` **or its commit-time re-flow** raises rolls back and surfaces `analysis-failed`;
    no dangling transaction, no untyped escape (the ADR-013 §4 CWE-460 fix). The program is unchanged.
    (TB7-T — extends case 26)
34. **Oversized-params / construction DoS** — `parameters` > `_MAX_PARAMS`, `pointer_levels` >
    `_MAX_POINTER_DEPTH`, or `array_len` > `_MAX_ARRAY_LEN` is rejected at the boundary
    (`VALIDATION`/`LIMIT_EXCEEDED`) before any worker call; a hung re-flow is bounded by the per-tool
    timeout that kills the worker. (TB7-D — extends case 28)
35. **Injection-steered malicious parameter name** — a `ParamSpec.name` with markup/`../path`/
    zero-width/RTL/control chars is rejected by `validate_write_name` (never written). (TB7-T —
    extends case 24)
36. **Cross-session structural isolation** — `allow_structural` + a signature/type apply on session A
    does not enable or mutate session B. (TB7-T / store-I — extends case 27)
37. **Structural-consent-required** — `set_function_signature`/`apply_data_type` on a session with
    `allow_structural=false` is denied "structural writes not permitted"; on a read-only session,
    "session is read-only" (the `require_write_consent(structural=True)` chokepoint —
    `manager.py:326-330`). (TB7-E / gating — extends cases 22/23)
38. **BOLA on the structural grant** — unchanged: a grant against an unknown/foreign session id yields
    the same `session-invalid` envelope (no oracle). (TB7-E / BOLA — same chokepoint as case 29)
39. **ADR-001 invariant under Phase-B writes** — the architecture-invariant test still passes: no
    JVM/PyGhidra import on any server-side module, including the new `set_function_signature`/
    `apply_data_type` handlers (the write **and** the type resolution execute only in the worker).
    (TB7-E — extends case 30)
40. **Address-not-in-map / out-of-bounds apply** — `apply_data_type` at an address outside the program
    memory map (or where the type footprint would overrun a region) fails closed
    (`analysis-failed`/`not-found`) with no write — worker map-confinement before the transaction.
    (TB7-T)

### TB7 (structural Phase C) — Composite-type creation (v1.1 — ADR-015, PROPOSED)

ADR-015 **Phase C** extends TB7 (structural) from Phase A's name-only renames and Phase B's
type-aware writes to the last structural-write rung — *creating* a NEW composite type:
`define_struct` and `define_union` (a composite built field-by-field from a bounded `FieldSpec`
list). It is **the same trust boundary** (TB7), **not a new one**: same TB1/TB6 (client
args/network), TB2 (server→worker RPC — gains two new write methods, same channel), TB4 (untrusted
worker output — note Phase C's result fields are all server/worker-controlled, so **none** are
`Untrusted`). **ADR-001 still holds: the server never loads the JVM or mutates; the field
resolution, the `StructureDataType`/`UnionDataType` assembly, and the `addDataType` write execute
only in the hardened worker.** Hostile-binary containment (TB3) and worker isolation (ADR-004) are
**unchanged**.

What is **new vs Phase B** (ADR-015 §1/§3/§5/§6): Phase C is the only structural write that **mutates
the program's type universe** (creates a type) rather than consuming existing types. The C-parser
surface ADR-013 §2 named stays **eliminated by construction** — a `FieldSpec.type` is the merged
Phase-B `TypeRef` (a flat reference, no nested define — ADR-015 §1), resolved by the existing
`_gh_resolve_type_ref`; `CParser`/`DataTypeParser` are never instantiated on a client value. The two
genuinely-new concerns are **(recursion)** a self-referential / cyclic definition (embed-self or
A↔B) — bounded by the ratified pre-registration model: the empty composite is **pre-registered in
the `DataTypeManager`** so a self-`named` *pointer* resolves (true self-referential structs work). A
by-value self-embed (incl. an array-of-self) is therefore an **explicit control** — rejected by the
boundary self-embed check (`validate_composite` → `VALIDATION`) and re-asserted defensively at the
worker (`_iter_composite_members`) — with the `_MAX_COMPOSITE_SIZE` total-size cap + transactional
rollback as backstops (any failure removes the pre-registered type, so no partial/orphan type survives); and **(integrity)** a **name collision** that, under a replace/keep conflict handler,
would silently overwrite or rename an in-use type — rejected fail-closed (no silent
replace/poison/wide-re-render). The wide re-render of ADR-013 §2c is **decoupled**: a new type
re-renders **nothing** until a *subsequent* Phase-B `apply_data_type` references it (already
threat-modeled). Composite *creation* is therefore the smaller surface once separated from
*application* — which is exactly why ADR-014 deferred it here.

| STRIDE | Threat (structural Phase C) | L×I | Mitigation (control · module) |
|--------|------------------------------|-----|-------------------------------|
| **E** | **Type-universe mutation without intent / escalation beyond the apply set** — the LLM autonomously creates a new struct/union | **H×H=Critical** | **same two-level default-deny** as Phase A/B: `session_enable_writes{allow_structural:true}` + each handler calls `require_write_consent(structural=True)` (the existing chokepoint — `manager.py:301-331`, **no new gate**); fixed allow-list (only `define_struct`/`define_union` in Phase C; nested-define + multi-type batches deferred; `runScript` forbidden); `session_undo` reverts the created type in one step (ADR-015 §1/§4) |
| **T** | **Recursive / self-referential definition** — a struct that embeds itself, or a cycle of structs (A embeds B embeds A), → infinite size / stack blow-up in assembly | M×M=**Med** | **fail-closed by construction** (pre-registration model, ADR-015 §3): the empty composite IS pre-registered before field resolution so a self-`named` *pointer* resolves (true self-referential structs work) — therefore a by-value self-embed is an **explicit control**: rejected by the **boundary self-embed check** (`validate_composite` → `VALIDATION`, incl. array-of-self) and **re-asserted at the worker** (`_iter_composite_members` rejects a `pointer_levels == 0` self-`named` member → rolled-back `analysis-failed`); a cross-type embed-cycle is **unconstructable** under one-composite-per-call/B-first (ADR-015 §1/§3); the `_MAX_COMPOSITE_SIZE` total-size cap + transactional rollback are the backstops (a failure removes the pre-registered type → no partial/orphan type). **Pointer-to-self is allowed and fixed-size.** No nested define → no recursive descent to bomb (abuse-cases 41/42/43) |
| **T** | **Name-collision integrity — silent redefine of an in-use type / data-poisoning** — a `define_*` whose `name` collides with an existing (recovered) type silently overwrites or renames it, corrupting every dependent decompilation | M×H=**High** | **fail-closed REJECT** conflict policy (ADR-015 §6): the worker checks for an existing type of that name (read-only `getDataType`) **before assembly + before `startTransaction`** and surfaces `analysis-failed` with **no write** if one exists; **never** `REPLACE_HANDLER`/silent-rename; Phase C is strictly **additive** (create genuinely-new types only) (abuse-case 44) |
| **T** | **Re-render blast radius of a new type** — defining a type re-renders dependent data/decompilation | L×L=**Low** (creation) | **bounded by construction**: a *new* type is referenced by **nothing** at `addDataType`, so creation re-renders **nothing**; the wide re-render is **decoupled** to the *subsequent* Phase-B `apply_data_type` (already threat-modeled — ADR-014 §7); a *redefine* of an in-use type is prevented by the §6 REJECT (ADR-015 §5) |
| **T** | **Structural stored-injection / data-poisoning via type / field names** — a malicious composite `name` or `FieldSpec.name` (markup/path/zero-width/RTL/control) persisted and re-served by `get_data_type`/`function_context`/`decompile_function` | M×M=**Med** | **reuse `validate_write_name`** (the identifier allow-list — `validation.py:362-396`) on the type name and **every** field name IN; the read path re-wraps `Untrusted[...]` + re-normalizes OUT (ADR-005) — same two-sided defense as ADR-012/013/014 §7 (abuse-case 47) |
| **D** | **Construction-time / fan-out consumption** — an oversized field count or total composite size (unbounded fan-out), or a burst of `define_*` calls, exhausts the worker | M×M=**Med** | **bounded at the boundary BEFORE / at the worker**: `_MAX_FIELDS` (≈256) and the per-field Phase-B `TypeRef` bounds rejected as `VALIDATION`/`limit-exceeded`; the assembled composite's **total computed size ≤ `_MAX_COMPOSITE_SIZE`** (≈1 MiB) is checked during worker assembly inside the one transaction — a post-resolution overflow **rolls back to `analysis-failed`**, while the boundary rejects the cases it can compute pre-resolution as `VALIDATION`/`limit-exceeded` (size sum overflow-guarded — CWE-190); each create is one bounded transaction; the per-tool **timeout kills the worker** on a hung assembly; concurrency cap + (HTTP) rate limit (CWE-400, `topic-reliability`, ADR-015 §2.3/§9, abuse-cases 45/46) |
| **R** | **Unattributable Phase-C mutation** | M×M=**Med** | **per-write audit: intent + outcome** (tool, session id (opaque), field count, applied/denied — **never** binary-derived content or the field names verbatim; redacted — `topic-logging-observability`); same posture as ADR-012/013/014 TB7-R |
| **E** | A Phase-C write bypasses the server to reach the JVM directly | L×H=**Med** | **ADR-001 invariant unchanged** — no JVM/PyGhidra import server-side (the architecture-invariant CI test covers the new `define_struct`/`define_union` handlers); the field resolution, the assembly, **and** the `addDataType` write are a typed worker RPC, not in-process (abuse-case 53) |

**Residual risk (added to §5).** Phase C raises LLM08 agency once more: within an `allow_structural`
session the composite-creation writes are autonomous, so an injection during that window can create a
junk type before the operator notices — bounded, not prevented, by the two-level opt-in, the §6
collision REJECT (no redefine-in-use), per-create audit, `session_undo`, and ADR-002 ephemerality.
**The two risks ADR-014 named for the deferral — recursive/self-referential definition and the wide
re-render — are designed out by construction** (the type isn't in the DTM at field-resolution, so
self-embed fails-closed; a new type re-renders nothing until a separately-threat-modeled Phase-B
`apply_data_type` references it — ADR-015 §3/§5). The worst case is a **junk type in a disposable
session**, wiped on evict — never host or durable-data compromise. **Still out of scope:** nested
`define` (an inline child composite in a field) and multi-type batches (their own future increments);
type deletion / redefinition of an existing type (the §6 REJECT keeps Phase C additive); enums/
typedefs/function-pointer composites; cross-session persistence (ADR-012 §4); `runScript`/arbitrary
script execution (permanently out of scope — PLAN §2).

### Abuse cases for the structural Phase-C increment (append to §6; benign/synthetic fixtures only)

These map 1:1 to new cases in `tests/security/test_abuse_cases.py` (ADR-015 §9). Each must FAIL the
attack (the control holds; the positive case 43 must SUCCEED), deterministic + hermetic, synthetic
fixtures only (master §5):

41. **Self-embed rejected (the recursion crux)** — a `define_struct` with a `FieldSpec.type` of
    `{named: "<this struct>"}` (no pointer — *embedding* self, incl. an array-of-self) is rejected at
    the boundary (`validate_composite` self-embed check → `VALIDATION`) and, defensively, **re-asserted
    at the worker** (`_iter_composite_members` rejects a `pointer_levels == 0` self-`named` member →
    rolled-back `analysis-failed`; the type IS pre-registered now, so this is an explicit guard, not a
    `not-found` — ADR-015 §3). No type defined; program unchanged.
    (TB7-D — the new recursive-definition surface, proven bounded)
42. **Embed-cycle cannot be assembled** — the "B-first, then A referencing B" flow cannot produce a
    true embed-cycle (A embeds B embeds A): defining B with an embedded not-yet-existing A fails
    `not-found`; a cross-type embed-cycle is unconstructable across the one-composite-per-call
    boundary (ADR-015 §1/§3.2). (TB7-D / integrity)
43. **Pointer-to-self allowed, fixed size (POSITIVE case)** — a `define_struct` modeling a
    linked-list `next` as `{named: "<this struct>", pointer_levels: 1}` (a true self-referential
    pointer, resolved against the pre-registered type; the opaque `{base: "void", pointer_levels: 1}`
    idiom also works) **succeeds**, size includes one pointer width, no blow-up. (Confirms the
    legitimate path works)
44. **Name-collision REJECT (no silent replace)** — a `define_struct`/`define_union` whose `name`
    already names a type in the `DataTypeManager` is rejected `analysis-failed` with **no write** (the
    existing in-use type is **unchanged** — the fail-closed REJECT handler); checked before
    `startTransaction`. (TB7-T — the redefine-in-use re-render / data-poisoning vector, proven absent)
45. **Oversized field-count / size DoS** — `fields` > `_MAX_FIELDS` (or a boundary-computable
    oversize) is rejected `VALIDATION`/`limit-exceeded` with no `addDataType`; a composite whose
    **post-resolution** total computed size exceeds `_MAX_COMPOSITE_SIZE` (e.g. 256 × `char[65536]`)
    is caught during worker assembly and **rolls back to `analysis-failed`** (the pre-registered type
    removed); size sum overflow-guarded (CWE-190/CWE-400). (TB7-D — extends Phase-B case 34)
46. **Duplicate field name rejected** — a composite with two `FieldSpec.name == "x"` is rejected
    `VALIDATION` (no write). (TB7-T / integrity)
47. **Malicious field / type name rejected** — a `FieldSpec.name` or the composite `name` with
    markup/`../path`/zero-width/RTL/control chars is rejected by `validate_write_name` (never written).
    (TB7-T — extends Phase-B case 35)
48. **Unresolvable field TypeRef fail-closed** — a `FieldSpec.type` with a well-formed but **unknown**
    `named` surfaces `not-found` with the program unchanged (resolution before `startTransaction`; no
    partial type). (TB7-T / atomicity — extends Phase-B case 32)
49. **TypeRef injection in a field rejected** — a `FieldSpec.type.named` carrying C-declaration syntax /
    a struct body (`"struct{int x;}"`, `"int*"`, `"a;b"`) is rejected by `validate_type_ref` (not a
    valid identifier; never parsed) → `VALIDATION`; no type defined. (TB7-T — the design-eliminated
    C-parser surface, proven absent; same class as Phase-B case 31, now in a field)
50. **Structural-consent-required** — `define_struct`/`define_union` on a session with
    `allow_structural=false` is denied "structural writes not permitted"; on a read-only session,
    "session is read-only" (the `require_write_consent(structural=True)` chokepoint). (TB7-E / gating —
    extends Phase-B case 37)
51. **Cross-session structural isolation** — `allow_structural` + a `define_struct` on session A does
    not enable or mutate session B. (TB7-T / store-I — extends Phase-B case 36)
52. **BOLA on the structural grant** — unchanged: a grant/define against an unknown/foreign session id
    yields the same `session-invalid` envelope (no oracle). (TB7-E / BOLA — same chokepoint as
    Phase-B case 38)
53. **ADR-001 invariant under Phase-C writes** — the architecture-invariant test still passes: no
    JVM/PyGhidra import on any server-side module, including the new `define_struct`/`define_union`
    handlers (the field resolution, the assembly, and the `addDataType` write all execute only in the
    worker). (TB7-E — extends Phase-B case 39)
54. **Commit-time atomicity** — a `define_struct` whose `addDataType` **or its commit** raises rolls
    back and surfaces `analysis-failed`; no dangling transaction, no half-created type (the reused
    `_in_transaction` — CWE-460). The program is unchanged. (TB7-T — extends Phase-B case 33)

### TB5 (delta) — Behavioral-equivalence differential run (v1.1 — ADR-016, ACCEPTED)

ADR-016 completes ADR-010's deferred `behavioral_equivalence` field. It measures whether the rebuilt
artifact behaves like the original **without ever running the hostile sample** (ADR-001 / D1): it
compares two **builds** on shared **synthetic** inputs — **(A)** a build from the fixture's
**trusted known source** (cJSON) and **(B)** the **recompiled renamed-decompiled-C** — and reports
the fraction of input vectors whose `(exit_code, stdout)` match byte-exactly (D2). It is computable
**only** for ground-truth fixtures carrying trusted source + inputs; otherwise it stays `None`
(honest unavailability — never a fabricated number). Diffing against the *real hostile original* is
**rejected** for v1.1 (would breach ADR-001).

This is the **same TB5 boundary** — attacker-derived C compiled — **not a new one**. ADR-016 only
**extends** it from compile-only to compile→**run**→capture (`ContainerExecRunner`), inside the
identical isolation `ContainerCompileRunner` already enforces (rootless, `--network none`, read-only
rootfs, all caps dropped, `no-new-privileges` + seccomp, CPU/memory/**pids** caps, killed on
timeout, non-root). The new surface is: (a) **executing** the candidate build (and, uniformly, the
trusted reference build — lower risk, still sandboxed); (b) feeding **author-controlled synthetic**
stdin vectors (NOT attacker-controlled); (c) **capturing bounded output**. The built artifact runs
from a dedicated `exec`-allowed tmpfs (`/run/x`) while the rootfs stays read-only and the compiler
scratch (`/tmp`) stays `noexec`. The differential **core executes nothing** — it only compares the
inert captured `(exit_code, stdout)` run-results (ADR-005); captured stdout is **data** (compared,
never executed/rendered). The pure metric is `None`/zero on any failure, so a stub/non-recompiling
candidate scores low **honestly**, never a harness crash.

| STRIDE | Threat | L×I | Mitigation |
|--------|--------|-----|------------|
| **T** | A malicious candidate build corrupts host/toolchain state | L×H=**Med** | build+run in a rootless container; read-only rootfs; source mounted **ro**; writable surfaces are ephemeral tmpfs only (`/tmp` noexec scratch + a small `/run/x` exec tmpfs for the artifact); non-root, all caps dropped |
| **I** | A candidate program (or `#include`/pragma) reads host files or exfiltrates | M×M=**Med** | `--network none` (no egress); no host paths mounted but the ro source; captured stdout is size-capped + carried as inert data; the sandbox holds no secrets |
| **D** | A candidate that **hangs, fork-bombs, over-allocates, or floods stdout** exhausts CPU/mem/pids/disk/the host | M×M=**Med** | engine **kill-on-timeout** (hang/loop); **pids** cap (fork-bomb); **memory** cap + OOM-kill (over-allocate); **bounded-streaming output-size cap** — the runner reads at most `max_stdout_bytes` at the subprocess boundary (`_read_capped`), so a stdout flood cannot blow up host memory **during** capture (ADR-016 F1; not merely the retained output), backstopped by kill-on-timeout + the memory/OOM cap (stdout flood — D3); each maps to `RunResult(ok=False)` → an honest non-match, not an escape or crash |
| **E** | Candidate-program / sandbox escape to host | L×H=**Med** | gVisor runtime in prod (ADR-004); `no-new-privileges` + seccomp; caps dropped; pinned + verified compiler image (supply chain); the hostile **binary** is never executed (D1) so no new "run the sample" boundary opens |

### Abuse cases for the behavioral-equivalence increment (append to §6; benign/synthetic fixtures only)

These map 1:1 to new cases in `tests/security/test_abuse_cases.py` (ADR-016 §Security). The
**boundary/pure** assertions (the output-cap logic, the metric's `None`/zero paths) are **hermetic**
(no real sandbox — a fake bytes-runner / direct calls, synthetic data only — master §5); the
**live-sandbox** ones (a real hanging / fork-bombing / over-allocating candidate contained by the
engine) keep the `skip`-marked integration convention. Each must FAIL the attack (the control
holds), deterministic + hermetic where marked:

55. **Output-flood contained (HERMETIC)** — a candidate whose run emits unbounded stdout is captured
    only up to `max_stdout_bytes`; `ContainerExecRunner` truncates the `RunResult.stdout` to the cap
    (anti output-flood DoS — D3). The byte-exact compare is over the capped prefix. **Residual:**
    `max_stdout_bytes` bounds peak host buffering **during** capture: the runner reads a bounded
    `read(cap)` at the subprocess boundary (`_read_capped`), not `capture_output`/`communicate` which
    would buffer the whole stream first (ADR-016 F1 closed; CWE-400). (TB5-D)
56. **Hostile run fails closed → honest non-match (HERMETIC)** — a build/spawn failure (engine
    `OSError`) or a non-recompiling candidate maps to `RunResult(ok=False)`, which
    `behavioral_equivalence` scores as a **non-match for every vector** → a low/zero metric, never a
    crash or a fabricated match (D2). A degenerate run pair (empty / mismatched-length) yields `None`
    (unavailable), not a guess. (TB5-D — measured-not-guaranteed)
57. **Captured output is data, never executed (HERMETIC)** — the differential core only *compares*
    the inert `(exit_code, stdout)` run-results; it never executes/evals/renders captured stdout
    (ADR-005). A `RunResult.stdout` that *would* be dangerous if eval'd round-trips as inert bytes
    through `behavioral_equivalence` with no side effects. (TB5-S/E — same posture as abuse-case 5)
58. **Hostile original is never executed (HERMETIC)** — the harness compares two C *builds* (trusted
    source A, recompiled candidate B); neither the `ExecRunner` port nor the metric ever receives or
    runs the analyzed binary. `behavioral_equivalence` is `None` when no trusted reference is supplied
    — it cannot be computed against the hostile sample (D1 / ADR-001, recorded out of scope). (TB5-E)
59. **Hang / fork-bomb / over-allocate contained (LIVE)** — a candidate TU that infinite-loops,
    fork-bombs, or over-allocates is reclaimed by the engine **timeout** / **pids** cap / **memory**
    cap (mapped to `ok=False`), not an escape or a stuck harness. Promoted to live integration (needs
    the real sandbox). (TB5-D)
60. **Sandbox isolation parity (LIVE)** — the `ContainerExecRunner` build+run enforces the SAME
    hardening as `ContainerCompileRunner` (`--network none`, read-only rootfs, dropped caps,
    `no-new-privileges`, resource caps) plus the exec-tmpfs/noexec-scratch split; a candidate cannot
    egress, write the host, or escalate. The argv-hardening half is asserted hermetically in
    `tests/unit/test_naming_compile.py`; the live containment is promoted to integration. (TB5-T/I/E)

### TB5 (delta) — Deeper behavioral-equivalence: output normalization + seeded fuzz (v1.2 — ADR-022)

ADR-022 refines the **measured** ADR-016 signal with two **pure, client-side** additions — **no new
boundary** and no new exec surface (the same `ContainerExecRunner` / TB5 sandbox just runs more
vectors). It **still never runs the hostile original** (ADR-001 / D1 preserved): A = trusted-source
build, B = recompiled renamed-C, both sandboxed.

- **Output normalization** (`normalize_output`, `behavioral_equivalence_normalized`) is a **pure
  inert transform** on already-captured `(exit_code, stdout)` bytes (ADR-005): it canonicalizes
  whitespace/line-endings and masks **volatile** tokens (pointer-like `0x…` hex, `HH:MM:SS` /
  ISO-8601 timestamps, clearly-labelled PIDs) before a *second*, looser compare. It **executes
  nothing**, masks only narrow well-delimited shapes (conservative — leaves ordinary text untouched,
  so it can only loosen: `normalized >= strict`), and `exit_code` is **never** normalized. The
  strict byte-exact `behavioral_equivalence` is **unchanged** and stays the **primary, conservative**
  signal; normalized is reported **alongside** it as the *equivalent modulo volatile output* signal —
  clients must not read it as a guarantee (it admits false positives by design).
- **Seeded fuzz vectors** (`generate_fuzz_vectors(seed, count, max_len)`) are **author-generated,
  synthetic, deterministic** stdin bytes (a fixed seed → fixed vectors via a *local* `random.Random`
  — **no wall-clock / no module-level randomness**, hermetic per `topic-testing`), **bounded** in
  count and per-vector length (CWE-400). They are fed to **both** builds through the existing TB5
  sandbox — never attacker-controlled, never driving the host. The generator only *produces* inert
  bytes; it executes nothing and fails closed (`ValueError`) on a negative bound.

**Measured-not-guaranteed preserved.** Both scores are quality *signals*, not guarantees; strict
stays the honest conservative number. The pure functions are 100%-covered unit-tested (normalizer
masking + a non-masking case proving no over-stripping; fuzz determinism + bounds; the headline
pointer-only-diff → strict<1 / normalized==1; and the `normalized >= strict` invariant on a mixed
set — `tests/unit/test_naming_metrics.py`); the gated differential e2e runs fixed **+** fuzz vectors
and reports both scores (`tests/e2e/test_behavioral_equivalence_oss.py`).

## 11. Addendum — v1.1 multi-principal authorization (TB6 strengthened — ADR-017)

ADR-017 makes the HTTP boundary (TB6) truly multi-principal and **closes the TB6-I per-principal
BOLA gap that ADR-011 §6 deferred**. Two mechanisms: (1) a **multi-token bearer** identity source
(`{token: principal-id}`, constant-time, no which-token timing oracle, generic reject); (2)
**per-principal session ownership** enforced in the single `SessionManager._get_live_locked`
chokepoint, so every session-scoped entry point (authorize, enable/disable writes, require-consent,
`ensure_worker`, tool-initiated close) denies a foreign caller the **same `SESSION_INVALID`** as an
unknown id (D2 — no oracle). Owner is server-derived at create and immutable. An operator-configurable **per-owner session
cap** (`GHIDRA_MCP_MAX_SESSIONS_PER_OWNER`; default off, global cap backstops) bounds noisy-neighbor. No tool/RPC/error-envelope contract change (reuses `SESSION_INVALID`);
ADR-001 preserved (authZ is server-only; worker untouched). See the strengthened **TB6** STRIDE rows
above.

### Cross-principal abuse cases (append to §6; benign/synthetic fixtures only)

These map 1:1 to `tests/security/test_abuse_cases.py` (TB6 multi-principal block) and run against the
**real** `SessionManager` + `MultiTokenBearerAuthenticator` (hermetic — injected clock, distinct
synthetic principal ids, synthetic tokens; NO real secrets/worker). Each FAILS the attack.

61. **Cross-principal READ** — principal B presenting A's live `session_id` to `authorize` is denied
    the **same `SESSION_INVALID`** as an unknown id (byte-identical envelope; no "exists"/"owned"
    leak). A's session is untouched and still authorizable by A. (TB6-I / BOLA / API1)
62. **Cross-principal WRITE** — B cannot `enable_writes` / `require_write_consent` /
    `ensure_worker`-spawn on A's session — all yield the same `SESSION_INVALID`; the op never runs
    (A's consent flag unchanged, no worker spawned for B). (TB6-E / TB7)
63. **Cross-principal CLOSE** — B closing A's session (`evict` with caller=B) is denied the same
    `SESSION_INVALID`; A's session is **not** evicted. (TB6-I/E)
64. **Principal spoof** — no token / wrong token / wrong scheme / empty token → generic `401`/`None`
    (no credential or which-token oracle); the only way to become a principal is to present its
    secret token. (TB6-S)
65. **Timing-oracle resistance (structural)** — the multi-token compare scans **every** entry with
    no early return; a last-position token still matches, proving the work is independent of which
    token matches. (TB6-S)
66. **Per-owner cap (noisy-neighbor)** — one principal at its per-owner session cap cannot create
    more (`LIMIT_EXCEEDED`), yet another principal can still create — no cross-principal starvation.
    (TB6-D / `topic-multi-tenancy`)
67. **Cross-principal isolation end-to-end (LIVE)** — two principals with distinct bearer tokens over
    the real HTTP transport: B presenting A's `session_id` gets `SESSION_INVALID` and A's
    session/worker/store are untouched. The manager + authenticator controls are proven hermetically
    (61-66); the per-request-principal → `ToolContext` → manager wiring is promoted to integration
    (WS5). (TB6-I)


## 12. TB8 — Annotation-import document → Server (v1.2 — ADR-018, ACCEPTED design)

The first **v1.2** increment adds cross-session annotation **persistence**: `session_export_annotations`
emits a versioned, **binary-hash-bound**, structured (inert) document of the session's `USER_DEFINED`
annotations; `session_import_annotations` **replays** such a document into a fresh same-binary session.
Persistence is **stateless/client-owned** (the server stores nothing — ADR-002 preserved); the new
boundary is the **import** of a client-supplied, possibly offline-tampered document.

**Core property:** import adds **no new write primitive** — it is a schema-validated, hash-bound,
consent-gated **batch replay of the existing v1.1 gated writes**, each re-validated and transacted. Its
blast radius equals the v1.1 write tools', no more.

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** | Document forged for / claims a different binary | `binary.sha256` verified against the session's real program hash; mismatch → fail closed (`validation`/`not-found`) |
| **T** | Document tampered offline (smuggled/injection-bearing entries) | every entry re-validated through the **live validators** (`validate_write_name`/`validate_comment_text`/`validate_target_ref`/`validate_type_ref`/`validate_signature`/`validate_composite`) and applied only via the **existing gated write path**; no document claim is trusted (two-sided validate-in defense) |
| **R** | Repudiation of a bulk import | per-import + per-entry audit (count, principal, session, outcome — sizes/flags only, never the values) |
| **I** | Confidential/hostile artifacts leave the session | strings stay untrusted-wrapped (ADR-005); **server persists nothing** (stateless); the exported document inherits the binary's CONFIDENTIAL class (master §5) — owned + classified by the client |
| **D** | Oversized / flooding document | bounded entry count + per-field sizes (schema); each replay is a bounded transaction; consent-gated; owner-scoped |
| **E** | Import does more than live writes / cross-owner | import ≡ existing gated writes (same consent, same `allow_structural`, same validators); **owner-scoped** (ADR-017) — a principal imports only into its own session |

**Residual / assumptions:** the client owns the exported artifact's confidentiality + integrity at rest
(out of our boundary by D2); applicability is content-hash-bound (no fuzzy/cross-binary apply).

### Abuse cases for the annotation-persistence increment (append to §6; benign/synthetic fixtures only)

These map 1:1 to the v1.2 ADR-018 tests (`tests/unit/test_annotation_validation.py`,
`tests/unit/test_annotation_persistence.py`) and run against the **real** `validate_annotation_document`
+ the real registry handlers with a fake `SessionManager` + `FakeGhidraPort` (hermetic — synthetic,
value-free fixtures, no real binary/secret/worker; the JVM-edge `_gh_export_annotations` enumeration is
integration-skipped like prior worker rungs). Each must FAIL the attack (the control holds); the
positive cases (68 export round-trip; 70 happy import) must SUCCEED:

68. **Export is read-only, owner-scoped, Untrusted-wrapped (POSITIVE)** — `session_export_annotations`
    requires **no** write consent, is denied the BOLA-safe `SESSION_INVALID` for a foreign/unknown id,
    emits only user-authored annotations dependency-ordered, wraps binary-derived strings
    `Untrusted` (ADR-005), and the **server overlays the authoritative `binary.sha256`** (not the
    worker's). The server persists nothing. (TB8-I/E)
    - **ADR-027 (v1.3, F7 narrowing — no new boundary):** export is now scoped to **session-authored
      targets**, fixing F7 over-inclusion (a 39-rename session leaked 13 auto-structs + 1138
      auto-comments). **Symbols + signatures** stay `USER_DEFINED`-enumerated (Ghidra's authoritative
      provenance). **Comments + composites** lack a reliable provenance signal, so the worker reads
      ONLY a server-supplied **change-log** selection — the comment/composite targets THIS session's
      gated writes actually applied. The change-log is **in-memory, session-lifetime, wiped on evict**
      and holds **identity keys only** (`(address, comment_type)` pairs + composite names) — **never a
      binary-derived value** (ADR-002/master §5). No trust boundary changes: TB8's import side is
      untouched; this is a correctness narrowing of the existing read-out. (TB8-I, ADR-018/ADR-027)
69. **Wrong-binary hash → fail closed** — `session_import_annotations` of a document whose
    `binary.sha256` ≠ the session's recorded program hash (or a session with no recorded hash) is
    rejected `VALIDATION` **before any write**; applying one binary's addresses/types to another is
    refused. (TB8-S — the applicability-spoof crux)
70. **Happy import replays the existing gated writes (POSITIVE)** — a well-formed, hash-matching,
    consented document applies every entry **via the existing write handlers/port methods** (a
    full-kinds document exercises all nine — proving import adds **no new write primitive**); the
    per-entry outcome report records applied/rejected (counts + kind/index only, never values).
    (TB8 core property)
71. **Tampered / injection-bearing entry rejected** — a document entry with an injection-steered
    `new_name` (markup / `../path` / zero-width / RTL / control char), a malicious comment, or a
    `TypeRef.named` carrying C-declaration syntax is rejected by the **live validators**
    (`validate_annotation_document` → `validate_entry` → `validate_write_name`/`validate_comment_text`/
    `validate_type_ref`) — fail closed, no write. Offline edits cannot smuggle an unvalidated write.
    (TB8-T)
72. **Oversized count / field → bounded** — a document with > `_MAX_ENTRIES` entries is
    `LIMIT_EXCEEDED`; an over-length comment is `LIMIT_EXCEEDED`; field/param/composite bounds reuse
    the existing write caps (DoS — CWE-400). (TB8-D)
73. **Structural entry without `allow_structural` → denied** — an import containing **any** structural
    entry — the Phase-A name-only renames `rename_local_variable`/`rename_parameter` (ADR-013) **or**
    the type-aware `set_function_signature`/`apply_data_type`/`define_struct`/`define_union`
    (ADR-014/015) — on a session with write consent but **not** `allow_structural` is denied up front
    "structural writes not permitted"; on a read-only session, "session is read-only" (the same
    `require_write_consent(structural=True)` chokepoint as live writes — the human-in-the-loop gate is
    not bypassed by importing). The up-front import gate (`STRUCTURAL_ENTRY_KINDS`) is single-sourced
    with the per-entry handlers, so it lists **every** kind whose handler requires structural consent.
    No structural write committed. (TB8-E / LLM08)
74. **Cross-owner import → `SESSION_INVALID`** — principal B importing into A's session is denied the
    same BOLA-safe `SESSION_INVALID` as an unknown id; A's session is untouched and no write runs
    (owner-scoped — ADR-017). (TB8-E / BOLA)
75. **Unknown `kind` / `schema_version` → rejected** — an entry with an unknown `kind` is rejected at
    document construction (the discriminated union admits no other variant); an unsupported
    `schema_version` is rejected `VALIDATION` (forward-compat is opt-in, never silent). No write.
    (TB8-T / fail-closed)
76. **Per-entry transaction + best-effort report** — a validation-clean entry whose **write** cannot
    apply (e.g. worker `not-found`) is recorded as rejected with a safe reason while the other clean
    entries still apply (each its own transaction; partial application matches the per-write model).
    The server persists nothing across the batch. (TB8-T / atomicity)
77. **ADR-001 invariant under persistence** — no JVM/PyGhidra import on any server-side module,
    including the new export/import handlers and the schema/validation code: export enumeration runs in
    the worker (`_gh_export_annotations`); import re-validation + replay-orchestration are JVM-free
    server code over the existing write RPCs. (TB8-E — extends the prior ADR-001 invariant cases)

## 13. TB6 (delta) — mTLS + OAuth identity sources (v1.2 — ADR-019; mTLS + OAuth BUILT)

Builds out the two `Authenticator` stubs ADR-011 left port-ready, **hardening TB6 — no new boundary**.
Both map a request to a `Principal(id)` that feeds the **ADR-017 ownership mechanism unchanged**
(distinct identity = distinct owner-scoped sessions). Delivered as two increments: **mTLS first —
BUILT (ADR-019 increment A)** (server-terminated, in-app uvicorn TLS + the `peer_certificate` seam —
no new dep; abuse cases 67-71 added below), **OAuth second — BUILT (ADR-019 increment B)** (a Bearer
**JWT** validated locally via JWKS — adds a pinned, vetted PyJWT+cryptography dep, `std-supplychain`;
abuse cases 72-82 added below).

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** | Forged / shared-secret identity | identity is **cryptographically proven** — CA-signed client cert (chain verified at the TLS layer to a configured CA) or a JWKS-verified JWT signature; generic `401`, no which-identity oracle |
| **T** | Tampered cert / token | mTLS chain verified to the configured CA; JWT verified with a **pinned alg** (no `alg:none`/RS-HS confusion) + `iss`/`aud`/`exp`/`nbf` |
| **R** | Repudiation | auth events logged (principal id, mechanism, outcome) — never the token/cert material |
| **I** | Credential disclosure | uniform `401`; token/cert never logged or echoed |
| **D** | Auth-path DoS | JWKS cached + bounded (no per-request IdP round-trip); mTLS handshake bounded; existing rate-limit/size caps |
| **E** | Mechanism grants extra capability | a valid identity gets only the read-only catalog + its **own** owner-scoped sessions (ADR-017); sub→principal only — per-scope/role authZ is out of scope |

**mTLS = server-terminated, in-app** (reverse-proxy-header trust is a deferred footgun). **OAuth =
JWT/JWKS local** (introspection deferred).

**mTLS abuse cases — ADDED (ADR-019 increment A), `tests/security/test_abuse_cases.py`:**
- **Case 67** — no client cert (None peer cert) → generic reject (fail closed, defense in depth atop
  the handshake gate). *(hermetic)*
- **Case 68** — empty / missing mapped field (empty CN, no CN) → generic reject (no anonymous
  principal). *(hermetic)*
- **Case 69** — two distinct verified certs → two distinct principals → two distinct owner-scoped
  sessions; cross-principal access is the same `SESSION_INVALID` as unknown (composes ADR-017,
  cases 61-63). *(hermetic)*
- **Case 70** — a cert from an **untrusted CA** (and a client presenting **no** cert) is rejected at
  the **TLS handshake** (uvicorn `ssl_cert_reqs=CERT_REQUIRED` + `ssl_ca_certs` — the connection never
  reaches the app; config guarantees the CA bundle is set for `auth_mode=mtls`). *(LIVE — implemented
  in `tests/integration/test_mtls_bridge.py`, integration-gated; a live uvicorn TLS listener + a
  synthetic untrusted-CA keypair. The same live test proves the POSITIVE path: a CA-signed cert
  authenticates as its CN-derived principal via the ADR-020 peer-cert bridge.)*
- **Case 71** — the cert subject/SAN material is **never logged** (TB6-R/I); `AuthContext` keeps the
  peer cert out of `repr`. *(hermetic)*

Cert parsing is hermetic with **synthetic** parsed-cert dicts (the `ssl.getpeercert()` shape); the
live uvicorn mTLS handshake (case 70) is integration-gated — no real keys/secrets.

**OAuth abuse cases — ADDED (ADR-019 increment B), `tests/security/test_abuse_cases.py`:**
- **Case 72** — a valid JWT → `Principal(sub)` → a distinct, owner-scoped session; cross-principal
  access is the same `SESSION_INVALID` as unknown (composes ADR-017, cases 61-63). *(hermetic)*
- **Case 73** — an unsigned **`alg:none`** token → generic reject (the pinned asymmetric allow-list
  forbids it; the token's `alg` is never trusted). *(hermetic)*
- **Case 74** — **alg-confusion** (an `HS256` token forged with the RSA *public* key as the HMAC
  secret, when only `RS256`/`ES256` are allowed) → reject. *(hermetic)*
- **Case 75 / 76** — wrong **`iss`** / wrong **`aud`** → reject. *(hermetic)*
- **Case 77 / 78** — **expired (`exp`)** / **not-yet-valid (`nbf`)** → reject. *(hermetic)*
- **Case 79** — **bad signature** (signed by a different key than the JWKS key) → reject. *(hermetic)*
- **Case 80** — **unknown `kid`** / JWKS-fetch failure → fail closed (bounded; no fail-open).
  *(hermetic — JWKS client mocked to raise)*
- **Case 81** — **missing `sub`** (validly signed) → reject (no anonymous principal). *(hermetic)*
- **Case 82** — the **token is never logged** (TB6-R/I); the authenticator's `repr` carries no token.
  *(hermetic)*

JWT validation is hermetic with an in-test **RSA/EC keypair** (PyJWT mints the tokens) and a
**mocked JWKS fetch** (the cached client is seeded directly) — no live IdP / network / real secrets.
The live IdP+JWKS path (real `PyJWKClient` fetch + a real IdP-minted token over the HTTP transport) is
**integration-gated** with a tracked reason.

**Live status (mTLS — FUNCTIONAL, ADR-020):** the authenticator + cert-field mapping + config + the
`CERT_REQUIRED` transport gate (ADR-019 increment A) are complemented by the uvicorn transport→scope
peer-cert **bridge** (`MtlsAwareProtocol`, ADR-020) — so `auth_mode=mtls` is **end-to-end
functional**: the verified client cert reaches the authenticator and resolves to its cert-derived
principal. The handshake `CERT_REQUIRED` gate is the first line; the in-app authenticator the second
(defense in depth). Fail-closed preserved (an empty/absent `getpeercert()` injects no `peercert` →
generic `401`); the cert is read **only** from the verified TLS object, never a header (no spoofing).
Verified live by `tests/integration/test_mtls_bridge.py` (real TLS, synthetic certs). No fail-open.

**Live status (OAuth, increment B):** the authenticator (JWKS fetch+cache, pinned-alg signature
verify, `iss`/`aud`/`exp`/`nbf`, `sub`→principal, fail-closed) + config + `build_authenticator`
wiring are built and unit-proven. The JWKS client is built lazily and reused (no per-request IdP
round-trip — TB6-D); the only network touch is the cached JWKS fetch, integration-gated in tests.


## 14. TB7 (delta) — Multi-type composite batch `define_types` (v1.2 — ADR-021, ACCEPTED design)

Extends the write/agency boundary (**TB7**, no new boundary): a new gated `define_types` tool creates
a **batch of interdependent new composites** in one transaction, where a field may reference **another
new composite in the same batch**. Generalizes ADR-015's pre-registration (pre-register ALL empties in
the batch → resolve → add → one transaction, rollback-all). The **load-bearing new control is a
by-value cycle detector.**

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **D** | A **by-value cycle** (A embeds B embeds A, or self) → infinite-size type | a **real by-value graph cycle detector** (pure, boundary, `O(V+E)`) rejects any cycle over `pointer_levels==0` member edges (incl. self / array-of-self) → `VALIDATION`, no write. **Pointer edges create no cycle** (fixed-size) → mutually-recursive *pointer* structs allowed |
| **D** | Oversized batch / fan-out | `_MAX_TYPES_PER_BATCH` + `_MAX_FIELDS`/type + **batch-total** size cap; one bounded transaction; per-tool timeout kills the worker |
| **T** | Partial / corrupt batch | **one transaction, rollback-all** on any failure — no partial batch, no orphan type |
| **I/E** | Injection / over-agency | structured `TypeRef` only (no C parser — ADR-014); name-collision (existing or intra-batch dup) fail-closed REJECT (ADR-015 §6); **structural** write-consent (ADR-012); owner-scoped (ADR-017); server never assembles (ADR-001) |

The formal abuse-case list landed with the implementation PR (`tests/security/test_abuse_cases.py`,
continuing the numbering after the current last case 82):

83. **By-value self-cycle rejected** — a `define_types` batch with a struct whose member embeds
    itself by value (`named == self`, `pointer_levels == 0`, incl. array-of-self) is rejected
    `VALIDATION` by the per-type self-embed check + the by-value cycle detector; no write. (TB7-D)
84. **A↔B by-value cycle rejected** — A has a by-value member of B and B a by-value member of A →
    the cycle detector rejects `VALIDATION`, no write. (TB7-D — the load-bearing control)
85. **A→B→C→A by-value cycle rejected** — a 3-node by-value cycle is detected/rejected. (TB7-D)
86. **A↔B POINTER cycle ALLOWED (positive)** — A has `B *next` and B has `A *prev`
    (`pointer_levels >= 1`) → no edge → the detector allows it (mutually-recursive pointer
    structures). Also: a diamond (A→B, A→C, B→D, C→D, by value, acyclic) is allowed. (positive)
87. **Oversized batch / per-type / batch-total** — a `types` list over `_MAX_TYPES_PER_BATCH` →
    `LIMIT_EXCEEDED` at the boundary; an over-`_MAX_FIELDS` per-type → `LIMIT_EXCEEDED`; a
    batch-total computed size over `_MAX_COMPOSITE_SIZE` → `limit-exceeded` at the worker
    (integration-gated, like ADR-015 case 45). (TB7-D / CWE-400/190)
88. **Duplicate type name in batch** — two batch entries named `T` → `VALIDATION`, no write. (TB7-T)
89. **Collision with an existing program type** — a batch name that already names a program type →
    fail-closed REJECT `analysis-failed`, whole batch rolled back (worker concern,
    integration-gated). (TB7-T)
90. **Partial failure → whole batch rolled back** — any member failure (unresolvable ref, size cap,
    `addDataType`/commit) rolls back the WHOLE batch via `_in_transaction` — no partial/orphan type
    (integration-gated). (TB7-T — one transaction, rollback-all)
91. **No C parsed** — a `CompositeSpec` field `type.named` carrying C-declaration syntax / a struct
    body is rejected by `validate_type_ref` (never parsed); the architecture-invariant scan confirms
    no `CParser`/`DataTypeParser` on a client value. (TB7-I)
92. **Cross-owner → SESSION_INVALID; structural-consent required** — `define_types` on a
    foreign/unknown session yields the same `SESSION_INVALID` envelope (BOLA, no oracle); on a
    session without `allow_structural`, it is denied (`require_write_consent(structural=True)`
    chokepoint). (TB7-E / gating / BOLA)

## 15. Note — live-regression CI harness (v1.3 — ADR-028, ACCEPTED)

The scheduled/labeled live-regression job (`.github/workflows/live-regression.yml`) drives the real
worker end-to-end (F2 + F7 hard gates) on **benign, locally-built synthetic micro-binaries only**
(master §5 — no real malware) under the **CI-relaxed crun** isolation (every other ADR-004 floor
held; prod keeps runsc/gVisor — `deploy/README.md`). It introduces **no new trust boundary**: it
exercises the EXISTING TB1–TB4 chain (client→server→worker→export) with trusted, in-repo fixtures —
the supply-chain controls of §4 (digest-pinned actions, signed worker image cosign-verified before
use, least-privilege OIDC) apply unchanged.
