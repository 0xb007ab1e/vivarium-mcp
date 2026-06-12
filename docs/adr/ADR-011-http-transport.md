# ADR-011: HTTP transport (v1.1) — secure-by-default, auth-pluggable

- **Status:** Proposed (design; gated — no transport code until this + the TB6 threat model are reviewed)
- **Date:** 2026-06-11
- **Deciders:** Human + PM (locked decisions below); recorded by Software Architect
- **Supersedes the deferral in:** ADR-006 (stdio-first; HTTP a gated v1.1 increment)

## Context

ADR-006 shipped stdio-only in v1 and kept the transport seam isolated to the `server/` shell
(`core`/`tools`/`sessions`/`security`/`ghidra` are transport-agnostic). HTTP adds the first
**network trust boundary** to the system: authentication, authorization, transport security, CORS,
rate limiting, payload caps, and exposure of the whole read-only tool surface to remote callers.
That boundary is threat-modeled separately as **TB6** (`docs/security/threat-model.md`); this ADR
records the **locked design decisions** that TB6's mitigations and the implementation slices build
on. It activates the rule modules ADR-006 deferred: `std-owasp-api`, `std-zero-trust`,
`topic-authn-authz` (re-imported in `CLAUDE.md`).

The use case remains a **single operator / their LLM host on the local machine** (occasionally a
trusted LAN or a reverse-proxied endpoint) — *not* a multi-tenant public SaaS. Decisions favor the
**smallest safe default** with explicit, gated opt-in to wider exposure.

## Decision

### 1. MCP transport flavor
Implement MCP **Streamable HTTP** (the current spec, 2025-03+). The deprecated HTTP+SSE transport is
**not** implemented. The stdio transport is unchanged and remains the default.

### 2. Bind modes (exposure) — secure-by-default
Transport + bind are config-selected; the **default is unchanged (stdio)**. HTTP supports three bind
modes, in order of increasing surface:
- **Loopback TCP (default for HTTP):** bind `127.0.0.1` only. Plaintext permitted (no network hop).
- **Unix domain socket (optional, same-host):** filesystem-permission auth, no TCP port; plaintext
  permitted. For same-host multi-client without exposing a port.
- **Network TCP (opt-in, GATED):** any non-loopback bind (incl. `0.0.0.0`) **requires TLS and an
  authenticator**, and is a **gated action** (it exposes the analysis surface to the network —
  `workflow-gated-actions`). The server **fails closed at startup** if a non-loopback bind is
  requested without TLS + auth configured.

> Secure-by-default (master §2): the safe configuration is the default; power is opt-in, never
> opt-out of safety.

### 3. Authentication — bearer baseline, strategy-pluggable (`Authenticator` port)
Authentication is a **strategy port** in the server shell so the three mechanisms compose behind one
interface (`authenticate(request) -> Principal | Reject`), default-deny:
- **Bearer token (BUILT in this increment):** a high-entropy token from the secret manager / injected
  env (never in code/config/VCS — `workflow-secrets`); **constant-time** compare; reject
  unauthenticated/invalid with a generic `401` (no oracle). Required for every TCP bind.
- **mTLS (port-ready, built when needed):** client-certificate verification per `std-zero-trust`;
  the `Authenticator` interface accommodates it (cert → `Principal`) without reworking the shell.
- **OAuth 2.1 resource-server (port-ready):** the MCP remote-auth profile (authorization-code +
  PKCE; validate `iss`/`aud`/`exp`, pinned alg) for any future multi-user/remote exposure.

Loopback and UDS binds **may** run unauthenticated (single trusted host) but auth is still
**configurable** there; a network bind **must** have an authenticator (startup fails closed otherwise).

### 4. Transport security (TLS)
- Plaintext allowed **only** on loopback/UDS. **Any network bind requires TLS** (TLS 1.2+, prefer
  1.3 — `topic-cryptography`); startup fails closed otherwise.
- Support **in-app TLS** (operator-supplied cert/key paths, from the secret store) **and** document
  **terminate-at-reverse-proxy** (nginx/Caddy/Envoy) — when proxied, the server binds loopback/UDS
  and trusts the proxy for TLS/mTLS.

### 5. API hardening (`std-owasp-api`)
Required on the HTTP surface, enforced in the shell (the tool/session layer is already bounded):
- **Per-client rate limiting + quotas** and **request size caps** (DoS / cost — API4); a slow/heavy
  caller cannot exhaust the worker pool (`topic-reliability` backpressure; ties to ADR-002 one-
  worker-per-session + eviction).
- **Strict CORS** (no `*` with credentials; explicit allow-list, default none) and security headers.
- **Consistent error envelope** for `401`/`403`/`429`/`400` reusing the existing error-envelope
  contract (RFC 9457-style; no internals leaked — `topic-error-handling`); never `200`-with-error.
- **Complete mediation:** authenticate **and** authorize **every** request server-side; the network
  edge does not replace the existing per-call validation/allow-listing (defense in depth).

### 6. Authorization & sessions
- v1.1 remains **single-principal** (one operator). Per-request **authZ** = authenticated principal
  may use the allow-listed read-only catalog. The session model is unchanged (persistent per-binary,
  TTL+idle evict, one worker per session — ADR-002).
- **BOLA / `std-owasp-api` API1 is closed by construction in v1.1, not by a per-principal owner
  check.** Two facts compose to eliminate the cross-principal surface: (a) `session_id` is a 256-bit
  CSPRNG `secrets.token_urlsafe` — an *unguessable capability*; `SessionManager.authorize()` is the
  single BOLA chokepoint and returns the *same* `SESSION_INVALID` for unknown/expired/evicted ids,
  never revealing another session's existence (`docs/contracts/error-envelope.md`); and (b) there is
  exactly **one** authenticated principal, so every session_id that exists was minted for, and is
  held only by, that one operator. There is therefore **no second principal** against whom to scope
  ownership — a per-principal `owner` field would be recorded and checked against a single constant
  identity (vacuous). Binding sessions to a *distinct* principal becomes load-bearing **only when
  multi-principal lands**, and is explicitly that increment's work (record `owner` at `create`,
  verify at `authorize`, deny-on-mismatch). Until then the capability + single-identity invariant is
  the control; the live HTTP edge (auth before any session reference) is validated by the slice-5
  abuse tests rather than asserted.
- No new tools, no mutation, no `runScript`: the HTTP surface exposes the **same frozen read-only
  catalog** (`docs/contracts/tool-catalog.md`). Adding HTTP does **not** change the tool/RPC/
  untrusted-envelope contracts.

### 7. Architecture (where the change lives)
Additive to the `server/` shell only (ADR-006 seam holds): a transport selector (`build_app` +
`run_stdio` | `run_http`), an ASGI app (the `mcp` SDK's Streamable HTTP), and middleware
(auth → rate-limit → size-cap → CORS/headers → handler). New config knobs in `config.py`
(transport, bind, TLS paths, auth mode + token source, rate limits, CORS origins), **validated at
startup, fail-closed** (`topic-config-environments`). `core`/`tools`/`sessions`/`ghidra` are
untouched.

## Consequences

- **Positive:** remote/multi-client access becomes possible; the smallest-surface default (stdio,
  else loopback) is preserved; auth is pluggable so mTLS/OAuth need no shell rewrite; the hostile-
  binary containment (TB3, the central control) is unchanged and unaffected by transport.
- **Negative / risk:** a real network attack surface now exists — mitigated by TB6 + the fail-closed
  defaults above. Misconfiguration (network bind without TLS/auth) is the top risk → made
  **impossible** by startup validation.
- **Gating:** running a network-bound server, pulling/binding host ports, and providing the bearer
  token/TLS material are gated/secret-managed actions (`workflow-gated-actions`,
  `workflow-secrets`).
- **Verification:** TB6 abuse cases become security tests (authn bypass, missing-auth network bind
  rejected, rate-limit enforced, oversized payload rejected, CORS reflection rejected, error
  envelope leaks nothing) — `topic-testing` + `workflow-cicd`. DAST against an ephemeral HTTP
  instance is added to the gated e2e.

## Open items (resolved before implementation)
- **Exposure default = loopback-only — CONFIRMED (human, 2026-06-11).** §2 stands as written.
- Rate-limit algorithm/limits and the exact CORS default set are fixed in the design doc
  (`docs/design/http-transport.md`) and tunable via config.
