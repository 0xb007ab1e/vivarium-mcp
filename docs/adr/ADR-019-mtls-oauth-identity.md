# ADR-019: mTLS + OAuth identity sources (pluggable principals)

- **Status:** Accepted (v1.2 design; human-ratified decisions D1–D3, 2026-06-14). Builds out the two
  `Authenticator` stubs ADR-011 left port-ready. **Hardens TB6 — no new trust boundary.** Delivered
  as **two implementation increments**: mTLS first, OAuth second.
- **Deciders:** Human (ratified sequencing / mTLS model / OAuth model, 2026-06-14) + PM; recorded by
  the Software Architect.
- **Relates to:** ADR-011 (HTTP transport — the `Authenticator` port, the `auth_mode` enum incl.
  `mtls`/`oauth`, and the `AuthContext.peer_certificate` seam), ADR-017 (multi-principal ownership —
  the mechanism these identity sources feed), `std-zero-trust`, `topic-authn-authz`, `std-supplychain`
  (OAuth's JWT dependency).

## Context

ADR-011 shipped the `Authenticator` strategy port + static bearer; ADR-017 added **multi-token bearer**
and the per-principal **session-ownership** mechanism. `MtlsAuthenticator` / `OAuthResourceAuthenticator`
remain **port stubs** that `raise NotImplementedError`. They are the remaining identity sources:
each maps a request to a `Principal(id)` that slots into the **existing ownership mechanism unchanged**
(ADR-017) — distinct certs / token subjects become distinct principals owning distinct sessions. This
unlocks real **multi-analyst deployment** with standard identity (client certificates / OAuth tokens)
instead of shared bearer secrets. No new MCP tool, RPC, or boundary — this is transport-layer
authentication that feeds the existing authZ.

## Decision (ratified)

### D1 — One ADR, two increments: **mTLS first, then OAuth.**
Both share the `Authenticator`/`AuthContext` seam, `build_authenticator`, the middleware →
`ToolContext.principal` threading, and the config patterns — so they're designed together. They
**implement/review/merge separately**: **mTLS first** (no new dependency — rides uvicorn's in-app TLS
+ the `peer_certificate` seam), **OAuth second** (adds a pinned JWT/JWKS dependency — a larger
supply-chain surface, kept to its own reviewable PR).

### D2 — mTLS = **server-terminated, in-app** (no header trust).
- uvicorn is configured with `ssl_ca_certs` (a configured client-CA bundle) + `ssl_cert_reqs =
  CERT_REQUIRED` — the TLS handshake itself **rejects any client without a CA-signed certificate**
  (the first gate, at the transport).
- The verified peer certificate is surfaced to **`AuthContext.peer_certificate`** (extracted from the
  ASGI scope by the auth middleware — the "TLS-terminator wiring" ADR-011 deferred). Python's `ssl`
  already exposes the parsed peer cert (subject / SAN), so **no new dependency** is needed for mTLS.
- `MtlsAuthenticator` maps a **configured cert field → principal id**: default **subject CN**,
  configurable to a SAN (DNS/URI/email) or the full subject DN. **Fail closed** — no verified peer
  cert, or an empty mapped field → reject (generic `401`, no oracle), even though uvicorn already
  required the cert (defense in depth).
- **Reverse-proxy-terminated mTLS** (trusting a proxy-supplied verified-DN header) is **deferred /
  out of scope** — trusting a header is a spoofing footgun; the in-app verified peer cert is the safe
  default.

### D3 — OAuth = **JWT access tokens validated locally via JWKS** (resource server).
- `OAuthResourceAuthenticator` validates a `Bearer` **JWT**: verify the signature against the issuer's
  **JWKS** (fetched + **cached** with a TTL — one outbound call from the *server*, not per request;
  the worker stays no-network), with a **pinned algorithm allow-list** (reject `alg:none` and any
  attacker-chosen/asymmetric-confusion alg — `topic-authn-authz`); validate **`iss`** (== configured
  issuer), **`aud`** (== configured audience), **`exp`/`nbf`** (small leeway); map the **`sub`** claim
  (configurable) → principal id. Any failure → generic `401` (no oracle). Token introspection
  (RFC 7662, opaque tokens) is **deferred** (it adds a per-request IdP round-trip + egress surface).
- **Dependency (std-supplychain):** add **PyJWT + cryptography**, **pinned by version + hash** and
  **vetted** before adoption (lands with the OAuth increment only). JWKS-key handling uses
  `cryptography`. (mTLS does **not** need this — `ssl` provides the parsed peer cert.)

### Principal mapping (both)
mTLS → the configured cert field; OAuth → the `sub` claim → `Principal(id=…)`. Both feed the **ADR-017
ownership mechanism unchanged**: distinct certs / subjects = distinct principals = distinct,
owner-scoped session ownership; the manager's owner check is untouched.

## Security (TB6 delta — STRIDE; hardening, no new boundary)

- **S (spoofing):** identity is **cryptographically proven** — a CA-signed client cert (chain verified
  to the configured CA at the TLS layer) or a JWKS-verified JWT signature — not a shared secret.
  Generic reject; no credential/which-identity oracle.
- **T (tampering):** mTLS cert chain verified to the configured CA bundle; JWT signature verified with
  a **pinned** alg (no `alg:none`, no RS/HS confusion) + `iss`/`aud`/`exp`/`nbf` checked.
- **R (repudiation):** auth events logged (principal id, mechanism, success/failure) — **never** the
  token, cert private material, or secrets (`topic-logging-observability`).
- **I (disclosure):** uniform `401` on any failure; the token/cert is never logged or echoed.
- **D (DoS):** JWKS is cached + bounded (no per-request IdP round-trip); the mTLS handshake is bounded
  by the server; existing rate-limit + size caps unchanged.
- **E (elevation):** a valid identity gets only the read-only catalog + its **own** owner-scoped
  sessions (ADR-017); the auth *mechanism* grants no extra capability. (Per-scope/role → fine-grained
  authZ is explicitly **out of scope** — sub→principal only; see Deferred.)

## Architecture & invariants
- **Reuses** the `Authenticator` port, `build_authenticator`, and the middleware →
  `ToolContext.principal` → manager owner-check path (ADR-017) **unchanged**. New wiring is minimal:
  (mTLS) extract the verified peer cert from the ASGI scope into `AuthContext`; (OAuth) JWKS-validate
  the bearer JWT.
- **No new MCP tool / RPC / envelope / catalog change** — `auth_mode ∈ {none,bearer,mtls,oauth}`
  already exists. Config gains: (mTLS) client-CA bundle path + principal-field selector; (OAuth)
  issuer / audience / JWKS URI / principal-claim / alg allow-list / leeway. Config lands in the impl PRs.
- **ADR-001/002 untouched** — auth is server-side only; the worker is unaffected; no durable state.

## Consequences
- Real multi-analyst deployment with **standard identity** (client certs / OAuth) on top of the v1.1
  ownership mechanism; distinct principals own distinct sessions.
- **mTLS increment:** no new dependency; server-terminated; the `peer_certificate` seam is realized.
- **OAuth increment:** +1 pinned, vetted JWT dependency; JWKS cached.
- **Deferred / out of scope:** reverse-proxy-header mTLS; OAuth token **introspection** (opaque
  tokens); OAuth **scopes → fine-grained per-tool authZ** (we map identity only); SPIFFE/workload
  identity. Revisit each with its own ADR.

## Alternatives considered
- **Reverse-proxy-terminated mTLS (trust a verified-DN header):** common in prod but a header-spoofing
  footgun unless the proxy is strictly enforced. **Rejected** as the default (D2); may return as an
  opt-in later.
- **OAuth token introspection (RFC 7662):** no JWT-parsing dep, but a per-request IdP round-trip +
  egress/SSRF surface from the server. **Rejected** for JWKS-local (D3); introspection deferred.
- **Both mechanisms in one PR:** fastest to "both done" but a large security-critical diff + a new dep
  landing together — hardest to review. **Rejected** for two increments (D1).
- **Status quo (bearer only):** multi-token bearer works but uses shared secrets, not standard
  identity. **Rejected** — the increment exists to add cert/OAuth identity.

## Implementation increments (follow this design PR)

**A — mTLS (first, no new dep):**
1. uvicorn `ssl_ca_certs` + `ssl_cert_reqs=CERT_REQUIRED` when `auth_mode=mtls`; surface the verified
   peer cert from the ASGI scope into `AuthContext.peer_certificate` (the middleware wiring).
2. `MtlsAuthenticator`: map the configured cert field (CN / SAN / DN) → `Principal`; **fail closed**
   on absent cert / empty field; generic reject.
3. config: client-CA bundle path (required for `mtls`) + principal-field selector; `build_authenticator`
   wiring; startup validation (mtls ⇒ CA bundle set).
4. threat-model **TB6 delta** + abuse cases (no client cert; cert from an untrusted CA; empty mapped
   field; **two distinct certs → two distinct owner-scoped principals**; cert private data never
   logged) + `topic-testing` gates. Cert parsing hermetic with **synthetic** certs; live mTLS handshake
   integration-gated. No real secrets.

**B — OAuth (second, +pinned JWT dep):**
1. add **PyJWT + cryptography** (pinned + hashed + vetted — `std-supplychain`).
2. `OAuthResourceAuthenticator`: JWKS fetch + cache; **pinned-alg** signature verify; `iss`/`aud`/
   `exp`/`nbf`; `sub` (configurable) → `Principal`; generic reject.
3. config: issuer / audience / JWKS URI (or static JWKS) / principal-claim / alg allow-list / leeway;
   `build_authenticator` wiring; startup validation.
4. threat-model **TB6 delta** + abuse cases (`alg:none`; wrong `iss`/`aud`; expired/not-yet-valid; bad
   signature; unknown `kid`; missing `sub`) + gates. JWT validation hermetic with a **test keypair**;
   JWKS fetch mocked (no live IdP / network in tests).
