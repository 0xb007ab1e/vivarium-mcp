# ADR-034 — Reverse-proxy-terminated mTLS (opt-in, shared-secret-anchored)

- **Status:** Accepted (v1.4; human-ratified 2026-06-17). Implements roadmap-v1.4 item #6 — the
  ADR-019 deferred/"rejected as default" reverse-proxy-header mTLS, returning as an **opt-in** mode
  with a hard, code-enforced trust anchor. Hardens/extends **TB6** (the HTTP boundary); server-only,
  no JVM edge. Ratified: **(1) a required pre-shared secret** authenticates the proxy (the mode
  cannot be enabled without it; constant-time compared; fail closed) — plus a mandatory network-
  isolation deployment constraint; **(2) the proxy forwards a pre-extracted identity string** (the
  verified client subject CN/DN), validated and used as the principal id.

## Context

ADR-019 D2 chose **server-terminated, in-app mTLS** and **rejected** trusting a proxy-supplied
verified-DN header as the default: a server that blindly trusts an `X-Client-Cert-*` header lets
**anyone who can reach it directly** spoof any identity (the header-spoofing footgun). But
TLS-terminating reverse proxies (nginx/Envoy/HAProxy) are the common prod topology, and ADR-019 left
the door open to "return as an opt-in later." This is that increment — made safe by a **code-enforced
trust anchor**, not a documentation hope.

## Decision

### D1 — A new opt-in auth mode `mtls-proxy`, gated on a REQUIRED shared secret (the trust anchor)

A new `ReverseProxyMtlsAuthenticator` (auth mode `mtls-proxy`) trusts a proxy-forwarded identity
header **only** when the request also carries a correct pre-shared secret:

- The proxy injects a secret header (`proxy_secret_header`, default `x-proxy-auth`) whose value the
  server compares **constant-time** (`hmac.compare_digest`) against the configured
  `proxy_shared_secret`. A missing/wrong secret → uniform `None` (generic reject, no oracle) — the
  identity header is **never** consulted.
- The secret is **mandatory**: config validation refuses to start in `mtls-proxy` mode without a
  `proxy_shared_secret` (length-floored like the bearer token). The mode is impossible to enable
  unsafely (fail closed; opt-in to power, master §2).
- **Deployment constraint (documented, mandatory):** the server MUST be network-isolated so only the
  trusted proxy can reach it (private bind / network policy). The shared secret is defense in depth
  *and* the code-enforced anchor; the operator must still not expose the server publicly. This is
  called out loudly in the threat model + deploy docs.
- **Rate-limit deployment constraint (gap round-4 Q9):** the app's per-client rate limiter keys on
  the transport **peer IP** — and it deliberately does NOT trust `X-Forwarded-For` (spoofable). In
  `mtls-proxy` mode every request arrives from the proxy's single IP, so the limiter collapses to
  **one shared bucket** for all principals (a per-principal request-rate DoS is not bounded by the
  app; it is a limitation, not a bypass). The **fronting proxy MUST enforce per-client rate
  limiting** in this mode. The per-owner **session cap** (ADR-017 STRIDE-D) still bounds resource
  starvation (one principal cannot exhaust the worker pool), so the residual is request-rate only.
  A post-auth per-principal limiter is a possible future enhancement, deliberately deferred (the
  limiter is pre-auth by design — reject cheaply before auth work — and moving it would weaken that).

### D2 — The proxy forwards a pre-extracted identity string (not a cert to re-parse)

The proxy (which terminated TLS and **verified the client cert chain**) forwards the already-extracted
client identity — the subject CN or DN — in `proxy_identity_header` (default
`x-client-cert-subject`). The server:

1. (after the secret check) reads the identity header; missing/empty → `None`.
2. **validates** it as a principal id: non-empty, length-bounded, no control/newline chars (it
   becomes the session-owner key — ADR-017 — and is attacker-influenced if the proxy is compromised;
   bound it). A malformed value → `None`.
3. maps it to `Principal(id=<identity>)` (full-capability, like the other non-OAuth principals —
   ADR-033; scope→authZ is OAuth-only).

The server does **not** re-parse a cert from the header (smaller untrusted-parse surface) and cannot
re-verify the chain anyway — the proxy did, and the secret anchors that trust. (Forwarding the full
PEM was considered and rejected as more surface for no added assurance.)

### D3 — Plumbing: request headers reach the authenticator via `AuthContext`

`AuthContext` gains `headers: Mapping[str, str]` (lowercased name → first value), populated by the
`AuthenticationMiddleware` from the ASGI scope (it already extracts `authorization` + the peer cert).
The new authenticator reads only its two configured header names; bearer/mTLS/OAuth authenticators
ignore it (unchanged). `AuthContext` stays transport-agnostic (a header mapping, not the raw scope).

### D4 — Identity, owner-scoping, capabilities, redaction unchanged

The resulting `Principal` is owner-scoped exactly like every other (ADR-017): it owns only its own
sessions; a foreign id is BOLA-safe. Full capability (ADR-033 narrows only OAuth). The shared secret
is a **secret**: never logged, excluded from `repr`, sourced from env/secret-manager
(`workflow-secrets`); a reject is generic (no oracle), and the identity value is never logged verbatim
(only that authn succeeded/failed for a principal id at the existing redaction level).

## Consequences

- Deployments behind a TLS-terminating proxy can use cert identity without the server terminating TLS
  — the common prod topology — without reintroducing the spoofing footgun (the secret is the
  enforced anchor; the mode can't start without it).
- Purely additive: a new auth mode + one `AuthContext` field + config; bearer/mTLS/OAuth/none paths
  are byte-for-byte unchanged. Server-only — no worker/JVM, no new trust boundary (TB6 extension),
  fully unit-testable (no live-verification dependency).
- The residual risk is operator misconfiguration (exposing the server directly AND leaking the
  secret); both are required to forge identity, and both are documented mandatory constraints.
- **Header precedence — the proxy MUST replace, not append (CWE-290).** The server reads the
  **first** value of a repeated `proxy_secret_header` / `proxy_identity_header` (`_header_map` is
  deterministic first-value-wins). So the trusted proxy MUST **strip any client-supplied** secret +
  identity headers and **set** its own (replace semantics — nginx `proxy_set_header`, not
  `add_header`); if it *appended* instead, a client that sends its own identity header first could
  win the first-value selection. This only bites once the shared secret has already leaked (the
  identity header is never consulted without a valid secret — D1), so it is defense-in-depth on top
  of the anchor, not the primary control — but it is a **required deploy constraint**, mirrored in
  `runbooks/http-exposure.md`.

## Decisions ratified by the human (2026-06-17)
1. **D1 — required shared secret anchor** (mandatory; constant-time; + network-isolation doc). ✅
2. **D2 — proxy forwards a pre-extracted identity string** (validated → principal id). ✅

## References
- ADR-019 (mTLS/OAuth identity; D2 rejected proxy-header as default — this is the opt-in return),
  ADR-017 (owner-scoped sessions), ADR-033 (capabilities; non-OAuth = full), master §2 (least
  privilege, fail closed, opt-in to power), `workflow-secrets`, `std-zero-trust`, threat-model TB6.
