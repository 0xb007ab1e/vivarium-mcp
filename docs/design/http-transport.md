# Design — HTTP transport (v1.1)

Implements ADR-011 (locked decisions) against threat-model TB6. **Design only** until reviewed/gated;
no transport code is written before this lands. The change is **additive to the `server/` shell**;
`core`/`tools`/`sessions`/`security`/`ghidra` are untouched (ADR-006 seam).

## Config (`config.py`) — validated at startup, fail-closed
New env knobs (12-Factor; `topic-config-environments`). Defaults preserve today's behavior (stdio):

| Env | Default | Meaning |
|-----|---------|---------|
| `VIVARIUM_TRANSPORT` | `stdio` | `stdio` \| `http` |
| `VIVARIUM_HTTP_BIND` | `127.0.0.1:8765` | `host:port`, or `unix:/path.sock` for UDS |
| `VIVARIUM_HTTP_TLS_CERT` / `_TLS_KEY` | unset | PEM paths (from secret store); enables in-app TLS |
| `VIVARIUM_HTTP_AUTH` | `bearer` (TCP) / `none` (loopback,UDS) | `bearer` \| `mtls` \| `oauth` \| `none` |
| `VIVARIUM_HTTP_BEARER_TOKEN` | unset | bearer secret (env-injected; never logged) |
| `VIVARIUM_HTTP_CORS_ORIGINS` | `` (none) | explicit allow-list; empty = no cross-origin |
| `VIVARIUM_HTTP_RATE` / `_BURST` | e.g. `10/s` / `20` | per-client token bucket |
| `VIVARIUM_HTTP_MAX_BODY` | reuse existing arg caps | request size cap (bytes) |

**Startup fail-closed rules** (refuse to boot, clear error — no insecure runtime state):
1. `transport=http` + non-loopback host (not `127.0.0.1`/`::1`/UDS) ⇒ **require** TLS cert+key
   **and** an authenticator (`auth != none`). Else abort.
2. `auth=bearer` ⇒ token must be present + non-trivial length. `auth=mtls` ⇒ CA/verify config present.
3. CORS origins must be explicit URLs (reject `*`).

## Authenticator port (the "support all 3" seam)
A small strategy interface in the shell; default-deny:
```
class Authenticator(Protocol):
    def authenticate(self, request) -> Principal | Reject: ...
```
- `BearerAuthenticator` — BUILT now. Constant-time compare of the `Authorization: Bearer …` token
  vs the configured secret; generic `401` on miss (no oracle).
- `MtlsAuthenticator` — port-ready; client-cert → `Principal` (built when needed).
- `OAuthResourceAuthenticator` — port-ready; validate JWT `iss`/`aud`/`exp`/pinned alg (built when needed).
- `NullAuthenticator` — loopback/UDS only; single trusted host; explicit, never the default on TCP.

`Principal` carries the identity that **owns sessions** (TB6-I / API1): a session created by a
principal is only usable by that principal.

## Middleware order (ASGI; outermost → innermost)
`TLS (in-app or proxy)` → `request-size cap` → `rate limit` → `authenticate` → `authorize`
(principal may use the read-only catalog; bind session ownership) → `CORS + security headers` →
`MCP Streamable HTTP handler` → existing tool dispatch (unchanged: validate → allow-list → port).
Errors map to the existing error envelope with `401/403/429/400/413`; never `200`-with-error, no
internals leaked.

## Server shell changes
- `server/app.py`: add `run_http(app, config)` beside `run_stdio`; `__main__` selects on
  `config.transport`. Use the `mcp` SDK's **Streamable HTTP** ASGI app; mount the middleware stack.
- No change to `build_app` tool registration, `core`, `tools`, `sessions`, `ghidra`.

## Slices (each: pure-where-possible core + shell wiring + tests; gated commit)
1. **Config + fail-closed validation** — knobs above + startup guards; unit tests for every
   fail-closed rule (network-without-TLS/auth aborts; `*` CORS rejected; missing token aborts).
2. **Authenticator port + BearerAuthenticator** — constant-time compare, generic 401; unit tests
   (valid/invalid/missing/timing-safe) + the mTLS/OAuth stubs satisfying the Protocol.
3. **HTTP shell (`run_http`) + middleware** — size cap, rate limit, CORS/headers, error mapping;
   integration test against an ephemeral loopback instance.
4. **Session-ownership authZ** — bind sessions to `Principal`; cross-principal access rejected
   (BOLA abuse test — extends §6 abuse cases).
5. **Security tests + DAST** — TB6 abuse cases (authn bypass, network-bind-without-auth refused,
   rate-limit enforced, oversized body rejected, CORS reflection rejected, error envelope leaks
   nothing) wired into `tests/security/` + a DAST pass in the gated e2e (`workflow-cicd`).
6. **Docs/runbooks** — deploy/run HTTP (loopback, UDS, network+TLS+token, reverse-proxy), secret
   handling for the bearer token + TLS material (`workflow-secrets`), rate-limit tuning.

## Non-goals (v1.1)
Multi-tenant authZ (single principal), mutation tools, OAuth/mTLS *implementations* (ports only).
The frozen tool/RPC/untrusted-envelope contracts are unchanged — HTTP exposes the same read-only catalog.
