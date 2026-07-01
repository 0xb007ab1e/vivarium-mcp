# Runbook: HTTP transport — expose the server (loopback / UDS / network+TLS)

> Service-specific (v1.1 — ADR-011 / threat-model **TB6**). Operating the MCP server over HTTP
> instead of stdio. Rules: `@rules/workflow-secrets.md`, `@rules/std-owasp-api.md`,
> `@rules/topic-config-environments.md`, `@rules/workflow-gated-actions.md`.

## When to use

- You need a **remote or multi-client** MCP host to reach the read-only tool catalog (stdio serves a
  single co-located host only).
- **When NOT to use:** if one local LLM host is the only consumer, stay on **stdio** (the default,
  smallest surface). HTTP adds the project's first network attack surface — only open it when you
  need it.

## Severity / impact

- Binding to a **non-loopback** address exposes the analysis surface to the network. That bind is a
  **gated action** (`workflow-gated-actions`) and **must** carry TLS + an authenticator — the server
  **refuses to boot** otherwise (fail-closed, ADR-011 §2/§4). Loopback/UDS are same-host only.
- The hostile-binary containment (worker isolation, TB3) is unchanged by transport.

## Prerequisites & access

- The server runs as `python -m vivarium` with the usual worker config (`VIVARIUM_WORKER_IMAGE`
  etc.). HTTP is selected purely by env (12-Factor; no rebuild).
- For any network bind: a **TLS cert + key** (PEM) and a **bearer token**, both pulled at runtime
  from the secret store / injected env — **never** in code, VCS, the image, or argv
  (`workflow-secrets.md`; argv is visible in `ps`). Gated human approval to open the network bind.
- `curl` (or any HTTP client) on the host for the verification step.

## Exposure ladder — pick the **lowest** rung that meets the need

Defaults preserve today's behavior (stdio). All knobs are validated at startup; a bad combination
aborts with a clear, redacted error (no insecure runtime state).

| Env var | Default | Notes |
|---|---|---|
| `VIVARIUM_TRANSPORT` | `stdio` | set `http` to enable HTTP |
| `VIVARIUM_HTTP_BIND` | `127.0.0.1:8765` | `host:port` (IPv6 as `[::1]:8765`) or `unix:/path.sock` |
| `VIVARIUM_HTTP_AUTH` | `none` on loopback/UDS · `bearer` on network | `none`/`bearer`/`mtls`/`oauth`/`mtls-proxy` (all implemented — ADR-019/033/034) |
| `VIVARIUM_HTTP_BEARER_TOKEN` | unset | required for `bearer`; **≥ 16 chars**; never logged |
| `VIVARIUM_HTTP_PROXY_SHARED_SECRET` | unset | **required** for `mtls-proxy` (the trust anchor); **≥ 16 chars**; never logged |
| `VIVARIUM_HTTP_PROXY_SECRET_HEADER` / `_PROXY_IDENTITY_HEADER` | `x-proxy-auth` / `x-client-cert-subject` | headers the proxy injects (secret + verified client identity) for `mtls-proxy` |
| `VIVARIUM_HTTP_TLS_CERT` / `_TLS_KEY` | unset | PEM paths; **both or neither**; required for any network bind |
| `VIVARIUM_HTTP_CORS_ORIGINS` | _(none)_ | comma-separated explicit origins; `*` is rejected |
| `VIVARIUM_HTTP_RATE_PER_SECOND` | `10` | per-client token-bucket refill rate |
| `VIVARIUM_HTTP_RATE_BURST` | `20` | per-client bucket size |
| `VIVARIUM_HTTP_MAX_BODY_BYTES` | `1048576` | request size cap (1 MiB); `413` over it |

> **Auth note:** `bearer` (and `none` on loopback/UDS) plus `mtls` + `oauth` (ADR-019) and
> `mtls-proxy` (ADR-034) are all implemented. `oauth` adds optional scope→per-tool authZ
> (`VIVARIUM_HTTP_OAUTH_WRITE_SCOPE` — ADR-033). `mtls-proxy` trusts a TLS-terminating reverse
> proxy's forwarded client identity, gated on a shared secret — see the constraint below.

### Rung 1 — Loopback TCP (same host, simplest)

Plaintext is permitted (no network hop). Auth defaults to `none` — acceptable only because the bind
is unreachable off-host.

```bash
VIVARIUM_TRANSPORT=http \
VIVARIUM_HTTP_BIND=127.0.0.1:8765 \
python -m vivarium
```

### Rung 2 — Unix domain socket (same host, no TCP port)

Access is gated by **filesystem permissions** on the socket — put it in a dir only the operator (and
the MCP host) can reach; no port is opened.

```bash
VIVARIUM_TRANSPORT=http \
VIVARIUM_HTTP_BIND=unix:/run/vivarium/mcp.sock \
python -m vivarium
# Then: chmod 0700 the containing dir; the socket inherits the process umask.
```

### Rung 3 — Network TCP (**GATED** — requires TLS + bearer)

For a trusted LAN or a host reachable by another machine. The server **fails closed** at startup
unless **both** TLS (cert+key) **and** a non-`none` authenticator are present.

```bash
# 1. Mint a high-entropy token and store it in the secret manager (NOT in a file in the repo):
#    python -c "import secrets; print(secrets.token_urlsafe(32))"
# 2. Inject token + TLS paths from the secret store at runtime (example shows env injection):
VIVARIUM_TRANSPORT=http \
VIVARIUM_HTTP_BIND=0.0.0.0:8765 \
VIVARIUM_HTTP_AUTH=bearer \
VIVARIUM_HTTP_BEARER_TOKEN="$(read-secret vivarium/bearer)" \
VIVARIUM_HTTP_TLS_CERT=/etc/vivarium/tls/cert.pem \
VIVARIUM_HTTP_TLS_KEY=/etc/vivarium/tls/key.pem \
VIVARIUM_HTTP_CORS_ORIGINS="https://your-mcp-host.example" \
python -m vivarium
```

Clients send `Authorization: Bearer <token>` over **https**.

### Alternative to Rung 3 — terminate TLS at a reverse proxy

Bind the server to **loopback or UDS** (Rung 1/2) and let nginx/Caddy/Envoy terminate TLS (and
optionally mTLS/OAuth) in front, forwarding to the loopback/socket. The server stays off the network
directly; the proxy owns the public cert. Keep the bearer token (or proxy-injected auth) in force.

#### `mtls-proxy` — trust the proxy's verified client identity (ADR-034)

When the proxy terminates **client-cert (mTLS)** and you want that identity inside the server, set
`VIVARIUM_HTTP_AUTH=mtls-proxy`. The proxy must inject TWO headers: the **shared secret**
(`x-proxy-auth` by default) and the **verified client identity** it extracted from the cert
(`x-client-cert-subject` by default, e.g. nginx `proxy_set_header X-Client-Cert-Subject
$ssl_client_s_dn;`). The server trusts the identity **only** when the secret matches (constant-time).

> ⚠️ **MANDATORY constraints — both, or this is a spoofing footgun:**
> 1. **Network-isolate the server so ONLY the proxy can reach it** (bind loopback/UDS, or a private
>    interface + firewall/NetworkPolicy). Anyone who can reach the server directly AND knows the
>    secret can forge any identity.
> 2. **Set a strong `VIVARIUM_HTTP_PROXY_SHARED_SECRET`** (≥16 chars, from your secret manager;
>    the mode refuses to boot without one) and have the proxy **strip** any client-supplied
>    `x-proxy-auth`/`x-client-cert-subject` headers before injecting its own (so a client can't
>    smuggle them through). Rotate it via `runbooks/secret-rotation.md`.
> 3. **Enforce per-client rate limiting AT THE PROXY** (gap round-4 Q9). The server's own limiter
>    (`VIVARIUM_HTTP_RATE_PER_SECOND`) keys on the peer IP and does NOT trust `X-Forwarded-For`, so
>    behind a proxy all principals share ONE bucket — a per-principal request-rate DoS isn't bounded
>    by the app in this mode (the per-owner session cap still bounds worker-pool starvation). Add a
>    per-client rate limit at the proxy (e.g. nginx `limit_req_zone` keyed on the client cert / real
>    client IP).

## Secret handling (bearer token + TLS key)

- Generate the token with a CSPRNG (`secrets.token_urlsafe(32)`); **≥ 16 chars** or startup aborts.
- Source the token and TLS **private key** from the secret manager / injected env at runtime —
  never commit them, bake them into the image, or pass on argv (`ps`-visible). TLS key file perms
  `0600`, owned by the run user.
- **Rotation:** follow `runbooks/secret-rotation.md` — provision the new token, roll consumers, then
  retire the old. Rotate immediately on any suspected exposure. The token is never logged (it is
  excluded from config/`repr` and redacted).

## Rate-limit & size tuning

- `VIVARIUM_HTTP_RATE_PER_SECOND` / `_BURST` are a **per-client** token bucket; raise the burst for
  a chatty single operator, lower the rate to harden against a flood. `_MAX_BODY_BYTES` caps request
  size (`413` over it). These are DoS controls (`std-owasp-api` API4) — keep them tight.
- **Reverse-proxy caveat:** the per-client bucket keys on the **TCP peer IP**. Behind a reverse
  proxy (the Rung-3 alternative) every request arrives from the **proxy's** IP, so all clients share
  one bucket — the limit degrades to **per-proxy**, not per-client. The server does **not** trust
  `X-Forwarded-For` (it is spoofable — CWE-290). In proxied deployments, **enforce per-client rate
  limiting at the proxy** (nginx `limit_req`, Caddy `rate_limit`, Envoy local rate limit) and treat
  the server's limiter as a coarse backstop.

## Verification

With the server running (use the right scheme/host per rung):

```bash
BASE=http://127.0.0.1:8765      # or https://host:8765 for Rung 3
# 1. Missing/!bad auth is rejected (bearer mode) — expect 401:
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/mcp"                       # → 401
# 2. Oversized body is rejected — expect 413 (cap = 1 MiB by default):
curl -s -o /dev/null -w '%{http_code}\n' -X POST --data-binary @big.bin "$BASE/mcp" # → 413
# 3. Security headers present on every response:
curl -sI -X POST "$BASE/mcp" | grep -iE 'x-content-type-options|x-frame-options|referrer-policy'
# 4. (network/TLS) HSTS present:
curl -sI "$BASE/mcp" | grep -i strict-transport-security
```

A misconfigured **network bind without TLS or auth must fail to start** — confirm the process exits
non-zero with a config error rather than serving:

```bash
VIVARIUM_TRANSPORT=http VIVARIUM_HTTP_BIND=0.0.0.0:8765 python -m vivarium; echo "exit=$?"  # → exit=2
```

## Rollback / abort

- **Revert to stdio** instantly: unset `VIVARIUM_TRANSPORT` (or set `stdio`) and restart. No data
  migration — sessions are ephemeral (ADR-002).
- If a network bind is misbehaving, drop to loopback/UDS or pull the bind while you investigate.

## Escalation

- Suspected unauthorized access or token leak → `runbooks/incident-response.md` **and**
  `runbooks/secret-rotation.md` (rotate the bearer token + TLS key); page security.

## Related

- `docs/adr/ADR-011-http-transport.md`, `docs/security/threat-model.md` (TB6),
  `docs/design/http-transport.md`; `runbooks/secret-rotation.md`, `runbooks/deploy.md`,
  `runbooks/incident-response.md`.

---
_Last validated: not yet (v1.1 increment — validate in a drill before relying on network exposure).
Owner: maintainer._
