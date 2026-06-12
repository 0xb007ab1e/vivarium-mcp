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

- The server runs as `python -m ghidra_mcp` with the usual worker config (`GHIDRA_MCP_WORKER_IMAGE`
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
| `GHIDRA_MCP_TRANSPORT` | `stdio` | set `http` to enable HTTP |
| `GHIDRA_MCP_HTTP_BIND` | `127.0.0.1:8765` | `host:port` (IPv6 as `[::1]:8765`) or `unix:/path.sock` |
| `GHIDRA_MCP_HTTP_AUTH` | `none` on loopback/UDS · `bearer` on network | `none`/`bearer` (`mtls`/`oauth` are **not implemented** in v1.1 — do not select) |
| `GHIDRA_MCP_HTTP_BEARER_TOKEN` | unset | required for `bearer`; **≥ 16 chars**; never logged |
| `GHIDRA_MCP_HTTP_TLS_CERT` / `_TLS_KEY` | unset | PEM paths; **both or neither**; required for any network bind |
| `GHIDRA_MCP_HTTP_CORS_ORIGINS` | _(none)_ | comma-separated explicit origins; `*` is rejected |
| `GHIDRA_MCP_HTTP_RATE_PER_SECOND` | `10` | per-client token-bucket refill rate |
| `GHIDRA_MCP_HTTP_RATE_BURST` | `20` | per-client bucket size |
| `GHIDRA_MCP_HTTP_MAX_BODY_BYTES` | `1048576` | request size cap (1 MiB); `413` over it |

> **Auth note:** only `bearer` (and `none` on loopback/UDS) is implemented in v1.1. `mtls`/`oauth`
> are port-ready stubs (ADR-011 §3) and are **not** usable yet — selecting them boots but fails the
> first request. Do not configure them.

### Rung 1 — Loopback TCP (same host, simplest)

Plaintext is permitted (no network hop). Auth defaults to `none` — acceptable only because the bind
is unreachable off-host.

```bash
GHIDRA_MCP_TRANSPORT=http \
GHIDRA_MCP_HTTP_BIND=127.0.0.1:8765 \
python -m ghidra_mcp
```

### Rung 2 — Unix domain socket (same host, no TCP port)

Access is gated by **filesystem permissions** on the socket — put it in a dir only the operator (and
the MCP host) can reach; no port is opened.

```bash
GHIDRA_MCP_TRANSPORT=http \
GHIDRA_MCP_HTTP_BIND=unix:/run/ghidra-mcp/mcp.sock \
python -m ghidra_mcp
# Then: chmod 0700 the containing dir; the socket inherits the process umask.
```

### Rung 3 — Network TCP (**GATED** — requires TLS + bearer)

For a trusted LAN or a host reachable by another machine. The server **fails closed** at startup
unless **both** TLS (cert+key) **and** a non-`none` authenticator are present.

```bash
# 1. Mint a high-entropy token and store it in the secret manager (NOT in a file in the repo):
#    python -c "import secrets; print(secrets.token_urlsafe(32))"
# 2. Inject token + TLS paths from the secret store at runtime (example shows env injection):
GHIDRA_MCP_TRANSPORT=http \
GHIDRA_MCP_HTTP_BIND=0.0.0.0:8765 \
GHIDRA_MCP_HTTP_AUTH=bearer \
GHIDRA_MCP_HTTP_BEARER_TOKEN="$(read-secret ghidra-mcp/bearer)" \
GHIDRA_MCP_HTTP_TLS_CERT=/etc/ghidra-mcp/tls/cert.pem \
GHIDRA_MCP_HTTP_TLS_KEY=/etc/ghidra-mcp/tls/key.pem \
GHIDRA_MCP_HTTP_CORS_ORIGINS="https://your-mcp-host.example" \
python -m ghidra_mcp
```

Clients send `Authorization: Bearer <token>` over **https**.

### Alternative to Rung 3 — terminate TLS at a reverse proxy

Bind the server to **loopback or UDS** (Rung 1/2) and let nginx/Caddy/Envoy terminate TLS (and
optionally mTLS/OAuth) in front, forwarding to the loopback/socket. The server stays off the network
directly; the proxy owns the public cert. Keep the bearer token (or proxy-injected auth) in force.

## Secret handling (bearer token + TLS key)

- Generate the token with a CSPRNG (`secrets.token_urlsafe(32)`); **≥ 16 chars** or startup aborts.
- Source the token and TLS **private key** from the secret manager / injected env at runtime —
  never commit them, bake them into the image, or pass on argv (`ps`-visible). TLS key file perms
  `0600`, owned by the run user.
- **Rotation:** follow `runbooks/secret-rotation.md` — provision the new token, roll consumers, then
  retire the old. Rotate immediately on any suspected exposure. The token is never logged (it is
  excluded from config/`repr` and redacted).

## Rate-limit & size tuning

- `GHIDRA_MCP_HTTP_RATE_PER_SECOND` / `_BURST` are a **per-client** token bucket; raise the burst for
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
GHIDRA_MCP_TRANSPORT=http GHIDRA_MCP_HTTP_BIND=0.0.0.0:8765 python -m ghidra_mcp; echo "exit=$?"  # → exit=2
```

## Rollback / abort

- **Revert to stdio** instantly: unset `GHIDRA_MCP_TRANSPORT` (or set `stdio`) and restart. No data
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
