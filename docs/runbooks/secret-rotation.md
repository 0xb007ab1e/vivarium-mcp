# Runbook: Secret Rotation

> Rules: `@rules/workflow-secrets.md`.

## When to use
- Rotating a credential on schedule, suspected exposure, or personnel change.

## Scope note (this service)
- **stdio transport (v1 default) has NO runtime secrets** (single process, no network, no auth
  boundary, no outbound credentials) — nothing to rotate.
- **HTTP transport (v1.1/v1.2 — ADR-017/019)** introduces credentials, read from the environment at
  runtime (never committed; injected by the deployment's secret store — there is no built-in secret
  manager). The rotatable ones:
  - **Bearer tokens** — `VIVARIUM_HTTP_BEARER_TOKENS` (comma-separated `principal:token` pairs; the
    multi-value list IS the dual-valid mechanism). `VIVARIUM_HTTP_BEARER_TOKEN` is the single-token
    form.
  - **mTLS client CA** — `VIVARIUM_HTTP_TLS_CLIENT_CA` (the trusted client-cert CA bundle).
  - **OAuth** has no stored secret to rotate — access tokens are per-request and JWKS-verified;
    signing-key rotation is the **external IdP's** concern (the server re-fetches JWKS).

## Steps (HTTP transport, add-new-before-revoke-old)
1. Mint the new credential: a bearer token — `openssl rand -base64 32` (high-entropy); an mTLS cert
   — issue from the CA. Store it in the secret store the deployment injects from (never commit it).
2. Provision alongside the old (dual-valid window): for bearer, set `VIVARIUM_HTTP_BEARER_TOKENS` to
   include BOTH the old and new pairs (e.g. `alice:OLD,alice:NEW`) so both authenticate; for mTLS,
   trust both old + new CA/intermediate during the overlap.
3. Roll out — restart the server with the updated env: `python -m vivarium` (HTTP mode, see
   `deploy.md`); verify the new credential authenticates in the structured auth logs.
4. Revoke the old credential: remove its pair from `VIVARIUM_HTTP_BEARER_TOKENS` (or drop the old CA)
   and restart. **For a confirmed compromise, revoke FIRST** (accept the brief auth outage).

## Verification
- Consumers authenticate with the new secret; the old is rejected; no auth-error spike.

## Escalation
- Confirmed exposure → run under `incident-response.md`; page security.

## Related
- `incident-response.md`; `@rules/workflow-secrets.md`; ADR-006 (HTTP v1.1).

---
_Last validated: not yet drilled (env vars verified against `config.py` / ADR-017/019). Owner: repo
maintainer (solo — no formal on-call rotation pre-1.0)._
