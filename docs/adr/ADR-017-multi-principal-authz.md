# ADR-017: Multi-principal authorization (per-principal session ownership)

- **Status:** Accepted (v1.1 design; human-ratified decisions, 2026-06-15). Realizes the
  per-principal owner check **deferred by ADR-011 §6**; closes threat-model **TB6-I**.
- **Deciders:** Human (ratified scope + deny-semantics, 2026-06-15) + PM; recorded by the Software
  Architect.
- **Relates to:** ADR-011 (HTTP transport — minted `Principal`, stashed it on the request scope, and
  deferred ownership), ADR-002 (one worker per session), ADR-012 (write-consent bound to principal +
  session), `std-owasp-api` (API1/BOLA), `std-zero-trust` (per-request authZ), `topic-authn-authz`,
  `topic-multi-tenancy` (per-principal isolation is a security boundary).

## Context

ADR-011 shipped the network surface and every seam for authorization: an `Authenticator` maps a
request to a `Principal(id)`, the `AuthenticationMiddleware` stashes it on the ASGI scope, and the
catalog is per-request authorized. **Two things were deliberately deferred** because they are vacuous
with a single operator:
- `SessionManager.create()` records **no owner**; `authorize()` / `_get_live_locked()` (the single
  BOLA chokepoint) perform **no owner check** — BOLA was "closed by construction" only because there
  was exactly one principal (ADR-011 §6; threat-model TB6-I, abuse case 6).
- The only built identity source is a **single shared bearer token** → one `Principal(id="bearer")`;
  mTLS/OAuth are port stubs (`NotImplementedError`).

The moment a second distinct principal can exist, the capability-only argument is insufficient and a
real per-principal ownership check becomes **load-bearing** (a cross-principal session reference is a
BOLA / `std-owasp-api` API1 break — a critical incident). This ADR makes the system correctly and
safely multi-principal.

## Decision (ratified)

### D1 — Scope: ownership mechanism **+ multi-token bearer** (a concrete distinct-identity source).
1. **Ownership binding (the mechanism — transport-agnostic, the security core):**
   - `_Session` gains an immutable `owner: str` (the creating principal's id).
   - `create(*, label, owner)` records it; the per-request `Principal` flows to `create`.
   - **Every ownership-checking entry point verifies `sess.owner == caller_principal.id`** and denies
     on mismatch: `authorize`, `enable_writes`, `disable_writes`, `require_write_consent`,
     `ensure_worker`, and `close`/`evict` initiated by a tool call. The check lives in the shared
     `_get_live_locked` chokepoint so it is **uniform and unbypassable** (complete mediation,
     `std-zero-trust`).
2. **Multi-token bearer (the identity source):** replace the single `bearer_token` with a
   **token → principal-id** map (loaded from env/secret-manager — each token a secret kept out of
   `repr`/logs, `workflow-secrets`). A `MultiTokenBearerAuthenticator` returns `Principal(id=<that
   token's configured id>)`. A single configured token remains valid (back-compat → its mapped id).
   This makes ownership **non-vacuous in production** without any TLS plumbing; mTLS/OAuth stay
   deferred port stubs (built when enabled).

### D2 — Deny semantics: an owner mismatch returns the **same `SESSION_INVALID`** as unknown/
expired/evicted.
No oracle distinguishes "exists but not yours" from "does not exist" — preserving the existing
BOLA-safe chokepoint (`std-owasp-api` API1; `error-envelope.md`). Deny-by-default, fail-closed; the
real cause is recorded **server-side only** in the audit log (principal id + session id, redacted of
secrets — `topic-logging-observability`).

### Principal threading
`ToolContext` gains `principal: Principal`. For **HTTP** it is built **per request** from the
scope-stashed principal (`AuthenticationMiddleware` already populates it); for **stdio** (no network
auth, single trusted host — ADR-006) it is the implicit **local operator** (`Principal(id="local")`),
so stdio stays single-principal and the ownership check is consistent (every session owned by
`local`). The server never trusts a client-supplied principal/owner — identity is derived
**server-side** from the authenticated request only.

## Threat model (STRIDE — the new per-principal boundary; strengthens TB6)

- **S (Spoofing a principal):** identity comes only from the authenticated request (bearer token →
  mapped id), never from client-supplied data; constant-time token compare, generic `401` (no
  oracle). Forging another principal requires their secret token.
- **T (Tampering with ownership):** `owner` is set once at `create` from the server-derived principal
  and is immutable; no tool can rewrite it.
- **R (Repudiation):** `create`/`authorize`-deny/`write-consent` log principal id + session id +
  outcome (audit trail), redacted of secrets.
- **I (Information disclosure — the core BOLA risk):** owner mismatch → uniform `SESSION_INVALID`
  (D2): no cross-principal existence/data leak. The 256-bit CSPRNG id remains an unguessable
  capability; ownership is the second, now-load-bearing control (defense in depth).
- **D (DoS):** per-principal session **cap/quota** so one principal cannot exhaust the global session
  table and starve others (noisy-neighbor — `topic-multi-tenancy`, `topic-reliability`); reuse the
  existing `max_sessions` global cap + add a per-owner cap.
- **E (Elevation):** a principal cannot act on another's session (read OR write); write-consent is
  already bound to principal+session (ADR-012) and now the session itself is owner-scoped. No
  principal gains another's worker (one worker per session, owner-gated before `ensure_worker`).

## Architecture & invariants
- The check is **in `SessionManager`** (the functional/stateful core), not scattered in handlers —
  one chokepoint, enforced under the existing re-entrant lock (`topic-concurrency`).
- **Deny-by-default / complete mediation:** every session-scoped entry point goes through the
  owner-checked `_get_live_locked`; a new session-scoped tool cannot forget the check.
- **No contract change to tools/RPC/untrusted-envelope.** `session_id` stays the opaque capability;
  the catalog is unchanged. (Config gains the multi-token map; `error-envelope` unchanged — reuses
  `SESSION_INVALID`.)
- ADR-001 preserved (server-only authZ; worker untouched). Identity/owner are plain ids, never
  binary-derived.

## Consequences
- BOLA is closed **by an enforced per-principal owner check**, not merely by the single-principal
  invariant — TB6-I deferral resolved; the control is exercised by real cross-principal abuse tests
  (principal B presents A's session id → `SESSION_INVALID`; B cannot enable writes / analyze / close
  A's session).
- Multiple operators can use one network endpoint with distinct tokens, each owning only their
  sessions; a per-owner session cap bounds noisy-neighbor.
- mTLS/OAuth remain deferred identity sources (port stubs) — when built, they slot into the same
  ownership mechanism unchanged.
- **Deferred / out of scope (recorded):** building mTLS/OAuth identity extraction; cross-principal
  *sharing* / delegation of a session (none — sessions are single-owner in v1.1); per-principal rate
  limits beyond the session cap.

## Implementation increment (follows this design PR)
1. `sessions/manager.py`: `_Session.owner`; `create(owner=...)`; owner verification in
   `_get_live_locked` (+ the write-consent/ensure_worker/close paths) → `SESSION_INVALID` on
   mismatch; per-owner session cap; audit-log principal+session+outcome. 100% on the critical authZ
   paths.
2. `config.py` + `server/auth.py`: token→principal-id map + `MultiTokenBearerAuthenticator`
   (constant-time, no which-token timing oracle, generic reject); single-token back-compat; tokens
   excluded from `repr`/logs.
3. `tools/registry.py` + `server/app.py` + `server/http_middleware.py`: thread the per-request
   `Principal` into `ToolContext`; `create(owner=ctx.principal.id)`, session-scoped handlers pass the
   caller principal to the manager; stdio → `local`.
4. threat-model **TB6** update (flip TB6-I "deferred" → enforced; new per-principal STRIDE rows) +
   cross-principal **abuse cases** (B uses A's id across read/write/close → `SESSION_INVALID`;
   per-owner cap; spoof/timing); `topic-testing` coverage gates. No real secrets in tests.
