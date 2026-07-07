# ADR-033 — OAuth scopes → fine-grained per-tool authorization

> **Naming note (post-ADR-038):** environment variables in this record predate the rename to Vivarium
> and appear under their original `GHIDRA_MCP_*` names — they are now `VIVARIUM_*` (e.g.
> `GHIDRA_MCP_HTTP_OAUTH_WRITE_SCOPE` → `VIVARIUM_HTTP_OAUTH_WRITE_SCOPE`). The authoritative config
> reference is [`docs/getting-started.md`](../getting-started.md) and `src/vivarium/config.py`.

- **Status:** Accepted (v1.4; human-ratified 2026-06-17). Implements roadmap-v1.4 item #5 — the
  ADR-019 deferred "OAuth scopes → fine-grained per-tool authZ". Hardens **TB6** (the HTTP network
  boundary); no new trust boundary, no JVM edge. Ratified: **(1) two capabilities `read`/`write`**
  (structural writes stay governed by the orthogonal runtime `allow_structural` consent); **(2)
  config-gated opt-in** — enforcement is OFF by default (OAuth stays identity-only, current
  behavior); a deployment opts in by configuring the write-scope string.

## Context

ADR-019 maps an OAuth access token's `sub` claim → `Principal` (**identity only**); every
authenticated identity gets the full tool catalog (ADR-019 §E explicitly deferred scope→authZ). So a
token minted for a read-only consumer can still drive the write tools (rename/comment/define/delete/
import) — the authN mechanism grants no *capability* differentiation. Master §2 (least privilege,
complete mediation) and `std-owasp-api` (API5 broken function-level authZ) want per-capability
authorization. This adds it, centralized, without breaking existing deployments.

## Decision

### D1 — Two capabilities: `read` and `write`

A `Principal` carries `capabilities: frozenset[str]` ⊆ `{"read", "write"}`. Every Tier-1 tool
requires exactly one capability:

- **`write`** — the 15 mutation tools: the consent toggles (`session_enable_writes`/
  `session_disable_writes`), `session_undo`, the annotation writes (`rename_function`/
  `rename_symbol`/`set_comment`), the structural writes (`rename_local_variable`/`rename_parameter`/
  `set_function_signature`/`apply_data_type`/`define_struct`/`define_union`/`define_types`/
  `delete_type`), and `session_import_annotations` (replays writes). The frozen `WRITE_TOOLS` set is
  the single source of truth (asserted complete vs. the catalog in tests).
- **`read`** — everything else: the read/query tools, the session lifecycle
  (`session_create`/`import`/`analyze`/`status`/`close`), and `session_export_annotations`
  (read-only). A read-only token can run the full import→analyze→read→export workflow but **cannot
  enable writes or drive any mutation**.

Structural granularity is **not** a token capability — it stays governed by the existing per-session
`allow_structural` runtime consent (ADR-013/015). A structural write must pass BOTH `write`
capability (token) AND `allow_structural` consent (session): defense in depth.

### D2 — Config-gated opt-in (default off; backward-compatible)

The `OAuthResourceAuthenticator` gains an optional `write_scope: str | None` (from
`Config.oauth_write_scope` / `GHIDRA_MCP_HTTP_OAUTH_WRITE_SCOPE`):

- **`write_scope` unset (default):** an OAuth token gets **full** capabilities (`{read, write}`) —
  identity-only, byte-for-byte the pre-ADR-033 behavior. No enforcement; nothing breaks.
- **`write_scope` set (opt-in):** a valid OAuth token always gets `read`; it gets `write` **iff** its
  `scope` (space-delimited string, RFC 6749/8693) or `scp` (array, common IdP variant) claim contains
  the configured `write_scope`. A read-only token (lacking that scope) is granted `read` only and is
  **denied every write tool**, fail closed.

**Non-OAuth principals** (stdio local operator, bearer, mTLS) carry **full** capabilities — they have
no scope concept (ADR-019 treats them as full-catalog identities); `_LOCAL_PRINCIPAL` and the
bearer/mTLS principals are unchanged. `Principal.capabilities` **defaults to full**, so only the
OAuth authenticator (with `write_scope` set) ever narrows it.

### D3 — Enforcement at the dispatch chokepoint (complete mediation)

Every tool is gated at the registry binding chokepoint (`_bind` and the async `_bind_analyze`),
**before** any model reconstruction or handler work: if `ctx.caller_capabilities` does not contain
the tool's `required_capability(name)`, the call is rejected. `ToolContext.caller_capabilities`
mirrors `caller_id` — it reads the per-request resolver's principal (HTTP) or the static principal
(stdio/tests). Server-side, every request, every tool — never a client-asserted capability
(complete mediation; `std-owasp-api` API5).

### D4 — Denial maps to the existing `VALIDATION` envelope (no error-contract change)

A capability denial raises `GhidraMcpError(VALIDATION)` with a value-free message ("access token
lacks the capability required for this tool"), **consistent with the analogous write-consent denial**
(`require_write_consent` → `VALIDATION` "session is read-only; write consent not granted"). This keeps
the frozen error envelope stable (no new `FORBIDDEN`/403 type) and matches the established
authZ-denial mapping. (A dedicated 403 error type is a future error-contract change, out of scope.)
The denial is logged redacted (tool + principal id + the missing capability — never the token).

## Consequences

- An OAuth deployment can mint **read-only** tokens that are mechanically barred from every write
  tool — closing the ADR-019 §E gap (API5). The write gate is now two independent controls: token
  `write` capability (who you are) AND `allow_structural`/write-consent (what this session opted into).
- Default behavior is unchanged (enforcement is opt-in via `oauth_write_scope`); existing OAuth/
  bearer/mTLS/stdio deployments are unaffected until they configure the write-scope.
- Server-only change (auth + registry chokepoint + config); no worker/JVM involvement, no new trust
  boundary. Fully unit-testable (no live worker needed).

## Decisions ratified by the human (2026-06-17)
1. **D1 — read/write only; structural stays runtime-consent.** ✅
2. **D2 — config-gated opt-in (default off; set `oauth_write_scope` to enable).** ✅

## References
- ADR-019 (OAuth/bearer/mTLS identity; §E deferred scope→authZ), ADR-017 (owner-scoped sessions),
  ADR-013/015 (`allow_structural` runtime consent), `std-owasp-api` API5, master §2 (least privilege,
  complete mediation), threat-model TB6.
