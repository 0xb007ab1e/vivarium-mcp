# ADR-036: Dedicated `forbidden` (403) authorization-denied error type

- **Status:** Accepted (v1.5; human-ratified 2026-06-18). Ratified: add an **additive** `forbidden`
  error type (403, not retryable) and move **all three** "authenticated + owns the session but not
  permitted for this op" denials to it — scope→tool capability (ADR-033) and write-consent +
  structural-consent absence (ADR-012). **Ownership / cross-caller denial STAYS `session-invalid`
  (404, BOLA-safe)**; malformed args STAY `validation-error`. Frozen error-envelope contract change
  (additive row + note, the `resource-exhausted` precedent — no slug repurposed). Server-only, no
  JVM edge. Addresses v1.5 roadmap item #3.
- **Date:** 2026-06-18
- **Deciders:** Human (ratifies the scope of the move + the type/status) + PM; recorded by the
  Software Architect.
- **Addresses:** `docs/archive/roadmap-v1.5.md` §3 — "dedicated 403/FORBIDDEN authZ error type."
- **Relates to / constrained by:** ADR-033 (OAuth scope→per-tool capability authZ — the denial this
  reclassifies), ADR-012 (write-consent gate — likewise), ADR-017 (owner-scoped sessions — the
  ownership denial that must STAY `session-invalid`), the frozen error-envelope contract
  (`docs/contracts/error-envelope.md`) and `core/errors.py` (its source of truth).

## Context

Two server-side authorization denials currently collapse onto `validation-error` (400):
`_authorize_capability` (ADR-033 scope→tool) and `require_write_consent` (ADR-012, both the
write-consent-absent and structural-not-allowed cases). ADR-033 §D4 deliberately kept the frozen
envelope stable for v1.4 by reusing `validation-error` and recorded a dedicated 403 type as "a future
error-contract change, out of scope." That future is this ADR.

Conflating "your request was malformed" (`validation-error`) with "you are not permitted to do this"
(an authorization decision) is poor authZ semantics (`std-owasp-api`): a client cannot distinguish a
fixable bad argument from a permission it simply lacks. A dedicated `forbidden`/403 fixes that.

**The load-bearing security subtlety:** a 403 must NOT become an existence oracle. Ownership /
cross-caller denial (ADR-017) is intentionally indistinguishable from "unknown/expired" — it returns
the BOLA-safe `session-invalid` (404) so a caller can never learn that *another* principal's session
exists (`std-owasp-api` API1). That denial must **stay** `session-invalid`; `forbidden` is only ever
raised **after** the owner check has already passed (the caller demonstrably owns the session).

## Decision

- **D1 — Add `ErrorType.FORBIDDEN = "forbidden"`** (status **403**, retryable **false**), with `_STATUS`
  and `_TITLE` ("Forbidden") entries in `ghidra/_errors.py`. Additive — no existing slug repurposed
  (the `resource-exhausted` precedent). No worker-slug mapping (it is a server-side decision, never a
  worker fault).
- **D2 — Move all three authZ/consent denials to `forbidden`:** `_authorize_capability` (capability
  absent) and `require_write_consent` (write consent absent; structural not allowed). They are one
  class — "authenticated, owns the session, not permitted for this operation" — and stay mutually
  consistent (the inverse of ADR-033 §D4, which had unified them on `validation-error`).
- **D3 — Invariant: ownership/cross-caller denial stays `session-invalid` (404, BOLA-safe).** It is
  raised at the shared owner check (`_get_live_locked`) *before* any consent/capability check, so
  `forbidden` cannot fire for a non-owner. `validation-error` stays for malformed args. This keeps
  403 from disclosing the existence of another principal's session.
- **D4 — Redaction.** The `forbidden` `detail` is a fixed, value-free string — never the token, the
  scope/claim contents, or which capability/consent is missing in a way that aids enumeration
  (error-envelope.md disclosure rules). The specific reason is logged server-side (the existing
  redacted `tool.authz_denied` line — tool + principal + required capability, never the token).
- **D5 — Contract change.** `docs/contracts/error-envelope.md` gains the `forbidden` row + an
  additive note (incl. the BOLA invariant); routed through the PM per the frozen-contract mandate.
  Clients that branch on `type` gain a new value to handle (additive; pre-1.0).

## Consequences

- **Positive:** clients can distinguish "not permitted" (403, terminal — get the capability / grant
  consent) from "malformed" (400, fix the request) and from "unknown/not yours" (404). Better authZ
  semantics with no behavioral change to *what* is allowed — only the *classification* of the denial.
  The two authZ denials stay consistent with each other.
- **Negative / trade-offs:** a frozen-contract change (additive) — every test asserting
  `validation-error` for a capability/consent denial moves to `forbidden`; clients branching on the
  envelope must learn the new type. Bounded, mechanical, and pre-1.0.
- **Security:** the BOLA invariant (D3) is the thing to not get wrong — verified by an explicit test
  that a foreign caller still gets `session-invalid` (not `forbidden`) on a write attempt. No new
  trust boundary; server-side only; no JVM edge → no live verification required.

## Alternatives considered

- **Move capability only, leave write-consent on `validation-error`** — smaller blast radius but
  re-splits one denial class across two types (undoes ADR-033 §D4's consistency). Rejected (D2).
- **Keep everything on `validation-error` (status quo)** — the conflation ADR-033 explicitly flagged
  as deferred debt. Rejected.
- **Use 401/`unauthorized`** — wrong semantics: the caller *is* authenticated; they lack a
  permission, not an identity. 403/`forbidden` is correct.
