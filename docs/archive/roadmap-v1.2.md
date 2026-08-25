# Roadmap — v1.2 backlog (candidate)

> Source of truth for delivery: [`PLAN.md`](../PLAN.md). Decisions are recorded as ADRs in
> [`docs/adr/`](adr/); the threat model is [`docs/security/threat-model.md`](security/threat-model.md);
> frozen contracts are in [`docs/contracts/`](contracts/); release history is
> [`CHANGELOG.md`](../CHANGELOG.md).

## Status

**Candidate backlog, not committed scope.** v1.1 shipped in **v0.2.0** and the F1 hardening in
**v0.2.1** (see the CHANGELOG); the v1.1 backlog is complete. The items below are the work the v1.1
ADRs **explicitly deferred / marked out-of-scope** — collected here so there is one authoritative,
prioritized list. Nothing here is started; each item is promoted to real work only through the
established rhythm:

> **design ADR → human ratification → implement (isolated worktree) → `sdlc-reviewer` security pass → CI green → gated merge.**

**Pre-1.0 note.** All items below are **additive** and backward-compatible (no existing
tool / RPC / envelope contract change), so each lands as a **minor** bump (`0.x`) under the project's
SemVer + frozen-contract posture. Items that open a **new trust boundary** (persistence, new auth
identity sources) **must be threat-modeled (STRIDE) before coding** ([`workflow-threat-model`]).

## Priorities (suggested)

| # | Item | Area | New trust boundary? | Expected bump | Source |
|---|------|------|---------------------|---------------|--------|
| 1 | mTLS + OAuth identity sources | Auth | hardens TB6 (no new boundary) | minor | ADR-011 §6 · ADR-017 |
| 2 | Composite nested-define / multi-type batches + cycle detector | Write/types | no (extends TB7) | minor | ADR-015 §1/§"Open" |
| 3 | Type deletion (gated) | Write/types | no (extends TB7) | minor | ADR-015 §6 |
| 4 | Mutation persistence / export | Write/lifecycle | **YES — new boundary** | minor | ADR-012 §"Open" |
| 5 | Behavioral-equivalence — deeper eval | Eval quality | no (extends TB5) | minor | ADR-016 §Deferred |
| — | Ops: finalize deploy/rollback runbooks | Ops | n/a | n/a | release-prep note |

---

## 1. Authentication — finish the pluggable identity sources

**What.** Build the two `Authenticator` strategies that are currently port stubs raising
`NotImplementedError`: **mTLS** (verified client-cert subject → principal) and **OAuth 2.1**
(resource-server token validation → principal).

**Why.** v1.1 shipped **multi-token bearer** + the per-principal **ownership mechanism** (ADR-017);
these identity sources slot into that same mechanism unchanged — distinct certs/subjects become
distinct principals. mTLS additionally needs the **TLS-terminator wiring** that ADR-011 deferred to
"a later slice."

**Notes.** Hardens the existing **TB6** network boundary (no *new* boundary). Honor
`std-zero-trust` (per-request authZ, mTLS everywhere) and `topic-authn-authz` (OAuth2/OIDC + PKCE,
pinned alg, `iss`/`aud`/`exp` validation). Keep generic-reject / no-credential-oracle parity with
the bearer authenticator.

**Source.** ADR-011 §6; ADR-017 §Decision/§Consequences ("mTLS/OAuth remain deferred identity
sources").

## 2. Composite types — nested-define / multi-type batches

**What.** Allow a `define_struct`/`define_union` whose field references a **new** (not-yet-existing)
composite, and/or **multi-composite batches** in one call (e.g. A containing a new B).

**Why.** v1.1 Phase C (ADR-015) shipped single-composite creation with a flat `TypeRef` (members
reference only existing or self types). Nesting/batches multiply the recursion surface.

**Hard requirement.** A **real by-value graph cycle detector** over member edges becomes mandatory
(the v1.1 single-composite/one-per-call invariant that made cross-type by-value cycles
*unconstructable* no longer holds). Keep the pre-registration model, the by-value self-embed
rejection, the size cap + transactional rollback, and fail-closed name-collision REJECT.

**Source.** ADR-015 §1 ("nested-define DEFERRED"), §3 (cycle-detector note), §"Open".

## 3. Type deletion (gated)

**What.** A gated tool to delete/redefine a composite (today a name collision is fail-closed
**REJECT** with no delete path — the client must pick a new name).

**Why.** Completes the create/delete lifecycle for client-authored types; prerequisite for a clean
"redefine in place" flow.

**Notes.** Extends **TB7** (write/agency). Deletion of an **in-use** type re-renders every dependent
decompilation — treat the redefine-in-use / data-poisoning vector deliberately (the reason v1.1 chose
REJECT-not-replace). Gate behind `allow_structural`; one transaction + rollback; audit.

**Source.** ADR-015 §6 ("deletion is itself a future gated tool, not in Phase C").

## 4. Mutation persistence / export — **new trust boundary**

**What.** A path to persist or export session annotations beyond the ephemeral session — e.g. a
`session_export_annotations` tool (design hook already noted), a saved-project / export-and-reimport
flow, or Ghidra Server integration.

**Why.** v1.1 mutations are **session-scoped + ephemeral** (lost on evict — ADR-002). Persistence is
the most-requested natural follow-on but is deliberately its own increment.

**Hard requirement.** **Opens a new trust boundary** — *import of attacker-influenced annotations*
back into a session. **Threat-model it (STRIDE) before coding** (`workflow-threat-model`): the
imported annotations are hostile-origin data (ADR-005 envelope on the way out still applies), and the
import path needs validation + provenance. Likely a new ADR + a dedicated threat-model section.

**Source.** ADR-012 §"Open" / design hook; ADR-012 cross-session-persistence note (out of scope for
v1.1, "separate, deferred, threat-modeled increment").

## 5. Behavioral-equivalence — deeper eval

**What.** Strengthen the ADR-016 differential harness beyond the v1.1 **I/O differential** (exit code
+ byte-exact stdout): **memory-state / coverage-guided** equivalence, **fuzz / auto-generated** input
vectors, and output **normalization**.

**Why.** v1.1 ships a measured, best-effort I/O oracle on trusted-source ground-truth fixtures; deeper
notions raise confidence in the naming/recompilation quality signal.

**Hard constraint (unchanged).** **Never execute the original hostile binary** — diffing against the
real hostile original stays **rejected** (it would breach ADR-001). Work stays inside the **TB5**
sandbox (rootless, no-egress, capped, kill-on-timeout) and remains a *measured metric, not a
guarantee*.

**Source.** ADR-016 §Decision (D1, rejected) / §"Deferred / out of scope".

---

## Permanently out of scope (not backlog)

- **`runScript` / arbitrary script execution** — the read-only/least-agency posture forbids it
  permanently (PLAN §2; ADR-012). Not a v1.2 candidate.
- **Diffing the real hostile binary** in the eval harness — breaches ADR-001 (item 5 constraint).

## Ops loose end (not a feature)

- Finalize the **`docs/runbooks/deploy.md`** and **`docs/runbooks/rollback.md`** scaffolds (they still
  carry `<cmd>` placeholders) with concrete commands + image-digest steps — flagged during v0.2.0
  release prep. Tracked here for visibility; can land any time independent of the feature backlog.
