# ADR-021: Multi-type composite batch (`define_types`) with by-value cycle detection

- **Status:** Accepted (v1.2 design; human-ratified D1–D2, 2026-06-15). Extends **ADR-015** (composite
  creation) — realizes the deferred **multi-type batch** + the **by-value cycle detector**. Extends
  trust boundary **TB7** (write/agency); **no new boundary**.
- **Deciders:** Human (ratified model = batch, cycle-rule = reject-by-value/allow-pointer, 2026-06-15)
  + PM; recorded by the Software Architect.
- **Relates to:** ADR-015 (Phase C `define_struct`/`define_union` + the pre-registration model this
  generalizes), ADR-012 (write-consent + one-transaction-per-call), ADR-014 (structured `TypeRef`,
  resolved-not-parsed), ADR-018 (persistence — see §Persistence interaction), ADR-017 (owner-scoped).

## Context

ADR-015 shipped `define_struct` / `define_union` — **one composite per call**, whose fields may
reference an existing/base type or **self** (pre-registered so a self-`named` pointer resolves; a
by-value self-embed rejected at the boundary). Cross-type by-value cycles were *structurally
impossible* there precisely because a field could only reference an **already-existing** type. ADR-015
**deferred** "a batch of N interdependent **new** types (A references new B)" because it "multiplies
the cycle-detection surface" and breaks one-call-one-composite. This increment adds exactly that —
with a **real by-value graph cycle detector** as the load-bearing new control.

## Decision (ratified)

### D1 — A new **`define_types` batch tool** (multi-type, one transaction).
Input: `{types: [CompositeSpec]}`, `CompositeSpec = {kind: "struct"|"union", name, fields: [FieldSpec],
packed?}` (`FieldSpec` unchanged from ADR-015). A field's `TypeRef.named` may now reference: an
existing program type, a base type, **self**, **or another composite defined in the same batch**.

- **One call == one transaction == one undoable unit** — the *batch* is the unit (ADR-012's property
  generalizes from "one composite" to "one batch"); `session_undo` reverts the whole batch.
- **Mixed struct + union in a batch is allowed.** The per-entry `kind` discriminator is fine **for a
  list input** (it selects which assembly path per entry); this does **not** reopen ADR-015's reason
  to split the *single* tools (a single tool with a meaningless-field discriminator). The existing
  `define_struct` / `define_union` **remain** for the common single-composite case.
- **No nested-inline define.** A `FieldSpec.type` is still a flat `TypeRef` (resolved, never a nested
  composite definition) — the batch covers "A references new B" without recursion in the resolver.
  Nested-inline recursion stays deferred (the batch is the chosen realization; §Deferred).

### D2 — Cycle rule: **reject by-value cycles, allow pointer cycles.**
Build a directed graph over the batch's composites: an edge **A → B** exists iff A has a member of
type B with **`pointer_levels == 0`** (a *by-value* member — includes an **array of B**). Run a real
cycle detector (DFS / topological sort):
- **Any by-value cycle → REJECT** (`VALIDATION`, no write) — a by-value cycle (incl. self) is
  infinite-size. This is the **load-bearing new control**: because all batch types are pre-registered
  in the DTM before field resolution (below), a by-value cycle *would otherwise resolve* to an
  infinite-size type.
- **Pointer members (`pointer_levels >= 1`) create NO edge** (a pointer is fixed-size) → **mutually
  recursive pointer structures are allowed** (e.g. `B *next` in A and `A *prev` in B). Self by-value
  is still rejected (ADR-015); self/mutual **pointer** refs are fine.
- The detector is **pure** (over the parsed batch, no I/O), bounded `O(V+E)` by the batch bounds, and
  runs **at the boundary before the worker** — 100%-covered (self-cycle, A↔B by-value, allowed
  pointer-cycle, diamond-without-cycle, array-of-self).

### Assembly (generalizes ADR-015 pre-registration; one transaction)
Boundary (pure, pre-worker): schema-validate → per-type `validate_composite` → dup-name-within-batch
→ **by-value cycle detector**. Worker (inside ONE transaction): **pre-register every empty composite
in the batch** (so any in-batch `named` ref — pointer or by-value — resolves) → resolve + add each
type's members → enforce the size cap → commit; **any failure rolls back the whole batch** (no partial
type, no orphan). `name`-collision with an existing program type, or a duplicate name within the
batch, is **fail-closed REJECT** (no write). Structured `TypeRef` only — **no C parsed** (ADR-014).

## Bounds (DoS — CWE-400)
- `_MAX_TYPES_PER_BATCH` (proposed **64**); `_MAX_FIELDS` per type (reuse, 256); a **batch-total
  computed-size cap** (reuse/scale `_MAX_COMPOSITE_SIZE`, 1 MiB, applied to the batch total).
- One bounded transaction; the per-tool **timeout kills the worker** on a hung assembly; the cycle
  detector is `O(V+E)`. Over any bound → fail closed before/at the worker.

## Security (TB7 delta — STRIDE; extends the write boundary, no new boundary)
- **T (partial/corrupt batch):** one transaction, **rollback-all** on any failure — no partial batch,
  no orphan type.
- **D (DoS):** the by-value cycle detector forbids infinite-size recursion; batch/field/size caps +
  bounded detector + timeout-kill bound assembly cost.
- **I/E:** unchanged from ADR-015 — structured `TypeRef` (no C parser), result fields are
  server/worker scalars (no `Untrusted` echo needed), consent-gated (**structural** —
  `require_write_consent(structural=True)`), **owner-scoped** (ADR-017), server never assembles
  (ADR-001 — worker-only). Name-collision REJECT preserves the redefine-in-use/data-poisoning
  protection (ADR-015 §6) per batch member.

## Persistence interaction (ADR-018) — recorded
ADR-018 export emits composites as **individual** `define_struct`/`define_union` entries. A batch's
**mutually-recursive pointer** types cannot round-trip as independent entries (importing A first fails
`not-found` on B's pointer target — no pre-registration across separate entries). Options: (a) add a
`define_types` **export-grouping + Entry variant** so interdependent composites round-trip as a batch;
(b) accept the limitation for now. **Decision: (b) for this increment** — record the limitation; a
`define_types` persistence variant is a **tracked follow-up** (the new tool is still usable live; only
round-trip of mutually-recursive pointer composites is affected).

## Consequences
- Clients can define an **interdependent type graph** (incl. mutually-recursive via pointers) in one
  undoable call; the single-composite tools remain for the common case; a **real by-value cycle
  detector** now exists (the foundation any future nested-define would need).
- Catalog **49 → 50**; `define_types` is **GATED** (write-consent + `allow_structural`).
- **Deferred / out of scope:** nested-inline recursive `FieldSpec` define (batch covers the
  capability); a `define_types` persistence/export grouping (tracked); cross-batch transactions.

## Implementation increment (follows this design PR)
1. **schemas:** `CompositeSpec` (kind-discriminated struct/union entry) + `DefineTypesIn{types:
   [CompositeSpec]}` (1..`_MAX_TYPES_PER_BATCH`) + `DefineTypesResult` (per-type name/kind/size/
   field_count; server/worker scalars) + bounds.
2. **validation:** `validate_types_batch` — per-type `validate_composite`, dup-name-within-batch, and
   the **by-value cycle detector** (pure graph over `pointer_levels==0` named edges among batch
   members; reject by-value cycles incl. self/array-of-self; allow pointer edges). **100%
   line+branch.**
3. **worker:** `_gh_define_types` — pre-register all empties → resolve + add per type → batch
   size-cap → one transaction, rollback-all; `GhidraPort.define_types` + adapter; dispatch RPC.
4. **registry:** `_handle_define_types` (`require_write_consent(structural=True)` → validate → port →
   audit → result); register in `TIER1_TOOL_NAMES` + `_HANDLERS` (catalog **49 → 50**).
5. **contracts:** tool-catalog `49 → 50` + row; rpc-protocol `+define_types`.
6. **threat-model:** TB7 delta + abuse cases (by-value self-cycle rejected; A↔B by-value cycle
   rejected; **A↔B pointer cycle ALLOWED**; oversized batch / per-type / total-size; dup name in
   batch; collision with an existing type; partial-failure rolls back the whole batch; no C parsed;
   cross-owner; structural-consent required) + `topic-testing` gates. Synthetic fixtures only.
