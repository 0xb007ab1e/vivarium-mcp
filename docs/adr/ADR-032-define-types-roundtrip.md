# ADR-032 — `define_types` annotation round-trip (interdependent composite graphs)

- **Status:** Accepted (v1.4; human-ratified 2026-06-17). Implements roadmap-v1.4 item #4 — the
  ADR-021 §Persistence-interaction deferred follow-up ("option (a)"). Closes the gap where
  **mutually-recursive pointer composites cannot round-trip** through annotation export/import.
  Ratified: **(1) export emits ALL session-authored composites as a SINGLE `define_types` batch
  entry**; **(2) >64 composites fail closed `limit-exceeded`** (no partial/lossy round-trip).
  Additive entry kind + a schema-version bump (1 → 2, both accepted on import). No new trust
  boundary (TB8 — annotation persistence — unchanged in shape).

## Context

ADR-018 export emits each session-authored composite as an **individual**
`define_struct`/`define_union` entry, and import replays them one-by-one through the existing
handlers. ADR-021 added `define_types` (a batch of interdependent composites created in ONE
transaction via pre-registration), but deferred the persistence story:

- **Mutually-recursive pointer composites can't round-trip.** If `A` has a `B*` field and `B` has an
  `A*` field, there is no order in which the two *individual* entries can be replayed — whichever
  imports first fails `not-found` on the other's pointer target (a `define_struct` resolves a `named`
  ref against the live DTM; the peer doesn't exist yet). Only the batch's pre-registration resolves
  the cycle.
- **Even acyclic interdependencies are at risk today:** the export iterates the change-log
  `composite_targets` in **set/log order, not dependency order**, so `A` embedding/pointing at `B`
  may already be emitted before `B` and fail on import. The fix must handle ordering too.

## Decision

### D1 — Export emits one `define_types` batch entry for all session-authored composites

The worker collects every reconstructable session-authored composite (the ADR-027 change-log
selection it already reads) into a **single `define_types` batch entry**
(`{"kind":"define_types","types":[{kind,name,fields}, …]}`), emitted **first** (before the
signatures/applies that may reference the types). Import replays it through the **existing**
`_handle_define_types` handler, whose pre-registration resolves **any** interdependency uniformly —
pointer cycles, by-value acyclic chains, and set-order non-determinism alike. No dependency-graph or
topological-sort machinery is needed (the batch is order-independent by construction).

Rationale (vs. per-SCC grouping): one batch is far simpler (a small worker change, no Tarjan/SCC
JVM-edge to build + live-verify), and it fixes the acyclic-misorder bug for free. The cost — every
composite export becomes a `define_types` entry (a single composite → a 1-type batch) — is benign.

### D2 — >64 composites fail closed (`limit-exceeded`)

A `define_types` batch is capped at `_MAX_TYPES_PER_BATCH = 64` (the CWE-400 fan-out bound). The
change-log allows up to 10,000 composites, so a session *could* author more than 64. Export of **more
than 64** session-authored composites raises **`limit-exceeded`** (worker-side, before any entry is
returned), with a clear message. A round-trippable interdependent type graph is bounded to ≤64
composites; >64 is pathological. The **live `define_types` tool keeps its 64 cap** unchanged; only
the *round-trip* of a >64-composite session is refused (the live writes that created them succeeded).

### D3 — Additive entry kind + schema-version bump (1 → 2; both accepted)

- New **`DefineTypesEntry`** (import) = `{kind:"define_types", types:[CompositeSpec]}` and its
  exported view **`ExportedDefineTypesEntry`** (each composite/field name `Untrusted`-wrapped —
  ADR-005, since the names are read out of the hostile program). Added to the `Entry` /
  `ExportedEntry` discriminated unions.
- `define_types` is added to **`STRUCTURAL_ENTRY_KINDS`** — importing it requires `allow_structural`
  consent exactly like the live tool (LLM08; the human-in-the-loop gate is not bypassed by import).
- On import each `DefineTypesEntry` is **re-validated via `validate_types_batch`** (the by-value
  cycle detector + per-type `validate_composite` + intra-batch unique-name) — same as the live tool;
  a legitimately-exported graph passes, a tampered one fails closed.
- **`ANNOTATION_SCHEMA_VERSION` bumps 1 → 2.** New exports are v2. Import accepts **`{1, 2}`** — a v2
  importer still understands v1 documents (the `define_struct`/`define_union` entry kinds remain in
  the union and replayable), so old documents keep importing; a (pre-change) v1 importer cleanly
  rejects a v2 document as "unsupported version" rather than choking on the unknown discriminator.

### D4 — Replay unchanged elsewhere; the import boundary is not widened

`define_types` import adds **no new write primitive** — it replays through the existing gated
`define_types` handler (`require_write_consent(structural=True)` + `validate_types_batch` + ONE
worker transaction with rollback), exactly the TB8 model (ADR-018): schema-validate → hash-bind →
consent-gate → per-entry re-validate → replay. The server still persists nothing (ADR-002). Owner
scoping (ADR-017) and redaction (only counts/sizes audited — never the imported type/field values)
are unchanged.

## Consequences

- Mutually-recursive pointer composites (and any acyclic-but-misordered interdependency) now
  round-trip losslessly through export → import, as a single atomic batch.
- The exported-document shape changes: composites appear as one `define_types` entry instead of N
  `define_struct`/`define_union` entries (schema v2). Old (v1) documents still import.
- Round-trip is bounded to ≤64 composites per session (D2); >64 → `limit-exceeded` (documented).
- The worker export edge (`_gh_export_annotations`) changes — **live-verified on a real worker**
  before merge (define A + B mutually pointer-recursive → export → re-import into a fresh session →
  both reconstructed): the F2/F7/ADR-030 rule (JVM edges can't be unit-tested).

## Decisions ratified by the human (2026-06-17)
1. **D1 — one `define_types` batch for all session-authored composites.** ✅
2. **D2 — >64 composites fail closed `limit-exceeded`.** ✅

## References
- ADR-021 §Persistence interaction (this is "option (a)"), ADR-018 (TB8 annotation persistence),
  ADR-027 (change-log `composite_targets`), ADR-015 (composite creation + name-collision REJECT),
  ADR-005 (untrusted-data envelope), ADR-017 (owner scoping), threat-model TB8.
