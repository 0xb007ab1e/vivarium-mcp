# ADR-015: Composite-type creation (write) tools — structural mutation Phase C

- **Status:** Accepted — design + the locked-decision calls **ratified by the human 2026-06-12**:
  (a) **`define_struct` + `define_union` now** (one composite/call; nested-define + multi-type
  batches deferred), (b) **recursion = pre-register the empty type so self-`named` pointers resolve
  (true self-referential types supported); by-value self-embed rejected at the boundary; cross-type
  by-value cycles structurally impossible in v1; total-size cap + transactional rollback as backstops
  (§3)**, (c) **name collision = fail-closed REJECT reusing an existing error slug (no new
  `ErrorType`)**. **Implementation remains gated** — the PROPOSED contract additions ratify into
  `docs/contracts/**` and the build lands via reviewed, gated PRs (no mutation code yet).
- **Date:** 2026-06-12
- **Deciders:** Human (ratified the scope / recursion-rule / conflict-policy calls) + PM; recorded by
  the Software Architect.
- **Builds on / constrained by:** ADR-001 (out-of-process — the server never loads the JVM or
  mutates), ADR-002 (one worker/session, kill + verified-wipe on evict), ADR-005 (untrusted-data
  envelope), ADR-006 (the catalog extensibility seam — additive, allow-listed), ADR-011 (HTTP edge
  composition), **ADR-012** (annotation mutation — the gate / one-transaction / audit model),
  **ADR-013 Phase A** (`rename_local_variable`/`rename_parameter`; the `allow_structural` consent
  hook; the corrected one-transaction `_in_transaction`), and the **merged ADR-014 Phase B**
  (`set_function_signature` + `apply_data_type`; the structured `TypeRef`/`ParamSpec` model; the
  `validate_type_ref`/`validate_signature`/`validate_calling_convention` validators; the
  `_gh_resolve_type_ref` worker edge). Frozen contracts in `docs/contracts/**`; threat-model **TB7
  (structural)** (`docs/security/threat-model.md` §10).
- **Extends:** ADR-014 §1 — the **explicit deferral** of new-composite creation to Phase C
  (`docs/adr/ADR-014-structural-mutation-phase-b.md:63-97`, `:458-461`, `:474-477`) and **WHY**: it
  is the **widest re-render surface** + reintroduces the **recursive/self-referential definition
  risk** (`:83-92`). This ADR honors the same human-ratified ADR-013 §2(a) pre-decision —
  **structured input, NEVER free-form C** (`docs/adr/ADR-013-structural-mutation.md:133-169`) — and
  **reuses Phase B's `TypeRef`/`ParamSpec`/`validate_type_ref` wholesale** (`schemas.py:1443-1491`,
  `validation.py:490-531`).

## The pre-decided constraint (NOT relitigated here)

ADR-013 §2(a)/KEY DECISION (b) and ADR-014 §2 — ratified by the human — locked the structured-input
model: a structural write accepts a **structured / constrained** type input (resolved `TypeRef`s,
bounded counts, closed vocabularies) and **never** a free-form C string parsed by Ghidra's
`CParser`/`DataTypeParser` (`docs/adr/ADR-014-structural-mutation-phase-b.md:26-35`,
`:102-108`). A new composite in Phase C is built **field-by-field** from a bounded list of
**`FieldSpec`**, where every `FieldSpec.type` is a **`TypeRef`** resolved by the existing
`_gh_resolve_type_ref` worker edge (`_jvm_bridge.py:1603-1689`) against the program's
`DataTypeManager` / the closed base vocab — `CParser`/`DataTypeParser` are **never** instantiated on
a client value. This ADR's entire design is built around eliminating the C-parser surface **by
construction**, exactly as Phase B did for signatures; free-form C ("`struct {...}`") is recorded in
§"Alternatives" only as the explicitly-rejected option.

## Context

ADR-014 Phase B shipped the first **type-aware** structural writes — `set_function_signature` and
`apply_data_type` — both of which *consume* `TypeRef`s over types that **already exist or derive from
the closed base vocabulary** (`docs/adr/ADR-014-structural-mutation-phase-b.md:76-81`). ADR-014 §1
**deferred** the one remaining structural-write rung to **Phase C**: *creating a brand-new composite
type* (struct/union) — the only path that **mutates the program's type universe** rather than
consuming it (`:83-92`, table row `:73`).

The functional gap this closes: a client (driven by ADR-007 semantic-naming) can recover that a
buffer is really a `struct {int id; char name[32]; void *next;}` from the decompiled C, but in
Phase B it can only *apply* a struct **Ghidra already recovered** — it has **nowhere to define a new
one**. `function_context`/`get_data_type` surface existing types as `Untrusted[...]`
(`_jvm_bridge.py:739-748`), but there is no creation path. Phase C closes this last rung.

ADR-014 named the two specific reasons for the deferral (`docs/adr/ADR-014-structural-mutation-phase-b.md:83-92`):

1. **Widest re-render blast radius** — a *new* type is, at creation, referenced by **nothing**
   (it is created in the `DataTypeManager`, not yet applied), so its *creation* re-renders nothing
   until a subsequent `apply_data_type` references it. This is a genuine de-risking property and a
   load-bearing part of this design (§"the re-render blast radius" below). The wide re-render is
   thus **decoupled** to the existing Phase-B `apply_data_type` (which is already threat-modeled).
2. **Recursive / self-referential definition risk** — a struct that *embeds* itself, or a cycle of
   structs (A contains B contains A), is the structured-input analogue of the parser-bomb
   consumption ADR-013 §2a worried about, now in **our** assembly code (§"the recursion crux"
   below). This is the one genuinely-new risk class Phase C introduces, and §3 designs the rule.

The catalog is at **45** tools (`docs/contracts/tool-catalog.md:9`); the structured-input machinery
(`TypeRef`, `ParamSpec`, `validate_type_ref`, `_gh_resolve_type_ref`, the `allow_structural` gate,
the corrected `_in_transaction`) is **all merged from Phase B** and is reused unchanged.

## Decision

### 1. Scope — `define_struct` + `define_union` as **two** worker write tools; one composite per call; nested-define DEFERRED

**Phase C creates a new composite type from a structured field list.** A composite is either a
**struct** (sequential/offset layout) or a **union** (overlaid, all fields at offset 0). The input is
`{name, fields: [FieldSpec], packed?}`; `FieldSpec = {name, type: TypeRef, offset?}`.

We recommend **two narrowly-typed tools rather than one `kind`-switched tool** — `define_struct` and
`define_union` — for the same typed-least-privilege reason ADR-012 rejected a generic `set_property`
and ADR-014 split the type-aware writes into two tools: a struct and a union differ enough (a struct
honors `offset`/`packed`; a union ignores both and overlays) that one schema with a `kind`
discriminator would carry fields meaningless for one variant (a struct-only `offset` on a union is a
silent foot-gun). Two tools keep each schema **total** for its variant (`topic-defensive-programming`
"make illegal states unrepresentable"). This is **KEY DECISION (a)** — confirm struct+union now vs.
struct-first.

| Candidate | Ghidra write API (worker-only) | Recommendation |
|-----------|--------------------------------|----------------|
| `define_struct` | `StructureDataType(CategoryPath.ROOT, name, 0, dtm)`; add each field via `.add(dt, dt.getLength(), name, comment)` (packed/sequential) or `.insertAtOffset(offset, dt, dt.getLength(), name, comment)` (explicit offset); `dtm.addDataType(struct, conflictHandler)` | **IN — Phase C** |
| `define_union` | `UnionDataType(CategoryPath.ROOT, name, dtm)`; add each field via `.add(dt, dt.getLength(), name, comment)` (offset is meaningless — all at 0); `dtm.addDataType(union, conflictHandler)` | **IN — Phase C** (recommended; KEY DECISION (a)) |
| **nested `define`** (a `FieldSpec.type` that itself *defines* a new inline composite) | a recursive descent that creates child composites in the same call | **DEFER — beyond Phase C** |

- **One composite per call (CONFIRMED — no batch of interdependent new types in v1).** A single
  call creates exactly one struct or one union. A "batch of N interdependent new types" (e.g. define
  A and B where A contains B in one call) is **deferred** — it multiplies the cycle-detection surface
  across types and breaks the clean "one tool call == one transaction == one undoable unit" property
  the whole mutation arc rests on (ADR-012 §4, `_jvm_bridge.py:1810-1822`). A client that needs B
  inside A defines **B first** (one call), then A referencing B by `named` `TypeRef` (a second call).
  Each is independently undoable via `session_undo`.
- **Nested-define DEFERRED (beyond Phase C).** A `FieldSpec.type` is a **`TypeRef`** — it references
  an *existing/base/derived* type, exactly as in Phase B. It may **not** itself carry a new-composite
  definition. This keeps `FieldSpec.type` resolution identical to Phase B's `_gh_resolve_type_ref`
  (no new recursion in the resolver) and caps nesting depth at **0 new types per call**. (A future
  increment could add a recursive `define` with its own depth bound; out of scope here — §"Open".)
- **`runScript` / arbitrary script execution** — remains permanently out of scope (PLAN §2,
  `docs/contracts/tool-catalog.md`). Phase C does **not** reopen it.

> **Creation, not application.** Once a composite is created, it is applied at an address by the
> **existing Phase-B `apply_data_type`** (which resolves a `named` `TypeRef` — `_jvm_bridge.py:1760-1808`).
> So Phase C is *creation only*; **application already exists**. A typical client flow is
> `define_struct{name:"Packet", fields:[...]}` → `apply_data_type{address:0x..., type:{named:"Packet"}}`.
> This decoupling is what keeps the wide re-render out of Phase C (see §5).

### 2. The new-composite input model (reuses Phase B `TypeRef`; adds `FieldSpec`/composite bounds)

No client-supplied string ever reaches `CParser`/`DataTypeParser`. The worker assembles
`StructureDataType`/`UnionDataType` field-by-field from `DataType` handles produced by the **existing**
`_gh_resolve_type_ref` (`_jvm_bridge.py:1603-1689`). Validation is allow-list resolution + bounds
(CWE-20), not parsing.

#### 2.1 `FieldSpec` — one member of a composite (PROPOSED schema)

```text
FieldSpec {
  name:   str            # validate_write_name (the EXISTING identifier allow-list — validation.py:362);
                         #   a field name is PERSISTED into the program DB and re-served by the read
                         #   tools, so it has the identical stored-injection profile as a ParamSpec.name
  type:   TypeRef        # the EXISTING Phase-B TypeRef — resolved by _gh_resolve_type_ref, NEVER parsed
  offset: int | None     # struct only: explicit byte offset (0..=_MAX_COMPOSITE_SIZE-1); None = append
                         #   sequentially. IGNORED for a union (all members overlay at offset 0).
}
```

#### 2.2 `DefineStructIn` / `DefineUnionIn` (PROPOSED schemas)

```text
DefineStructIn(_SessionScopedIn) {
  name:   str                       # the new type's name — validate_write_name (persisted)
  fields: list[FieldSpec]           # bounded: 1..=_MAX_FIELDS (recommend 256); non-empty
  packed: bool = False              # True → packed (no alignment padding); False → default alignment
}

DefineUnionIn(_SessionScopedIn) {
  name:   str                       # validate_write_name
  fields: list[FieldSpec]           # bounded: 1..=_MAX_FIELDS; offset ignored per field
}
```

#### 2.3 Bounded counts (the construction-time DoS guard — extends ADR-014 §2.5)

Reusing the Phase-B `TypeRef` bounds (`pointer_levels ≤ _MAX_POINTER_DEPTH=8`,
`array_len ≤ _MAX_ARRAY_LEN=65536` — `schemas.py:41-43`) and adding two composite-level bounds:

- `_MAX_FIELDS` ≈ **256** — a composite with >256 members is pathological; bounds construction cost
  and the cycle-detection / size-summation work (CWE-400).
- `_MAX_COMPOSITE_SIZE` ≈ **1 MiB (1_048_576 bytes)** — the **total computed size** of the assembled
  composite (sum of member sizes for a struct, max for a union, including any explicit-offset gaps)
  is bounded **before `addDataType`**. This is a primary guard against the recursion/fan-out DoS:
  even a non-cyclic but enormous definition (a struct of 256 `char[65536]` arrays ≈ 16 MiB) is
  rejected (CWE-190/CWE-400 — guard the size sum against overflow + the cap).
- `name` / `FieldSpec.name`: `validate_write_name` (`_MAX_NAME=1024`, identifier allow-list —
  `validation.py:362-396`) — persisted values, strict allow-list (stored-injection defense).
- `offset` (struct): `0 ≤ offset < _MAX_COMPOSITE_SIZE`; bounded integer; never free text.

**Why this admits no C string into Ghidra's parser:** every field is a closed enum
(`TypeRef.base`), a bounded integer (`pointer_levels`/`array_len`/`offset`/`_MAX_FIELDS`), a bool
(`packed`), or a single bounded *identifier* token (`name`/`FieldSpec.name`/`TypeRef.named`) that is
**looked up** (`named`) or **validated against the identifier allow-list** (`name`). The worker
constructs `StructureDataType`/`UnionDataType`/`PointerDataType`/`ArrayDataType` entirely from typed
Java objects. `DataTypeParser`/`CParser` are **never instantiated** on a client value — identical to
ADR-014 §2 (`docs/adr/ADR-014-structural-mutation-phase-b.md:194-199`).

### 3. THE recursion / self-reference crux (RATIFIED: pre-registration + cycle-detection + size cap + rollback)

A composite references other types via `FieldSpec.type`. **Ratified model (KEY DECISION (b),
2026-06-12):** the empty composite is **pre-registered** in the `DataTypeManager` at the start of the
transaction — *before* its fields are resolved — so a self-`named` `TypeRef` resolves and **true
self-referential types are supported** (the common linked-list / tree / graph case, e.g. a `Node`
with a `Node* next`). Pre-registration is a mutation **inside** the one transaction, so safety no
longer rests on the "not yet in the DTM → `not-found`" shortcut; it rests on **three now-load-bearing
controls**: an explicit by-value self/cycle rejection, the total-size cap, and transactional rollback.

1. **Pointer-to-self — ALLOWED (fixed size).** `{named: "<self>", pointer_levels: 1}` (a `next`
   pointer) is the pointer width regardless of target and resolves against the pre-registered type —
   true self-referential structs work. The opaque `{base: "void", pointer_levels: 1}` idiom also
   remains available (and is the only option for a pointer to a *different* not-yet-defined type,
   since nested-define is deferred — §1).
2. **Embedding-self / by-value cycle — REJECTED (infinite size); now an EXPLICIT control.** Because
   the type IS in the DTM during field resolution, a by-value self-reference *would* resolve, so it
   must be **actively rejected** (not left to fail `not-found`):
   - **Boundary check (`validate_composite`, §4):** reject any `FieldSpec.type` with `named == <this
     composite's name>` and `pointer_levels == 0` (a by-value embed of self — incl. an array of self),
     with `VALIDATION`, before the worker.
   - **Cross-type by-value cycle is structurally impossible in v1:** nested-define is deferred and a
     call references only EXISTING types (which predate — and so cannot embed-by-value — the
     just-pre-registered type) or self (caught above). One composite per call ⇒ no A↔B by-value cycle
     can be assembled. (When nested-define / multi-type batches are someday added, a real
     graph-cycle detector over the by-value member edges becomes mandatory — recorded for that
     increment.)
   - **Backstop:** the `_MAX_COMPOSITE_SIZE` (1 MiB) running total-size check during assembly catches
     any residual blow-up (incl. embedding many large *existing* types), aborting → rollback.
3. **Referencing an existing type — ALLOWED (Phase B semantics).** Resolves normally; bounded by the
   size cap.

**Atomicity (the partial-write window pre-registration introduces is closed by rollback):**
pre-register-empty → resolve + add each field (size-checked) → `dtm`-finalize/commit all run inside
the **one corrected `_in_transaction`**. ANY failure — an unresolvable field `TypeRef` (`not-found`),
a by-value self-embed that slips past the boundary check, the size cap, or a **name collision**
(§"name collision", fail-closed reject) — raises → the transaction rolls back → **the pre-registered
empty type is removed, leaving no partial/orphan type.** `FieldSpec.type` is a flat `TypeRef` (no
nested define — §1), so no unbounded recursive descent enters our assembly code.

**Recursion rule, stated for ratification (KEY DECISION (b) — RATIFIED):** *the empty composite is
pre-registered so self-`named` pointers resolve (true self-referential types supported); a by-value
self-embed (or array-of-self) is rejected at the boundary (`VALIDATION`); cross-type by-value cycles
are structurally impossible in the one-composite-per-call v1 (a real cycle detector is required only
if nested-define lands); the total-size cap + transactional rollback are the backstops, and rollback
guarantees no partial type survives a failed definition.*

### 4. New validators (PROPOSED for `core.validation`) + gating/atomicity (reuse Phase B)

Pure, I/O-free, allow-list, fail-closed — the established `validation.py` posture
(`validation.py:8-14`). They **reuse** the merged `validate_type_ref` (`validation.py:490-531`) and
`validate_write_name` (`validation.py:362-396`).

- `validate_field_spec(field) -> None` — `field.name` via `validate_write_name` (persisted → strict
  allow-list); `field.type` via the **existing** `validate_type_ref`; `offset` is `None` or a bounded
  non-negative int `< _MAX_COMPOSITE_SIZE`.
- `validate_composite(payload, *, kind) -> None` — validates a `DefineStructIn`/`DefineUnionIn`:
  `name` via `validate_write_name`; `1 ≤ len(fields) ≤ _MAX_FIELDS` (non-empty, bounded — CWE-400);
  **no duplicate `FieldSpec.name`** within the composite (a struct/union with two `x` members is
  rejected — `VALIDATION`); each field via `validate_field_spec`; the **self-embed boundary check**
  (§3.2: reject `field.type.named == payload.name and field.type.pointer_levels == 0 and
  field.type.array_len is None` — an embedded self); `offset` only meaningful for `kind == "struct"`
  (a non-`None` `offset` on a union is a `VALIDATION` — total schema per variant). The **total
  computed size** cap (`_MAX_COMPOSITE_SIZE`) is enforced **at the worker** after resolution (it needs
  the resolved `DataType.getLength()` of each `named`/derived field — a worker concern, like the
  Phase-B `not-found`), with the **boundary** rejecting the obviously-oversized cases it can compute
  without resolution (sum of `base`/array footprints).

These are **critical-path** (new agency surface; the typed barrier for the type universe) → **100%
coverage + mutation testing** (master §4, `topic-testing`). They contain **no** type-string parsing
(the structured model — `validate_type_decl`, the free-form-C bounder ADR-013 §2a named, stays a
named, rejected alternative).

**Gate (CONFIRMED — no new mechanism, reuse Phase B wholesale).** `define_struct`/`define_union` are
structural → each handler calls the **existing** `ctx.sessions.require_write_consent(args.session_id,
structural=True)` (`registry.py:668`, `:698`, `:728`, `:754` — the Phase-A/B handler shape) before
validating inputs and delegating. **No new consent flag, no new lifecycle tool.** A session must have
`session_enable_writes{allow_structural: true}`; otherwise the call fails closed (`VALIDATION`
"structural writes not permitted" / "session is read-only"). The two-level default-deny opt-in (writes
off → annotations → structural) is unchanged.

**Atomicity (CONFIRMED — reuse the corrected one-transaction `_in_transaction`).** The single
`addDataType` write wraps in `_in_transaction("define_struct"/"define_union", write)`
(`_jvm_bridge.py:1810-1822`) — one tool call == one transaction == one undoable unit, commit **inside**
the try, best-effort suppressed rollback on any failure. `session_undo` (`registry.py`) reverts the
created type in one step. **No `_in_transaction` change needed** (the ADR-013 §4 CWE-460 fix already
covers any commit-time fixup; creating an *unreferenced* type has minimal commit-time re-flow — §5 —
but the fix is in place regardless).

**Resolution-before-transaction (extends ADR-014 §4).** **All `FieldSpec.type` resolution and the
name-collision lookup (§6) are read-only and happen BEFORE `startTransaction`** (the existing
`_gh_resolve_type_ref` is read-only — `_jvm_bridge.py:1603-1689`). An unresolvable field type
(including the self-embed that fails `not-found`), a duplicate field name, a name collision, or an
over-vocab/over-bounds field surfaces a clean `VALIDATION`/`not-found`/`analysis-failed` with **no
transaction opened** (fail closed, no partial type). Only the `addDataType` write is transacted.

### 5. The re-render blast radius (bounded — by being a NEW type)

A new/changed type re-renders dependent data items and decompiled functions (ADR-013 §2c,
`docs/adr/ADR-013-structural-mutation.md:196-208`). **For Phase C this is bounded by construction:**
at the moment of `addDataType`, the new composite is referenced by **nothing** — no data item is
typed with it, no function signature uses it. Its *creation* therefore re-renders **nothing**. The
wide re-render only happens when a **subsequent `apply_data_type`** lays the type at an address (or a
`set_function_signature` uses it) — and those are the **already-threat-modeled Phase-B tools**
(ADR-014 §5/§7). This decoupling — *create with zero blast radius, then apply via the existing
bounded tool* — is the load-bearing reason composite *creation* is the smaller surface once
separated from *application*, and why ADR-014 deferred it to its own increment without it carrying the
re-render risk. (Contrast: *redefining an existing, in-use type* WOULD have wide re-render — but §6's
name-collision policy **rejects** redefinition, so Phase C never overwrites an in-use type.)

### 6. Name-collision policy (KEY DECISION (c)) — RECOMMEND fail-closed REJECT

`DataTypeManager.addDataType(dt, conflictHandler)` takes a `DataTypeConflictHandler` that decides what
happens when a type of the same name already exists. The choices and our recommendation:

| Handler | Behavior on collision | Verdict |
|---------|----------------------|---------|
| `REPLACE_HANDLER` | silently **replaces** the existing type | **REJECT** — silently mutating an in-use type is the wide-re-render foot-gun (§5) and a data-poisoning vector (an injection redefines `FILE`/a recovered struct, corrupting every dependent decompilation) |
| `DEFAULT_HANDLER` / `KEEP_HANDLER` | keeps existing / renames the new (`Packet.conflict1`) | **REJECT** — silent rename produces a type the client didn't ask for (least-astonishment violation; the client thinks it created `Packet` but got `Packet.conflict1`) |
| **fail-closed REJECT (recommended)** | the worker **checks for an existing type of that name BEFORE assembly** (a read-only `getDataType` lookup, like `_gh_resolve_type_ref`) and surfaces a clean `analysis-failed`/`already-exists` with **no write** if one exists | **RECOMMEND** — fail closed, no silent replace/rename, the client must pick a new name or explicitly delete-then-create (deletion is itself a future gated tool, not in Phase C) |

**Recommended policy (KEY DECISION (c)): fail-closed REJECT on name collision** — a `define_struct`/
`define_union` whose `name` already names a type in the `DataTypeManager` is rejected with no write
(checked **before `startTransaction`**, so it is a clean failure with no partial type). This **never
silently replaces or renames** an existing type, eliminating the redefine-in-use re-render and
data-poisoning vector (§5). It keeps Phase C strictly *additive* (create genuinely-new types only),
consistent with the additive ADR-006 seam. The error is mapped to the **existing** `analysis-failed`
slug (no new error code; see §7). (A future "replace existing type" capability, if ever wanted, is its
own narrower gated increment with its own re-render threat model — out of scope.)

### 7. PROPOSED RPC additions (for PM ratification into `rpc-protocol.md` §4)

Two **new worker-facing RPC methods** added to the frozen allow-list (`RPC_METHODS`,
`worker/dispatch.py:86-91` / `rpc-protocol.md:70-86`), mirroring the ADR-014 write methods (params =
tool schema minus `session_id`; worker returns plain values; the server wraps binary-derived fields).
**No new server-side lifecycle tool** — the gate reuses `session_enable_writes` (§4).

| New RPC method | params | result | errors (`rpc-protocol.md` §5) |
|----------------|--------|--------|-------------------------------|
| `define_struct` | `{name: str, fields: [FieldSpec], packed: bool}` | `{name: str, kind: "struct", size: int, field_count: int, applied: bool}` | `-32602 invalid-params` (bad name/field/shape/dup-name/self-embed), `-32004 not-found` (an unresolvable `FieldSpec.type.named`), `-32008 limit-exceeded` (>`_MAX_FIELDS` / >`_MAX_COMPOSITE_SIZE`), `-32010 analysis-failed` (name collision / addDataType / txn / commit failed → rolled back) |
| `define_union` | `{name: str, fields: [FieldSpec]}` | `{name: str, kind: "union", size: int, field_count: int, applied: bool}` | same set as `define_struct` (no `offset`/`packed`) |

- **Unresolvable `FieldSpec.type`** (unknown `named`, incl. a self-`named` since the type isn't in the
  DTM yet) → `not-found` (the field type does not exist — same slug as a missing function in Phase B).
  A malformed field/shape/dup-name/self-embed → `invalid-params` at the server boundary. Over-bound
  field-count/size → `limit-exceeded`. A **name collision** or an `addDataType`/commit failure →
  `analysis-failed` (rolled back). **No new error *codes*** — the existing slug→`ErrorType` map
  (`rpc-protocol.md:99-104`) covers `invalid-params`/`not-found`/`limit-exceeded`/`analysis-failed`.
  **No new `ErrorType` member.** (If a distinct `already-exists` slug is preferred over reusing
  `analysis-failed` for the collision, that is a one-row contract addition for the PM to weigh —
  recommend reusing `analysis-failed` to avoid a new slug, with the audit log recording the cause.)
- **`name`/`kind`/`size`/`field_count`/`applied` are server/worker-controlled scalars → bare.** The
  composite's `name` echoed back is **the one WE set + server-validated** → SAFE (the asymmetry of
  ADR-012/013/014 §6: values we set are bare; binary-derived echoes are `Untrusted`). There is **no**
  binary-derived field in the result (we deliberately do **not** echo a re-rendered C declaration of
  the type — that would be a binary-derived `Untrusted` field and adds surface for no value; the
  client already knows the structure it asked for). *(If a future result echoes Ghidra's rendered
  layout, it MUST be `Untrusted[...]` — ADR-005.)*

### 8. PROPOSED tool-catalog + schema additions (for PM ratification)

The catalog count moves from **45** (`docs/contracts/tool-catalog.md:9`) to **45 + 2 = 47** (two
worker write tools; no new lifecycle tool). The count tests update (`test_tools_registry.py`,
`test_tool_schemas.py`, `tool-catalog.md:9`). Both tools are session-scoped (`_SessionScopedIn`),
`frozen`, `extra="forbid"` (every existing tool — `schemas.py:41-58`). If KEY DECISION (a) is
**struct-first**, the count is **45 + 1 = 46** and `define_union` defers.

**New pydantic schema sketches** (mirroring the merged ADR-014 structural style; reuse `TypeRef`/
`ParamSpec`-style bounds; the `# Phase C` stub at `schemas.py:347-351` of ADR-014 is realized here):

```python
# --- composite-type creation (v1.1 — ADR-015 Phase C; GATED by allow_structural) ---------------
# Reuses the merged Phase-B TypeRef (schemas.py:1443) — a FieldSpec.type is a flat TypeRef (NO
# nested define — ADR-015 §1). NO free-form C: the worker assembles StructureDataType/UnionDataType
# from already-resolved DataType handles via the existing _gh_resolve_type_ref (_jvm_bridge.py:1603).
_MAX_FIELDS = 256              # a composite with >256 members is pathological (CWE-400)
_MAX_COMPOSITE_SIZE = 1_048_576  # 1 MiB cap on the assembled composite's total computed size

class FieldSpec(_In):
    """One member of a new composite type (ADR-015 §2.1).

    `name` is PERSISTED into the program DB and re-served by the read tools → strict
    `validate_write_name` allow-list (stored-injection defense). `type` is the EXISTING Phase-B
    `TypeRef` (resolved, never parsed). `offset` is struct-only (a union overlays all members at 0).
    """
    name: str = Field(min_length=1, max_length=_MAX_NAME)   # validate_write_name (persisted)
    type: TypeRef
    offset: int | None = Field(default=None, ge=0, lt=_MAX_COMPOSITE_SIZE)  # struct only; None = append

class DefineStructIn(_SessionScopedIn):
    """Arguments for `define_struct` — create a NEW struct from a field list (ADR-015 §2.2).

    Gated by session_enable_writes{allow_structural: true} + require_write_consent(structural=True).
    Name collision → fail-closed REJECT (ADR-015 §6). All field types resolved BEFORE the txn.
    """
    name: str = Field(min_length=1, max_length=_MAX_NAME)       # validate_write_name (persisted)
    fields: list[FieldSpec] = Field(min_length=1, max_length=_MAX_FIELDS)  # non-empty, bounded
    packed: bool = Field(default=False)
    # model_validator: no duplicate field names; no self-embed (named==name & no pointer/array)

class DefineStructResult(_Out):
    """Result of `define_struct` (ADR-015 §7). All fields server/worker-controlled → SAFE (no
    binary-derived echo — ADR-015 §7)."""
    name: str           # the name WE set + server-validated — SAFE
    kind: str           # "struct" — SAFE
    size: int           # assembled total size in bytes — worker scalar, SAFE
    field_count: int    # SAFE
    applied: bool       # SAFE

class DefineUnionIn(_SessionScopedIn):
    """Arguments for `define_union` — create a NEW union (ADR-015 §2.2; offset/packed N/A)."""
    name: str = Field(min_length=1, max_length=_MAX_NAME)
    fields: list[FieldSpec] = Field(min_length=1, max_length=_MAX_FIELDS)
    # model_validator: no duplicate field names; no self-embed; each FieldSpec.offset MUST be None

class DefineUnionResult(_Out):
    """Result of `define_union` (ADR-015 §7) — all SAFE (no binary-derived echo)."""
    name: str
    kind: str           # "union"
    size: int
    field_count: int
    applied: bool
```

**Bounds / allow-list / validation (per tool):**

- `name`: `validate_write_name` (`validation.py:362`) — persisted type name, strict identifier
  allow-list; **collision-checked at the worker before assembly** (fail-closed REJECT — §6).
- `fields`: `1 ≤ len ≤ _MAX_FIELDS`; **no duplicate `FieldSpec.name`**; **no self-embed**
  (`validate_composite` — §4); total computed size ≤ `_MAX_COMPOSITE_SIZE` (worker, post-resolution).
- `FieldSpec.name`: **reuse `validate_write_name`** — persisted + re-served, identical stored-injection
  profile as a Phase-B `ParamSpec.name`.
- `FieldSpec.type`: the **existing** `validate_type_ref` (`validation.py:490`) at the boundary; the
  worker resolves via `_gh_resolve_type_ref` and `not-found`s an unknown `named` (incl. a self-`named`,
  since the type isn't in the DTM yet — §3).
- `FieldSpec.offset` (struct): bounded non-negative int `< _MAX_COMPOSITE_SIZE`; `None` = append.
- Every handler **authorizes + requires structural write consent** (`require_write_consent(
  structural=True)`) before delegating — fail closed (`registry.py:728`/`:754` shape).

> `Untrusted[...]` posture (ADR-012/013/014 §6): unusually for a write result, **every** Phase-C
> result field is **SAFE** — the `name`/`kind`/`size`/`field_count`/`applied` are all server- or
> worker-controlled (the name is the one we set + validated; the size is a worker-computed scalar).
> There is **no echoed binary-derived field** (we do not return a Ghidra-rendered declaration). If a
> future field echoes Ghidra output it MUST be `Untrusted[...]`.

### 9. Validation & abuse

**Input validation (TB7 / TB1 — the composite definition is attacker-INFLUENCED):** the decompiled C
the client reasons over is hostile (ADR-005); an indirect prompt injection (TB4) can steer the client
into a malicious composite payload (a self-embed bomb, a 10k-field struct, a name that collides with
a recovered type to poison it, a markup field name). The whole payload is validated at the boundary,
allow-list only (`std-owasp-proactive` #5, CWE-20): `validate_composite` / `validate_field_spec` +
the **existing** `validate_type_ref` + `validate_write_name` for the type name and every field name.
**No value is parsed by a C-type parser** — the §2 structured model assembles typed Java objects;
`CParser`/`DataTypeParser` are never instantiated on a client value.

**Stored-injection / data-poisoning** is the same class as ADR-012/013/014 §7: the composite `name`
and every `FieldSpec.name` written now are persisted and re-served by `get_data_type`/
`function_context`/`decompile_function` wrapped `Untrusted[...]`. Two-sided defense unchanged:
`validate_write_name` in, untrusted-envelope out. **Plus** the §6 name-collision REJECT prevents the
worse poisoning variant — *redefining an existing in-use type*.

**Abuse tests to add** (extend `tests/security/test_abuse_cases.py` / threat-model §6 / §10;
benign/synthetic fixtures only, master §5; each must FAIL the attack — deterministic + hermetic;
numbering continues from the Phase-B case **40**):

41. **Self-embed rejected (the recursion crux)** — a `define_struct` with a `FieldSpec.type` of
    `{named: "<this struct>"}` (no pointer/array — *embedding* self) is **rejected**: at the boundary
    by the `validate_composite` self-embed check (`VALIDATION`) and, defensively, at the worker by
    `not-found` (the type isn't in the DTM yet — §3.2). No type is defined; program unchanged. (TB7-D
    — the new recursive-definition surface, proven bounded.)
42. **Embed-cycle cannot be assembled** — the "B-first, then A referencing B" flow cannot produce a
    true embed-cycle (A embeds B embeds A): defining B with an embedded not-yet-existing A fails
    `not-found`; so a cross-type embed-cycle is unconstructable across the one-composite-per-call
    boundary (§1/§3.2). (TB7-D / integrity)
43. **Pointer-to-self allowed, fixed size** — a `define_struct` modeling a linked-list `next` as
    `{base: "void", pointer_levels: 1}` (the v1 opaque-pointer idiom — §3.1) **succeeds**, size =
    sum incl. one pointer width, no blow-up. (Positive case — confirms the legitimate path works;
    `topic-testing` behavior coverage.)
44. **Name-collision REJECT (no silent replace)** — a `define_struct`/`define_union` whose `name`
    already names a type in the `DataTypeManager` is **rejected** `analysis-failed` with **no write**
    (the existing in-use type is **unchanged** — the fail-closed REJECT handler, §6); checked before
    `startTransaction`, no partial type. (TB7-T — the redefine-in-use re-render / data-poisoning
    vector, proven absent.)
45. **Oversized field-count / size DoS** — `fields` longer than `_MAX_FIELDS`, or a composite whose
    total computed size exceeds `_MAX_COMPOSITE_SIZE` (e.g. 256 × `char[65536]`), is **rejected**
    (`VALIDATION`/`limit-exceeded`) before/at the worker with no `addDataType`; the size sum is
    overflow-guarded (CWE-190/CWE-400). (TB7-D — extends Phase-B case 34.)
46. **Duplicate field name rejected** — a composite with two `FieldSpec.name == "x"` is rejected
    `VALIDATION` (no write). (TB7-T / integrity)
47. **Malicious field / type name rejected** — a `FieldSpec.name` or the composite `name` with
    markup/`../path`/zero-width/RTL/control chars is **rejected by `validate_write_name`** (never
    written). (TB7-T — extends Phase-B case 35.)
48. **Unresolvable field TypeRef fail-closed** — a `FieldSpec.type` with a well-formed but **unknown**
    `named` surfaces `not-found` with the program **unchanged** (resolution is before
    `startTransaction`); no partial type. (TB7-T / atomicity — extends Phase-B case 32.)
49. **TypeRef injection in a field rejected** — a `FieldSpec.type.named` carrying C-declaration syntax
    / a struct body (`"struct{int x;}"`, `"int*"`, `"a;b"`) is **rejected by `validate_type_ref`** (not
    a valid identifier; never parsed) → `VALIDATION`; no type defined. (TB7-T — the design-eliminated
    C-parser surface, proven absent; same as Phase-B case 31, now in a field.)
50. **Structural-consent-required** — `define_struct`/`define_union` on a session with
    `allow_structural=false` is denied "structural writes not permitted"; on a read-only session,
    "session is read-only" (the `require_write_consent(structural=True)` chokepoint). (TB7-E / gating
    — extends Phase-B case 37.)
51. **Cross-session structural isolation** — `allow_structural` + a `define_struct` on session A does
    **not** enable or mutate session B; B stays read-only, store independent. (TB7-T / store-I —
    extends Phase-B case 36.)
52. **BOLA on the structural grant** — unchanged: a grant/define against an unknown/foreign session id
    yields the same `session-invalid` envelope (no oracle). (TB7-E / BOLA — same chokepoint as
    Phase-B case 38.)
53. **ADR-001 invariant under Phase-C writes** — the architecture-invariant test still passes: no
    JVM/PyGhidra import on any server-side module, including the new `define_struct`/`define_union`
    handlers (the field resolution, the assembly, and the `addDataType` write all execute only in the
    worker). (TB7-E — extends Phase-B case 39.)
54. **Commit-time atomicity** — a `define_struct` whose `addDataType` **or its commit** raises
    **rolls back** and surfaces `analysis-failed`; no dangling transaction, no half-created type
    (exercises the §4 reused `_in_transaction` — CWE-460). The program is unchanged. (TB7-T — extends
    Phase-B case 33.)

**Mutation/contract testing:** `validate_composite`, `validate_field_spec`, and the structural-consent
path are **critical-path** (the typed barrier for the program's type universe + new agency/authZ) →
**100% coverage + mutation testing** (master §4, `topic-testing`). The reused `validate_type_ref` /
`_in_transaction` keep their existing critical-path coverage. The real `_gh_define_struct` /
`_gh_define_union` JVM edges (the collision check, the `StructureDataType`/`UnionDataType` assembly,
the size-cap check, `addDataType`) are coverage-omitted JVM edges exercised only by the real-worker
integration suite — the same posture as every `_gh_*` (`_jvm_bridge.py:1603` `# pragma: no cover`,
ADR-014 §7).

## Consequences

- **Positive:** closes the **last** structural-write rung (creating new composite types) on the
  smallest surface that delivers it; **eliminates the C-parser injection surface by construction**
  (ADR-013 §2a honored — `FieldSpec.type` is a flat `TypeRef`, no string parsed); **reuses Phase B
  wholesale** — the `TypeRef`/`ParamSpec` model, `validate_type_ref`, `_gh_resolve_type_ref`, the
  `allow_structural` gate, and the corrected `_in_transaction` (no new gate/transaction mechanism);
  **decouples the wide re-render** to the existing Phase-B `apply_data_type` (a new type re-renders
  nothing until applied — §5); the **recursion risk is bounded by construction** (the type isn't in
  the DTM at field-resolution, so self-embed fails-closed `not-found`; no recursive descent in our
  assembly — §3); name collisions are **fail-closed REJECT** (no silent replace/poison — §6); ADR-001
  containment unchanged; each create is atomic + reversible (`session_undo`) + audited; additive
  through the ADR-006 seam (no contract rewrite).
- **Negative / risk:** Phase C adds the **type-universe mutation** surface — even bounded, it is new
  agency (LLM08 rises: an injection during an `allow_structural` window can create a junk type,
  bounded by the gate, `session_undo`, per-create audit, and ADR-002 ephemerality — a junk type in a
  **disposable** session, wiped on evict, never host/durable compromise). The `addDataType`/assembly
  JVM edges and the collision/size checks are Ghidra-version-sensitive (mitigated by the integration
  suite + bounded timeouts + fail-closed `not-found`/`analysis-failed`). The v1 opaque-pointer idiom
  for self-reference (§3.1) is less ergonomic than a true self-`named` pointer — a documented
  trade-off, revisitable.
- **Negative:** four new schemas (`FieldSpec`, two `*In` + two results) + two new validators
  (`validate_field_spec`/`validate_composite`) + two RPC methods + two worker bridge edges
  (`_gh_define_struct`/`_gh_define_union`); clients must learn that a new composite is built from
  `FieldSpec` (not a C body) and that self-reference is an opaque pointer in v1.
- **Open / deferred:** **nested `define`** (a `FieldSpec.type` that defines an inline child composite)
  and **multi-type batches** (define N interdependent types in one call) are deferred to their own
  future increments (§1); **type deletion / redefinition of an existing type** is deferred (the §6
  REJECT keeps Phase C additive); a true self-`named` pointer via empty-type pre-registration is the
  recorded alternative to the opaque-pointer idiom (§3.1, KEY DECISION (b)); enums/typedefs/function-
  pointer composites are out of scope here (struct+union only); cross-session persistence stays
  deferred (ADR-012 §4); `runScript` stays permanently out of scope (PLAN §2).

## Alternatives considered

- **Free-form C struct/type definition** (accept `struct {int x; char *p;}` and parse via
  `DataTypeParser`/`CParser`): maximally expressive and matches how a human uses Ghidra, but it is the
  **largest injection-into-API surface** (ADR-013 §2a) — a small interpreter fed attacker-influenced
  input, with parser-bomb consumption and unintended-type-definition side effects. **Rejected** —
  pre-decided against by ADR-013 §2a / KEY DECISION (b), ratified by the human; the structured
  `FieldSpec` model (§2) is the chosen typed-least-privilege posture (`std-owasp-llm` LLM07).
- **A single `define_data_type{kind}` tool** (one schema with a struct/union discriminator): fewer
  tools, but it carries fields meaningless for one variant (struct-only `offset`/`packed` on a union)
  — a silent foot-gun. **Rejected** in favor of two total-per-variant tools (§1, KEY DECISION (a)),
  the same typed-least-privilege split ADR-014 used for the two type-aware writes.
- **`REPLACE_HANDLER` (overwrite on name collision):** matches how a human iterates in Ghidra, but it
  silently mutates an in-use type — the wide-re-render foot-gun and a data-poisoning vector
  (§5/§6). **Rejected** in favor of fail-closed REJECT (KEY DECISION (c)); redefinition, if ever
  wanted, is its own narrower gated increment.
- **Pre-register the empty composite in the DTM so a self-`named` pointer resolves:** more ergonomic
  (a true self-pointer), but it makes the empty type a mutation *inside* the transaction (a
  partial-write window) and adds resolver complexity. **Deferred** — v1 uses the opaque-pointer idiom
  (§3.1); recorded as the KEY DECISION (b) alternative.
- **Allow a batch of interdependent new types in one call:** higher value sooner, but multiplies the
  cycle-detection surface across types and breaks the one-call-one-transaction-one-undo property.
  **Rejected** — one composite per call; B-first then A-referencing-B (§1).
- **Defer composite creation entirely (never build Phase C):** keeps the surface minimal, but leaves
  the semantic-naming loop unable to *create* a recovered struct — a real capability gap once Phase B
  shipped *applying* one. **Rejected** — Phase C closes the loop on a now-well-understood structured
  model.

---

## Design summary

ADR-015 (structural mutation **Phase C**) closes the **last** structural-write rung that ADR-014 §1
deferred: **creating** new composite types — `define_struct` + `define_union` (recommend both;
struct-first is the alternative). The input is a **structured `FieldSpec` list** (`{name, type:
TypeRef, offset?}`), **never free-form C** — it **reuses the merged Phase-B `TypeRef` /
`validate_type_ref` / `_gh_resolve_type_ref` machinery wholesale**, so the worker assembles
`StructureDataType`/`UnionDataType` from already-resolved `DataType` handles and **`CParser`/
`DataTypeParser` are never instantiated on a client value** — the C-parser surface is eliminated by
construction. The two genuinely-new risks ADR-014 named are designed out: **(recursion)** the type
isn't in the `DataTypeManager` at field-resolution time, so a self-*embed* fails-closed `not-found`
(plus a boundary self-embed check + a `_MAX_COMPOSITE_SIZE` total-size cap), while pointer-to-self
(fixed size) is the common allowed case (modeled as an opaque `void*` in v1); and **(re-render)** a
new type re-renders **nothing** until a *subsequent* Phase-B `apply_data_type` references it — the
wide blast radius is decoupled to the already-threat-modeled application tool. Name collisions are
**fail-closed REJECT** (no silent replace — no redefine-in-use poisoning). It **reuses Phase A/B
wholesale** — the `allow_structural` gate (`require_write_consent(structural=True)`), the corrected
one-transaction `_in_transaction`, `validate_write_name`, and the audit/`session_undo` machinery —
adding **no** new gate or transaction mechanism; one composite per call (no batch). Catalog: **45 →
47** (two worker write tools; **46** if struct-first). ADR-001 holds (the server never mutates;
resolution, assembly, and the write run only in the worker). Threat-model TB7 (structural) is extended
with the Phase-C specifics.

**Files in this design PR:** `docs/adr/ADR-015-composite-type-creation.md` (this file);
`docs/security/threat-model.md` §10 TB7 (structural) extended with a Phase-C subsection (this PR).
**Proposed for PM ratification into the frozen contracts** (NOT edited here):
`docs/contracts/tool-catalog.md` (count 45→47, two rows + Phase-C/nested-define deferral note),
`docs/contracts/rpc-protocol.md` §4 (two RPC methods + `FieldSpec` param shape),
`src/ghidra_mcp/tools/schemas.py` (`FieldSpec`, `DefineStructIn`/`Result`, `DefineUnionIn`/`Result`,
the `_MAX_FIELDS`/`_MAX_COMPOSITE_SIZE` constants — realizing the ADR-014 `# Phase C` stub),
`src/ghidra_mcp/core/validation.py` (`validate_field_spec`, `validate_composite`),
`worker/dispatch.py` (`RPC_METHODS` += 2), and the worker bridge edges (`_gh_define_struct`,
`_gh_define_union`) in `src/ghidra_mcp/ghidra/_jvm_bridge.py`. No `_in_transaction`, `TypeRef`, or
`_gh_resolve_type_ref` change is needed (the Phase-A/B primitives already cover Phase C).

## KEY DECISIONS FOR HUMAN RATIFICATION

**(a) Phase-C scope — RECOMMEND: ship BOTH `define_struct` and `define_union` now (catalog 45→47);
DEFER nested-`define` and multi-type batches.** Rationale: a struct and a union are the two composite
kinds a client recovers from decompilation; both reuse the same `FieldSpec`/`TypeRef`/gate/transaction
machinery, so shipping both costs little marginal surface (a union is the simpler variant — no
`offset`/`packed`) and avoids a Phase-D just for unions. Two **total-per-variant** tools beat one
`kind`-switched tool (no struct-only fields on a union — `topic-defensive-programming`). *Alternative
(struct-first, catalog 45→46):* ship `define_struct` only and defer `define_union` if the union
variant wants its own review — confirm. **Nested-`define`** (an inline child composite in a field) and
**multi-type batches** (N interdependent types in one call) are deferred regardless — they multiply
the recursion/cycle surface and break one-call-one-transaction-one-undo (§1).

**(b) The recursion / cycle rule — RECOMMEND: pointer-to-self is allowed (fixed size; modeled as an
opaque `void*` in v1 since the type isn't yet in the `DataTypeManager`); embedding-self and
embedding-cycles are REJECTED — fail-closed because the type isn't yet registered (`not-found`),
reinforced by a boundary self-embed check (`validate_composite`) and a `_MAX_COMPOSITE_SIZE` total-size
cap.** No unbounded recursion enters our assembly code: `FieldSpec.type` is a flat `TypeRef` (no nested
`define` — see (a)), so there is no recursive descent to bomb (§3). **Sub-decision:** for an *ergonomic
true self-pointer* (e.g. `next: <this struct>*`), prefer the v1 **opaque-pointer idiom** (recommended —
zero resolver change, the type need not pre-exist) or the **empty-type pre-registration** alternative
(a true self-`named` pointer, but a mutation inside the transaction + resolver complexity — §3.1)?

**(c) Name-collision policy — RECOMMEND: fail-closed REJECT** (the worker checks for an existing type
of that name BEFORE assembly and surfaces `analysis-failed` with no write if one exists), **never**
`REPLACE_HANDLER` (silent overwrite of an in-use type → wide re-render + data-poisoning) or a silent-
rename handler (least-astonishment violation). This keeps Phase C strictly **additive** (create
genuinely-new types only), consistent with the ADR-006 additive seam and §5's "create with zero blast
radius." **Sub-decision:** map the collision to the **existing `analysis-failed`** slug (recommended —
no new error code) or add a distinct `already-exists` slug (one contract row; clearer client signal)?
