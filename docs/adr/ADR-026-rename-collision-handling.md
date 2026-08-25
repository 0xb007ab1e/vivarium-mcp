# ADR-026: Rename name-collision handling (v1.3 finding F5)

- **Status:** PROPOSED (awaiting human ratification of the (a)/(b)/(c) choice)
- **Date:** 2026-06-16
- **Severity of driving finding:** **LOW** (defense-in-depth / UX; not a security or correctness defect)
- **Deciders:** PM (contract owner) + human ratification
- **Relates to:** ADR-012 (mutation tools / write model), ADR-013 (structural mutation),
  ADR-015 (composite-type creation — fail-closed REJECT on *type* name collision),
  ADR-018 (annotation persistence); v1.3 acceptance finding **F5**.
- **Contract impact:** options (a) = **none**; (b)/(c) = **a result-field / behavior change →
  contract touch → PM routing required** (frozen-contract posture, CLAUDE.md WS0).

---

## Context

During the v1.3 blind acceptance run (gzip 1.13, 39 renames applied end-to-end), independent
LLM namers proposed the **same name (`build_huffman_table`) for two different functions**. The
acceptance harness disambiguated client-side (suffixing `_<addr>`). The finding (F5, LOW):

> A real client driving many renames can produce **name collisions**, and there is no
> dedup/disambiguation step.

The question this ADR must answer **before** designing any mechanism: **is this a server concern
at all, or purely a client-workflow concern?** That requires knowing what the server actually does
today when a duplicate name is written.

### What the server actually does today (investigated, not assumed)

| Path | Code | Behavior on a duplicate name |
|------|------|------------------------------|
| **`rename_function`** | `_jvm_bridge._gh_rename_function` → `func.setName(new_name, SourceType.USER_DEFINED)` | **Succeeds silently.** Ghidra functions live in the global namespace but are **keyed by entry address**; two functions may carry the identical name. `setName` does **not** raise, does **not** auto-suffix, and the rename commits. The acceptance run's two `build_huffman_table` functions would both have applied cleanly. |
| **`rename_symbol`** | `_jvm_bridge._gh_rename_symbol` → `symbol.setName(new_name, SourceType.USER_DEFINED)` | **Asymmetric.** For symbols sharing a namespace (e.g. two labels/data in the same scope), Ghidra's `Symbol.setName` **can raise `DuplicateNameException`**. That is caught by `_in_transaction`, the transaction is **rolled back**, and the client gets a generic **`analysis-failed`** (no dedicated slug, no structured "collision" indicator). For symbols in distinct namespaces, no collision occurs. |
| **Validation** | `core/validation.validate_write_name` | Pure **charset/length allow-listing only** (leading letter/underscore; `[A-Za-z0-9_$.]`; reject control/bidi/zero-width). It is **stateless and I/O-free** — it has **no program handle and therefore cannot check uniqueness**. It does not, and structurally **cannot**, detect a collision. |

**Net:** function-name duplicates **succeed silently**; same-namespace symbol duplicates **fail
closed with an opaque `analysis-failed`**; the validator is uniqueness-blind by design (functional
core / imperative shell — uniqueness is program state, a worker concern).

### Contrast with ADR-015 (why type collisions REJECT but function renames should not)

ADR-015 §6 chose **fail-closed REJECT** for *composite-type* name collisions. That decision does
**not** transfer to function renames, because the risk profiles are opposite:

- **Type collision (ADR-015):** the only Ghidra outcomes are `REPLACE_HANDLER` (silently **mutates
  an in-use type** → mass re-render + data-poisoning foot-gun) or `KEEP/DEFAULT_HANDLER` (silently
  **renames the new type** `Packet.conflict1` → least-astonishment violation). Both are silent and
  harmful; REJECT is the only safe choice. Duplicate type names are **never legitimate** in an
  additive create-only model.
- **Function-name collision (here):** Ghidra **legitimately permits** duplicate function names
  (distinguished by address). Real binaries genuinely contain many same-named functions: static
  helpers compiled into multiple translation units, `huft_build`/`build_tree`-style families (the
  acceptance run *confirmed* gzip has >1 table-builder), template instantiations, COMDAT folding
  survivors. There is **no silent-mutation foot-gun**: a second `build_huffman_table` does not
  overwrite the first; both functions keep their own address-keyed identity and decompilation.
  Rejecting it would **break legitimate workflows** to prevent a non-problem.

So the ADR-015 precedent argues *against*, not *for*, server rejection of function renames.

### Is F5 a security finding? (honest assessment)

No. Walking the relevant threat classes for the write path (TB-write, ADR-012):

- **Data poisoning / stored injection (LLM01):** unaffected — the name is already charset-validated
  by `validate_write_name`; a collision is two *valid* names that happen to match. No new injection
  surface.
- **Wide re-render foot-gun:** does **not** apply to function renames (address-keyed; no overwrite),
  which is precisely why ADR-015's REJECT was scoped to *types*, not renames.
- **DoS / unbounded growth:** none — a collision is O(1) per write, already bounded by the existing
  per-call write model and consent gate.
- **Confidentiality / least privilege / agency (LLM08):** unchanged — renames remain gated by
  `session_enable_writes` consent.

F5 is a **client-workflow / usability observation**, correctly rated **LOW**. The "risk" is purely
that a downstream *human reading the program* may be mildly confused by two functions sharing a
name — a cosmetic ambiguity Ghidra itself tolerates and that the address always disambiguates.

---

## Decision drivers

- **Proportionality (least machinery for a LOW finding).** Do not add server state, a uniqueness
  index, or a contract change unless it addresses a *real* risk. It does not.
- **Honor Ghidra's model.** Duplicate function names are legal and meaningful; the server must not
  invent a stricter model than the tool it fronts (least astonishment).
- **Functional core / imperative shell.** Uniqueness is *program state*; the pure validator cannot
  and should not learn it. Any collision check would have to live in the worker (a read-only
  pre-lookup), adding a round-trip and worker code for a cosmetic concern.
- **Frozen-contract posture (WS0).** Any `RenameResult` field or behavioral change is a contract
  touch routed through the PM. The bar to spend that budget on a LOW finding is high.
- **Don't regress fail-closed.** The existing same-namespace-symbol REJECT (mapped to
  `analysis-failed`) is correct and must be preserved under any option.

---

## Options considered

### (a) Client-only / documentation — **RECOMMENDED**

Collision handling is a **client responsibility**. No server change.

- **Server behavior:** unchanged. Function-name duplicates apply (Ghidra-legal); same-namespace
  symbol duplicates continue to fail closed (`analysis-failed`, rolled back).
- **Deliverables (docs only):**
  1. **Tool-catalog note** (`docs/contracts/tool-catalog.md`, `rename_function`/`rename_symbol`
     rows): state explicitly that *function names need not be unique (Ghidra distinguishes by
     address); the server does not dedup; a symbol rename within an occupied namespace fails closed
     with `analysis-failed`.* This documents existing behavior — **not a contract change**.
  2. **Client-guidance section** (catalog or `docs/archive/roadmap-v1.3-findings.md` F5 resolution): the
     recommended client practice for a multi-rename pass —
     - maintain a name→address map across the batch;
     - on a proposed-name collision, **disambiguate client-side** (the harness's `_<addr>` suffix,
       or a semantic tiebreak such as `build_huffman_table_static`/`_dynamic` per call-graph role);
     - treat collisions as a *naming-quality* signal, not an error.
  3. **Acceptance-harness note:** record that `scripts/acceptance_run.py` already implements the
     reference dedup (suffix-on-collision), so the recommended practice ships as working code.
- **Pros:** zero server machinery; zero contract spend; honors Ghidra's legal duplicate-name model;
  matches the proven harness behavior; correct for a LOW cosmetic finding.
- **Cons:** the server gives the client no *signal* that a collision occurred — a naive client that
  wants to react must track names itself. (Acceptable: tracking proposed names across a batch is
  trivially client-side, and the harness demonstrates it.)

### (b) Server-side surfacing (non-rejecting)

`rename_*` performs a read-only worker pre-lookup and returns a structured **`collided: bool`**
(and/or a `collision_count`) when `new_name` already names another USER_DEFINED function/symbol —
**without rejecting** (the rename still applies, preserving Ghidra's legal-duplicate model).

- **Mechanics:** the worker, *before* the write txn, does a read-only `getGlobalFunctions(new_name)`
  / symbol-table lookup; the server adds a `collided` field to `RenameResult`.
- **Contract impact:** **adds a result field** to `RenameResult` (and thus `RenameSymbolResult`) →
  a one-row `tool-catalog.md` + `rpc-protocol.md` change → **PM routing required**. Additive and
  backward-compatible (existing clients ignore the field).
- **Pros:** the client gets an explicit, structured signal to drive its own disambiguation; no
  workflow breakage (still applies).
- **Cons:** adds a worker round-trip/read per rename, worker code, and test surface; spends frozen-
  contract budget; **for a LOW finding whose remedy the client can already compute itself**. The
  signal is information the client already has (it chose both names). Risk of scope creep toward a
  uniqueness service the project deliberately doesn't have.

### (c) Server-side REJECT (opt-in strict mode)

A strict mode (e.g. a session flag or per-call `reject_on_collision`) **fail-closed rejects** a
rename whose `new_name` collides with an existing USER_DEFINED name, paralleling ADR-015.

- **Contract impact:** new input flag/mode + a collision error semantic → **PM routing required**;
  larger surface than (b).
- **Pros:** symmetric with ADR-015's type-collision REJECT; deterministic uniqueness for clients
  that *want* it.
- **Cons:** **fights Ghidra's model** — duplicate function names are legitimate (the acceptance run
  literally hit a real case in gzip). Even opt-in, it encodes a "uniqueness is correct" assumption
  that is false for binaries; risks clients enabling it and then failing on real same-named families.
  Most machinery for the least-justified outcome on a LOW finding. The ADR-015 precedent does
  **not** apply (see Context) — types must be unique; functions need not be.

---

## Recommendation

**Adopt option (a) — client-only / documentation. No server change.**

Rationale, stated plainly: F5 is **LOW** and **not a security or correctness defect**. The server's
current behavior is **already correct** — function-name duplicates apply (honoring Ghidra's
address-keyed model), and same-namespace symbol duplicates already fail closed. The only gap is
*documentation* of that behavior plus a *recommended client practice*, and the acceptance harness
**already ships the reference implementation** (suffix-on-collision). Adding a result field (b) or a
reject mode (c) spends frozen-contract budget and worker code to hand the client information it
already possesses, to address a cosmetic ambiguity that Ghidra itself tolerates. That is
gold-plating a LOW finding.

If the PM later observes **real clients repeatedly needing the signal** (i.e. dedup proves
non-trivial in practice, not just in the harness), option **(b)** is the correct escalation — it is
additive, backward-compatible, and preserves the legal-duplicate model. **(c) is not recommended**
under any current evidence: it contradicts Ghidra's model and the precedent it superficially
resembles (ADR-015) does not transfer.

### Consequences of (a)

- **Positive:** no code change, no contract spend, no new worker round-trip, no test surface; the
  documented behavior matches reality and the proven harness; the project keeps its deliberate
  "no uniqueness service" stance.
- **Negative / accepted:** the server emits no machine-readable collision signal; a client that
  wants to react tracks proposed names itself (trivial, demonstrated by the harness). Accepted for a
  LOW cosmetic finding; revisit via (b) only on evidence of real-client need.
- **Preserved invariants:** same-namespace symbol-rename REJECT (`analysis-failed`, rolled back)
  stays; `validate_write_name` stays uniqueness-blind (functional core); the write-consent gate is
  untouched.
- **Follow-ups (docs-only, non-gated, within this workstream's lane if assigned):**
  - tool-catalog clarification note on `rename_*` collision behavior (documents existing behavior);
  - F5 resolution paragraph + recommended client dedup practice in the v1.3 findings doc;
  - harness note pointing at the reference suffix-on-collision implementation.

---

## Decisions needing human ratification

1. **The (a)/(b)/(c) choice.** Architect recommends **(a) client-only / documentation — no server
   change.** Confirm, or direct (b)/(c).
2. **Contract implication (only if (b) or (c) is chosen):** (b) adds a `collided` (and optional
   `collision_count`) field to `RenameResult`/`RenameSymbolResult` + the matching `rpc-protocol.md`
   result; (c) adds an input flag/mode + a collision-reject semantic. **Either is a frozen-contract
   touch → must route through the PM (batch-atomicity / WS0)**, not edited ad hoc by a feature
   workstream. Option (a) has **no** contract impact (the tool-catalog note documents existing
   behavior).
3. **Severity acceptance.** Confirm F5 is accepted as **LOW / cosmetic, not security**, so option
   (a)'s "document + recommend client practice, no server enforcement" is an acceptable resolution
   (master §7 — accepted risk is owned and documented here).
