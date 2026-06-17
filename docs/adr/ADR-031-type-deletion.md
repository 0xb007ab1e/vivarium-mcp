# ADR-031 — Gated deletion of session-authored composite types

- **Status:** Accepted (v1.4; human-ratified 2026-06-17). Implements roadmap-v1.4 item #3 (the
  ADR-015 §6 deferred "type deletion / redefine" capability), **scoped down** to the safe core.
  Ratified scope: **delete only** (no redefine this increment); **session-authored composites only**
  (names in the ADR-027 change-log `composite_targets`); **allow deletion of an in-use type and
  report the dependent count** (Ghidra reverts dependents to undefined). Additive; **no new trust
  boundary** (extends the existing structural-write surface TB7). Supersedes ADR-015 §6's "deletion
  is a future gated tool" note.

## Context

ADR-015 (Phase C) added composite *creation* (`define_struct`/`define_union`) and ADR-021 added the
batch `define_types`. A name collision on creation is fail-closed REJECT (ADR-015 §6) — the client
cannot replace or overwrite an existing type. The missing inverse is **deletion**: today a client that
created `Packet` this session, then realizes it was wrong, has no way to remove it (and cannot
re-create it under the same name because creation rejects the collision). The roadmap (#3) promotes
deletion.

### The single hardest constraint (drives the whole design)

ADR-015 §5/§6 named the foot-gun precisely: **deleting or redefining an *in-use* type has a wide
re-render blast radius** — Ghidra's `DataTypeManager.remove(dt, monitor)` deletes the type AND reverts
every dependent (data items typed with it, function signatures using it) to undefined. Deleting a
**Ghidra-recovered / auto-analysis** struct (e.g. a reconstructed `FILE`) is therefore a
**data-poisoning vector**: an injected instruction to "delete type X" could corrupt every dependent
decompilation. ADR-015 §6 rejected silent replace/rename for exactly this reason.

The defense that makes deletion safe is **not** in-use detection (which only narrows, not eliminates,
the vector) — it is **bounding *which* types can be deleted at all**.

## Decision

### D1 — Operation: `delete_type` only (no redefine)

One new gated tool, `delete_type{session_id, name}`. **Redefine is NOT in this increment** — a client
that wants to change a type does `delete_type` then `define_struct`/`define_union` (two gated calls).
An *atomic* "replace existing type in one transaction" remains a future, narrower increment with its
own re-render threat model (as ADR-015 §6 foresaw). Rationale: smallest surface; the delete-then-create
sequence covers the real need; atomicity only matters for an in-use type, and the by-construction bound
below already makes the in-use case the user's own applications.

### D2 — Deletable set: **session-authored composites ONLY** (the load-bearing safety decision)

`delete_type` may delete a type **iff its name is in this session's change-log `composite_targets`** —
i.e. a composite THIS session created via `define_struct`/`define_union`/`define_types` (ADR-027 D1
recorded the created name on `applied=True`). Authority is **server-side**: the handler checks the
change-log BEFORE any RPC; a name that is not session-authored is rejected with no worker call.

Consequences:

- **No data-poisoning of recovered analysis.** A Ghidra auto-analysis struct, a built-in type, or a
  type created by *another* session is **never deletable** — its name is not in this session's
  change-log. The injection "delete type `FILE`" fails closed (FILE was not session-authored).
- **The blast radius is the user's own work.** The only deletable types are ones this session created;
  at creation they re-rendered nothing (ADR-015 §5), and any subsequent re-render came from this
  session's own `apply_data_type`/`set_function_signature` calls. Deleting therefore only reverts the
  caller's own applications — expected, not surprising.
- **Stateless-server posture preserved (ADR-002).** The change-log is the existing in-memory,
  per-session, owner-scoped structure (ADR-027); no new persistence. The worker stays untrusted and
  authority never depends on the worker (which only ever deletes the name the server already
  authorized).
- The worker is a **dumb delete-by-name**: it does not know or enforce "session-authored" — that is
  the server's job (the change-log lives server-side; the worker has no session history). Defense in
  depth: the worker still rejects deleting a non-composite or a built-in (see D5).

### D3 — In-use handling: allow + report `dependents_reverted`

Deletion proceeds even if the type is in use; Ghidra's `remove` reverts dependents to undefined. The
result reports `dependents_reverted` (a count) for transparency. Per D2 those dependents are the
caller's own applications, so reverting them is the expected effect of "delete my type", not a
surprise. (Refuse-if-in-use was considered and rejected as less ergonomic with no added safety once D2
bounds the set.) The count is computed **before** the remove (read-only) and is a plain integer — no
binary-derived text.

### D4 — Gating, validation, transaction, audit (same spine as ADR-015)

- **Gated** behind per-session **write consent + `allow_structural`** (`require_write_consent(...,
  structural=True)`), identical to `define_struct`/`define_union`/`define_types`.
- **Untrusted name validated** at the boundary via the existing `validate_write_name` (shape/bounds/
  allow-list) BEFORE the change-log check — the `name` is attacker-influenced input even though it is a
  lookup key, not a persisted value.
- **One transaction + rollback** in the worker; a remove failure rolls back and surfaces a clean
  `analysis-failed` (no partial state).
- **Change-log upkeep:** on `applied=True`, the handler **removes** the deleted name from the session's
  `composite_targets` (a new owner-scoped `SessionManager.forget_composite_target`), so a later export
  never references a deleted type and the name can be re-created (creation's collision check now passes).
- **Audit (master §5):** log intent + outcome with the tool name, session id, `name` **length** only,
  and `applied` — never the name's contents (attacker-influenced) and never any binary-derived text.

### D5 — Worker `delete_type` RPC + the JVM edge

New RPC method `delete_type{name}` (server→worker; the server has already authorized it). Worker
`_gh_delete_type`:

1. `dt = manager.getDataType(CategoryPath.ROOT, name)` (read-only). Not found → `not-found` (no txn).
2. Defense in depth: if `dt` is not a composite (`Structure`/`Union`) or is a built-in/pointer/array →
   reject `analysis-failed` (the server only ever authorizes session-authored composite names, so this
   is belt-and-suspenders against a desync). No txn opened.
3. Count dependents (read-only, before the write) for `dependents_reverted` — best-effort via the
   `DataTypeManager` parent/use APIs. **REQUIRES-LIVE-VERIFICATION** of the exact API on Ghidra 12.1.2.
4. In ONE transaction: `manager.remove(dt, TaskMonitor.DUMMY)`; verify it returned/took effect; commit.
   On any exception → roll back the transaction → `analysis-failed`.

Per the F2/F7/ADR-030-Phase-1 lesson, `_gh_delete_type` is a `# pragma: no cover` JVM edge that unit
tests cannot exercise — it is **live-verified on a real worker** before merge (create a composite,
apply it, delete it, assert deleted + dependents reverted).

### D6 — Scope / bounds

- **Composites only** (struct/union) — the only types `define_*` can create, so the only types that
  can be session-authored. Deleting enums/typedefs/function-defs is out of scope (not creatable yet).
- No batch delete this increment (single `name`); a batch variant is a trivial future extension if
  measured to matter (note it, don't build it).
- Catalog grows by exactly one tool (50 → 51); the allow-list stays exhaustively asserted.

## Consequences

- Completes the create/delete pair for session-authored composites; unblocks "I made a typo in a
  struct" without a new session.
- The deletable-set bound (D2) is what keeps this additive and TB7-internal rather than a new boundary:
  the worst an injection achieves is deleting a type the *current session itself* created — its own
  work, already gated twice (consent + `allow_structural`).
- A future atomic redefine / built-in or recovered-type deletion would each be its own increment with a
  fresh re-render threat model; explicitly out of scope here.

## Decisions ratified by the human (2026-06-17)
1. **D1 — delete only**, no redefine this increment. ✅
2. **D2 — session-authored composites only** (change-log gated, server-side authority). ✅
3. **D3 — allow deleting an in-use type; report `dependents_reverted`**. ✅

## References
- ADR-015 §5/§6 (re-render blast radius; deletion deferred as a future gated tool), ADR-021 (batch
  composites), ADR-027 (user-authored change-log `composite_targets`), ADR-013/014 (structural-write
  spine, `allow_structural`), ADR-002 (stateless server / worker untrusted), threat-model TB7.
