# ADR-056: Data-type enumeration — read-only `list_data_types` tool

- **Status:** **Accepted** (2026-08-12). A read-only browse/list tool; part of the v1.8 "all Ghidra
  coverage" increment program.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("do increment 13"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — `DataTypeManager.getAllDataTypes()` is the same
  iterator `get_data_type` already walks. A probe confirmed a **fresh** program's manager is empty
  (0 types) and stays empty after `apply_type_archive` unless a signature is actually applied — so
  the manager holds exactly the types **established in the session** (defined/applied/analysis-added),
  which is what this tool lists.

## Context

Vivarium had `get_data_type` (resolve ONE type by name), but no way to **enumerate** the types a
session has established — after `define_struct`/`define_types`, `apply_data_type`, or
`apply_type_archive` (inc 8), a caller had no way to answer "which types are now available to
reference?" `list_data_types` is the list-counterpart, completing the standard list+get pair (like
`list_functions`+`get_function`).

This is the tractable read-only slice this increment. The bigger remaining bucket — **BSim** (function
similarity) is installed but its signature generation needs a configured LSH vector factory + per-
function decompile (a multi-probe rabbit hole, deferred), **Version-Tracking** needs a second loaded
program (a session-model change), and **PDB/DYLD** are fixture-blocked. `list_data_types` needs only
the manager Vivarium already reads.

## Decision

### D1 — A new `list_data_types` tool (Tier-1, read-only, paginated)

`list_data_types(session_id, offset, limit, name_contains?)` — the standard paginated shape
(`_Page` + an optional case-insensitive substring filter, exactly like `list_functions`). It iterates
`DataTypeManager.getAllDataTypes()` and returns **lightweight summary rows** `{name, kind, size}` plus
`total` + `truncated`.

### D2 — Summary rows, not full definitions

Unlike `get_data_type` (which returns a type's full **rendered definition** — struct layout etc.),
`list_data_types` returns only `name`/`kind`/`size` per type. A program can hold thousands of types
(e.g. after `apply_type_archive`), so shipping the rendered layout for every row would be huge; the
caller fetches a specific type's full definition via `get_data_type`. This is the same list/get split
as `list_functions` (summary) → `get_function` (detail).

### D3 — Scope: the program's DataTypeManager (session-established types)

It lists the **program's** `DataTypeManager` — the types this session established (defined, applied,
or added by analysis). A fresh program's manager is empty (grounded); that is honest, not a bug — the
tool's purpose is to browse what the session has established, and it composes with the type-write
tools. (Built-in base types live in a separate manager and are intentionally out of scope — the same
scope as `get_data_type`.)

### D4 — Read-only, bounded

Read-only: it reads the manager; no decompile, execution, or mutation. Bounded by `limit`
(server-clamped) with `offset` paging + a `truncated` flag. Added to the Tier-1 read allow-list; no
write-consent.

### D5 — Output: name untrusted, kind/size safe

Each type `name` is binary/library-derived → wrapped in the **untrusted-data envelope** (ADR-005),
consistent with `get_data_type`'s `name`. `kind` (a closed category string) and `size` are
server/worker scalars and stay bare.

## Alternatives considered

- **Include built-in base types (int/char/…) too** — rejected for this increment: it would mean
  merging a second manager + dedup, and diverges from `get_data_type`'s scope. Keeping the same scope
  (the program manager) makes list+get a consistent pair. A "list the base vocabulary" variant can be
  a later additive option.
- **Return the full rendered definition per row** — rejected: too heavy at scale; `get_data_type`
  already gives the full definition for a single type.
- **Ship a bucket item (BSim / Version-Tracking / PDB) instead** — not tractable this increment (BSim
  signature-gen config rabbit hole; VT needs a second program; PDB/DYLD need fixtures).
  `list_data_types` is the grounded slice.

## Consequences

- **Positive:** completes the list+get pair for data types; answers "which types has this session
  established / can I reference?" — composing with `define_struct`/`apply_type_archive`.
- **Cost / risk:** low — read-only, no mutation; a bounded manager walk. Adds one Tier-1 read-only
  tool (the frozen catalog count increments 63 → 64; read-only 47 → 48).

## Testing (master §4)

- **Unit:** schema — paginated bounds; each type `name` is `Untrusted`, `kind`/`size` bare. Registry —
  the handler validates `name_contains` (when given) and dispatches.
- **Integration (gated real worker):** import a blob, add a struct type to the program manager, then
  `list_data_types` and assert the type appears with `total >= 1` (a fresh manager is empty, so the
  test establishes a type first) — the grounded proof-of-concept.

## Rollout

Additive — a new opt-in read-only tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is read-only and needs no write-consent.
