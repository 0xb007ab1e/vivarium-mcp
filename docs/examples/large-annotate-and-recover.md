# Example 3 (large): recover & document a function cluster, then persist it

**Goal:** you've triaged the binary (Example 2) and want to *do the reverse-engineering work* — name
functions and variables, recover a `struct`, fix up signatures, leave comments — and then **save that
work** so it survives the ephemeral session and can be replayed later or shared. This is the full
**gated write** workflow plus **streaming** (for scale) and **annotation persistence**.

**You'll use:** `session_enable_writes` (the consent gate) → `analysis_order` (leaf-first plan) →
`start_decompile_stream` + `fetch_job_results` (scale) → `rename_function` / `rename_parameter` /
`rename_local_variable` → `define_struct` / `apply_data_type` / `set_function_signature` →
`set_comment` → `session_undo` → `session_export_annotations` → (fresh session) `session_import_annotations`.

> Continues from Example 2 (the C2 client), session `S3`, already analyzed. `*` = envelope-wrapped.
> **Everything here is session-scoped and ephemeral** — it lives only until the session is evicted,
> *unless you export it* (step 8). The server never mutates the program; each write runs in the worker
> inside one Ghidra transaction (commit on success, roll back on failure).

---

## 1. Opt in to writing (the single consent gate)

A session is **read-only until you say otherwise.** Recovering types/signatures is a *structural*
write, so opt into that too:

```jsonc
session_enable_writes { "session_id": "S3", "allow_structural": true }
// → { "session_id": "S3", "writes_enabled": true, "allow_structural": true }
```

This is the one human-in-the-loop checkpoint (LLM08 — least agency): nothing below can run without it,
and `session_disable_writes` flips back to read-only at any time. Omitting `allow_structural` leaves
the *structural* tools (`define_*`, `apply_data_type`, `set_function_signature`,
`rename_local_variable`, `rename_parameter`) denied with `forbidden` while still allowing plain
renames + comments.

## 2. Plan the order: leaf-first (`analysis_order`)

Name **helpers before the code that calls them** — once a callee has a meaningful name and signature,
the caller's decompilation reads far better. `analysis_order` returns the cluster in leaf-first
(reverse-topological) order, with recursion cycles condensed:

```jsonc
analysis_order { "session_id": "S3", "root": "0x405310", "max_depth": 64, "max_nodes": 2000 }
// → { "components": [
//       { "members": ["0x4058e0"], "is_recursive": false },   // a pure leaf — name this FIRST
//       { "members": ["0x405880"], "is_recursive": false },
//       { "members": ["0x405310"], "is_recursive": false }     // the beacon fn (root) — name it LAST
//     ],
//     "self_recursive": [], "unresolved_callers": [], "truncated": false }
```

Work the `components` top-to-bottom. `unresolved_callers` (indirect/virtual calls the static graph
couldn't resolve) are surfaced, never dropped — note them as gaps.

## 3. Pull the cluster's decompilation at scale (`start_decompile_stream`)

For a handful of functions you'd call `decompile_function` each. For a *large* cluster, stream them:
the worker decompiles and emits one chunk per function while you start reading the early ones.

```jsonc
start_decompile_stream { "session_id": "S3", "functions": ["0x4058e0","0x405880","0x405310"] }
// → { "job": "J1", "total_estimate": 3, "state": "running" }

fetch_job_results { "session_id": "S3", "job": "J1", "limit": 32 }
// → { "chunks": [
//       { "seq": 0, "address": "0x4058e0", "code*": "uint FUN_004058e0(byte *p, uint n) { uint h=0; … }" },
//       { "seq": 1, "address": "0x405880", "code*": "void FUN_00405880(void *cfg, char *line) { … }" } ],
//     "next_cursor": 2, "done": false, "truncated": false }

// re-call with cursor:2 until done:true (chunks arrive in seq order; dedupe by seq on resume).
fetch_job_results { "session_id": "S3", "job": "J1", "cursor": 2, "limit": 32 }
// → { "chunks": [ { "seq": 2, "address": "0x405310", "code*": "…" } ], "next_cursor": 3, "done": true }
```

`job_status` reports progress without pulling chunks; `cancel_job` stops a long run early and frees the
worker. One streaming job per session.

## 4. Name a leaf function, its parameters, and its locals

`FUN_004058e0` is a small hashing helper (`h = h*33 + c` over `n` bytes — a classic djb2). Name the
function, then its parameter and the accumulator local:

```jsonc
rename_function       { "session_id": "S3", "function": "0x4058e0", "new_name": "djb2_hash" }
// → { "address": "0x4058e0", "old_name*": "FUN_004058e0", "new_name": "djb2_hash", "applied": true }

rename_parameter      { "session_id": "S3", "function": "0x4058e0", "parameter": "p", "new_name": "data" }
// → { "address": "0x4058e0", "old_name*": "p", "new_name": "data", "applied": true }     // structural

rename_local_variable { "session_id": "S3", "function": "0x4058e0", "variable": "h", "new_name": "hash" }
// → { "address": "0x4058e0", "old_name*": "h", "new_name": "hash", "applied": true }      // structural
```

`new_name` is run through an identifier allow-list **on the way in** (stored-injection defense), so a
malicious name can't smuggle anything into the project. Renames are name-only — they don't change
behavior or layout.

## 5. Recover a struct and apply it (`define_struct`, `apply_data_type`, `set_function_signature`)

`FUN_00405880` parses config lines into a fixed structure. From the decompiled field offsets you
reconstruct the layout — define it as a real type, then *apply* it so every access decompiles as
`cfg->host` instead of `*(undefined8 *)(param + 8)`:

```jsonc
// 5a. Define the recovered struct. TypeRefs are RESOLVED against the program's type manager —
//     never parsed from a C string (the C-parser injection surface doesn't exist here).
define_struct {
  "session_id": "S3", "name": "beacon_config",
  "fields": [
    { "name": "magic",    "type": { "base": "uint32" },                 "offset": 0 },
    { "name": "host",     "type": { "base": "char", "pointer_levels": 1 }, "offset": 8 },
    { "name": "port",     "type": { "base": "uint16" },                 "offset": 16 },
    { "name": "interval", "type": { "base": "uint32" },                 "offset": 20 },
    { "name": "key",      "type": { "base": "uint8", "array_len": 32 }, "offset": 24 }
  ]
}
// → { "name": "beacon_config", "kind": "struct", "size": 56, "field_count": 5, "applied": true }

// 5b. Tell the analysis that the global at 0x49a0c0 IS a beacon_config.
apply_data_type { "session_id": "S3", "address": "0x49a0c0",
                  "type": { "named": "beacon_config", "pointer_levels": 0 } }
// → { "address": "0x49a0c0", "type_name*": "beacon_config", "size": 56, "applied": true }

// 5c. Fix the parser's signature so callers type-check + read cleanly.
set_function_signature {
  "session_id": "S3", "function": "0x405880",
  "return_type": { "base": "void" },
  "parameters": [ { "name": "cfg",  "type": { "named": "beacon_config", "pointer_levels": 1 } },
                  { "name": "line", "type": { "base": "char", "pointer_levels": 1 } } ]
}
// → { "address": "0x405880", "old_signature*": "void FUN_00405880(void *, char *)",
//     "new_signature*": "void FUN_00405880(beacon_config *cfg, char *line)", "applied": true }
```

If several types reference *each other* (e.g. a node with a `next` pointer, or two mutually-recursive
structs), define them in one atomic batch with **`define_types`** — a field's `type.named` may point at
another member of the same batch. Pointer cycles are allowed; a by-value cycle is rejected up front;
and the **whole batch rolls back if any member fails** (all-or-nothing). For self-referential pointer
structs, name the type itself in a field — it's pre-registered so the self-pointer resolves.

## 6. Leave a comment for the next reader (`set_comment`)

```jsonc
set_comment { "session_id": "S3", "address": "0x405310", "comment_type": "PLATE",
              "text": "C2 beacon: builds POST, AES-encrypts payload, sends to beacon_config.host" }
// → { "address": "0x405310", "comment_type": "PLATE", "applied": true }
```

Comment text is normalized on the way in (same stored-injection defense as names). `text: null` clears
a comment.

## 7. Made a mistake? Undo the last write (`session_undo`)

```jsonc
session_undo { "session_id": "S3" }
// → { "session_id": "S3", "undone": true }     // reverts the last committed mutation transaction
```

## 8. Persist your work so it outlives the session (`session_export_annotations`)

Everything above is ephemeral — `session_close` (or any eviction) wipes it. Export it to a portable,
**binary-hash-bound** JSON document you can store client-side and replay later:

```jsonc
session_export_annotations { "session_id": "S3" }
// → { "document": {
//       "schema_version": 2,
//       "binary": { "sha256": "9f2a…", "size": 51240 },
//       "entries": [
//         { "kind": "define_types", "types": [ { "name": "beacon_config", "kind": "struct", "fields": […] } ] },
//         { "kind": "apply_data_type", "address": "0x49a0c0", "type": { "named": "beacon_config" } },
//         { "kind": "set_function_signature", "function": "0x405880", … },
//         { "kind": "rename_function", "function": "0x4058e0", "new_name": "djb2_hash" },
//         { "kind": "set_comment", "address": "0x405310", "comment_type": "PLATE", "text": "C2 beacon: …" }, … ]
//   } }
```

It's **read-only** (no consent needed), owner-scoped, dependency-ordered (types first, then the
applies/signatures that use them, then renames, then comments), and bounded. The server stores
nothing — persistence is yours to own.

## 9. Replay into a fresh session (`session_import_annotations`)

Later — a new day, a new session on the *same* binary — replay the document to get all your names,
types, and comments back:

```jsonc
// (fresh session S4: create → import the SAME binary → analyze → enable writes{allow_structural:true})
session_import_annotations { "session_id": "S4", "document": { /* the exported doc */ } }
// → { "session_id": "S4", "total": 5, "applied": 5, "rejected": 0,
//     "outcomes": [ { "index": 0, "kind": "define_types", "applied": true },
//                   { "index": 1, "kind": "apply_data_type", "applied": true }, … ] }
```

Import is the one trust boundary worth understanding: the document is **fully untrusted** → it's
schema-validated, its `binary.sha256` is checked against the loaded program (replaying onto the wrong
binary fails closed), it requires the same write-consent, and **each entry is re-validated and replayed
through the exact same gated write path** as if you'd called the tools by hand. It adds *no* new write
primitive — it's a hash-bound, consent-gated batch replay. You get a per-entry `outcomes` report
(best-effort: a stale entry can be `rejected` with a reason without failing the rest).

## 10. Close

```jsonc
session_close { "session_id": "S3" }   // (and S4)
// → { "store_wiped": true }
```

---

## What you learned

- Writing is **default-deny** — one explicit `session_enable_writes` gate, with `allow_structural` for
  type/signature work; nothing mutates the program server-side.
- **Leaf-first** (`analysis_order`) is the efficient naming order; **streaming** (`start_decompile_stream`)
  lets you work a large cluster without waiting for the whole decompile.
- You recover real structure — `define_struct`/`define_types` (atomic, cycle-checked),
  `apply_data_type`, `set_function_signature` — with type references **resolved, never parsed from C**.
- Work is **ephemeral by design**, but `session_export_annotations` → `session_import_annotations`
  gives you durable, **hash-bound**, replayable annotations — your RE work, portable and safe.

This is the effective end-to-end loop: **triage** (Example 2) → **recover & document** (here) →
**persist** → resume or share. For the "does this actually work on a real, stripped binary?" question,
read the [blind-analysis deep-dive](blind-analysis-sqlite.md).
