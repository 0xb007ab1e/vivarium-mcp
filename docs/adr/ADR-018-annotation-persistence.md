# ADR-018: Cross-session annotation persistence (export + import)

- **Status:** Accepted (v1.2 design; human-ratified decisions D1–D3, 2026-06-14). First v1.2 increment.
  **Opens a new trust boundary, TB8** (annotation-import document → server). Realizes the
  `session_export_annotations` design hook ADR-012 deferred.
- **Deciders:** Human (ratified scope / state-location / format, 2026-06-14) + PM; recorded by the
  Software Architect.
- **Relates to:** ADR-012 (write tools + the export design hook + the deferred-persistence note),
  ADR-013/014/015 (the structural writes that import replays), ADR-002 (per-session ephemeral wipe —
  the posture this preserves), ADR-005 (untrusted-data envelope), ADR-001 (server never parses a
  binary), ADR-017 (owner-scoped sessions).

## Context

v1.1 mutations are **session-scoped + ephemeral** — they live in the worker's program object across
tool calls but are **lost on eviction by design** (ADR-002's verified wipe). An analyst therefore
cannot **resume a triage**: close the session and the accreted renames/comments/signatures/types are
gone. ADR-012 sketched a `session_export_annotations` hook and flagged the two risks of persistence:
**(a)** an *import-of-attacker-influenced-annotations* boundary, and **(b)** reintroducing *durable
confidential state* that ADR-002's wipe deliberately removed.

This ADR delivers round-trip persistence **without** reintroducing durable server state and
**without** adding any new write primitive.

## Decision (ratified)

### D1 — Export **+** import (round-trip), designed together; implement export first.
One ADR, one new boundary (**TB8**). Export is the read-out; import is the validated replay that makes
an analysis *reusable* (resume a triage in a fresh session for the same binary).

### D2 — **Stateless / client-owned** artifact.
`session_export_annotations` **returns** the document to the MCP client; `session_import_annotations`
**takes** it as a tool argument. The server and worker keep **no persistent store** — ADR-002's
*no-durable-confidential-state* posture is preserved. The **client owns persistence** and, with it,
the artifact's confidentiality: the document contains binary-derived annotations and **inherits the
analyzed binary's CONFIDENTIAL classification** (master §5) — the server never writes it to disk.

### D3 — **Structured annotation document**, replayed through the existing gated write path.
A **versioned, binary-hash-bound** JSON document of **typed** entries (one per existing write tool).
Import **replays** each entry through the **existing** gated write handlers + validators. **No
Ghidra-native project (.gzf)** — that would make import a Ghidra deserialization of
attacker-influenced project data (a new hostile-parse surface in the worker, unvalidatable
field-by-field). The server only ever handles **structured annotation JSON** — never parses a binary
(ADR-001); the document is **inert data**, never executable/Ghidra-native.

## The document (shape)

```
{ "schema_version": 1,
  "binary": { "sha256": "<program hash>", "name": "<…>", "size": <…> },   // applicability binding
  "entries": [                                                            // dependency-ordered
    { "kind": "define_struct"|"define_union", … },                       // TYPES FIRST
    { "kind": "set_function_signature"|"apply_data_type", … },           // then refs to them
    { "kind": "rename_function"|"rename_symbol"|"rename_local_variable"|"rename_parameter", … },
    { "kind": "set_comment", … } ] }
```
Each entry mirrors an existing write tool's payload (selector/target + value). Binary-derived strings
(names, comments) are wrapped in the **untrusted envelope** (ADR-005) on export. Entries are emitted
in a **dependency-safe order** (composites/types before the signatures/applies that reference them)
and import preserves that order.

## Export (read-out)

`session_export_annotations(session_id)` → a new worker RPC `export_annotations` enumerates the
program's **`USER_DEFINED`** annotations only (Ghidra `SourceType.USER_DEFINED` symbols, user
comments, user-applied data types / signatures, user-defined composites) — **not** Ghidra's
auto-analysis output. The server assembles the versioned, hash-bound document. **Read-only** (no
write consent). **Owner-scoped** (ADR-017 — the caller's own session only). **Bounded:** entry-count
+ size caps; over the cap → fail closed (`limit-exceeded`), never a silent truncation that would
produce an incomplete-but-plausible artifact.

## Import (read-in) — the new boundary, TB8

`session_import_annotations(session_id, document)` treats the document as **fully untrusted** (it may
have been tampered offline). The server:
1. **Schema-validates** the document (pydantic): supported `schema_version`, bounded entry count +
   sizes, unknown fields rejected — fail closed.
2. **Verifies applicability:** `document.binary.sha256` **==** the target session's program hash, else
   fail closed (`validation`/`not-found`). Applying one binary's addresses/types to another is
   meaningless and dangerous.
3. **Gates** exactly like live writes: `require_write_consent`; any **structural** entry additionally
   requires `require_write_consent(structural=True)` (LLM08 — the human-in-the-loop capability gate is
   not bypassed by importing). The **structural** kinds (`STRUCTURAL_ENTRY_KINDS`, the single source of
   truth shared with the handlers) are **every** entry whose live handler calls
   `require_write_consent(structural=True)`: the Phase-A name-only renames
   `rename_local_variable`/`rename_parameter` (ADR-013) **and** the Phase-B/C type-aware writes
   `set_function_signature`/`apply_data_type`/`define_struct`/`define_union` (ADR-014/015). A
   local/param-only document is therefore denied up front without `allow_structural`, identical to the
   per-entry handler.
4. **Per entry:** re-validate through the **same** validator (`validate_write_name` /
   `validate_comment_text` / `validate_target_ref` / `validate_type_ref` / `validate_signature` /
   `validate_composite`), then **replay via the existing write handler/worker RPC**, each in its own
   Ghidra transaction with rollback. **No claim in the document is trusted** — it supplies only
   *proposed* writes.
5. Returns a **per-entry outcome report** (applied / rejected + reason); best-effort per entry (partial
   application is acceptable and matches the per-write transaction model). **Audited** (count,
   principal, session, per-entry outcome — sizes/flags only, never the imported values).

**The core security argument:** import adds **no new write primitive** — it is a schema-validated,
hash-bound, consent-gated **batch replay of existing gated writes**, each re-validated and transacted.
Its blast radius is exactly that of the v1.1 write tools, no more.

## Security (TB8 — STRIDE; full threat-model section + abuse cases land with the implementation)

- **S (spoof applicability):** the `binary.sha256` binding is verified against the session's real
  program hash; a document for a different/forged binary is rejected.
- **T (tampered document):** every entry is re-validated through the live validators and applied only
  via the gated write path; offline edits cannot smuggle an unvalidated write or an
  injection-bearing name/comment (two-sided validate-in defense, as live writes).
- **R (repudiation):** import is audited (count, principal, session, per-entry outcome).
- **I (information disclosure):** the exported document carries the binary's **confidential,
  hostile-origin** artifacts off-server to the client (master §5) — strings stay untrusted-wrapped;
  the **server persists nothing** (D2), so no durable confidential state is created server-side. The
  client owns + classifies the artifact.
- **D (DoS):** bounded entry count + per-field sizes; each replay is a bounded transaction; import is
  consent-gated and owner-scoped.
- **E (elevation):** import can do **only** what the live write tools can (same consent, same
  `allow_structural`, same validators); **owner-scoped** (ADR-017) — a principal imports only into its
  own session. No new capability, no cross-owner reach.

## Architecture & invariants
- **Ports & adapters:** one new `GhidraPort.export_annotations`; **import is server-side orchestration**
  (registry) over the **existing** port write methods — **no new worker write method**.
- **ADR-001 preserved:** the server handles only structured annotation JSON; enumeration + application
  happen in the worker; **no binary parsed server-side**; the document is inert (not Ghidra-native).
- **ADR-002 preserved:** no server/worker persistent store; "persistence" is the client holding the
  returned document.
- **Contracts (land in the impl PR):** +2 tools (`session_export_annotations`,
  `session_import_annotations`; catalog **47 → 49**) + **1** worker RPC (`export_annotations`); import
  reuses existing write RPCs. Error envelope unchanged (reuse
  `validation`/`limit-exceeded`/`not-found`/`analysis-failed` — no new `ErrorType`).

## Consequences
- Analysts can **resume a triage** (export before evict → import into a fresh same-binary session)
  while the server stays **stateless + ephemeral** (ADR-002 intact); durability + confidentiality live
  with the client artifact.
- A **new trust boundary (TB8)** is added — threat-modeled here; the formal `threat-model.md` TB8
  section + abuse cases land with the implementation.
- **Deferred / out of scope:** a server-managed export store; Ghidra-native project import;
  cross-binary / fuzzy application; auto-export on eviction (the client must export explicitly before
  evict). Revisit only with a new ADR.

## Alternatives considered
- **Server-managed store** (export by id, reload by id): more convenient, but reintroduces the durable
  confidential state ADR-002 removes + a storage/retention/access boundary. **Rejected** (D2).
- **Ghidra-native project (.gzf) round-trip:** captures everything, but import = Ghidra deserializing
  attacker-influenced project data (new hostile-parse surface, opaque, unvalidatable). **Rejected** (D3).
- **A new bulk-write worker RPC:** simpler orchestration, but a *new* write primitive widens the abuse
  surface beyond the audited per-tool writes. **Rejected** — replay the existing gated writes instead.
- **Export-only now, import later:** lower risk, but persistence without reload is half the value.
  **Rejected** (D1) — designed together so the format is import-validation-shaped from the start.

## Implementation increment (follows this design PR)
1. **schemas:** `AnnotationDocument` + the typed `Entry` union (one variant per write tool) + bounds;
   `SessionExportAnnotationsIn/Out`, `SessionImportAnnotationsIn/Out` (with the per-entry outcome report).
2. **validation:** `validate_annotation_document` (version, bounds, hash presence) + per-entry dispatch
   to the **existing** validators (no new write-validation logic).
3. **worker:** `_gh_export_annotations` (enumerate `USER_DEFINED` annotations, dependency-ordered) +
   the dispatch RPC method; `GhidraPort.export_annotations` + adapter.
4. **registry:** `_handle_session_export_annotations` (read, owner-scoped, untrusted-wrapped, bounded)
   + `_handle_session_import_annotations` (schema-validate → hash-verify → consent → per-entry
   validate + replay + audit → outcome report).
5. **contracts:** tool-catalog 47→49 + 2 rows; rpc-protocol +`export_annotations`.
6. **threat-model:** formal **TB8** section + abuse cases (tampered doc, wrong-binary hash, oversized
   count/field, injection in an imported name/comment, structural entry without `allow_structural`,
   cross-owner import, unknown `kind`/`schema_version`) + `topic-testing` coverage gates. No real
   binaries/secrets in tests — synthetic fixtures only.
