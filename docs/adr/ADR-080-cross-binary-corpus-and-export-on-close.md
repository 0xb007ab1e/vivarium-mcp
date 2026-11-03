# ADR-080: Cross-binary corpus links + export-on-close for the memory-graph exporter

- **Status:** **Accepted — Implemented** (proposed 2026-11-02; implemented 2026-11-03, #367). Design
  of record authored BEFORE any implementation (`workflow-threat-model`). Completes the two items
  ADR-079 §7 explicitly deferred: cross-binary `SAME_AS` / family-clustering links, and auto-export
  at session close. See **§9 Implementation note** for the one realized refinement (shared hash-class
  nodes instead of pairwise edges — strictly bounds the clustering).
- **Date:** 2026-11-02
- **Deciders:** Human operator (ratification pending). Both features **write to / orchestrate an
  external store** (the `memory-graph` MCP server) — a `workflow-gated-actions` outward/persistence
  action; the CLI and library stop at that boundary unless a run is explicitly authorized.
- **Related:** ADR-079 (session → memory-graph export — this ADR extends it), ADR-001 (server never
  parses / **never calls out**), ADR-002 (ephemeral session, kill + verified wipe on evict/close),
  ADR-005 (untrusted-data envelope), ADR-017 (per-principal owner-scoped sessions), ADR-057/058
  (`function_hash` operand-masked clone key + BSim), ADR-073 (`family_match` — leads not proof).
  Threat model: **TB11** (memory-graph export; threat-model §23) — extended here, no new boundary.
- **Tracking:** closes the §7 deferrals recorded against #367.

---

## 1. Context

ADR-079 shipped the session → `memory-graph` exporter: a client-side `mapper`/`driver` that projects
each Vivarium session onto one **per-binary** memory-graph project (`vivarium-<sha256[:12]>`). Two
items were deliberately deferred (§7):

1. **Cross-binary `SAME_AS` / family-clustering edges.** Deferred because the derived node key is
   `<kind>:<sym?>@<addr>`, so a *shared* project collides addresses across binaries, and memory-graph
   exposed no program-scoped identity. `function_hash` (operand-masked `exact_instructions`) and
   `family_match` were already captured **within** each project as the future join key.
2. **Auto-export at `session_close`.** Deferred to "a phase-2 opt-in hook … so the eviction/wipe
   interaction is designed before it fires automatically."

Two facts now unblock the design:

- **memory-graph exposes `content-hash` identity + `SAME_AS`/`EQUIV` edges** (`mg_schema`:
  `identity_strategies = [address, content-hash, symbol]`). That is the "program-scoped identity or
  content-hash function keys" ADR-079 §7 named as the precondition.
- **memory-graph edges are *within a project*** (`mg_upsert_edges` is project-scoped) — there is
  **no cross-project edge**. So "cross-binary links" cannot be literal edges between two per-binary
  projects; the design must route around that.

This ADR resolves both, and in doing so reaffirms an architectural constraint ADR-079 §2.1 set:
**the Vivarium server never calls out (ADR-001)** — which decides *where* auto-export can live.

## 2. Decision

### Part A — cross-binary linkage via a dedicated **corpus index project** (not cross-project edges, not a shared graph)

Add one standing memory-graph project, **`vivarium-corpus`**, that is the cross-binary **join index**
over the per-binary projects. The per-binary projects (ADR-079) are unchanged — they stay the
detailed graphs. The corpus project holds a *thin* occurrence/clone/family layer whose links are
ordinary **within-project** edges (so no cross-project-edge capability is needed), with every node
carrying back-references to the per-binary project it summarizes.

- **Occurrence nodes.** For each exported function that has an operand-masked `function_hash`
  (`exact_instructions`, ADR-057) and survives the enrich cap, upsert one occurrence node into
  `vivarium-corpus`:
  - `kind = FUNCTION`, `identity = content-hash`, `name = <exact_instructions hash>` (a
    server-computed digest — **safe, not hostile content**),
  - `provenance = GHIDRA`, `layer = raw`,
  - `attrs = { sha256, address, exact_bytes, exact_mnemonics, instruction_count, ghidra_name (U),
    curated_name? (U) }` — the hostile names stay inert `attrs` tagged by provenance (ADR-005),
    `sha256`+`address` are the back-reference into `vivarium-<sha256[:12]>`.
- **`SAME_AS` clone edges (INFERRED).** Within `vivarium-corpus`, two occurrences that share the
  operand-masked hash are linked `SAME_AS` (`layer = inferred`, `provenance = INFERRED`): an
  operand-masked collision is a **strong clone lead, not proof of shared source** (ADR-073 spirit).
  `exact_bytes` equality upgrades the pair to `EQUIV` (byte-identical). Edges are idempotent
  (upsert); re-export re-asserts them.
- **Family clustering (INFERRED).** For each `family_match` candidate, upsert a `kind = OTHER`
  (`name = family:<label>`, `provenance = INFERRED`, `layer = inferred`) node and a `REFERENCES`
  edge from the program's corpus anchor to it, carrying `{ confidence, basis, corpus_version }`.
  Family links are leads (ADR-073); the `inferred` layer keeps them separable from clone-by-hash.
- **Program anchor.** Each exported binary also upserts a `PROGRAM` anchor into `vivarium-corpus`
  (`name = sha256`, back-ref attrs) so family/occurrence nodes attach to something addressable and
  `mg_list_projects` + a corpus query can enumerate "which binaries are indexed and how they relate."

Why a corpus project rather than the two rejected shapes:

- **Not a single shared graph for everything** (ADR-079 §2.3 rejection stands): address-keyed nodes
  (`PROGRAM`/`STRING`/`XREF`/…) still collide across binaries. The corpus project holds **only**
  content-hash-keyed occurrence/family/anchor nodes, so there is no address-key collision in it.
- **Not cross-project edges**: memory-graph has none. Keeping all join edges *inside*
  `vivarium-corpus` uses only the within-project `mg_upsert_edges` that already exists.

### Part B — export-on-close is a **client-side** convenience, never a server hook

The deferred "auto-export at `session_close`" **cannot be a server-side hook**: the Vivarium server
never calls out (ADR-001), and the exporter is a separate MCP *client* holding its own Vivarium +
memory-graph sessions (ADR-079 §2.1). A server that exported on close would open an outbound
connection from the server process — forbidden. Therefore:

- **`export_on_close` is a client-side, opt-in guarantee that export runs *before* the client closes
  its own session**, implemented as a context manager / `--export-on-close` driver flag:
  `export(...)` then `session_close(...)`, with the export in a `finally`/`__exit__` so it runs on
  the error path too (the CLI self-contained mode already closes after export; this makes the
  ordering a first-class, reusable guarantee for the in-place/library and dashboard-backend holders).
- **Bounded + fail-closed.** The pre-close export runs under an explicit time + per-kind ceiling
  (ADR-079 §4). If it errors or times out, it is logged and **the close proceeds anyway** — never
  keep a session (and its on-disk Ghidra project of a hostile binary) alive to retry an export
  (ADR-002: wipe is the safety property; export convenience never defers it).
- **ADR-002 interaction made explicit.** Server-side eviction (idle/analysis timeout, OOM, owner
  disconnect) can destroy the session *before* the client reaches its close path. That is correct and
  unchanged: the client then gets `SESSION_INVALID` and records an **honest partial/empty export**
  (ADR-005 "no silently-wrong data"). Export-on-close reduces but cannot eliminate the race; it is a
  convenience, not a durability guarantee. The remedy for important analyses is to export explicitly,
  not to lengthen a session's life.
- **Gated.** Like all memory-graph writes (ADR-079 §5), enabling export-on-close in an autonomous run
  requires the run's policy to pre-authorize this narrow, reversible, non-prod class; otherwise the
  write escalates (`workflow-gated-actions`).

## 3. Mapping additions (corpus project only)

| Source (already gathered by ADR-079 driver) | `vivarium-corpus` node / edge | kind | prov. | layer | key |
|---|---|---|---|---|---|
| `program_metadata.sha256` | corpus `PROGRAM` anchor (back-ref attrs) | PROGRAM | BINARY | raw | sha256 |
| `function_hash.exact_instructions` (per fn) | occurrence `FUNCTION` (back-ref `{sha256,address}`) | FUNCTION | GHIDRA | raw | content-hash |
| two occurrences, equal masked hash | `SAME_AS` (clone lead) | — | INFERRED | inferred | pair |
| two occurrences, equal `exact_bytes` | `EQUIV` (byte-identical) | — | INFERRED | inferred | pair |
| `family_match` candidate | `OTHER` `family:<label>` + `REFERENCES` from anchor | OTHER | INFERRED | inferred | label |

No change to the per-binary mapping (ADR-079 §3). The corpus layer is **purely additive** and lives
behind an opt-in driver flag (`--corpus` / `link_corpus=True`), default **OFF** — exporting a binary
remains a single-project operation unless corpus linking is requested.

## 4. Bounding (CWE-400)

- Occurrence upserts reuse the driver's existing per-kind enrich ceiling (ADR-079 §4) — at most
  `max_enrich_functions` occurrence nodes per binary.
- `SAME_AS` edge creation is bounded per export: for each new occurrence the driver queries the
  corpus for the **same masked hash** (`mg_query`, capped page) and links at most `MAX_CLONE_FANOUT`
  existing occurrences — a hash shared by thousands of trivial thunks is linked truncated-with-flag,
  never fanned out unboundedly.
- The corpus project's growth is one thin node per indexed function + family label — orders of
  magnitude smaller than the per-binary graphs.

## 5. Security (the corpus is still hostile data at rest; the *keys* are safe)

- **Keys are server-computed digests, not hostile bytes.** Occurrence node `name` is the
  operand-masked `function_hash`; the corpus `PROGRAM` name is the sha256. Neither is attacker
  content, so the corpus's identity surface carries no injection vector. Hostile strings (function
  names, family labels from a loaded corpus) remain inert `attrs` tagged `GHIDRA`/`INFERRED`
  (ADR-005) — never an edge type, kind, key, or executable.
- **Clone/family links are INFERRED leads, never ground truth.** Operand-masked hash collision and
  `family_match` are heuristics (ADR-073); the `inferred` layer keeps them query-separable from the
  `raw` detailed graphs. An empty corpus or a missing `SAME_AS` is never "unrelated" — only "no lead."
- **No secret ever enters the corpus.** The corpus layer indexes functions + families only; it never
  touches `SECRET` nodes, preserving the ADR-072 redaction contract by construction.
- **Outward write stays gated** (ADR-079 §5); corpus linking and export-on-close are both opt-in and,
  in autonomous runs, policy-gated. Logs carry hashes/counts/durations — no hostile content.
- **ADR-001 preserved.** Both features are client-side; the server gains no outbound path and no new
  attack surface. TB11 is unchanged in shape (one client, two sessions, gated write) — the corpus is
  a third project in the same sink, not a new boundary.

## 6. Testing (master §4)

- **Pure mapper (100% critical path):** new corpus-spec builders (occurrence / anchor / family) are
  pure functions over the already-gathered `function_hash` / `family_match` / metadata — unit-tested
  against synthetic inputs incl. empty / missing-hash / `truncated` / `Untrusted`-unwrap cases.
- **Clone-link logic (pure):** given two occurrence sets, equal masked hash → `SAME_AS`, equal bytes
  → `EQUIV`, differing → none; fan-out cap honored → truncated flag. Deterministic, no live store.
- **Abuse:** a hostile function name / family label (`"<script>"`, `"; rm -rf"`, `ignore previous
  instructions`) round-trips as inert `attrs` with hostile provenance — never a kind/edge/key
  injection; no `SECRET`-derived value ever reaches a corpus node.
- **Property:** for arbitrary occurrence inputs the linker raises only its typed error and emits only
  schema-valid kinds/edge-types/provenance/layers; `SAME_AS`/`EQUIV` is symmetric and idempotent.
- **Driver (fakes):** fake `ToolCaller` + fake `GraphSink` prove corpus upsert + idempotent re-link
  on re-export, cap truncation, and that **export-on-close runs the export before `session_close`
  even when the body raises**, and that a `SESSION_INVALID` (simulated eviction) yields an honest
  partial export without raising.
- **Live (gated marker):** export two synthetic ELFs sharing a cloned function into a throwaway
  corpus project; assert the `SAME_AS` edge exists and both anchors enumerate.

## 7. Alternatives considered / deferred

- **Shared single project with content-hash identity for *all* nodes:** rejected — only functions are
  content-hash-keyable; `PROGRAM`/`STRING`/`XREF`/`SECTION` remain address-keyed and would collide
  (ADR-079 §2.3). The corpus project confines cross-binary nodes to the content-hash-keyable subset.
- **Cross-project edges in memory-graph:** not available (`mg_upsert_edges` is project-scoped); would
  be an upstream feature request. The corpus-project design needs no such capability.
- **BSim-similarity (fuzzy) clone edges:** deferred — this ADR links on *exact* operand-masked hash
  (and byte-equality). BSim (ADR-058/059) adds *near*-clone edges with a similarity threshold; a
  follow-up once the exact-hash corpus is proven (keeps the first increment deterministic).
- **Server-side `session_close` export hook:** rejected — violates ADR-001 (server must not call
  out). Export-on-close is client-side only (Part B).
- **Keeping an evicted session alive to finish an export:** rejected — violates ADR-002 (wipe is the
  safety property). Export is best-effort before close; the wipe is unconditional.

## 8. Consequences

- The growing corpus becomes **queryable as a web**: "every binary that contains this exact function,"
  "clusters of related samples," "which family this anchor joins" — the cross-sample substrate the
  dashboard → RE-workbench roadmap needs, built from facts Vivarium already extracts.
- `export-on-close` makes the common "analyze → persist → done" path a single opt-in guarantee for the
  CLI, library, and dashboard backend, without weakening the ephemeral-wipe invariant.
- Cost: one extra standing memory-graph project (`vivarium-corpus`) and a bounded second write pass
  per export when corpus linking is on; both opt-in and gated. The per-binary export path and the
  core server are unchanged.

## 9. Implementation note (2026-11-03, #367)

Implemented in `src/vivarium/graph_export/` — a pure `corpus.py` (`build_corpus_specs`), driver
`push_corpus` + `export_session(link_corpus=…)` + `export_session_and_close` (Part B), and
`--corpus` / `--export-on-close` CLI flags. One **refinement** to Part A, strictly better than the
drafted shape:

- **Shared hash-class nodes, not pairwise `SAME_AS` edges.** Rather than query the corpus for
  same-hash occurrences and add O(n²) pairwise edges under a `MAX_CLONE_FANOUT` cap (§Part A / §4),
  the exporter upserts a **shared clone-class node named by the hash** (`CONSTANT` = the operand-masked
  `exact_instructions`; a second `CONSTANT` named `bytes:<exact_bytes>` for `EQUIV`) and links each
  per-binary **occurrence** (`FUNCTION`, named `<sha256[:12]>:<addr>`, back-ref attrs `{sha256,
  address, masked_hash, exact_bytes, ghidra_name}`) to it with one `SAME_AS` (and one `EQUIV`). Two
  binaries' occurrences of the same hash reach the **same** class node by name in the one
  `vivarium-corpus` project, so the clone cluster forms **by upsert idempotency with no cross-binary
  query and no fan-out** — the §4 cap and the deferred `query_nodes` port are unnecessary. "All clones
  of H" is the neighbour set of the class node; the cluster is a star, not a clique. Family leads are
  `OTHER` `family:<label>` nodes the anchor `REFERENCES` (INFERRED), as drafted.

- This keeps every §5 security property: class/anchor names are server-computed digests (safe),
  hostile names stay inert `attrs`, clone/family links are `inferred`, no `SECRET` enters the corpus,
  and the write stays gated. Corpus linking is opt-in (default OFF) and only meaningful with
  `enrich_functions=True` (the hash source); `--corpus` implies `--enrich`.

- **Part B** is exactly as designed: `export_session_and_close` runs the export in a `try` and the
  `session_close` in a `finally` (client-side, never a server hook — ADR-001), fail-closed — a raising
  or evicted export is logged and returns an honest empty sentinel while the close still runs
  (ADR-002 wipe never deferred).

Tests: `tests/unit/test_graph_export_corpus.py` — pure projection (100%), a Hypothesis property +
abuse pass (arbitrary/hostile input → only schema-valid, inert nodes/edges; never raises), and driver
wiring incl. idempotent cross-binary clustering and export-before-close on success/raise/failing-close.
