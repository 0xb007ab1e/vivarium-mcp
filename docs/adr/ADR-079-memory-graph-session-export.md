# ADR-079: Export RE sessions to the memory-graph knowledge graph

- **Status:** **Proposed** (2026-10-27; drafted by the assistant). Design of record authored BEFORE
  any implementation (`workflow-threat-model`). Responds to the standing goal of persisting every
  Vivarium reverse-engineering session into a durable, queryable knowledge graph so RE findings
  survive across sessions (cross-session RE memory feeding the dashboard → RE-workbench roadmap).
- **Date:** 2026-10-27
- **Deciders:** Human operator (ratification pending). The export **writes to an external store**
  (the `memory-graph` MCP server) — a `workflow-gated-actions` outward/persistence action; the CLI
  and library both stop at that boundary unless a run is explicitly authorized.
- **Related:** ADR-001 (server never parses / never calls out), ADR-002 (ephemeral session, wipe
  on evict), ADR-005 (untrusted-data envelope), ADR-017 (per-principal owner-scoped sessions),
  ADR-072 (secret scan is REDACTED), ADR-073/074/075 (heuristic scanners = leads not proof),
  ADR-076 / TB9 (`McpToolCaller` — the live MCP client reused here), ADR-078 (atlas composition
  over read-only tools). Threat model: **TB11** (threat-model §23, new).

---

## 1. Context

`memory-graph` is a purpose-built reverse-engineering knowledge graph exposed over MCP. Its schema
(`mg_schema`) is a near-exact superset of what Vivarium's read-only tools already emit:

- **node kinds:** `PROGRAM FUNCTION STRING IMPORT EXPORT EXTERNAL IOC SECRET CONSTANT VTABLE
  SECTION COMMENT VULN TYPE STRUCT ...`
- **edge types:** `CONTAINS CALLS XREF REFERENCES IMPORTS EXPORTS ANNOTATES DECODED_BY SAME_AS ...`
- **provenance:** `BINARY GHIDRA INFERRED USER` · **layers:** `raw inferred curated`

Every fact Vivarium surfaces (functions, calls, xrefs, strings, imports/exports, IOCs, crypto,
secrets, capabilities, family match, and the analyst's own renames/comments/types) maps onto a node
or edge in that vocabulary. The pieces to build the graph already exist as Tier-1/Tier-2 read-only
tools (used wholesale by ADR-078's atlas); **no new worker capability and no new analysis path is
required** — the exporter is a pure consumer of existing tool output (ADR-001 intact).

## 2. Decision

Add a Vivarium-repo package `src/vivarium/graph_export/` that projects a Vivarium session onto
memory-graph node/edge upserts, plus a CLI driver. The design is **ports & adapters**
(`topic-architecture-patterns`):

- **Functional core — `mapper.py` (pure):** maps each Vivarium `*Out` model to a list of
  `NodeSpec` / `EdgeSpec` value objects. No I/O, no server, no SDK — unit-tested in full against
  synthetic `Out` instances (meets the §4 coverage gate with zero live dependencies).
- **Ports — `ports.py`:** `ToolCaller` (the Vivarium read-only source) and `GraphSink` (the
  memory-graph destination) protocols, plus the `NodeSpec` / `EdgeSpec` dataclasses.
- **Imperative shell — `driver.py`:** orchestrates `pull (ToolCaller) → map (pure) → push
  (GraphSink)`, bounded and resumable; holds no mapping logic.
- **Adapters:** `McpToolCaller` (reused from the ADR-076 dashboard backend — a live MCP client to a
  Vivarium server) and `McpGraphSink` (a live MCP client to the `memory-graph` server). Tests use
  in-memory fakes of both ports.

### 2.1 The boundary (why the exporter is NOT in the server)

The Vivarium **server never calls out** (ADR-001). The exporter is therefore a **separate MCP
*client*** that holds two sessions — one to the Vivarium server (read), one to memory-graph (write)
— and never runs inside the server process. This keeps the server a pure read-only source and
memory-graph the sink; the glue is client-side.

### 2.2 Usage models

stdio sessions are per-process and owner-scoped (ADR-017): a second client cannot attach to another
client's live session. Two supported entry points, one mapper:

1. **Self-contained (CLI / batch — primary):** the driver creates its **own** Vivarium session from
   a binary path (`session_create → session_import → session_analyze`), pulls every read-only tool,
   maps, pushes to memory-graph, then `session_close`. Fully automatable (CI, cron, dashboard
   button). This is what "export a binary's analysis to the graph" means operationally.
2. **In-place (library):** `export_session(tool_caller, graph_sink, session_id)` accepts a
   `ToolCaller` already bound to a live session (the dashboard backend's own session, a test's
   fake). Same mapper; the holder of the session drives it. This is "export THIS session."

### 2.3 Project granularity — one memory-graph project per binary

memory-graph `Node` has a **fixed field set** (`kind name provenance layer address attrs`); it has
**no program/scope field**, and the derived node key is `<kind>:<sym?>@<addr>` (addressable) or
`<kind>:<sym?>:<name>` (addressless). In a *shared* project `func:?@0x1000` from binary A collides
with the same address in binary B. Therefore:

- **One memory-graph project per analyzed binary**, named `vivarium-<sha256[:12]>`, description
  carrying the full sha256 + format + architecture. Within a project there is exactly one `PROGRAM`,
  so address-keyed nodes are unambiguous.
- **Idempotent:** re-exporting the same binary looks the project up by name (`mg_list_projects`)
  and upserts into it; re-analysis updates in place (upsert returns `created: false`).
- **The growing corpus is the SET of these projects** (enumerable via `mg_list_projects`).
- **Cross-binary links** (`SAME_AS` on `function_hash`/BSim, family clustering) require
  program-scoped identity memory-graph does not expose today — **deferred** (§7). Family/BSim
  results are stored *within* each project as attributes/nodes, not as cross-project edges, in v1.

## 3. Mapping (full enrichment — v1)

Every source is an existing read-only tool. `U` = the value was Vivarium-`Untrusted` (hostile
origin); it is stored as inert node `name`/`attrs` and carries provenance `BINARY`/`GHIDRA` so every
downstream consumer treats it as data (ADR-005, §5).

| Vivarium tool (`*Out`) | memory-graph node / edge | kind | prov. | layer | key basis |
|---|---|---|---|---|---|
| `program_metadata` / `program_fingerprint` | `PROGRAM` | PROGRAM | BINARY | raw | name=sha256 |
| `list_functions` → `FunctionSummary` | `FUNCTION`; `PROGRAM CONTAINS FUNCTION` | FUNCTION | GHIDRA | raw | address |
| `get_function` → `FunctionDetail` | enrich FUNCTION attrs (signature `U`, is_thunk, conv `U`) | — | GHIDRA | raw | address |
| `cyclomatic_complexity` | FUNCTION attr `complexity` | — | GHIDRA | raw | address |
| `function_hash` | FUNCTION attr `function_hash` (SAME_AS basis — deferred) | — | GHIDRA | raw | address |
| `call_graph` → `CallEdge` | `FUNCTION CALLS FUNCTION` | — | GHIDRA | raw | from@/to@ |
| `xrefs_to`/`xrefs_from` → `Xref` | `XREF` (addr→addr, attr `ref_type`) | — | GHIDRA | raw | from@/to@ |
| `list_imports` → `ImportedSymbol` | `IMPORT`; `PROGRAM IMPORTS IMPORT` | IMPORT | GHIDRA | raw | name (`U`) or addr |
| `list_exports` → `ExportedSymbol` | `EXPORT`; `PROGRAM EXPORTS EXPORT` | EXPORT | GHIDRA | raw | address |
| `list_strings` → `DefinedString` | `STRING`; `PROGRAM CONTAINS STRING` | STRING | BINARY | raw | address |
| `ioc_scan` → `IocMatch` | `IOC`; `IOC REFERENCES STRING`/source addr | IOC | INFERRED | inferred | value (`U`) |
| `crypto_constant_scan` → `CryptoConstantFinding` | `CONSTANT`; `CONSTANT REFERENCES` source addr | CONSTANT | INFERRED | inferred | address |
| `crypto_detect` → `CryptoIndicator` | `CONSTANT` (crypto indicator) + REFERENCES | CONSTANT | INFERRED | inferred | address/detail |
| `secret_scan` → `SecretFinding` | `SECRET` (REDACTED — masked+hash only) | SECRET | INFERRED | inferred | address/pattern |
| `capability_scan` → `CapabilityMatch` | `VULN` (capability) + ATT&CK attrs + evidence REFERENCES | VULN | INFERRED | inferred | rule_id |
| `family_match` → `FamilyCandidate` | PROGRAM attr `family_candidates` (deferred cross-link) | — | INFERRED | inferred | — |
| `session_export_annotations` (renames) | FUNCTION/symbol `name` overlay | — | **USER** | **curated** | address |
| `session_export_annotations` (comments) | `COMMENT`; `COMMENT ANNOTATES` addr | COMMENT | **USER** | **curated** | address+slot |
| `session_export_annotations` (types) | `STRUCT`/`UNION` + `HAS_FIELD` | STRUCT/UNION | **USER** | **curated** | name |

### 3.1 Provenance / layer policy

- **raw + BINARY/GHIDRA** — direct extraction (functions, calls, xrefs, strings, imports/exports).
- **inferred + INFERRED** — heuristic scanners (IOC, crypto, secret, capability, family): *leads,
  not proof* (ADR-073/074/075). The layer label keeps them separable from ground truth at query
  time; an empty inferred set is never "benign".
- **curated + USER** — the analyst's own annotations (renames, comments, types). A USER rename
  overrides the GHIDRA `name` on the same `FUNCTION` node (upsert-by-address, higher layer wins by
  convention; both provenances recorded).

## 4. Bounding (CWE-400 — the exporter inherits every tool's caps)

The exporter adds no new unbounded surface: each source tool is already paginated/capped, and the
driver calls them with explicit caps and walks pagination to a hard per-kind total ceiling
(`_MAX_EXPORT_*`), surfacing `truncated` onto the `PROGRAM` node (honest partial view, ADR-005).
A session that would exceed a ceiling is exported truncated-with-flag, never silently or unboundedly.
Node/edge batches to memory-graph are chunked.

## 5. Security (the exported graph is hostile data at rest)

- **Untrusted content crosses the boundary as inert data.** Function names, strings, IOC values,
  import names, decompiled signatures, secret previews — all Vivarium-`Untrusted` — become node
  `name`/`attrs` tagged provenance `BINARY`/`GHIDRA`/`INFERRED`. memory-graph is a **data store, not
  an executor**; it never runs, renders, or follows them. ADR-005's contract is preserved *by
  provenance*: any consumer of a `BINARY`/`GHIDRA`/`INFERRED` node name/attr treats it as
  attacker-controlled (no execute/eval/render/URL-follow). This is documented on the node schema.
- **Secrets stay redacted (ADR-072).** `SECRET` nodes carry only `masked_preview` + salted
  `preview_hash` + `category`/`pattern_id` — **never** the raw secret. The exporter asserts the raw
  value is absent before upsert (fail-closed).
- **Owner scope (ADR-017).** The in-place routine exports only a session the caller owns; a
  foreign/unknown `session_id` is `SESSION_INVALID`, no oracle. The CLI mode owns the session it
  creates.
- **Outward write is gated.** Writing to memory-graph is an external-persistence action
  (`workflow-gated-actions`): the CLI requires an explicit target, and in autonomous runs the write
  escalates unless the run's policy pre-authorizes this narrow, reversible, non-prod class. No
  secrets are logged; logs carry session id (opaque), project name, per-kind counts, durations.

## 6. Testing (master §4)

- **Pure mapper — 100% (critical path):** every `*Out` → `NodeSpec`/`EdgeSpec` mapping unit-tested
  against synthetic inputs, incl. empty/`truncated`/`Untrusted`-unwrap/redacted-secret cases.
- **Abuse tests:** a malicious function name / string / IOC carrying `"<script>"`,
  `"; rm -rf"`, `ignore previous instructions` round-trips as inert node data with hostile
  provenance (never an edge type, kind, or key injection); a `SecretFinding` never yields a node
  attr equal to a raw secret.
- **Property test:** for arbitrary `Out` payloads the mapper raises only its typed error, never an
  arbitrary exception — and emits only schema-valid kinds/edge-types/provenance/layers.
- **Driver:** fake `ToolCaller` + fake `GraphSink` prove pull→map→push, idempotent re-export
  (upsert), pagination walk, and ceiling truncation. One live integration test (own Vivarium session
  over a synthetic ELF → a throwaway memory-graph project) behind the live-worker marker.

## 7. Alternatives considered / deferred

- **A new in-server MCP tool (`session_export_graph`):** rejected — it makes the server an MCP
  *client* with outbound network, violating ADR-001.
- **Shared single memory-graph project for all binaries:** rejected for v1 — address-key collision
  (§2.3). Deferred until memory-graph exposes program-scoped identity or content-hash function keys.
- **Cross-binary `SAME_AS` / family clustering edges:** deferred (needs the above). `function_hash`
  and `family_match` are stored *within* a project as the future join key.
- **Auto-export at `session_close` (ADR-002 interaction):** deferred to a phase-2 opt-in hook. v1 is
  explicit/manual (CLI or library call) so the eviction/wipe interaction is designed before it fires
  automatically.

## 8. Consequences

- RE findings become durable and queryable across sessions; a corpus of analyzed binaries grows one
  project at a time, each an archify-ready graph and the substrate for the RE-workbench.
- Vivarium gains a first *external* integration surface — isolated to a client-side package, gated,
  and adding no server attack surface.
- Cost: a second always-available MCP dependency (`memory-graph`) for the export path only; the core
  server is unaffected.
