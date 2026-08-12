# Contract: Tier-1 Tool Catalog (FROZEN — WS0)

> Pydantic source of truth: [`src/vivarium/tools/schemas.py`](../../src/vivarium/tools/schemas.py).
> Allow-list registry: [`src/vivarium/tools/registry.py`](../../src/vivarium/tools/registry.py).
> **Read-by-default.** 41 of the 56 tools are read-only; the **15 mutation/write tools** below are
> **default-deny**, gated by per-session write-consent (`session_enable_writes`) — structural writes
> additionally by `allow_structural`. **`runScript`/arbitrary script execution is permanently out of
> scope** (PLAN §2), and the tool surface is a **fixed allow-list** (no dynamic registration).

## Conventions (apply to every tool)

- **Allow-list only:** the catalog is fixed; there are exactly **56** tools (asserted in tests by
  `len(TIER1_TOOL_NAMES) == 56`). The breakdown:
  22 Tier-1 read-only (v1) + 5 v1.1 semantic-naming support tools (ADR-007) + 8 v1.1 Tier-2
  reporting/metrics tools (ADR-008; all read-only) + **1 Function ID library-match tool (ADR-042
  Phase 1: `identify_functions`; read-only)** + **6 v1.1 mutation/write tools (ADR-012) + 8
  structural-write tools (ADR-013 Phase A + ADR-014 Phase B + ADR-015 Phase C + ADR-021 batch
  `define_types` + ADR-031 `delete_type`)** + **4 v1.x streaming-extraction tools (ADR-040:
  `start_decompile_stream` + the generic `fetch_job_results`/`job_status`/`cancel_job`;
  read-only, output-only)** + **2 v1.2 annotation-persistence tools (ADR-018:
  `session_export_annotations` read-only + `session_import_annotations` GATED)**. That is **41
  read-only + 15 mutation/write** (the 15 = the 6 ADR-012 write tools + the 8 structural-write tools
  + the gated `session_import_annotations`; it matches the `WRITE_TOOLS` frozenset in `registry.py`).
  Every write tool is GATED by per-session write-consent (structural additionally by
  `allow_structural`); import is GATED identically (and additionally by `allow_structural` when any
  imported entry is structural).
- **Session-scoped:** every tool except `session_create` takes an opaque `session_id`, authorized
  server-side (BOLA defense). Inputs are `frozen` and reject unknown fields (`extra="forbid"`).
- **Bounded by default:** list/search/read tools take `offset` + `limit` (or `length`) with hard
  caps enforced by pydantic AND `core.validation` before the worker (DoS — PLAN §3 F7):
  `limit ≤ 10000` (default 100), `read_bytes.length ≤ 1 MiB`, query/name ≤ 4096/1024 chars.
- **Untrusted output is wrapped:** every binary-derived field is `Untrusted[...]` (ADR-005);
  server-computed scalars (addresses we normalized, counts, sizes, sha256) are bare.
- **Failures** return the [error envelope](error-envelope.md).

## Catalog

### Session lifecycle (server-side; not worker RPC)
| Tool | Input | Output | Notes |
|------|-------|--------|-------|
| `session_create` | `SessionCreateIn{label?}` | `SessionInfo` | opaque CSPRNG id; no worker yet; cap-checked |
| `session_import` | `SessionImportIn{source_ref, expected_sha256?, loader?, processor?, base_addr?, entry?}` | `SessionInfo` | size cap enforced **before** Ghidra; digest verified; path confined (`source_ref` is a path under `VIVARIUM_IMPORT_ROOT`). **Loader hints (ADR-045, F1) are additive + opt-in:** `loader` (`auto`/`binary`, default `auto`) — `auto` drives the opinion/container loaders (ELF/PE) **byte-for-byte as before**; `binary` drives `BinaryLoader` for a **headerless raw/firmware image** and REQUIRES `processor` (a Ghidra `LanguageID` in the allow-list `vivarium.core.languages` — the full installed set, e.g. `ARM:LE:32:Cortex`, `x86:LE:64:default`, `MIPS:BE:32:default`, `RISCV:LE:32:default`) + `base_addr` (image base, bounded to the processor's address width); optional `entry` (entry-point seed, `>= base_addr`). **Hex loaders (ADR-046):** `intel-hex`/`motorola-hex` drive `IntelHexLoader`/`MotorolaHexLoader` for hex-delivered firmware — REQUIRE `processor` only; `base_addr`/`entry` are rejected (the records carry their own addresses). Hints are validated **server-side before the worker** (allow-list + width bounds, CWE-20); the worker re-validates the language against the installed set (defense in depth) and fails closed `not-found`. No hint set ⇒ byte-for-byte the pre-ADR-045 path |
| `session_analyze` | `SessionAnalyzeIn{timeout_seconds?, profile?, progress?}` | `SessionInfo` | bounded by analysis timeout → kills worker on expiry; `profile` (`default`/`light`/`deep`, ADR-029 B) is **additive** — `default` is a byte-for-byte no-op; `light` trades depth for speed/heap, `deep` adds depth; reduces/adjusts depth only (no new capability). `progress` (bool, default `false`, ADR-030 Phase 1) is **additive + opt-in** — `true` emits bounded, redacted worker→server `$/progress` notifications (percent + closed phase enum only) relayed to the **server log only** (Phase 1); default `false` is byte-for-byte today's single-frame exchange; the analysis deadline is **not** extended by progress. **Client progress (ADR-030 Phase 2):** when the MCP client supplies a standard `progressToken` (MCP `_meta`), the server streams each frame to the client as a `notifications/progress` (percent out of 100; closed-vocab phase as the message) — no extra arg needed (a token implies progress, so the server forces worker emission on). **No token ⇒ byte-for-byte the pre-Phase-2 path** (inline, no client relay) |
| `session_status` | `_SessionScopedIn{session_id}` | `SessionInfo` | state/TTL; no binary content |
| `session_close` | `SessionCloseIn{session_id}` | `SessionCloseOut{store_wiped}` | kill worker + **verified wipe** (ADR-002) |

### Streaming extraction (v1.x — ADR-040; READ-ONLY, output-only; pull-based job + cursor)
> The worker emits results incrementally (`$/chunk`, rpc-protocol §4) while the server buffers them;
> the client **pulls** bounded batches by cursor so the LLM can reason over early units while the rest
> extract. A job handle is bound to its session+principal (BOLA) and lives inside the worker lifetime
> (ADR-002). **One active streaming job per session** (a second `start_*` → `limit-exceeded`). Every
> chunk's binary-derived fields carry the untrusted-data envelope, exactly like a one-shot result.

| Tool | Input | Output | Notes |
|------|-------|--------|-------|
| `start_decompile_stream` | `StartDecompileStreamIn{session_id, functions?: [str], progress?}` | `JobStartOut{job, total_estimate?, state}` | starts bulk decompile over the function set (default: all, bounded by the existing decompile total cap); returns an opaque `job` handle immediately. Worker streams one `function` chunk per decompiled function |
| `fetch_job_results` | `FetchJobResultsIn{session_id, job, cursor?, limit?}` | `JobResultsOut{chunks: [DecompiledChunk], next_cursor, done, truncated}` | drains up to `limit` (default 32, max 256) buffered chunks from the server in `seq` order + the next cursor + `done`; resumable (re-fetch from an earlier cursor; client dedupes by `seq`). `chunks[].code` is `Untrusted` |
| `job_status` | `JobStatusIn{session_id, job}` | `JobStatusOut{state, phase, done, total?, buffered, eta_seconds?, started_at}` | server-side counters only — no binary content; `state ∈ {running, paused, done, error, cancelled}` |
| `cancel_job` | `CancelJobIn{session_id, job}` | `CancelJobOut{cancelled}` | aborts the in-flight extraction (server→worker `$/cancel` notification — ADR-041) + discards the buffer, freeing worker capacity early; idempotent |

### Code
| Tool | Input | Output |
|------|-------|--------|
| `decompile_function` | `DecompileFunctionIn{function}` | `DecompiledFunction{address, name*, c_code*, signature*}` |
| `disassemble` | `DisassembleIn{start?, function?, max_instructions≤10000}` | `DisassembleOut{instructions[], truncated}` |
| `list_functions` | `ListFunctionsIn{offset, limit≤10000, name_contains?}` | `FunctionListOut{functions[], total, truncated}` |
| `get_function` | `GetFunctionIn{function}` | `FunctionDetail{address, name*, signature*, size, is_thunk, calling_convention*?}` |

### Cross-references
| Tool | Input | Output |
|------|-------|--------|
| `xrefs_to` | `XrefsIn{target, offset, limit}` | `XrefsOut{xrefs[], total, truncated}` |
| `xrefs_from` | `XrefsIn{target, offset, limit}` | `XrefsOut{xrefs[], total, truncated}` |

### Strings / symbols / data / types
| Tool | Input | Output |
|------|-------|--------|
| `list_strings` | `ListStringsIn{offset, limit, min_length}` | `StringListOut{strings[], total, truncated}` |
| `list_symbols` | `ListSymbolsIn{offset, limit, name_contains?}` | `SymbolListOut{symbols[], total, truncated}` |
| `get_symbol` | `GetSymbolIn{identifier}` | `Symbol{address, name*, kind, namespace*?}` |
| `list_data` | `ListDataIn{offset, limit}` | `DataListOut{data[], total, truncated}` |
| `get_data_type` | `GetDataTypeIn{name}` | `DataType{name*, kind, size, definition*}` |

### Comments (read-only)
| Tool | Input | Output |
|------|-------|--------|
| `get_comments` | `GetCommentsIn{offset, limit, address?}` | `CommentListOut{comments[], total, truncated}` |

### Memory / bytes / search
| Tool | Input | Output |
|------|-------|--------|
| `memory_map` | `MemoryMapIn{session_id}` | `MemoryMapOut{blocks[]}` |
| `read_bytes` | `ReadBytesIn{address, length≤1 MiB}` | `ReadBytesOut{address, data* (hex), length, truncated}` |
| `search_bytes` | `SearchBytesIn{pattern_hex, offset, limit}` | `SearchBytesOut{matches[], total, truncated}` |
| `search_strings` | `SearchStringsIn{query, offset, limit}` | `SearchStringsOut{strings[], total, truncated}` |

### Metadata
| Tool | Input | Output |
|------|-------|--------|
| `program_metadata` | `ProgramMetadataIn{session_id}` | `ProgramMetadata{sha256, size_bytes, format, architecture, endianness, compiler*?, entry_point?, function_count, analysis_complete}` |

### Semantic-naming support (v1.1 — ADR-007; READ-ONLY, output-only, NEVER mutates the DB)
These drive the client-side workflow of turning Ghidra pseudo-C into well-named, plausibly-
recompilable C. The **client LLM** does the naming + synthesis (no server-side LLM); the server
supplies facts + a leaf-first plan. Graph *extraction* is worker-only (ADR-001); the leaf-first
*ordering* is the **pure server-side core** (`src/vivarium/core/callgraph.py`). Best-effort C —
**compile-rate + behavioral equivalence are MEASURED metrics, NOT guarantees** (ADR-007). All graph
node `name`s and decompiled C stay `Untrusted` (ADR-005). Bounded (`max_nodes ≤ 50000`,
`max_edges ≤ 200000`, `max_depth ≤ 256`) — DoS via huge/deep/cyclic graphs (threat-model TB4).

| Tool | Input | Output |
|------|-------|--------|
| `call_graph` | `CallGraphIn{root?, max_depth, max_nodes, max_edges}` | `CallGraphOut{nodes[{address, name*, is_external, has_unresolved_calls}], edges[{from_address, to_address}], unresolved_callers[], truncated}` |
| `callees` | `CalleesIn{function, offset, limit}` | `CallNeighborsOut{neighbors[], total, unresolved, truncated}` |
| `callers` | `CallersIn{function, offset, limit}` | `CallNeighborsOut{neighbors[], total, unresolved, truncated}` |
| `analysis_order` | `AnalysisOrderIn{root?, max_depth, max_nodes, max_edges}` | `AnalysisOrderOut{components[{members[], is_recursive}], unresolved_callers[], self_recursive[], truncated}` |
| `function_context` | `FunctionContextIn{function, include_decompilation, max_callees, max_callers, max_strings}` | `FunctionContext{address, name*, signature*, is_external, decompilation*?, callees[], callers[], referenced_strings[]*, has_unresolved_calls, truncated}` |

> `analysis_order` returns components in **leaf-first reverse-topological order** (sinks first,
> entry roots last); recursion/mutual-recursion cycles are condensed into one component
> (`is_recursive`); unresolved indirect/virtual edges are surfaced, never dropped. External/
> imported/thunk functions are flagged `is_external` (KNOWN names — do not re-infer). See
> `docs/design/semantic-naming.md`.

### Tier-2 reporting / metrics (v1.1 — ADR-008; READ-ONLY)

| Tool | Input | Output |
|------|-------|--------|
| `cyclomatic_complexity` | `CyclomaticComplexityIn{function}` | `CyclomaticComplexity{address, name*, complexity, block_count, edge_count, incomplete}` |
| `list_imports` | `ListImportsIn{offset, limit}` | `ImportListOut{imports[{name*, library*?, address?}], total, truncated}` |
| `list_exports` | `ListExportsIn{offset, limit}` | `ExportListOut{exports[{name*, address}], total, truncated}` |
| `coverage` | `CoverageIn{}` | `CoverageOut{total_bytes, defined_code_bytes, defined_data_bytes, undefined_bytes, code_ratio, data_ratio, function_count}` |
| `ioc_scan` | `IocScanIn{offset, limit, categories?, min_length}` | `IocScanOut{matches[{category, value*, source_address?}], total, truncated}` |
| `crypto_constant_scan` | `CryptoConstantScanIn{offset, limit}` | `CryptoConstantScanOut{findings[{algorithm, kind, address}], total, truncated}` |
| `call_graph_metrics` | `CallGraphMetricsIn{root?, max_depth, max_nodes, max_edges, top_n}` | `CallGraphMetricsOut{function_count, edge_count, leaf_count, root_count, recursive_component_count, self_recursive_count, unresolved_caller_count, top_fan_in[{address, name*, count}], top_fan_out[…], truncated}` |
| `program_summary` | `ProgramSummaryIn{max_complex_functions, max_iocs, include_call_graph}` | `ProgramSummary{metadata, function_count, import_count, export_count, string_count, coverage?, call_graph_metrics?, top_complex_functions[], ioc_counts[{category, count}], crypto_algorithms[], truncated}` |

> `ioc_scan` and `crypto_constant_scan` are **heuristic triage aids, not authoritative detections**
> (false positives/negatives expected); `cyclomatic_complexity`/`coverage` reflect Ghidra's recovered
> CFG / *defined* bytes, not ground truth (ADR-008). Derivation is pure-core (ADR-001); only raw
> extraction (`function_cfg`/`imports`/`exports`/`coverage`) touches the worker. See
> `docs/design/tier2-metrics.md`.

### Function ID (FID) library-match identification (ADR-042 Phase 1; READ-ONLY)

| Tool | Input | Output |
|------|-------|--------|
| `identify_functions` | `IdentifyFunctionsIn{limit, min_score?}` | `IdentifyFunctionsOut{matches[{address, matched_name*, library*, score}], total, truncated}` |

> A FID match is a **best-effort, possibly-multiple HINT, not an authoritative identity** — one row
> per surviving candidate (a function may match several library candidates above the threshold).
> `min_score` absent ⇒ the worker uses Ghidra's FID default score threshold (fail-safe). The matched
> library function `matched_name` + `library` descriptor are binary-derived → `Untrusted`-wrapped
> (ADR-005); `address`/`score` are safe. Bounded by `limit` (`truncated` honest when more matched);
> read-only (runs the FID service, no DB mutation — ADR-001/ADR-042 Phase 1).

### Mutation / write tools (v1.1 — ADR-012; GATED by per-session write-consent — threat-model TB7)

The first **write** surface. **Default-deny:** a session is read-only until the operator calls
`session_enable_writes` (the single human-in-the-loop consent gate — LLM08); every write then runs
`authorize → require_write_consent → validate → port → audit`. The server **never mutates** — the
write executes only in the worker, inside **one Ghidra transaction** (commit on success, roll back
on failure — ADR-012 §4). Mutations are **session-scoped + ephemeral** (lost on evict, ADR-002).
Attacker-influenced `new_name`/`text` are validated **on the way in** (`validate_write_name`
identifier allow-list / `validate_comment_text` normalization — stored-injection defense, §7).

| Tool | Input | Output | Notes |
|------|-------|--------|-------|
| `session_enable_writes` | `SessionEnableWritesIn{session_id, allow_structural=false}` | `SessionWriteStateOut{session_id, writes_enabled, allow_structural}` | the consent gate; server-side, no worker RPC |
| `session_disable_writes` | `SessionDisableWritesIn{session_id}` | `SessionWriteStateOut` | revoke → read-only; server-side |
| `session_undo` | `SessionUndoIn{session_id}` | `SessionUndoOut{session_id, undone}` | undo last committed mutation txn (requires consent) |
| `rename_function` | `RenameFunctionIn{function, new_name}` | `RenameResult{address, old_name*, new_name, applied}` | transaction-wrapped; `new_name` allow-listed |
| `rename_symbol` | `RenameSymbolIn{identifier, new_name}` | `RenameSymbolResult{address, old_name*, new_name, kind, applied}` | transaction-wrapped |
| `set_comment` | `SetCommentIn{address, comment_type∈{EOL,PRE,POST,PLATE,REPEATABLE}, text?}` | `SetCommentResult{address, comment_type, applied}` | `text=null` clears; text normalized on the way in |
| `rename_local_variable` | `RenameLocalVariableIn{function, variable, new_name}` | `StructuralRenameResult{address, function*, old_name*, new_name, applied}` | **structural** (ADR-013); HighFunction path, name-only; gated by `allow_structural` |
| `rename_parameter` | `RenameParameterIn{function, parameter, new_name}` | `StructuralRenameResult{address, function*, old_name*, new_name, applied}` | **structural**; name-only; gated by `allow_structural` |
| `set_function_signature` | `SetFunctionSignatureIn{function, return_type: TypeRef, parameters: [ParamSpec], calling_convention?}` | `SetFunctionSignatureResult{address, function*, old_signature*, new_signature*, applied}` | **structural** (ADR-014 Phase B); structured input; gated by `allow_structural` |
| `apply_data_type` | `ApplyDataTypeIn{address, type: TypeRef, clear_existing=false}` | `ApplyDataTypeResult{address, type_name*, size, applied}` | **structural** (ADR-014 Phase B); applies an EXISTING/resolvable type; gated by `allow_structural` |
| `define_struct` | `DefineStructIn{name, fields: [FieldSpec], packed=false}` | `DefineStructResult{name, kind, size, field_count, applied}` | **structural** (ADR-015 Phase C); creates a NEW struct; gated by `allow_structural` |
| `define_union` | `DefineUnionIn{name, fields: [FieldSpec]}` | `DefineUnionResult{name, kind, size, field_count, applied}` | **structural** (ADR-015 Phase C); creates a NEW union; gated by `allow_structural` |
| `define_types` | `DefineTypesIn{types: [CompositeSpec]}` | `DefineTypesResult{types: [{name, kind, size, field_count}], applied}` | **structural** (ADR-021); creates a BATCH of interdependent NEW composites in ONE transaction (a field may reference another batch member); GATED by write-consent + `allow_structural`; **by-value cycles rejected, pointer cycles allowed** |
| `delete_type` | `DeleteTypeIn{name}` | `DeleteTypeResult{name, deleted, dependents_reverted}` | **structural** (ADR-031); deletes a composite by name; GATED by write-consent + `allow_structural`; **session-authored ONLY** — only a composite THIS session created (change-log) is deletable, else `not-found` with no worker call (no data-poisoning of Ghidra-recovered/built-in types); deleting an in-use type reverts dependents to undefined and reports the count |

> `CompositeSpec` = `{kind: "struct"\|"union", name, fields: [FieldSpec], packed=false}` (a struct
> honors `offset`/`packed`; a union overlays all members at offset 0 and rejects a member `offset`).
> A `define_types` batch is `1..64` entries (`_MAX_TYPES_PER_BATCH`); a field's `type.named` may
> reference an existing program type, a base type, **self**, or **another composite in the same
> batch**. The boundary runs a **by-value cycle detector**: an edge A→B exists iff A has a member of
> type B (a batch member) with `pointer_levels == 0` (by-value; **array-of-B counts**); ANY by-value
> cycle (incl. self / array-of-self) → `VALIDATION`, no write. A `pointer_levels >= 1` member creates
> **no edge** → mutually-recursive *pointer* structs are allowed. The worker pre-registers ALL empty
> composites in the batch, resolves + adds each, batch-total size-caps, and rolls back the WHOLE batch
> on any failure (no partial type). Name collision (existing or intra-batch dup) → fail-closed REJECT.
> `define_types` **is** the annotation-persistence carrier for composites (ADR-032): export emits ALL
> session-authored composites as ONE `define_types` batch entry (schema v2), so mutually-recursive
> pointer composites round-trip via the import handler's pre-registration. >64 composites →
> `limit-exceeded` on export (the round-trippable graph is bounded).
>
> `TypeRef` = `{base: BaseType|null, named: str|null, pointer_levels: 0..8, array_len: 1..65536|null}`
> (exactly one of `base`/`named`); `ParamSpec` = `{name, type: TypeRef}`; `FieldSpec` =
> `{name, type: TypeRef, offset?}` (struct only; union members are all at offset 0). A `TypeRef` is
> **resolved** against the program's `DataTypeManager` (or the closed `base` vocab) — **never parsed
> from a C string** (ADR-014 §2; the C-parser injection surface is eliminated by construction).
> Unresolvable / out-of-vocab / out-of-bounds → fail closed.
>
> **Structural writes** (`rename_local_variable`/`rename_parameter` — name-only, ADR-013 Phase A;
> `set_function_signature`/`apply_data_type` — structured, ADR-014 Phase B; `define_struct`/
> `define_union` — composite *creation*, ADR-015 Phase C) require, in addition to write consent, the
> `allow_structural` opt-in (`session_enable_writes{allow_structural: true}` →
> `require_write_consent(structural=True)`). Echoed `function`/`old_*`/`type_name` are `Untrusted`
> (binary-derived); the names/types we set + `define_*` results are bare (server/worker-controlled).
> For `define_struct`/`define_union` the empty composite is **pre-registered** so self-`named`
> pointers resolve (true self-referential types); a **by-value self-embed (incl. array-of-self) is
> rejected**, name collisions are fail-closed REJECTED, and a 1 MiB size cap + transactional rollback
> bound the rest (ADR-015 §3). See `docs/adr/ADR-012-mutation-tools.md`,
> `docs/adr/ADR-013-structural-mutation.md`, `docs/adr/ADR-014-structural-mutation-phase-b.md`,
> `docs/adr/ADR-015-composite-type-creation.md`.

### Cross-session annotation persistence (v1.2 — ADR-018; TB8)
| Tool | Input | Output | Notes |
|---|---|---|---|
| `session_export_annotations` | `SessionExportAnnotationsIn{session_id}` | `SessionExportAnnotationsOut{document}` | **read-only** (no consent); owner-scoped; worker enumerates `USER_DEFINED` annotations only, dependency-ordered, bounded (over the cap → `limit-exceeded`); **session-authored composites emit as ONE `define_types` batch entry** so interdependent types round-trip (ADR-032; >64 → `limit-exceeded`); binary-derived strings `Untrusted`-wrapped; server overlays the authoritative `binary.sha256` |
| `session_import_annotations` | `SessionImportAnnotationsIn{session_id, document}` | `SessionImportAnnotationsOut{session_id, total, applied, rejected, outcomes[{index, kind, applied, reason?}]}` | **GATED** (write-consent; `allow_structural` if any entry is structural); document **fully untrusted** → schema-validate → **binary-hash binding verified** → consent → **per-entry re-validate + replay via the EXISTING gated write path** (no new write primitive); per-entry outcome report; server persists nothing |

> The annotation **document** = `{schema_version, binary:{sha256, name?, size?}, entries:[Entry]}`,
> a versioned (**v2**; import accepts {1, 2} — ADR-032), **binary-hash-bound**, dependency-ordered
> (composites/types first, then refs, renames, comments) list of typed `Entry` variants — one per
> existing write tool (`rename_function`/`rename_symbol`/`rename_local_variable`/`rename_parameter`/
> `set_comment`/`set_function_signature`/`apply_data_type`/**`define_types`** (the composite carrier,
> ADR-032)/`define_struct`/`define_union` (the latter two still import for v1 docs)). It is **inert structured
> JSON** (never Ghidra-native — ADR-018 D3). **Export** is the read-out (read-only). **Import** is the
> new trust boundary (TB8): it adds **no new write primitive** — it is a schema-validated, hash-bound,
> consent-gated **batch replay of the existing v1.1 gated writes**, each re-validated through the live
> validators and applied in its own Ghidra transaction (best-effort per entry). Persistence is
> **stateless/client-owned** (the server stores nothing — ADR-002 preserved). Export adds **one** worker
> RPC (`export_annotations`); import reuses the existing write RPCs (no new import RPC). See
> `docs/adr/ADR-018-annotation-persistence.md`.

> **Rename name-collisions (documenting existing behavior — ADR-026 / F5).** `rename_function`
> **duplicate names are permitted and apply** — Ghidra keys functions by entry address, so two
> functions may legitimately share a name (real binaries do — e.g. multiple table-builders). A
> `rename_symbol` colliding with an existing same-namespace symbol **fails closed** (Ghidra
> `DuplicateNameException` → transaction rollback → `analysis-failed`). The server does **not**
> auto-suffix or reject function-name duplicates; **clients that drive many renames should
> de-duplicate/disambiguate proposed names client-side** (the acceptance harness does). No result
> field signals a collision (out of scope — ADR-026 option (a)).

> `*` marks an `Untrusted[...]`-wrapped (binary-derived) field.

## Out of scope / deferred
**`runScript` / arbitrary script execution is permanently out of scope** (PLAN §2) — it is the one
capability deliberately excluded by design, not a pending increment. The full structural mutation arc
has **shipped**: Phase A renames (ADR-013), Phase B signature/type-apply (ADR-014), Phase C composite
*creation* (`define_struct`/`define_union`, ADR-015), the multi-type interdependent batch
(`define_types` with its by-value cycle detector, ADR-021), and `delete_type` (ADR-031) — all in the
Mutation section above. Adding any *new* tool is a reviewed, gated change to this fixed allow-list
(ADR-006 extensibility seam).
