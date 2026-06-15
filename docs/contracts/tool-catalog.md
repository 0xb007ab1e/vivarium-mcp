# Contract: Tier-1 Read-Only Tool Catalog (FROZEN — WS0)

> Pydantic source of truth: [`src/ghidra_mcp/tools/schemas.py`](../../src/ghidra_mcp/tools/schemas.py).
> Allow-list registry: [`src/ghidra_mcp/tools/registry.py`](../../src/ghidra_mcp/tools/registry.py).
> **Read-only in v1** — no mutation tools, no `runScript`, no dynamic tool surface (PLAN §2).

## Conventions (apply to every tool)

- **Allow-list only:** the catalog is fixed; there are exactly **50** tools (asserted in tests) —
  22 Tier-1 read-only (v1) + 5 v1.1 semantic-naming support tools (ADR-007) + 8 v1.1 Tier-2
  reporting/metrics tools (ADR-008; all read-only) + **6 v1.1 mutation/write tools (ADR-012) + 6
  v1.1 structural-write tools (ADR-013 Phase A + ADR-014 Phase B + ADR-015 Phase C)** + **2 v1.2
  annotation-persistence tools (ADR-018: `session_export_annotations` read-only +
  `session_import_annotations` GATED)** — the 12 mutation tools GATED by per-session write-consent
  (structural additionally by `allow_structural`); import is GATED identically (and additionally by
  `allow_structural` when any imported entry is structural).
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
| `session_import` | `SessionImportIn{source_ref, expected_sha256?}` | `SessionInfo` | size cap enforced **before** Ghidra; digest verified; path confined |
| `session_analyze` | `SessionAnalyzeIn{timeout_seconds?}` | `SessionInfo` | bounded by analysis timeout → kills worker on expiry |
| `session_status` | `_SessionScopedIn{session_id}` | `SessionInfo` | state/TTL; no binary content |
| `session_close` | `SessionCloseIn{session_id}` | `SessionCloseOut{store_wiped}` | kill worker + **verified wipe** (ADR-002) |

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
*ordering* is the **pure server-side core** (`src/ghidra_mcp/core/callgraph.py`). Best-effort C —
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
> `define_types` is NOT (yet) an annotation-persistence entry variant — round-trip of mutually-
> recursive pointer composites is a tracked follow-up (ADR-021 §Persistence interaction).
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
| `session_export_annotations` | `SessionExportAnnotationsIn{session_id}` | `SessionExportAnnotationsOut{document}` | **read-only** (no consent); owner-scoped; worker enumerates `USER_DEFINED` annotations only, dependency-ordered, bounded (over the cap → `limit-exceeded`); binary-derived strings `Untrusted`-wrapped; server overlays the authoritative `binary.sha256` |
| `session_import_annotations` | `SessionImportAnnotationsIn{session_id, document}` | `SessionImportAnnotationsOut{session_id, total, applied, rejected, outcomes[{index, kind, applied, reason?}]}` | **GATED** (write-consent; `allow_structural` if any entry is structural); document **fully untrusted** → schema-validate → **binary-hash binding verified** → consent → **per-entry re-validate + replay via the EXISTING gated write path** (no new write primitive); per-entry outcome report; server persists nothing |

> The annotation **document** = `{schema_version, binary:{sha256, name?, size?}, entries:[Entry]}`,
> a versioned, **binary-hash-bound**, dependency-ordered (composites/types first, then refs, renames,
> comments) list of typed `Entry` variants — one per existing write tool
> (`rename_function`/`rename_symbol`/`rename_local_variable`/`rename_parameter`/`set_comment`/
> `set_function_signature`/`apply_data_type`/`define_struct`/`define_union`). It is **inert structured
> JSON** (never Ghidra-native — ADR-018 D3). **Export** is the read-out (read-only). **Import** is the
> new trust boundary (TB8): it adds **no new write primitive** — it is a schema-validated, hash-bound,
> consent-gated **batch replay of the existing v1.1 gated writes**, each re-validated through the live
> validators and applied in its own Ghidra transaction (best-effort per entry). Persistence is
> **stateless/client-owned** (the server stores nothing — ADR-002 preserved). Export adds **one** worker
> RPC (`export_annotations`); import reuses the existing write RPCs (no new import RPC). See
> `docs/adr/ADR-018-annotation-persistence.md`.

> `*` marks an `Untrusted[...]`-wrapped (binary-derived) field.

## Deferred (NOT yet built — gated, reviewed catalog additions)
**Nested-define / multi-type batches** (defining several interdependent composites in one call — which
would require a real by-value cycle detector, ADR-015 §3) and `runScript`/arbitrary script execution
remain deferred, each a separate, separately-threat-modeled increment (`runScript` is permanently out
of scope, PLAN §2). Adding any deferred tool is a reviewed, gated change to this allow-list (ADR-006
extensibility seam). The full structural mutation arc — Phase A renames, Phase B signature/type-apply,
Phase C composite *creation* (`define_struct`/`define_union`) — has shipped; see the Mutation section
above.
