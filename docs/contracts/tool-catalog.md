# Contract: Tier-1 Read-Only Tool Catalog (FROZEN — WS0)

> Pydantic source of truth: [`src/ghidra_mcp/tools/schemas.py`](../../src/ghidra_mcp/tools/schemas.py).
> Allow-list registry: [`src/ghidra_mcp/tools/registry.py`](../../src/ghidra_mcp/tools/registry.py).
> **Read-only in v1** — no mutation tools, no `runScript`, no dynamic tool surface (PLAN §2).

## Conventions (apply to every tool)

- **Allow-list only:** the catalog is fixed; there are exactly **27** tools (asserted in tests) —
  22 Tier-1 read-only (v1) + 5 v1.1 semantic-naming support tools (ADR-007, also read-only).
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

> `*` marks an `Untrusted[...]`-wrapped (binary-derived) field.

## Deferred (NOT yet built — gated, reviewed catalog additions)
Tier-2 reporting/metrics (complexity, coverage, imports/exports, IOC/crypto scans, call-graph
*metrics*, program-summary), **mutation tools (gated)**, and `runScript` remain deferred. (The
semantic-naming *support* tools above — call graph adjacency, leaf-first order, function context —
are delivered in v1.1 per ADR-007; they are read-only and distinct from Tier-2 call-graph
*metrics*.) Adding any deferred tool is a reviewed,
gated change to this allow-list (ADR-006 extensibility seam).
