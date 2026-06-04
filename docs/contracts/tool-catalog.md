# Contract: Tier-1 Read-Only Tool Catalog (FROZEN — WS0)

> Pydantic source of truth: [`src/ghidra_mcp/tools/schemas.py`](../../src/ghidra_mcp/tools/schemas.py).
> Allow-list registry: [`src/ghidra_mcp/tools/registry.py`](../../src/ghidra_mcp/tools/registry.py).
> **Read-only in v1** — no mutation tools, no `runScript`, no dynamic tool surface (PLAN §2).

## Conventions (apply to every tool)

- **Allow-list only:** the catalog is fixed; there are exactly **22** tools (asserted in tests).
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

> `*` marks an `Untrusted[...]`-wrapped (binary-derived) field.

## Deferred (NOT in v1 — do not build)
Tier-2 reporting/metrics (complexity, coverage, imports/exports, IOC/crypto scans, call-graph
metrics, program-summary), mutation tools, and `runScript` are v1.1. Adding any is a reviewed,
gated change to this allow-list (ADR-006 extensibility seam).
