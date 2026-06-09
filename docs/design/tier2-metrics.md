# Design: Tier-2 reporting & metrics tools (v1.1)

> Status: implemented (v1.1). Implements ADR-008. Read-only, output-only, no new trust
> boundary. Derivation is JVM-free (pure core); only raw extraction touches the worker (ADR-001).
> Every binary-derived field is `Untrusted[...]`-wrapped at the `core.envelope.wrap` chokepoint
> (ADR-005). All outputs are bounded (DoS — std-cwe CWE-400).

## 1. Tools (pydantic source of truth: `tools/schemas.py`)

| Tool | Input | Output | Compute |
|------|-------|--------|---------|
| `cyclomatic_complexity` | `CyclomaticComplexityIn{function}` | `CyclomaticComplexity{address, name*, complexity, block_count, edge_count, incomplete}` | worker `function_cfg` → **pure** `E−N+2` |
| `list_imports` | `ListImportsIn{offset, limit}` | `ImportListOut{imports[{name*, library*?, address?}], total, truncated}` | worker `imports` |
| `list_exports` | `ListExportsIn{offset, limit}` | `ExportListOut{exports[{name*, address}], total, truncated}` | worker `exports` |
| `coverage` | `CoverageIn{}` | `CoverageOut{total_bytes, defined_code_bytes, defined_data_bytes, undefined_bytes, code_ratio, data_ratio, function_count}` | worker `coverage` → **pure** ratios |
| `ioc_scan` | `IocScanIn{offset, limit, categories?, min_length}` | `IocScanOut{matches[{category, value*, source_address?}], total, truncated}` | **pure** over `list_strings` (existing RPC) |
| `crypto_constant_scan` | `CryptoConstantScanIn{offset, limit}` | `CryptoConstantScanOut{findings[{algorithm, kind, address}], total, truncated}` | **pure** over `search_bytes` (existing RPC) |
| `call_graph_metrics` | `CallGraphMetricsIn{root?, max_depth, max_nodes, max_edges, top_n}` | `CallGraphMetricsOut{function_count, edge_count, leaf_count, root_count, recursive_component_count, self_recursive_count, unresolved_caller_count, top_fan_in[{address, name*, count}], top_fan_out[…], truncated}` | **pure** over `call_graph` (ADR-007 RPC + `core.callgraph`) |
| `program_summary` | `ProgramSummaryIn{max_iocs, max_complex_functions, include_call_graph}` | `ProgramSummary{metadata, function_count, import_count, export_count, string_count, coverage?, call_graph_metrics?, top_complex_functions[], ioc_counts[{category, count}], crypto_algorithms[]*, truncated}` | **server aggregation** |

`*` = `Untrusted[...]` (binary-derived). Addresses (server-normalized), counts, ratios, categories,
and algorithm labels (closed vocabulary) are bare.

## 2. Pure cores (JVM-free, 100%-tested — `src/ghidra_mcp/core/`)

### `core/metrics.py`
- `cyclomatic_complexity(block_count, edge_count) -> int` — McCabe `M = E − N + 2` for a single
  connected procedure (P=1); clamped to `≥ 1` (a straight-line function is 1). Pure arithmetic over
  the worker-extracted CFG counts.
- `compute_call_graph_metrics(adjacency, unresolved, *, top_n) -> CallGraphMetricsResult` — over the
  resolved adjacency (`caller → [callees]`): fan-out per node = len(callees); fan-in = reverse
  in-degree; `leaf_count` (fan-out 0), `root_count` (fan-in 0); `top_fan_in`/`top_fan_out` (top-N,
  deterministic tie-break by address); reuses `core.callgraph.compute_analysis_order` for
  `recursive_component_count` / `self_recursive_count`. No JVM, iterative, size-robust.

### `core/iocscan.py`
- `scan_iocs(strings, *, categories, min_length) -> list[IocHit]` — anchored, bounded regexes per
  category over `(address, value)` string rows: `ipv4`, `ipv6`, `url`, `domain`, `email`, `md5`,
  `sha1`, `sha256`, `windows_path`, `unc_path`. Returns `(category, value, source_address)`; dedups
  by (category, value). **Heuristic** (ADR-008 caveat). ReDoS-safe (no catastrophic backtracking;
  linear patterns, capped input length).
- `CRYPTO_SIGNATURES` + `scan_crypto_constants(matches) -> list[CryptoHit]` — maps each known
  constant byte-pattern (AES forward S-box prefix, SHA-256/SHA-512/MD5/SHA-1 init vectors, common
  magics) to `(algorithm, kind)`; the *byte search* itself is delegated to the worker `search_bytes`
  RPC (existing), this core owns the signature table + result shaping. **Heuristic.**

## 3. Worker extraction (worker-only, JVM — ADR-001). New RPC methods: 4.

| Worker RPC | Returns (plain) | Ghidra |
|---|---|---|
| `function_cfg` | `{address, name, block_count, edge_count, incomplete}` | BasicBlockModel over one function (count blocks + CFG edges; `incomplete` if unresolved flow) |
| `imports` | `{imports:[{name, library?, address?}], total, truncated}` | ExternalManager / SymbolTable external symbols |
| `exports` | `{exports:[{name, address}], total, truncated}` | SymbolTable external entry points / exported symbols |
| `coverage` | `{total_bytes, defined_code_bytes, defined_data_bytes, function_count}` | Listing: sum instruction vs defined-data vs total addresses |

`ioc_scan`, `crypto_constant_scan`, `call_graph_metrics` add **no** worker RPC — they compose the
existing `list_strings`, `search_bytes`, and `call_graph` RPCs server-side.

## 4. `program_summary` (server-side aggregation, no naming/no synthesis)

Composes, all bounded: `program_metadata` + `list_functions`(total) + `list_imports`/`list_exports`
(totals) + `list_strings`(total) + `coverage` + `call_graph_metrics` (if `include_call_graph`) +
the top-`max_complex_functions` by `cyclomatic_complexity` + an `ioc_scan` summary (counts per
category, capped at `max_iocs` scanned) + `crypto_constant_scan` algorithm set. Every binary-derived
field wrapped (ADR-005). A one-shot triage report; the heavy lists stay in the dedicated tools.

## 5. Bounds / DoS caps (enforced at the tool boundary, before the worker)

- list tools: `offset` + `limit ≤ 10 000` (`_Page`).
- `ioc_scan`: scans a bounded page of strings (`limit`), each truncated to a max length before regex
  (ReDoS/`std-cwe` CWE-400); `truncated` if more strings exist.
- `crypto_constant_scan`: bounded number of signature searches, each via the already-bounded
  `search_bytes`; `truncated` on cap.
- `call_graph_metrics`: inherits ADR-007 `max_nodes ≤ 50k` / `max_edges ≤ 200k` / `max_depth ≤ 256`.
- `cyclomatic_complexity`: single function; worker caps block/edge enumeration.
- `program_summary`: `max_iocs`/`max_complex_functions ≤ 1024`; `include_call_graph` default true.

## 6. Module / boundary map

| Concern | Location | JVM? |
|---|---|---|
| Tool schemas (frozen In/Out) | `src/ghidra_mcp/tools/schemas.py` | no |
| Tool handlers (authorize → validate → delegate) | `src/ghidra_mcp/tools/registry.py` | no |
| **Complexity + call-graph metrics (pure)** | `src/ghidra_mcp/core/metrics.py` | **no** |
| **IOC + crypto-signature scan (pure)** | `src/ghidra_mcp/core/iocscan.py` | **no** |
| Adapter: compose RPCs + wrap + invoke cores | `src/ghidra_mcp/ghidra/rpc_client.py` | no |
| Port interface | `src/ghidra_mcp/ghidra/port.py` | no |
| Worker RPC methods (allow-list + dispatch) | `worker/dispatch.py` (`function_cfg`, `imports`, `exports`, `coverage`) | no |
| **CFG / imports / exports / coverage extraction** | `src/ghidra_mcp/ghidra/_jvm_bridge.py` | **yes — worker only** |

## References
- ADR-008 (decision), ADR-001 (out-of-process), ADR-005 (untrusted envelope), ADR-006 (catalog seam),
  ADR-007 (call-graph core reused by `call_graph_metrics`). McCabe (1976) cyclomatic complexity.
  `docs/contracts/tool-catalog.md`, `docs/security/threat-model.md`.
