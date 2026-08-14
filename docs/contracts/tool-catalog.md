# Contract: Tier-1 Tool Catalog (FROZEN — WS0)

> Pydantic source of truth: [`src/vivarium/tools/schemas.py`](../../src/vivarium/tools/schemas.py).
> Allow-list registry: [`src/vivarium/tools/registry.py`](../../src/vivarium/tools/registry.py).
> **Read-by-default.** 53 of the 69 tools are read-only; the **16 mutation/write tools** below are
> **default-deny**, gated by per-session write-consent (`session_enable_writes`) — structural writes
> additionally by `allow_structural`. **`runScript`/arbitrary script execution is permanently out of
> scope** (PLAN §2), and the tool surface is a **fixed allow-list** (no dynamic registration).

## Conventions (apply to every tool)

- **Allow-list only:** the catalog is fixed; there are exactly **69** tools (asserted in tests by
  `len(TIER1_TOOL_NAMES) == 69`). The breakdown:
  22 Tier-1 read-only (v1) + **1 p-code emulation tool (ADR-049: `emulate`; read-effect-only)** +
  **1 p-code listing tool (ADR-052: `get_pcode`; read-only)** +
  **1 high (SSA) p-code tool (ADR-053: `get_high_pcode`; read-only)** +
  **1 stack-frame tool (ADR-054: `stack_frame`; read-only)** +
  **1 basic-block CFG tool (ADR-055: `basic_blocks`; read-only)** +
  **1 data-type listing tool (ADR-056: `list_data_types`; read-only)** +
  **1 function match-hash tool (ADR-057: `function_hash`; read-only)** +
  **1 BSim similarity tool (ADR-058: `bsim_similarity`; read-only)** +
  **1 whole-program BSim find-similar tool (ADR-059: `find_similar_functions`; read-only)** +
  **1 two-program Version Tracking tool (ADR-060: `version_track`; read-only w.r.t. the session)** +
  **1 cross-binary BSim corpus search tool (ADR-062: `bsim_search_corpus`; read-only w.r.t. the session)** +
  **1 C++ demangler tool (ADR-050: `demangle`; read-only, program-independent)** +
  5 v1.1 semantic-naming support tools (ADR-007) + 8 v1.1 Tier-2
  reporting/metrics tools (ADR-008; all read-only) + **1 Function ID library-match tool (ADR-042
  Phase 1: `identify_functions`; read-only)** + **6 v1.1 mutation/write tools (ADR-012) + 9
  structural-write tools (ADR-013 Phase A + ADR-014 Phase B + ADR-015 Phase C + ADR-021 batch
  `define_types` + ADR-031 `delete_type` + ADR-051 `apply_type_archive`)** + **4 v1.x
  streaming-extraction tools (ADR-040: `start_decompile_stream` + the generic
  `fetch_job_results`/`job_status`/`cancel_job`; read-only, output-only)** + **2 v1.2
  annotation-persistence tools (ADR-018: `session_export_annotations` read-only +
  `session_import_annotations` GATED)** — plus **1 data-flow slicing tool (ADR-064:
  `data_flow_slice`; read-only)** — plus **1 struct-recovery tool (ADR-069: `recover_struct`;
  read-only, propose-only)** — plus **1 firmware-secret scan tool (ADR-072: `secret_scan`;
  read-only, heuristic, REDACTED)**. That is **56 read-only + 16 mutation/write** (the 16 = the 6
  ADR-012 write tools + the 9 structural-write tools + the gated `session_import_annotations`; it
  matches the `WRITE_TOOLS` frozenset in `registry.py`).
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
| `session_import` | `SessionImportIn{source_ref, expected_sha256?, loader?, processor?, base_addr?, entry?, pdb_ref?}` | `SessionInfo` | size cap enforced **before** Ghidra; digest verified; path confined (`source_ref` is a path under `VIVARIUM_IMPORT_ROOT`). **Loader hints (ADR-045, F1) are additive + opt-in:** `loader` (`auto`/`binary`, default `auto`) — `auto` drives the opinion/container loaders (ELF/PE) **byte-for-byte as before**; `binary` drives `BinaryLoader` for a **headerless raw/firmware image** and REQUIRES `processor` (a Ghidra `LanguageID` in the allow-list `vivarium.core.languages` — the full installed set, e.g. `ARM:LE:32:Cortex`, `x86:LE:64:default`, `MIPS:BE:32:default`, `RISCV:LE:32:default`) + `base_addr` (image base, bounded to the processor's address width); optional `entry` (entry-point seed, `>= base_addr`). **Hex loaders (ADR-046):** `intel-hex`/`motorola-hex` drive `IntelHexLoader`/`MotorolaHexLoader` for hex-delivered firmware — REQUIRE `processor` only; `base_addr`/`entry` are rejected (the records carry their own addresses). **Self-describing (ADR-047):** `dex`/`macho`/`apk` force `DexLoader`/`MachoLoader`/`ApkLoader` for Android DEX / Mach-O / APK — NO hints allowed (the format carries processor + layout; `auto` also detects these). **Fat-Mach-O slice (ADR-048):** an optional allow-listed `processor` on `loader="macho"` selects that arch slice (via the `program_loader` builder); omit for the default slice. DYLD-component selection is fixture-blocked (deferred). **Companion PDB (ADR-061):** an optional `pdb_ref` (a second confined + size-capped path under `VIVARIUM_IMPORT_ROOT`, `loader="auto"` only) applies a Microsoft PDB's symbols/types to the freshly-loaded PE **before** analysis (Ghidra's cross-platform `pdb2` reader → `DefaultPdbApplicator.applyNoAnalysisState`); a hostile/malformed PDB fails closed `not-found`. Not a write tool (applied at load, no write-consent). **Companion debug map (ADR-071):** an optional `debug_ref` + `debug_format="map"` (a second confined + size-capped path, `loader="auto"` only, mutually exclusive with `pdb_ref`) applies a detached name→address symbol map (linker/`nm`/`.sym` dump) as `IMPORTED` labels to the freshly-loaded ELF **before** analysis; a malformed map fails closed `not-found`, out-of-space addresses are skipped honestly. Not a write tool (applied at load). `debug_format="dwarf"` (detached DWARF) is a tracked follow-up — the schema does not yet accept it. **Multi-region scatter-load (ADR-065):** an optional `regions` list (≤64) drives a headerless raw import into ONE program with N memory blocks — each region `{source_ref | offset+length, base_addr, entry?}` supplies its bytes (its own confined ref, OR a slice of the parent `source_ref`) at its `base_addr`. REQUIRES `loader="binary"` + one shared `processor` (all blocks share the Language — a differing arch is a separate session, ADR-065 D5); mutually exclusive with the top-level single-region `base_addr`/`entry`. Every region is confined + size-capped **before the worker** (per-region CWE-22/CWE-400); overlapping address ranges are rejected server-side (D2). Absent ⇒ byte-for-byte the single-region path. Hints are validated **server-side before the worker** (allow-list + width bounds, CWE-20); the worker re-validates the language against the installed set (defense in depth) and fails closed `not-found`. No hint set ⇒ byte-for-byte the pre-ADR-045 path |
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
| `get_pcode` | `GetPcodeIn{start?, function?, max_instructions≤10000}` | `GetPcodeOut{instructions[]{address, mnemonic*, pcode[]*}, truncated}` | **ADR-052** p-code (IR) listing (read-only). Lifts each instruction to its raw low p-code ops (`Instruction.getPcode()`) — the SAME IR `emulate` interprets — WITHOUT executing anything; program DB untouched. Bounded like `disassemble` (+ a per-instruction op cap). `mnemonic` + each `pcode` op are `*`=UNTRUSTED (Ghidra-lifted) |
| `get_high_pcode` | `GetHighPcodeIn{function, max_ops≤10000}` | `GetHighPcodeOut{ops[]{address, op*}, truncated}` | **ADR-053** high (SSA) p-code (read-only). Decompiles the function and returns its REFINED IR (`HighFunction.getPcodeOps()`) — SSA + dead-code-eliminated + constant-folded (e.g. `mov eax,5; add eax,3` → a single `COPY 0x8`). Between `get_pcode` (raw IR) and `decompile_function` (C). Read-only; decompiler disposed per call. Each `op` is `*`=UNTRUSTED (decompiler-derived) |
| `data_flow_slice` | `DataFlowSliceIn{function, seed(addr), direction=backward\|forward, max_nodes≤10000, max_depth≤10000}` | `DataFlowSliceOut{seed, direction, nodes[]{address, pcode_op*, role=def\|use\|boundary}, truncated}` | **ADR-064** bounded intra-function def-use slice (read-only). Decompiles to the SSA `HighFunction` and walks the def-use graph from the p-code op at `seed`: `backward`=defs feeding it (provenance), `forward`=uses it feeds. Intra-function — an undefined input (param/constant) is a `boundary` node, never followed across the edge. Bounded by `max_nodes`/`max_depth`; `truncated` honest. Each `pcode_op` is `*`=UNTRUSTED (decompiler-derived) |
| `recover_struct` | `RecoverStructIn{function, base(name\|addr), max_fields≤10000, max_accesses≤10000}` | `RecoverStructOut{base, fields[]{offset, size, inferred_type*, access=load\|store\|addr, confidence=observed}, total_span, truncated}` | **ADR-069** propose a struct layout from access patterns (read-only, **propose-only**). Decompiles to the SSA `HighFunction` and walks the accesses off the `base` pointer (pointer arithmetic `PTRSUB`/`PTRADD`/`INT_ADD` + `LOAD`/`STORE`, unioned across all SSA instances) — one field per observed access. **Never writes** — materializing a proposal goes through the gated `define_struct`/`apply_data_type`. Intra-function; overlapping/conflicting accesses reported as-observed. Bounded by `max_fields`/`max_accesses`; `truncated` honest. `inferred_type` is `*`=UNTRUSTED (decompiler-derived); offsets/sizes are safe scalars |
| `stack_frame` | `StackFrameIn{function}` | `StackFrameOut{frame_size, variables[]{name*, stack_offset, data_type*, size, is_parameter}}` | **ADR-054** recovered stack layout (read-only). Reads `Function.getStackFrame()` — the locals + stack parameters the Stack analyzer populated during auto-analysis (offset, name, type, size). An un-analyzed function returns an empty list (not an error — `session_analyze` first). `name` + `data_type` are `*`=UNTRUSTED (Ghidra/binary-derived); offsets/sizes are safe scalars |
| `basic_blocks` | `BasicBlocksIn{function, max_blocks≤10000}` | `BasicBlocksOut{blocks[]{address, end_address, size, successors[]}, truncated}` | **ADR-055** control-flow graph (read-only). Walks `BasicBlockModel` over the function and returns each basic block's address range + intraprocedural successor edges (the CFG STRUCTURE — vs `cyclomatic_complexity`, which returns only counts). All fields are server-normalized addresses/counts — nothing untrusted (no instruction text) |
| `function_hash` | `FunctionHashIn{function}` | `FunctionHashOut{address, exact_bytes, exact_instructions, exact_mnemonics, instruction_count}` | **ADR-057** function match-hashes (read-only). Ghidra's OWN function hashers (behind its function-match/diff): `exact_bytes` (identical code+operands), `exact_instructions` (OPERANDS MASKED — matches relocated/recompiled clones), `exact_mnemonics` (mnemonic sequence). Two functions sharing a hash are duplicates at that granularity — find statically-linked lib copies / repeated routines. Hashes are opaque decimal-string equality tokens; all fields SAFE |
| `bsim_similarity` | `BsimSimilarityIn{function_a, function_b}` | `BsimSimilarityOut{address_a, address_b, similarity}` | **ADR-058** BSim FUZZY similarity (read-only). Generates each function's BSim feature signature (`GenSignatures` + the bundled `medium_32/64` weights) and returns their cosine `similarity` in `[0,1]` (1.0 = identical) — the *continuous* counterpart to `function_hash`'s exact match, for near-duplicates / variant routines. Decompiles both functions but does NOT mutate; bounded to two functions. All fields SAFE (addresses + a computed score) |
| `find_similar_functions` | `FindSimilarFunctionsIn{function, min_similarity=0.7, limit=20, max_scan=500}` | `FindSimilarFunctionsOut{target_address, matches[]{address, name*, similarity}, functions_scanned, truncated}` | **ADR-059** whole-program BSim clone/variant search (read-only). One `GenSignatures` scan of the target + up to `max_scan` functions, ranked by cosine similarity ≥ `min_similarity` (top `limit`). Built on `bsim_similarity`. Decompiles each scanned function (cost ∝ `max_scan`, wall-clock-bounded) but does NOT mutate. Only each match `name` is `*`=UNTRUSTED; addresses/score/counts are SAFE |
| `version_track` | `VersionTrackIn{source_ref_a, source_ref_b, correlator=exact_instructions, min_confidence=0.0, limit=100}` | `VersionTrackOut{matches[]{source_address, destination_address, similarity, confidence}, match_count, truncated}` | **ADR-060** two-program Version Tracking (read-only w.r.t. the session). Loads BOTH refs FRESH in the session's worker (the session's own program is NOT a participant — untouched), auto-analyzes both, runs the chosen (closed allow-list: `exact_instructions`/`exact_bytes`/`exact_mnemonics`/`duplicate_function`) VT correlator over their loaded+initialized address sets, returns function matches filtered by `min_confidence` (log-scale) sorted high-to-low (top `limit`), then RELEASES + WIPES both programs. Both refs confined + size-capped server-side (CWE-22/CWE-400); gated like `session_import` (capability), NOT write-consent (no session mutation). All fields SAFE (addresses + computed scores) |
| `bsim_search_corpus` | `BsimSearchCorpusIn{target_ref, reference_refs[1..16], min_similarity=0.7, limit=100, max_scan=500}` | `BsimSearchCorpusOut{matches[]{target_address, target_name*, reference_index, reference_address, reference_name*, similarity}, target_functions_scanned, corpus_functions_scanned, truncated}` | **ADR-062** cross-binary BSim search over an EPHEMERAL corpus (read-only w.r.t. the session). Loads the target + a bounded (≤16) reference corpus FRESH in the session's worker one at a time (BSim vectors survive each program's release — memory bounded), BSim-signs each with the target's `medium_NN` weights, and returns each target function's best reference match at cosine similarity ≥ `min_similarity` (top `limit`), then WIPES everything. **No persistent DB** (ADR-062 D0; stateless mandate ADR-002 intact) — the corpus is exactly `reference_refs`. References of a different address size than the target are skipped (D3). All refs confined + size-capped server-side (CWE-22/CWE-400); gated like `session_import` (capability), NOT write-consent. Only match `*`=names are UNTRUSTED; addresses/index/score/counts SAFE |
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
| `list_data_types` | `ListDataTypesIn{offset, limit, name_contains?}` | `DataTypeListOut{data_types[]{name*, kind, size}, total, truncated}` | **ADR-056** the list-counterpart to `get_data_type` (read-only). Enumerates the program `DataTypeManager` — the types established in THIS session (defined via `define_struct`/`define_types`, applied via `apply_data_type`/`apply_type_archive`, or analysis-added); a fresh program's manager is empty. Lightweight summary rows (no rendered definition — fetch that per type via `get_data_type`). `name` is `*`=UNTRUSTED; kind/size are safe |

### Comments (read-only)
| Tool | Input | Output |
|------|-------|--------|
| `get_comments` | `GetCommentsIn{offset, limit, address?}` | `CommentListOut{comments[], total, truncated}` |

### Memory / bytes / search
| Tool | Input | Output |
|------|-------|--------|
| `memory_map` | `MemoryMapIn{session_id}` | `MemoryMapOut{blocks[]}` |
| `read_bytes` | `ReadBytesIn{address, length≤1 MiB}` | `ReadBytesOut{address, data* (hex), length, truncated}` |
| `emulate` | `EmulateIn{start, set_registers?, write_memory?, max_steps≤1M, stop_at?, read_registers?, read_memory?}` | `EmulateOut{steps_executed, stop_reason, registers[]{name, value*}, memory[]{address, data*, length}}` | **ADR-049 p-code emulation** (read-effect-only). Ghidra's p-code **interpreter** — NO native execution / syscalls / I/O; program DB not mutated. Bounded by `max_steps` (server-clamped, default 100k) + the per-call wall-clock kill + worker memory cap. Register/memory readback VALUES are `*`=UNTRUSTED (attacker-influenced). All parsing/emulation stays in the ephemeral worker container |
| `demangle` | `DemangleIn{mangled≤8KiB, scheme=auto\|gnu\|msvc}` | `DemangleOut{demangled*?, scheme?}` | **ADR-050 C++ demangler** (read-only, program-independent). Resolves a mangled symbol via Ghidra's GNU/Itanium + MSVC demanglers (`auto` tries both). The mangled string is HOSTILE binary-derived input — length-bounded (DoS guard) + the worker wall-clock kill backs it. `demangled` `*`=UNTRUSTED; `None` if not a mangled name in a tried scheme (non-mangled input is not an error). No program is loaded or mutated |
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
| `secret_scan` | `SecretScanIn{offset, limit, categories?, min_length, entropy_threshold}` | `SecretScanOut{findings[{address?, category, pattern_id, masked_preview*, preview_hash, entropy?}], total, truncated}` | **ADR-072** firmware-secret scan (read-only, heuristic, **REDACTED**). Pure core over `list_strings` (like `ioc_scan`) — flags `hardcoded_credential` (keyword-adjacent + high-entropy blob), `key_material` (PEM/OpenSSH/PGP headers), `format_magic` (bootloader/container magic), `property_secret_name` (secret-implying key names, the T19 `WIFI_PWD` case). **Never emits the raw secret** (ADR-072 D3): `masked_preview` masks the middle (`*`=UNTRUSTED), `preview_hash` is a salted 12-hex correlation handle; server logs carry only address/category/pattern_id/hash. HEURISTIC — leads, not proof |
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
| `apply_type_archive` | `ApplyTypeArchiveIn{archive: generic_clib\|generic_clib_64\|windows_vs12_32\|windows_vs12_64\|mac_osx}` | `ApplyTypeArchiveResult{archive, functions_updated, applied}` | **structural** (ADR-051); applies a BUNDLED Ghidra type-archive's function signatures to same-named functions (resolves libc/Win32 API prototypes). `archive` is a CLOSED allow-list — the worker maps it to a `.gdt` in the pinned install; NO client path (CWE-22). One transaction (`session_undo` reverts). All result fields SAFE. Gated by `allow_structural` |
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
