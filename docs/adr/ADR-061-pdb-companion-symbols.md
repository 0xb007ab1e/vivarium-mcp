# ADR-061: PDB companion symbols — apply a Microsoft PDB at import (`session_import` `pdb_ref`)

- **Status:** **Accepted + Implemented** (2026-08-13). Feasibility was grounded live BEFORE any design
  commitment (both the hermetic fixture path and the headless Ghidra apply API), then built.
- **Date:** 2026-08-13
- **Deciders:** Human operator (picked PDB as the next v1.8 bucket item); assistant grounded the
  feasibility end-to-end and chose the companion-at-import shape.

## Context

Microsoft **PDB** (Program Database) files carry the debug symbols + types for a Windows PE (function
names, parameters, structs). A stripped PE analyzed without its PDB is far less legible; applying the
PDB recovers the real names/types. This is the standard Windows-RE workflow and the natural next item
in the v1.8 bucket after the loader-coverage work (ADR-045…048) and the two-program tools (ADR-058…060).

A PDB is **not a loader** — it is **supplemental symbol/type data applied to an already-loaded PE**.
So it does not fit the ADR-045 loader-hint `loader=` switch; it is a *second companion file* paired
with the primary binary. This ADR decides how that second file enters Vivarium without abandoning the
single-program session model or the containment guarantees, and enumerates the new trust surface (a
second hostile file — the **PDB parser** — in the worker) for the threat-model delta.

## Feasibility — grounded live BEFORE design (2026-08-13)

Both legs were proven in the pinned worker before writing this ADR (the VT-style discipline):

- **Hermetic fixture, no Windows SDK.** `clang --target=x86_64-pc-windows-msvc -c -gcodeview` +
  `lld-link /debug /nodefaultlib /entry:mainCRTStartup` (LLVM 19) produces a tiny **PE32+ (~2.5 KB) +
  a real MSVC PDB v7.00 (~60 KB)** with a matching CodeView GUID/age in the PE debug directory — fully
  deterministic, no MSVC toolchain / SDK required. gzip+base64 the pair is ~0.5 KB + ~1.3 KB (the PDB
  is mostly zero-padding), so it **embeds** in the live test (no in-container toolchain).
- **Headless Ghidra apply (pure Java, works on Linux).** Ghidra's `pdb2` reader + applicator:
  `PdbParser.parse(path, PdbReaderOptions(), monitor)` → `pdb.deserialize()` →
  `new DefaultPdbApplicator(pdb, program, program.getDataTypeManager(), program.getImageBase(),
  PdbApplicatorOptions(), monitor, MessageLog())` inside a transaction → **`applyNoAnalysisState()`**
  (the headless method — `applyDataTypesAndMainSymbolsAnalysis()` needs an *active analysis session*
  and throws "No active analysis session" outside one). Grounded end-to-end: loading the fixture PE and
  applying its PDB landed the real C function names (`the_answer` / `helper_routine` / `mainCRTStartup`)
  as program symbols (symbol count 8 → 10). The native `os/win_x86_64/pdb.exe` path is **not** used
  (Windows-only); only the cross-platform Java reader.

## Decision

### D1 — A `pdb_ref` companion on `session_import` (NOT a loader switch, NOT a standalone tool)

`session_import(..., pdb_ref?)`: an **optional second file** — a Microsoft PDB — resolved through the
**same confined import root** as `source_ref` (CWE-22: no arbitrary path; size-capped identically,
CWE-400). When set, after the PE is loaded the worker parses the PDB and applies its symbols/types to
the freshly-loaded program **before** analysis. It is **additive + opt-in**: when `pdb_ref` is `None`
(the default) the import path is **byte-for-byte** the pre-ADR-061 behaviour (the RPC params carry no
`pdb_ref` key), preserving the ADR-029/030 no-op guarantee.

### D2 — Applied at IMPORT time to the FRESH program → NOT a write tool (no write-consent)

The PDB is applied while the program is *being loaded* (fresh, no prior established state), exactly like
a loader hint enriches a raw image at load. It therefore does **not** mutate an already-established
program and does **not** pull in the ADR-012 write-consent surface — it is part of the **capability-gated
import** (gated like `session_import` itself), not a mutation tool. Applying PDB symbols *before*
auto-analysis is also the correct order: a later `session_analyze` benefits from the recovered names.
Rejected alternative: a standalone `apply_pdb` write tool that mutates an analyzed program — larger
surface (write-consent), and PDB is inherently a load-time enrichment.

### D3 — `pdb_ref` pairs with the opinion-loaded PE (`loader="auto"`) only, in the initial cut

PDB is a Windows-PE concept. The initial cut allows `pdb_ref` only with `loader="auto"` (the PE case);
any other `loader` value with `pdb_ref` set is rejected server-side (fail closed, no silent ignore). A
raw-image + PDB combination (force-applying a PDB's symbols by address to a headerless image) is a
possible later extension, deliberately out of scope here.

### D4 — Bounds & failure handling (the PDB parser is hostile-input surface)

- The PDB is **size-capped** before load (reuse the `source_ref` cap; CWE-400) and **confined-root
  resolved** (CWE-22) — no new file-read or unbounded-input surface.
- The PDB **parser is the new attack surface** (a malformed/hostile PDB): parse/deserialize/apply run
  inside the worker's existing containment (no egress, ro-rootfs, dropped caps, gVisor, mem/pids/cpu
  caps, wall-clock kill — ADR-002/004, unchanged). A parser failure is caught and mapped to a
  category-safe error (fail closed) — never a leaky stack trace (master §5 / ADR-005).
- No GUID enforcement in the initial cut: the operator explicitly pairs `source_ref` + `pdb_ref`, and a
  mismatched PDB yields wrong-but-**contained** symbols (all binary-derived output is untrusted-
  enveloped anyway — ADR-005). A future refinement may verify the PE debug-directory GUID/age against
  the PDB before applying; noted, not built.

### D5 — Output classification (unchanged)

`session_import` returns only server-computed `SessionInfo` fields (state, sha256, size) — no
binary-derived content. The applied symbols/types become part of the program and surface later through
the existing read tools (`list_symbols`, `get_function`, …), where they are **already** untrusted-
enveloped (ADR-005). So this ADR adds **no** new output surface and needs no schema output change.

## New trust-boundary surface (see the TB3 delta)

The PDB crosses the **binary → analyzer** boundary (**TB3**, the primary HOSTILE boundary) into the
same hardened worker — a **second hostile input across TB3**, not a new boundary class. The delta the
threat-model must state:

- **A second hostile file: the PDB, parsed by a complex parser.** PDB parsing is a real attack surface
  (MSF container + multiple typed streams). It runs entirely inside the unchanged ADR-004 isolation
  stack; the reader is pure data-in, no code execution; a parser fault fails closed.
- **Confined + size-capped.** Both `source_ref` and `pdb_ref` are confined-root-resolved + size-capped
  before any byte reaches the JVM (ADR-001).
- **Applied to the fresh program, transient worker.** The symbols land in the session's own program (as
  intended — this IS the enrichment); the program + worker are wiped on evict (ADR-002) like any import.
- **No new egress / caps change.** The worker stays network-less, ro-rootfs, dropped-caps, gVisor.

## Consequences

- **Positive:** Windows PE reverse-engineering gets its real names/types back — a major legibility win,
  the standard workflow. Small, additive increment; no new tool, no write-consent surface, no output
  schema change; mirrors the proven ADR-045 companion-at-import idiom.
- **Cost / risk:** a second confined file per import and a new (complex) parser surface, both inside the
  existing containment. The `applyNoAnalysisState()` path is the supported headless entry; grounded.

## Implementation record (2026-08-13)

- **Schema** (`schemas.py`): `SessionImportIn` gains `pdb_ref: str | None` (confined path, ≤512);
  `_validate_loader_hints` rejects `pdb_ref` unless `loader="auto"` (D3), fail closed.
- **Server adapter** (`rpc_client.py`): when `pdb_ref` is set, `_resolve_and_cap(pdb_ref)` confines +
  size-caps + OOM-pre-flights the PDB (the same shared helper as `source_ref`), then threads a `pdb_ref`
  RPC param; `pdb_ref=None` sends no key (byte-for-byte no-op).
- **Worker** (`_jvm_bridge.py`): `_gh_import` applies the PDB via `_apply_pdb` after the auto load —
  `PdbParser.parse` → `deserialize` → `DefaultPdbApplicator(...).applyNoAnalysisState()` in a
  transaction; a parse/apply failure maps to a category-safe `not-found` (fail closed).
- **Tests:** unit — `pdb_ref` accepted with `auto`, rejected with any other loader. Live integration
  (`test_import_pdb.py`) — the embedded fixture PE+PDB import applies the PDB and the recovered function
  name appears in `list_symbols`; added to the `live-regression.yml` hard-gate list.

## Testing (master §4)

- **Unit:** schema — `pdb_ref` bounded (≤512); allowed with `loader="auto"`, rejected with
  binary/hex/dex/macho/apk; `None` default = no-op.
- **Integration (gated real worker):** import the fixture PE with its PDB → a PDB-recovered function name
  (`the_answer`) is present in the program's symbols; without `pdb_ref` it is not. Abuse: an oversized
  PDB is rejected before load (the shared cap).
