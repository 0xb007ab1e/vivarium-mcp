# ADR-071: Debug-info import beyond PDB — apply DWARF / a symbol map at import (`session_import` `debug_ref`)

- **Status:** **Proposed** (awaiting human ratification; v1.9). Item 8 of the post-v1.8 capability-gap
  batch (ADR-064..072).
- **Date:** 2026-08-13
- **Deciders:** Human operator (to ratify); drafted by the assistant from the post-v1.8 capability-gap
  survey (the ELF/embedded counterpart to the Windows-PDB item already shipped as ADR-061).
- **Context source:** ADR-061 added a companion Microsoft **PDB** (`pdb_ref`) applied at import to
  recover names/types on Windows PEs. The equivalent for the **ELF/embedded** world is missing. A
  stripped-with-separate-debug ELF ships its debug info in a *separate* file (a `.debug` / split-DWARF
  companion), and much embedded/legacy RE work has only a flat **symbol map** — an IDA-style `.map`, a
  linker `.sym`, or an `nm` dump. Vivarium can load the stripped ELF (ADR-045) but has no way to pair it
  with that companion, so the real function names/types stay lost. This ADR proposes the ELF-side mirror
  of ADR-061.

## Context

`session_import` (ADR-045) loads the primary binary and `pdb_ref` (ADR-061) applies a Windows PDB, but
there is **no** path to apply ELF/embedded debug info. In the Unix/embedded toolchain the debug data is
routinely *detached*: `objcopy --only-keep-debug` / split-DWARF (`.dwo`/`.debug`) produce a separate
file, and a stripped production ELF is analyzed with only a linker `.map` or `nm`-style `.sym` list to
recover names. Ghidra already carries a **DWARF analyzer** that consumes DWARF and lands real
functions/parameters/structs; a plain name→address map is even cheaper to apply as program symbols. The
capability exists in the worker — Vivarium just does not let the operator supply the companion file.

A detached-debug file is **supplemental symbol/type data applied to an already-loaded ELF**, exactly the
ADR-061 shape — not a loader (ADR-045 `loader=`). So it is a *second companion file* paired with the
primary binary, and it is **also hostile, attacker-controlled input** (a debug file can be crafted just
like the binary): it must be confined-root resolved (CWE-22), size-capped before the worker (CWE-400),
parsed worker-only (ADR-001), and fail closed on malformed input (ADR-005 / CWE-20).

## Decision

### D1 — A `debug_ref` companion on `session_import` (mirror `pdb_ref` exactly)

`session_import(..., debug_ref?, debug_format?)`: an **optional second file** — detached ELF debug info
or a symbol map — resolved through the **same confined import root** as `source_ref` (CWE-22) and
**size-capped identically** (reuse the `source_ref` cap; CWE-400). When set, after the primary program is
loaded the worker parses the debug file and applies its symbols/types to the freshly-loaded program
**before** analysis, so a later `session_analyze` benefits from the recovered names. It is **additive +
opt-in**: when `debug_ref` is `None` (the default) the import path is **byte-for-byte** the pre-ADR-071
behaviour (the RPC params carry no `debug_ref`/`debug_format` key), preserving the ADR-029/030 no-op
guarantee. `debug_ref` and `pdb_ref` are mutually exclusive (a program takes one companion debug source);
setting both is rejected server-side, fail closed.

### D2 — A `debug_format` hint enum, MVP-scoped (fail closed on the rest)

`debug_format: Literal["dwarf","map"]` names how the worker parses `debug_ref`:

| `debug_format` | Companion file | Applicator (worker-only) |
|---|---|---|
| `dwarf` | Detached DWARF / split-DWARF `.debug` for a stripped ELF | Ghidra's own **DWARF analyzer** — the high-value case (functions, params, structs). |
| `map` | A plain **name→address** list: IDA `.map`, linker `.sym`, or `nm` dump | Cheap, safe symbol application (labels only; no types). |

The initial cut scopes exactly these two formats — `dwarf` for the real legibility win, `map` because it
is cheap and low-risk. Any unrecognized `debug_format` is rejected at the schema boundary (CWE-20, no
silent default). Richer sources (STABS, DWARF-in-CodeView-on-ELF, per-line info) are deliberately
out of scope, noted for a later ADR.

### D3 — Applied at IMPORT time to the FRESH program → NOT a write tool

The debug info is applied while the program is *being loaded* (fresh, no prior established state), exactly
like a loader hint enriches a raw image and exactly like ADR-061's PDB. It therefore does **not** mutate
an already-established program and does **not** pull in the ADR-012 write-consent surface — it is part of
the **capability-gated import** (gated like `session_import` itself), not a mutation tool. Rejected
alternative: a standalone `apply_debug` write tool that mutates an analyzed program — a larger surface
(write-consent), when detached debug info is inherently a load-time enrichment.

### D4 — `debug_ref` pairs with the ELF case only, in the initial cut

DWARF and detached-debug are ELF/Unix concepts. The initial cut allows `debug_ref` only with the ELF
loader path (`loader="auto"` resolving to an ELF, or an explicit ELF loader hint); any non-ELF `loader`
value with `debug_ref` set is rejected server-side (fail closed, no silent ignore). A `.map` applied by
address to a headerless raw image is a plausible later extension, deliberately out of scope here.

### D5 — Bounds & failure handling (the debug parser is hostile-input surface)

- `debug_ref` is **size-capped** before load (reuse the `source_ref` cap; CWE-400) and **confined-root
  resolved** (CWE-22) — no new file-read or unbounded-input surface (mirrors ADR-061 D4).
- The **debug parser is the new attack surface** (a malformed/hostile DWARF or map): parse/apply run
  inside the worker's existing containment (no egress, ro-rootfs, dropped caps, gVisor, mem/pids/cpu caps,
  wall-clock kill — ADR-002/004, unchanged). A parser/apply failure is caught and mapped to a
  category-safe error (fail closed) — never a leaky stack trace (master §5 / ADR-005). DWARF is the
  complex case (the same class of container/typed-stream risk ADR-061 flagged for PDB); a `.map` is a
  simple text parse.
- No consistency enforcement in the initial cut: the operator explicitly pairs `source_ref` + `debug_ref`,
  and a mismatched companion yields wrong-but-**contained** symbols (all binary-derived output is
  untrusted-enveloped anyway — ADR-005). A future refinement may check DWARF build-id against the ELF
  `.note.gnu.build-id` before applying; noted, not built.

### D6 — Contract delta (WS0, atomic)

Additive optional fields on an existing tool → `docs/contracts/tool-catalog.md` (update the
`session_import` row) + `docs/contracts/rpc-protocol.md` (new optional `debug_ref`/`debug_format` import
params + worker-side apply step). **No new tool**, so the catalog count is unchanged (mirrors ADR-061).
Lands atomically with the schema per the frozen-contract mandate.

## Security / threat-model delta

The debug file crosses the **binary → analyzer** boundary (**TB3**, the primary HOSTILE boundary) into
the same hardened worker — a **second hostile file across TB3**, not a new boundary class (identical
posture to the ADR-061 PDB delta):

- **A second hostile file: detached debug info, parsed by a complex parser (DWARF).** DWARF parsing is a
  real attack surface; it runs entirely inside the unchanged ADR-004 isolation stack; the reader is
  data-in, no code execution; a parser fault fails closed. The `map` path is a bounded text parse.
- **No new agency (ADR-001/LLM08):** applied at load, read-only thereafter; no write tool, no execution,
  no script path.
- **Confined + size-capped (CWE-22/CWE-400):** both `source_ref` and `debug_ref` are confined-root-resolved
  + size-capped before any byte reaches the JVM (ADR-001).
- **Untrusted output (ADR-005):** the applied symbols/types become part of the program and surface later
  only through the existing read tools, where they are **already** untrusted-enveloped — so this ADR adds
  **no** new output surface (`session_import` still returns only server-computed `SessionInfo`).
- **Applied to the fresh program, transient worker:** the symbols land in the session's own program (as
  intended — this IS the enrichment); program + worker are wiped on evict (ADR-002). **No egress / caps
  change.**

## Alternatives considered

- **A standalone `apply_debug` write tool over an analyzed program** — rejected (D3): larger surface
  (write-consent), when detached debug is inherently a load-time enrichment.
- **Force `debug_ref` through the ADR-045 `loader=` switch** — rejected: debug info is *not* a loader; it
  supplements an already-loaded program (same reasoning ADR-061 gave for PDB).
- **Auto-discover a sibling `.debug` next to the binary** — rejected: implicit filesystem probing widens
  the confined-root contract and hides input provenance; the operator explicitly pairs the two files.
- **A single generic `debug_ref` with format sniffing (no `debug_format`)** — rejected for the MVP:
  content-sniffing a hostile file to pick a parser is exactly the ambiguity to avoid (CWE-20); an explicit
  enum fails closed on anything unscoped.
- **Ship `dwarf` only / `map` only** — rejected: `dwarf` is the high-value case and `map` is nearly free
  and covers the large stripped-ELF-with-linker-map population; both together are the 80% at low added
  cost.

## Consequences

- **Positive:** closes the ELF/embedded gap left by ADR-061 — stripped-with-separate-debug ELFs and
  map-only embedded targets get their real names/types back, the standard Unix/embedded RE workflow.
  Small, additive; no new tool, no write-consent surface, no output schema change; reuses the proven
  ADR-045/ADR-061 companion-at-import idiom and Ghidra's own DWARF analyzer.
- **Negative / cost:** a second confined file per import and a new (DWARF) parser surface, both inside the
  existing containment; a worker-side apply step to validate via the gated live-regression. A mismatched
  or non-decompilable companion fails closed (category-safe error); DWARF apply requires the ELF path
  (D4). Worker-side change → needs a worker rebuild + pin bump before the live gate exercises it.
- **Scope:** SemVer **minor** (additive optional import fields). STABS / richer DWARF line-info / raw-image
  `.map` = future ADRs.

## Testing (master §4)

- **Unit:** schema validation — `debug_ref` bounded (≤512, confined path); `debug_format` enum accepts
  `dwarf`/`map` and rejects anything else; `debug_ref` allowed only on the ELF loader path and rejected
  otherwise (D4); `debug_ref` + `pdb_ref` mutually exclusive (D1); `None` default = byte-for-byte no-op
  (RPC carries no key). Server-side size-cap / confinement proven before the worker.
- **Integration (gated real worker, live-regression):** build a small ELF with a companion **DWARF**
  `.debug` (hermetic: `gcc -g` + `objcopy --only-keep-debug`/split-DWARF, embedded gzip+base64 like the
  ADR-061 PDB fixture) → import with `debug_ref`+`debug_format="dwarf"` → assert a DWARF-recovered function
  name **and** a recovered type appear via `list_symbols` / `get_function`; without `debug_ref` they do
  not. Repeat with a plain `.map` (`debug_format="map"`) → assert the mapped name is applied as a symbol.
  Add to the live-regression hard-gate list.
- **Abuse:** an oversized debug file is rejected before load (the shared cap); a malformed/hostile DWARF
  fails closed to a category-safe error (no stack-trace leak); a mismatched companion yields only
  contained, untrusted-enveloped symbols (no crash, no escape).

## Rollout

Additive + opt-in → no migration; `debug_ref=None` is byte-for-byte the pre-ADR-071 import. Worker-side
change → needs a worker rebuild + `.github/worker-image.pin` bump (per the worker-change-validation-recipe)
before the live gate exercises the DWARF/map apply. Contract delta (D6) lands atomically through the PM
(frozen-contract mandate). Merge stays gated.
