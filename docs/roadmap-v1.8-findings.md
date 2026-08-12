# v1.8 findings — external real-world run: bare-metal firmware RE via MCP (2026-07-22)

> Source of truth for delivery: [`PLAN.md`](../PLAN.md); decisions are ADRs in [`docs/adr/`](adr/).
> This document records findings from a **real-world end-to-end use of the Vivarium MCP by an external
> client** (Claude Code, driving RE of embedded device firmware) and proposes candidate **v1.8 backlog**
> items. Promotion path unchanged: **finding → design ADR → human ratification → implement (isolated
> worktree) → `sdlc-reviewer` → CI green → gated merge.** Prior findings doc:
> [`roadmap-v1.3-findings.md`](roadmap-v1.3-findings.md).

## What was run

An MCP client attempted to load **bare-metal device firmware** into Vivarium for decompilation:

- **Target — a dual-SoC IoT recorder ("T19"):** main **Actions ATS3085** image (ARM Cortex-M / Thumb,
  Zephyr RTOS, load `0x10000000`) + a **Telink TLSR9** connectivity image (RISC-V RV32, NimBLE, load
  `0x0`) + an ARM recovery image (load `0x11000000`). All three are **raw MCU images — no ELF/PE
  header, no section table** (extracted from a vendor OTA container).
- Client flow attempted: `session_create` → `session_import` → `session_analyze` → decompile/rename/
  export.

## What worked / what didn't (isolated)

- ✅ **`session_create`** works; sessions spawn hardened per-session workers as designed.
- ✅ **Ingestion resolves once the input is under the import root.** The initial wall was operator
  error (staging outside `VIVARIUM_IMPORT_ROOT`); once staged under it, `source_ref` resolves.
- ✅ **The worker imports real, well-formed ELFs** — verified end-to-end with an **x86-64** static ELF
  and a real **AARCH64** shared object. So the worker's ARM/RISC-V processor support is present and
  fine (Processors dir ships ARM, ARMCortex, AARCH64, RISCV, …).
- ❌ **No path to import a raw (headerless) binary.** `session_import` takes only `source_ref`
  (+`expected_sha256`) — **no processor / base-address / loader hint** — so Ghidra can't auto-detect a
  format-less MCU image, and the import fails.
- ❌ **Hand-built ELF wrappers (correct machine/base/entry, `readelf`-clean) → worker `500`
  internal-error** in the MCP import path, *after* a clean FID-DB attach, with **no exception on worker
  stdout**. Could not reproduce the exact Ghidra error via the worker image's `analyzeHeadless`
  because the **worker image is distroless (no `bash`)**, so the wrapper script can't run there.
- **Outcome for the client:** the firmware RE was completed **out-of-band** with local Ghidra headless
  (`-loader BinaryLoader -processor ARM:LE:32:Cortex -loader-baseAddr …` on the raw blobs) — i.e. the
  capability Vivarium is missing is exactly *raw-image loader control*.

Evidence staged under the import root (`~/vivarium-imports/`): `t19_{app,recovery}_arm.{bin,elf}`,
`t19_wifi_riscv.{bin,elf}`, `probe_aarch64.so` (the AARCH64 import that succeeded).

## Findings → proposed v1.8 backlog (prioritized)

| # | Sev | Finding | Proposed v1.8 fix | Contract / bump |
|---|---|---|---|---|
| **F1** | **High** | **No raw-binary import.** `session_import` can't load headerless MCU/firmware images — the dominant case for embedded RE — because there is no way to specify processor + base address (Ghidra's `BinaryLoader` path is unreachable). | Add **optional loader hints** to `session_import`: `loader` (`auto`\|`binary`), `processor` (LanguageID, e.g. `ARM:LE:32:Cortex`, `RISCV:LE:32:RV32GC`), `base_addr`, optional `entry`. When `binary`, drive Ghidra's `BinaryLoader` with these. Validate against an allow-list of installed LanguageIDs; keep it additive/opt-in (auto stays default). | additive (new optional fields + new untrusted-input validation path); **minor** |
| **F2** | Med | **`session_import` tool description is not self-sufficient.** It says only *"a pre-registered upload id or an allow-listed mount path"* — never names `VIVARIUM_IMPORT_ROOT`, gives no example, and lists no reject reasons. It's the *only* surface an MCP client/agent reads, so the (well-written) `getting-started.md` import-root docs are undiscoverable in-band. This cost an external agent many failed calls. | Rewrite the `SessionImportIn.source_ref` docstring/schema description to state: input must be a path **under `VIVARIUM_IMPORT_ROOT`**, give a concrete example, and name the reject reasons. | additive (doc/description only); **patch** |
| **F3** | Med | **No MCP resource documents importing.** `ListMcpResources` returns none, so a client can't fetch the import how-to at runtime. | Expose a small MCP resource (e.g. `vivarium://docs/importing`) mirroring getting-started Step 4–5 (import root + `source_ref` + loader hints from F1). | additive; **patch/minor** |
| **F4** | Low | **Unactionable errors.** `input reference could not be resolved` (VALIDATION) is indistinguishable between *not under the import root*, *not found*, and *malformed path*; and the raw-image failure surfaces as a bare `500 the worker reported an internal error` with nothing on worker stdout. | Make the resolver error name the configured root + the specific reason (path-escape vs missing vs size-cap). Ensure the worker **logs the actual import exception** (structured) so a `500` is diagnosable. (Respect ADR-005: keep binary-derived detail out of client-facing text; the *category* is safe.) | additive (error text + worker log field); **patch** |
| **F5** | Low / investigate | **Synthetic-ELF import path bug (or Ghidra rejection).** A `readelf`-clean, section-bearing 32-bit ARM/RISC-V ELF (real ELFs of the same arch import fine) fails in the MCP import path with no surfaced cause. Root cause unknown — blocked by F4 (no worker exception logged) + distroless image (no `bash` to run `analyzeHeadless` for a local repro). | Gated on F4 (surface the exception). If it's a genuine Ghidra rejection of hand-built ELFs, F1 (native raw loader) makes it moot; if it's a wrapper bug, fix in the import path. Add a raw-image fixture to the acceptance harness. | none (bugfix); **patch** |

## Notes
- **F1 is the headline** and the general capability gap: Vivarium today assumes auto-detectable
  containers (ELF/PE); embedded/bare-metal RE — a core RE use case — needs explicit loader control.
  Recommend an ADR (`session_import` loader hints) with a LanguageID allow-list + the threat-model
  note (untrusted `processor`/`base_addr` are low-risk config strings, validated pre-worker).
- F2–F4 are cheap, high-leverage discoverability/observability fixes independent of F1.
- This run did **not** exercise a naming/quality regression (the firmware analysis itself succeeded
  out-of-band); all findings are **ingestion/UX/observability**, not analysis quality.
