# ADR-047: `session_import` self-describing loaders — DEX / Mach-O

- **Status:** **Accepted** (2026-08-12). Third increment of the "expose more Ghidra loaders" program
  (after ADR-045 raw, ADR-046 hex).
- **Date:** 2026-08-12
- **Deciders:** Human operator (directed "all" Ghidra-coverage gaps); assistant implemented.
- **Context source:** Enumerated the pinned worker's loaders + **verified live** that both the `auto`
  (opinion) path and a forced `MachoLoader`/`DexLoader` load minimal synthetic Mach-O (ARM64) and
  DEX files, detecting `AARCH64:LE:64:AppleSilicon` / `Dalvik:LE:32:DEX_KitKat` from the header.

## Context

Ghidra self-detects **Mach-O** (macOS/iOS) and Android **DEX** (and APK/CDEX) from their headers.
The probe above shows Vivarium's existing **`auto` path already loads both** — the gap was not
capability but **validation + docs**: the ADR-045 material described `auto` as "ELF/PE only", and no
test proved Mach-O/DEX ingestion. Additionally, there was no way to **force** a specific loader when
opinion is ambiguous (or, later, to select a Mach-O fat slice).

Unlike raw (ADR-045) or hex (ADR-046), these formats are **self-describing**: the file carries its
own processor and memory layout. So the hint shape is "force the loader, supply nothing else".

## Decision

### D1 — Add `dex` / `macho` to the `loader` enum; they take **no** hints

`SessionImportIn.loader` becomes `Literal["auto","binary","intel-hex","motorola-hex","dex","macho"]`.
For `dex`/`macho` the server **forbids** `processor`/`base_addr`/`entry` (the format supplies them;
passing any is ambiguous → fail closed, not silently ignored) — the same rule as `auto`, except the
worker **forces** the named loader instead of letting opinion choose.

### D2 — Worker forces the loader with no language

The worker maps the token via `_NAMED_LOADERS` (extended with `DexLoader`/`MachoLoader`) and calls
`pyghidra.open_program(…, loader=<class>)` with **no `language`** (the shared `_open_named_loader`
now takes an optional `processor`: hex passes it, self-describing passes `None`). No rebase. Same
`# pragma: no cover - JVM edge` posture; correctness proven by the gated integration test. A file
that doesn't match the forced format → category-safe `not-found`.

### D3 — Same security envelope (ADR-045/ADR-001) + execution stays in the container

Server validates the closed `loader` enum + rejects hints **before** the worker; it never touches the
JVM. New inputs are config tokens, not bytes; no new agency (read-only import, no script execution);
the analyzed bytes are parsed only inside the hardened, ephemeral, network-isolated worker container
— never the host (standing operator directive). Contract delta (tool-catalog + rpc-protocol) atomic.

## Alternatives considered

- **Do nothing (rely on `auto`)** — rejected in part: `auto` *does* load these, but (a) it was
  untested/undocumented (the real gap this ADR closes) and (b) there's no way to force a loader when
  opinion is ambiguous. Adding the explicit values + the gate fixes both; `auto` remains the default.
- **APK / DYLD-cache / fat-Mach-O slice selection now** — deferred: APK is a zip container
  (`ApkLoader`) and fat/DYLD need slice/component **options** (a richer hint shape). Add them as a
  follow-on once the option-passing design is settled; this ADR covers the single-slice self-
  describing case.

## Consequences

- **Positive:** Mach-O (iOS/macOS) + Android DEX ingestion is now a **tested, documented** capability;
  clients can force the loader. Corrects the "auto = ELF/PE only" misconception.
- **Cost:** each named loader wants a live-worker validation pass (same gate pattern). APK/DYLD/fat
  remain follow-ons.

## Testing (master §4)

- **Unit:** schema — `dex`/`macho` validate with no hints; reject `processor`/`base_addr`/`entry`; rpc
  threads only `{loader}`.
- **Integration (gated real worker):** `test_import_selfdescribing.py` builds a minimal ARM64 Mach-O
  and an empty DEX in-container and loads **each via both `auto` and the forced loader**, asserting
  the detected format + architecture family — PASSED live 8.4s; added to the live-regression hard-gate
  list (floor 10→11 / 12→13).

## Rollout

Additive + default-off (`loader` defaults to `auto`) → no migration. Documented in
`vivarium://docs/importing`. Merge stays **gated**.
