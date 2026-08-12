# ADR-047: `session_import` self-describing loaders — DEX / Mach-O

- **Status:** **Accepted** (2026-08-12; amended same day to add `apk` and record the fat-slice /
  DYLD deferral). Third + fourth increments of the "expose more Ghidra loaders" program (after
  ADR-045 raw, ADR-046 hex).
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

### D1 — Add `dex` / `macho` / `apk` to the `loader` enum; they take **no** hints

`SessionImportIn.loader` becomes
`Literal["auto","binary","intel-hex","motorola-hex","dex","macho","apk"]`. For these self-describing
loaders the server **forbids** `processor`/`base_addr`/`entry` (the format supplies them; passing any
is ambiguous → fail closed, not silently ignored) — the same rule as `auto`, except the worker
**forces** the named loader instead of letting opinion choose. (`apk` was added in the amendment; an
APK is a zip whose `classes.dex` is loaded — verified live, auto + forced, both → `Android APK` /
`Dalvik`.)

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
- **APK** — **added** in the amendment: `ApkLoader` is self-describing (no options), so it fits the
  same hint-free mechanism as `dex`/`macho`.
- **DYLD-cache / fat-Mach-O slice selection** — **deferred (grounded):** `pyghidra.open_program` has
  **no loader-options / LoadSpec-selection parameter** (confirmed from its signature), so choosing a
  specific fat slice or a DYLD-cache component is not reachable through the current open path. A
  fat/universal Mach-O still loads its *default* slice via `loader="macho"` (verified). Selecting a
  slice/component needs a lower-level `LoaderService` + `LoadSpec` + options mechanism and a new
  hint field — a separate future increment, not this one.

## Consequences

- **Positive:** Mach-O (iOS/macOS) + Android DEX ingestion is now a **tested, documented** capability;
  clients can force the loader. Corrects the "auto = ELF/PE only" misconception.
- **Cost:** each named loader wants a live-worker validation pass (same gate pattern). APK/DYLD/fat
  remain follow-ons.

## Testing (master §4)

- **Unit:** schema — `dex`/`macho` validate with no hints; reject `processor`/`base_addr`/`entry`; rpc
  threads only `{loader}`.
- **Integration (gated real worker):** `test_import_selfdescribing.py` builds a minimal ARM64 Mach-O,
  an empty DEX, and an APK (zip + `classes.dex`) in-container and loads **each via both `auto` and the
  forced loader** (six loads), asserting the detected format + architecture family — PASSED live ~8s;
  added to the live-regression hard-gate list (floor 10→11 / 12→13).

## Rollout

Additive + default-off (`loader` defaults to `auto`) → no migration. Documented in
`vivarium://docs/importing`. Merge stays **gated**.
