# ADR-046: `session_import` loader selection — Intel-HEX / Motorola-SREC

- **Status:** **Accepted** (2026-08-12). First increment of the "expose more of Ghidra's loaders"
  program; follows ADR-045 (F1 raw loader) in the same additive shape.
- **Date:** 2026-08-12
- **Deciders:** Human operator (directed "all" Ghidra-coverage gaps); assistant implemented.
- **Context source:** Ghidra ships ~32 loaders; Vivarium's `loader` hint only had `{auto, binary}`.
  The pinned worker's loaders were enumerated live (`LoaderService.getAllLoaderNames()`), and Intel
  HEX + Motorola S-record were verified loadable via PyGhidra before this design was fixed.

## Context

Vendor MCU firmware is frequently delivered as an **Intel-HEX** or **Motorola S-record (SREC)** text
file, not a raw `.bin` — the format you get *before* you'd ever have a headerless image for the
ADR-045 raw path. Ghidra has `IntelHexLoader` / `MotorolaHexLoader`, but `session_import` couldn't
select them: `loader ∈ {auto, binary}` only, and `auto` (the opinion system) does not reliably
auto-detect these text formats. So a common firmware-RE ingestion path was unreachable.

Unlike a raw image, a hex file **carries its own load addresses** in the records — but it carries no
processor. So the hint shape differs from `binary`: it needs `processor`, and `base_addr`/`entry`
would be meaningless.

## Decision

### D1 — Add `intel-hex` / `motorola-hex` to the `loader` enum; each takes `processor` only

`SessionImportIn.loader` becomes `Literal["auto","binary","intel-hex","motorola-hex"]`. For the two
hex loaders the server requires **`processor`** (validated against the ADR-045 allow-list) and
**rejects `base_addr`/`entry`** (the records are absolute — supplying an offset is ambiguous, so it
fails closed rather than being silently ignored). `auto` still forbids all hints; `binary` unchanged.

### D2 — Worker drives the named Ghidra loader with the language; no rebase

The worker maps the client token to the Ghidra loader class
(`_NAMED_LOADERS = {intel-hex: IntelHexLoader, motorola-hex: MotorolaHexLoader}`) and calls
`pyghidra.open_program(…, language=<processor>, loader=<class>)`. There is **no `setImageBase`** (the
loader lays memory out from the record addresses). Same `# pragma: no cover - JVM edge` posture as
the raw path; correctness proven by the gated integration test. An uninstalled language / unloadable
file → category-safe `not-found` (defense in depth on top of the server allow-list).

### D3 — Same security envelope as ADR-045

Server validates `loader` (closed enum) + `processor` (positive allow-list, CWE-20) **before** the
worker; the server never touches the JVM (ADR-001). New inputs are config values, not bytes; no new
agency (read-only import, no script execution); the analyzed bytes stay in the hardened, ephemeral,
network-isolated worker container (never the host). Contract delta (tool-catalog + rpc-protocol)
lands atomically (WS0).

## Alternatives considered

- **A generic "pass any Ghidra loader name + arbitrary options"** — rejected: unbounded option
  surface = untrusted-input risk on the worker + a fuzzy contract. A closed enum with per-loader
  validation is safer and clearer; add loaders one ADR at a time as their hint shape is understood.
- **Relying on `auto`** — rejected: the opinion system does not reliably pick the hex loaders (text
  formats), and there's no way to force them.
- **Accepting `base_addr` as an offset for hex** — deferred: `open_program` doesn't cleanly pass the
  loader's base option, and absolute records cover the common case. Revisit if a relative-hex need
  appears.

## Consequences

- **Positive:** unlocks hex-delivered firmware ingestion (a core embedded-RE format); additive +
  opt-in (auto/binary paths untouched); establishes the `loader`-selection pattern for the next
  formats (DEX/APK, Mach-O/DYLD, COFF/a.out — each a follow-on ADR with its own hint shape).
- **Cost:** each named loader needs a live-worker validation pass (the same gate pattern).

## Testing (master §4)

- **Unit:** schema — hex loaders require `processor`; reject missing processor, reject
  `base_addr`/`entry`, reject an unsupported processor; rpc params thread only `{loader, processor}`.
- **Integration (gated real worker):** `test_import_hex.py` builds a synthetic Intel-HEX in-container,
  imports via `loader="intel-hex"`, and asserts the architecture, a block at the record address, and
  that `read_bytes` returns the loaded bytes. Registered in the live-regression hard-gate list
  (floor 9→10 / 11→12). `motorola-hex` shares the worker code path (`_open_named_loader`) and is
  covered by the unit + validation tests + the pre-design PyGhidra verification.

## Rollout

Additive + default-off (`loader` defaults to `auto`) → no migration. Documented in the
`vivarium://docs/importing` resource. Merge stays **gated**.
