# ADR-070: Extended firmware container unwrap + loaders

- **Status:** **Accepted** (ratified by the human operator 2026-08-13; targets v1.9). Item 7 of the ADR-064..072
  post-v1.8 capability-gap batch.
- **Date:** 2026-08-13
- **Deciders:** Human operator (to ratify); drafted by the assistant from the post-v1.8
  capability-gap survey (the ingestion item adjacent to ADR-045 / ADR-065).
- **Context source:** v1.8 broadened the *loader* set (ELF/PE/Intel-HEX/SREC/DEX/Mach-O/APK —
  ADR-045..048), but real firmware routinely arrives wrapped in a **container** that Ghidra does not
  unwrap. The real "T19" firmware RE had to be un-nested **by hand**: the vendor OTA was an `AOTA`
  wrapper around an Actions `LZMA`/XZ payload that had to be decompressed offline *before*
  `session_import` could see a loadable image. Every such image today forces the operator out of
  Vivarium and into ad-hoc host-side tooling — exactly the untrusted-parsing step the containment
  architecture exists to avoid.

## Context

A firmware container is a wrapper — a vendor OTA envelope, a U-Boot `uImage`, an Android boot image,
or simply a gzip/LZMA/XZ-packed section — whose *payload* is the thing Ghidra can load. Vivarium's
loaders (ADR-045..048) all assume the caller already holds the raw image. When the input is a
container, the operator must unwrap it elsewhere, hand-decompress packed sections, and re-feed the
result — losing provenance and, worse, running an untrusted parser on the host (contradicting the
standing operator directive that all hostile bytes are parsed only inside the ephemeral worker).

**The critical framing:** a firmware container is **HOSTILE, attacker-controlled input parsed BEFORE
Ghidra**. Unwrapping it is a *new untrusted-parser attack surface* that Ghidra's own loaders do not
cover — the classic weakness classes apply directly: `CWE-20` (malformed header/length fields),
`CWE-400` (**decompression bombs** — a few KB of XZ expanding to gigabytes), and unbounded recursion
of nested wrappers. This is precisely the shape ADR-005 (untrusted-data envelope, fail closed) and
ADR-001 (keep the parse off the server process) were written for. The MVP must therefore be **narrow,
bounded, and opt-in**, not a general "unwrap anything" engine.

This is **ingestion**, additive on top of ADR-045 and adjacent to ADR-065 (multi-region): once a
container is unwrapped, the contained image(s) become ordinary loader inputs and the existing
decompile/xref/export path works unchanged. A container that yields several images at several bases
feeds the ADR-065 `regions` path.

## Decision

### D1 — Additive, opt-in `container` hint; absence is a byte-for-byte no-op

Extend `SessionImportIn` with one optional field, `container`, naming the wrapper format to unwrap
before loading. When `container` is absent the RPC params and worker call are **identical to today** —
the ADR-045/065 paths are untouched (the ADR-029/030/045 opt-in guarantee; no new key crosses the
wire). The default is *not* auto-detect: an operator opts in explicitly, mirroring ADR-045's rejection
of heuristic raw detection.

`container` is a **closed enum**, an allow-list of well-specified formats (D2). `container` combines
with the existing `loader`/`processor`/`base_addr` hints and with ADR-065 `regions`: the container is
unwrapped first, then the contained image(s) are handed to the named loader (or to `auto` when the
payload is self-describing).

### D2 — Strict format allow-list; MVP scope is a couple of well-specified formats

The v1.9 MVP allow-list is deliberately small and each entry has an unambiguous, magic-anchored
header spec:

| Token | Format | Payload |
|---|---|---|
| `uimage` | U-Boot legacy `uImage` (magic `0x27051956`, 64-byte header, CRC + declared length) | the wrapped kernel/blob, optionally compressed (D3). |
| `androidboot` | Android boot image (`ANDROID!` magic, page-aligned kernel/ramdisk regions) | the kernel region (surfaced for import; ramdisk out of MVP scope). |
| `gzip` / `xz` / `lzma` | bare compressed stream (a packed section) | the decompressed image (D3). |

Vendor OTA wrappers (e.g. `AOTA`) and exotic per-vendor container formats are **explicitly deferred** —
they are proprietary, under-specified, and each is a bespoke parser (high fuzz/DoS surface for low
generality). They can be added one ADR/increment at a time behind the same allow-list + caps, exactly
as ADR-046/047 grew the loader set. Unknown token → `validation` reject (positive allow-list, CWE-20).

### D3 — Hard size + decompression-ratio caps, enforced server-side BEFORE the worker (zip-bomb defense)

The container/compressed input passes the existing import **size cap** unchanged, *before* anything is
parsed. On top of that, decompression is bounded by **two** hard limits, both validated + clamped
server-side ahead of the worker (CWE-400 / ADR-001 posture, mirroring every other bounded tool):

- an **absolute output cap** — the decompressed payload may not exceed a hard byte ceiling (a
  multiple of the capped input, and an absolute maximum); and
- a **decompression-ratio cap** — output ÷ input may not exceed a fixed ratio.

Whichever binds first **aborts the unwrap and fails closed** (`validation` / category-safe) — a bomb
never materializes a large buffer. Decompression is streamed against the output cap (abort on
overflow), never decompress-then-check. **Nested wrappers are bounded** by a small fixed unwrap-depth
limit (default: one level; container→payload, no recursion into the payload) so a wrapper-in-wrapper
chain cannot exhaust the parser. The per-analysis wall-clock kill (ADR-002) is the backstop.

### D4 — Keep the parse OUT of the server process (ADR-001)

Two admissible placements, in order of preference:

1. **Worker-only** where Ghidra/PyGhidra already provides the unwrap (Ghidra loads some of these
   forms natively) — the JVM edge parses inside the hardened, ephemeral, network-isolated worker
   container, never the server, `# pragma: no cover - JVM edge` as elsewhere. This is preferred for
   any format Ghidra covers.
2. **A tightly-bounded pure-Python parser** for the simple, well-specified headers/streams the worker
   does not cover (uImage header, gzip/xz/lzma streams via the stdlib decompressors under the D3
   caps). It runs **inside the worker process**, not the server, so a parser bug cannot touch the
   server or the host. It is small, allow-listed, fully fuzzed (Testing), and fails closed.

Either way the **server never parses container bytes** — it validates the `container` token, the size
cap, and the numeric caps, then routes to the worker. The standing operator directive holds: hostile
bytes are parsed only inside the container, never on the host.

### D5 — Contract delta routes through the frozen-contract process (WS0, atomic)

The new field touches `docs/contracts/tool-catalog.md` (the `session_import` row) and
`docs/contracts/rpc-protocol.md` (the `import` params + the two decompression caps). Per the CLAUDE.md
WS0 mandate those are **frozen contracts** — this ADR *proposes* the delta; the actual contract-file
edits land atomically with the schema change as one reviewed unit, not ad hoc. No catalog count change
(additive field on an existing tool, as ADR-045/065).

## Security / threat-model delta (`workflow-threat-model`, TB1 client→server + TB3 server→worker)

- **New untrusted-parser attack surface (the headline risk):** unwrapping runs a parser over
  attacker-controlled container bytes *before* Ghidra. This is the central reason the format set is a
  strict allow-list (D2), the parse is kept off the server (D4), and the parser is fuzzed (Testing).
- **Decompression bomb / DoS (CWE-400):** the absolute-output cap + ratio cap + unwrap-depth limit
  (D3) bound the unwrap before + inside the worker; streamed abort means no large buffer is ever
  allocated; the ADR-002 wall-clock kill is the backstop.
- **Malformed input (CWE-20):** magic-anchored, length-checked header parsing; any header/length/CRC
  inconsistency fails closed category-safe (ADR-005) — no binary-derived detail to the client.
- **Untrusted output (ADR-005):** the unwrapped payload is still hostile binary-derived data; nothing
  changes about how it is treated downstream (envelope-wrapped, never executed/rendered/followed).
- **No new agency (ADR-001/LLM08):** this only changes *how the existing import obtains a loadable
  image* — no new tool, no write capability, no script execution. Read-only import posture intact.
- **Trust boundary:** the container parse is pinned to the TB3 worker edge (D4); the server process
  never loads the JVM and never parses the binary/container.

## Alternatives considered

- **Unwrap on the host / in the server process** — rejected: violates ADR-001 and the standing
  operator directive; a bomb or parser bug would hit the server/host directly. The unwrap must live in
  the worker (D4).
- **A general "auto-detect + unwrap anything" engine** — rejected for v1.9: unbounded format sprawl is
  unbounded fuzz/DoS surface for little marginal value; the explicit allow-list + per-format increments
  (the ADR-046/047 model) is safer and matches ADR-045's rejection of heuristic detection.
- **Support vendor OTA (`AOTA`) formats now** — deferred: proprietary + under-specified; each is a
  bespoke parser best added one ADR/increment at a time behind the same caps once a real spec is in
  hand. The MVP proves the mechanism on well-specified formats first.
- **A separate `unwrap_container` tool** — rejected: duplicates the confinement/size-cap/digest logic
  and widens the catalog; an additive optional field on the existing import is smaller surface and
  matches the ADR-045/065 precedent.
- **Decompress-then-check the size** — rejected: that *is* the bomb. D3 streams against the output cap
  and aborts before materializing the payload.

## Consequences

- **Positive:** closes the "had to hand-unwrap the OTA before import" gap the T19 RE hit head-on;
  keeps the untrusted unwrap inside the container instead of on the operator's host; additive + opt-in
  so zero risk to the existing import paths; composes with ADR-065 for containers that yield multiple
  regions; establishes the capped-unwrap pattern future container formats reuse.
- **Negative / cost:** a new untrusted parser is a real security liability — it earns its keep only
  with the strict allow-list, hard caps, worker-only placement, and a **fuzz corpus** in CI; each new
  format is a new fuzz target. A pure-Python parser (D4 path 2) is new first-party attack surface that
  must stay small and 100%-covered (critical path).
- **Scope:** SemVer **minor** (additive, opt-in ingestion capability). Vendor OTA + heterogeneous /
  nested unwrap = future ADRs.

## Testing (master §4)

- **Unit:** schema validation — unknown `container` token rejected (allow-list); the output-cap,
  ratio-cap, and unwrap-depth limits clamped/enforced server-side before the worker; a malformed
  header (bad magic / inconsistent length / failed CRC) rejected category-safe; the no-container
  default proven a byte-for-byte no-op (params identical when the field is absent).
- **Decompression-bomb abuse (CWE-400):** a small high-ratio gzip/xz input must **abort at the cap**
  (`truncated`/`validation`, no large allocation) — proven with a synthetic bomb fixture built at test
  time; both the absolute-output cap and the ratio cap exercised; a nested wrapper past the depth
  limit rejected.
- **Fuzzing (master §4 abuse/fuzz — emphasized):** the new container/decompression parser is a
  first-class fuzz target (hypothesis / a corpus of mutated headers) — malformed, truncated, and
  adversarial inputs must never crash, hang, or over-allocate; always fail closed. This is a
  merge-gating requirement for the parser, tracked like the frame-decoder fuzz work.
- **Integration (gated real worker, live-regression):** build a **benign synthetic** `uImage`
  (`0x27051956`) wrapping a small gzip-compressed raw payload → import with `container="uimage"` →
  assert the payload is unwrapped, loaded, and analyzable (functions recovered); a standalone
  gzip-packed image imported with `container="gzip"` likewise. **No real firmware/malware in CI** —
  synthetic fixtures only (master §5). Add to the live-regression hard-gate list.

## Rollout

Additive + default-off → no migration; absence of `container` = today's behavior. Worker-side change
(and any pure-Python parser shipped in the worker) → needs a worker rebuild + `.github/
worker-image.pin` bump (per the worker-change-validation-recipe) before the live gate exercises it.
MVP = `uimage` + `gzip`/`xz`/`lzma` (+ `androidboot`); vendor-OTA and heterogeneous/nested unwrap are
follow-on increments behind the same allow-list + caps. Document in `getting-started.md`. Merge stays
**gated**.
