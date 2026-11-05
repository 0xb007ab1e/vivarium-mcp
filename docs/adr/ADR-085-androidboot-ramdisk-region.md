# ADR-085: Android boot-image ramdisk region (`session_import` `container_region`)

- **Status:** **Proposed** (drafted by the assistant 2026-11-05; closes the ADR-070 androidboot
  ramdisk deferral tracked as GH #380). Awaiting human ratification.
- **Date:** 2026-11-05
- **Deciders:** Human operator (ratification pending); drafted by the assistant from GH #380.
- **Context source:** ADR-070's androidboot container loader surfaces the **kernel** region for
  analysis and explicitly deferred the **ramdisk** — a (usually compressed) cpio *filesystem*, not
  loadable code — to "a separate filesystem-extract capability." #380 (ramdisk) is that follow-on.

## Context

An Android boot image is `header | kernel | ramdisk | second`. The ADR-070 loader
(`container="androidboot"`) parses the `ANDROID!` header (pure `core.androidboot`) and slices the
**kernel** as the loadable payload. The header parse already computes the **ramdisk** window
(`ramdisk_offset`/`ramdisk_size`); it is simply not surfaced. The ramdisk holds the initramfs — init
scripts (`init.rc`), configs, keys, small binaries — exactly the content RE triage wants.

Vivarium analyzes one binary per session, so a *filesystem* does not map cleanly onto a program. The
pragmatic, architecture-fitting surface for triage is to **load the decompressed ramdisk bytes as a
flat binary**: `list_strings` / `search_strings` / the `deobfuscate_strings` family then recover the
file names, script text, embedded strings and keys. The structured cpio file-tree (listing + per-file
extraction) is a larger, separate capability (Scope B) deferred to a future ADR.

## Decision

### D1 — `container_region` selects the androidboot region

Add an optional `container_region: "kernel" | "ramdisk"` to the import spec. For
`container="androidboot"` it chooses which region the loader surfaces; it defaults to `"kernel"`
(the pre-ADR-085 behavior, fully backward-compatible) and is ignored for other containers. With
`container_region="ramdisk"` the loader slices the page-aligned ramdisk window and surfaces its
**decompressed** bytes as the payload (loaded raw).

### D2 — Decompress the ramdisk (reuse ADR-070 streaming) or pass raw cpio

The sliced ramdisk is codec-detected by magic (pure `core.androidboot.detect_ramdisk_codec`):
**gzip** (`1f 8b`) and **xz** (`fd 37 7a 58 5a 00`) are streamed through the existing ADR-070
bomb-capped decompressor; an **uncompressed cpio newc** archive (`070701`/`070702`) is passed through
raw. Any other codec (notably **lz4**, which Android frequently uses — stdlib has no lz4, so it needs
a dependency) is **rejected** with a clear category-safe error and tracked as a separate follow-up.
The same streamed, zip-bomb output cap (ADR-070 D3) bounds the decompression — a ramdisk bomb never
materializes.

### D3 — Raw load; no cpio parsing (Scope A)

The decompressed ramdisk bytes are loaded as a **flat binary** (the existing payload pipeline). No
cpio structure is parsed in this ADR — the value is the recoverable *content* (names, scripts, keys,
strings). A structured cpio parser + file listing + per-inner-file extraction is **Scope B**, a
future ADR (filesystem-extract proper).

### D4 — Bounds + fail-closed

`ramdisk_size == 0` (no ramdisk) and an empty/past-EOF window fail closed (`ValueError` →
category-safe). The decompression is bounded by the ADR-070 `max_decompressed_bytes` /
`max_decompression_ratio` caps + the ADR-002 wall-clock kill. An unsupported codec fails closed. All
parsing stays in the worker (ADR-001/D4); the server never touches the bytes.

### D5 — Contract delta (WS0, atomic)

Additive, backward-compatible: the import spec gains `container_region?: "kernel" | "ramdisk"`
(default `kernel`). No new tool. `docs/contracts/tool-catalog.md` + `docs/contracts/rpc-protocol.md`
note the selector and the ramdisk constraints (gzip/xz/raw-cpio; lz4 unsupported; raw load).

## Security / threat-model delta

- **Untrusted input (ADR-005 / TB3):** the ramdisk is hostile-origin, like every container payload —
  parsed + decompressed only in the worker, bounded by the ADR-070 caps + the wall-clock kill. The
  decompressed bytes are loaded raw and treated as untrusted program content; nothing is executed.
- **DoS (CWE-400):** the ramdisk decompression reuses the ADR-070 streamed zip-bomb cap (output ÷
  input ratio + absolute cap); a malicious ramdisk cannot inflate unbounded. The slice is bounded by
  the header's capped `ramdisk_size` and the real file size (no over-read).
- **No new execution surface:** raw load only — no cpio interpretation, no execution; the existing
  loader + read tools operate on the bytes.
- **Fail-closed:** no ramdisk / empty window / unsupported codec → category-safe error, never a
  partial or guessed result.
- **Trust boundary unchanged:** header parse + slice + decompress + load are the TB3 worker edge; the
  server never parses the image.

## Alternatives considered

- **A full cpio parser + file listing + per-file extraction (Scope B)** — deferred: a materially
  larger capability (new hostile-fuzzed parser, a listing surface, an inner-file selection API) and
  the ADR-070 "filesystem-extract" proper. Scope A (raw load) delivers the core triage value now.
- **Decompress-then-check instead of streamed** — rejected: violates ADR-070 D3 (a bomb would
  materialize); the streamed cap is reused.
- **Support lz4 now** — rejected: stdlib has no lz4; adding a dependency for it is a separate,
  vetted supply-chain change (follow-up). gzip/xz/raw-cpio cover the common cases.
- **A separate `container="androidboot_ramdisk"` value** — rejected: a `container_region` selector is
  cleaner and keeps the single androidboot container entry.

## Consequences

- **Positive:** unblocks ramdisk triage (names, `init.rc`, configs, keys, embedded strings) with a
  small, architecture-fitting change that reuses the ADR-070 decompression pipeline; the kernel path
  is unchanged (default).
- **Negative / cost:** a flat raw load (no file structure) — a specific inner file is not individually
  analyzable yet (Scope B). lz4 ramdisks are unsupported pending a dependency. A worker-edge change to
  validate via the gated live-regression.
- **Scope:** SemVer **minor** (additive, backward-compatible — `container_region` defaults to
  `kernel`). Scope B (cpio file-tree + per-file extract) + lz4 remain future work.

## Testing (master §4)

- **Unit (hermetic):** `detect_ramdisk_codec` maps the gzip/xz/cpio magics and returns `None` for
  lz4/unknown (fuzz: arbitrary bytes never raise). Schema: `container_region` accepts `kernel` /
  `ramdisk`, defaults to `kernel`, rejects other values. The pure header parser's `ramdisk_offset`/
  `ramdisk_size` are already covered.
- **Integration (gated real worker, live-regression):** a synthetic androidboot image whose ramdisk
  is a **gzip-compressed cpio** containing a known file (`init.rc` with a marker string) → import
  with `container_region="ramdisk"` and assert the marker string is recovered (`list_strings`);
  assert the default (kernel) import still loads the kernel (regression). Added to the live-regression
  hard-gate list at the worker repin.
- **Abuse:** a ramdisk-bomb (high-ratio gzip) is capped (`limit-exceeded`); an image with no ramdisk
  / an unsupported (lz4) ramdisk fails closed; a header claiming a ramdisk past EOF never over-reads.

## Rollout

Additive + backward-compatible (`container_region` defaults to `kernel`) → no migration. Worker-side
change → needs a worker rebuild + `.github/worker-image.pin` bump (per the
worker-change-validation-recipe) before the live gate exercises it. Reuses the ADR-070 decompression;
raw load, no new execution. Merge stays **gated**.
