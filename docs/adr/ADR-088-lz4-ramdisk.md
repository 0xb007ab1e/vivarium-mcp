# ADR-088: lz4-compressed Android ramdisk support (standard + legacy frame)

- **Status:** **Proposed** (drafted 2026-11-05). Implements the ADR-085 lz4 follow-up (GH #414).
- **Date:** 2026-11-05
- **Deciders:** Human operator (chose "legacy + standard frame" scope); assistant built the pure
  legacy-frame parser + the worker decode path + the vetted `lz4` dependency.
- **Context source:** ADR-085 (#380) shipped `container_region="ramdisk"` for gzip / xz /
  uncompressed-cpio and **failed closed on lz4** (stdlib has no lz4), tracking it as #414. This ADR
  adds lz4.

## Context

Android/kernel ramdisks are frequently **lz4**-compressed — and overwhelmingly in the **legacy**
lz4 frame format (`02 21 4c 18`), which `python-lz4`'s `lz4.frame` API does **not** decode (it only
handles the **standard** lz4 frame `04 22 4d 18`). Covering real Android lz4 ramdisks therefore needs
both: standard frame via `lz4.frame`, and a hand-rolled legacy-frame decoder over `lz4.block`.

## Decision

### D1 — Detect both lz4 frame formats

`core.androidboot.detect_ramdisk_codec` gains two codecs: `"lz4"` (standard frame magic
`04 22 4d 18`) and `"lz4-legacy"` (legacy frame magic `02 21 4c 18`). Any other leading bytes still
return `None` (fail closed).

### D2 — Standard frame via `lz4.frame` (streamed under the bomb cap)

The worker's decompressor factory (`_open_comp`, ADR-070) opens a `"lz4"` ramdisk with
`lz4.frame.open(path, "rb")` — a file-like streaming reader fed into the existing
`_stream_to_payload` zip-bomb cap (output ceiling + output÷input ratio), exactly like gzip/xz.

### D3 — Legacy frame via a pure parser + `lz4.block`

The legacy frame (magic + repeated `[u32 compressed_block_size][block]`, each block ≤ 8 MiB
uncompressed) has no stdlib or `lz4.frame` decoder. A new **pure** `core.lz4legacy.parse_legacy_frame`
validates the magic + walks the block records, validating each `u32` size against the remaining
buffer before advancing, and returns the bounded list of `(offset, size)` block spans — it never
decompresses, never over-reads, is total on arbitrary bytes (a validated list or a typed
`Lz4LegacyError`), and is adversarially fuzzed. The worker (`_Lz4LegacyReader`) decompresses each
span with `lz4.block.decompress(..., uncompressed_size=8 MiB)` and serves the result through
`_stream_to_payload` under the same bomb cap.

### D4 — Vetted dependency (`lz4`, supply chain)

Add `lz4` (python-lz4, BSD-3-Clause, a widely-used C extension) to the pinned, hash-locked runtime
dependencies (`requirements.lock` via `pip-compile --generate-hashes`) — vetted (no typosquat;
canonical PyPI name) and captured in the worker-image SBOM. It is imported only inside the worker
(`_jvm_bridge`, `# pragma: no cover`); `core.lz4legacy` (the framing parser) has **no** `lz4` import,
so it is hermetically fuzzable without the dependency.

### D5 — Bounds (CWE-400/20/190)

`parse_legacy_frame` caps the block count; each block's `uncompressed_size` is capped at 8 MiB; the
streamed output stays under the ADR-070 bomb cap (ceiling + ratio) and the ADR-002 wall-clock kill.
A corrupt/hostile lz4 stream fails closed (`limit-exceeded` on a bomb, `not-found` on malformed).

## Security / threat-model delta

- **New untrusted input (ADR-005 / TB3):** lz4 ramdisk bytes are hostile; the legacy framing parser
  is pure + fuzzed + fail-closed, the decode is bounded + bomb-capped, and runs only in the worker.
  No new trust boundary (an existing `container`-unwrap codec).
- **Supply chain:** one new vetted, hash-pinned, SBOM'd dependency (`lz4`). It adds a C extension to
  the image; it is a mature, popular, OSI-licensed package.
- **DoS (CWE-400):** block-count cap + 8 MiB per-block output cap + the ADR-070 bomb cap + the
  wall-clock kill bound the decode; a bomb never materializes (streamed, not buffered-whole).

## Alternatives considered

- **Standard frame only** — rejected by the operator: misses the common Android legacy-lz4 case.
- **Shell out to the `lz4` CLI** — rejected: a subprocess on hostile bytes + a non-Python dependency;
  the library + pure framing parser is tighter and testable.
- **Defer (keep failing closed)** — rejected by the operator: lz4 ramdisks are common enough to
  warrant the vetted dependency.

## Consequences

- **Positive:** real Android lz4 ramdisks (legacy + standard) are surfaced by
  `container_region="ramdisk"` (and then by `ramdisk_list`, ADR-087); the legacy framing parser is
  hermetically fuzzed.
- **Negative / cost:** one new C-extension dependency (image size + supply-chain surface); a
  worker-edge decode path (`# pragma: no cover`) validated via the gated live-regression.
- **Scope:** SemVer **minor** (additive codec). lz4 with an unusual block size or dictionary is out
  of scope (the legacy/standard ramdisk cases are covered); a nested double-compression is not
  auto-unwrapped.

## Testing (master §4)

- **Unit (hermetic):** `core.lz4legacy` — happy path (magic + block spans), abuse (bad magic,
  truncated block size, oversized block, block cap) + a **Hypothesis fuzz** proving total/fail-closed
  on arbitrary bytes; `detect_ramdisk_codec` recognises both lz4 magics.
- **Integration (gated real worker, live-regression):** build an androidboot image whose ramdisk is a
  **legacy-lz4** cpio, import `container_region="ramdisk"`, and assert a known string is recovered
  (slice → lz4-legacy decode → raw cpio load); likewise a **standard-frame** lz4 ramdisk. Added to
  the live-regression hard-gate list at the worker repin.
- **Abuse:** a corrupt lz4 stream fails closed; an lz4 bomb trips the cap (`limit-exceeded`).

## Rollout

Additive codec + one vetted hash-pinned dependency → no migration, but the lockfile + worker image
change, so it needs a worker rebuild + pin bump (per the worker-change-validation-recipe) before the
live gate exercises it. Reuses the ADR-070 bomb cap + the ADR-085 ramdisk slice. Merge stays
**gated**.
