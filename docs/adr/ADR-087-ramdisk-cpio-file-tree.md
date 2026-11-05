# ADR-087: Android ramdisk cpio file-tree + per-file extract (`ramdisk_list`)

- **Status:** **Proposed** (drafted 2026-11-05). Implements the ADR-085 Scope-B follow-up (GH #415).
- **Date:** 2026-11-05
- **Deciders:** Human operator (asked to work the ADR-085 ramdisk follow-ups); assistant scoped +
  built the pure cpio parser + the read-only tool.
- **Context source:** ADR-085 (#380) shipped `container_region="ramdisk"` as **Scope A** — the raw
  decompressed cpio bytes surfaced as a flat image for string/byte triage — and explicitly deferred
  **Scope B** (a structured file tree + per-file extraction) to #415. This ADR builds Scope B.

## Context

An Android ramdisk is a (usually compressed) cpio `newc` / `newc-crc` filesystem. Scope A lets a
caller `list_strings` / `read_bytes` over the flat image, but there is no structured view: which
files exist, their sizes/types, and where each file's bytes sit. RE of a ramdisk (find `init.rc`,
a keyfile, a service binary) wants the tree.

## Decision

### D1 — `ramdisk_list`: a read-only cpio file-tree tool

Add one Tier-1 **read-only** tool `ramdisk_list(session_id, offset?, limit?, max_entries?)` →
`RamdiskListOut{entries[{path, size, mode, kind, address}], total, truncated}`. It parses the cpio
members of the **currently-loaded ramdisk program** (a Scope-A `container_region="ramdisk"` import —
a flat decompressed cpio image) and returns each member's path, size, `st_mode`, `kind`
(`file`/`dir`/`symlink`/`other`), and the **hex program address** of its data.

### D2 — Per-file extract composes with `read_bytes` (no new tool)

Each entry carries the absolute program `address` of its data + its `size`; a caller extracts one
file with the existing `read_bytes(address, size)`. No dedicated extract tool — the tool count grows
by exactly 1 (79 → 80), and the untrusted-byte return path is the already-ratified `read_bytes`.

### D3 — Pure, fuzzed cpio parser in the functional core

The parse is a pure `core.cpio.parse_newc_entries(data, *, max_entries)` — it walks the `newc`/
`newc-crc` member headers, validates every length against the remaining buffer before advancing, and
returns bounded `CpioEntry` metadata; it **never materializes a member's data**, never recurses, and
is total on arbitrary bytes (a validated list or a typed `CpioError`). The member bytes are hostile
(ADR-005): the parser is adversarially fuzzed (Hypothesis) to prove the fail-closed contract. The
worker reads the flat image and calls the core; the server never parses the cpio.

### D4 — Bounds (CWE-20/400/190)

`max_entries` caps the member count; a 256 MiB image-scan cap bounds the worker-side read of the
flat image; every header field is validated against the buffer (no over-read / over-allocation). A
program that is not a well-formed cpio `newc` archive fails closed `not-found` (category-safe) — the
tool only makes sense on a ramdisk import, and says so honestly rather than returning garbage.

### D5 — Contract delta (WS0, additive)

New tool `ramdisk_list` (+1). New schemas `RamdiskListIn` / `RamdiskEntry` / `RamdiskListOut` — the
`path` is wrapped UNTRUSTED (binary-derived name, ADR-005); `size`/`mode`/`kind`/`address` are safe.
`docs/contracts/tool-catalog.md` gains the row + the count bump (80).

## Security / threat-model delta

- **Untrusted input (ADR-005 / TB3):** the cpio bytes are hostile; the pure parser is fuzzed +
  fail-closed, the member names are returned UNTRUSTED. No new trust boundary (it reads an
  already-loaded program, like `list_strings`).
- **DoS (CWE-400):** `max_entries` + the 256 MiB scan cap + the ADR-002 wall-clock kill bound the
  parse; member data is never materialized.
- **No new execution / write surface:** read-only; the program DB is not mutated; no bytes are
  executed. Same capability class as `list_strings`/`read_bytes`.

## Alternatives considered

- **A dedicated `ramdisk_extract(path)` tool** — rejected: `read_bytes` at the returned address+size
  already extracts one file; a second tool is surface without capability.
- **Parse at import time + stash the tree** — rejected: stateful + couples the loader to the tree; a
  read-only tool over the loaded image is cleaner and reuses the existing read path.
- **Server-side parse over client-fetched bytes** — rejected: pushes the whole image over the wire
  and scatters the hostile-parse; the worker already holds the bytes.

## Consequences

- **Positive:** a structured ramdisk file tree + clean per-file extract, within the existing import
  + read model; the pure cpio parser is hermetically fuzz-tested (no worker needed for the core).
- **Negative / cost:** +1 tool; a new JVM-edge method (`# pragma: no cover`) that reads the flat
  image + calls the core, validated via the gated live-regression (worker rebuild + pin bump).
- **Scope:** SemVer **minor** (additive read-only tool). lz4 ramdisks (#414) are orthogonal (a codec,
  ADR-085 follow-up); a nested-archive / recursive-unpack tree is a possible future refinement.

## Testing (master §4)

- **Unit (hermetic):** `core.cpio` — happy path (files/dirs/symlinks, order, offsets, newc-crc),
  abuse (bad magic, missing trailer, oversized name/filesize, non-hex field, entry cap), and a
  **Hypothesis fuzz** proving total/fail-closed on arbitrary bytes + a well-formed round-trip. A
  deterministic `cpio_newc_archive` fixture builder.
- **Integration (gated real worker, live-regression):** build an androidboot image whose ramdisk is
  a gzip cpio with known files, import `container_region="ramdisk"`, call `ramdisk_list`, assert the
  tree (names/kinds/sizes) and that `read_bytes` at an entry's address recovers its content. Added to
  the live-regression hard-gate list at the worker repin.
- **Abuse:** `ramdisk_list` on a non-cpio program fails closed `not-found`.

## Rollout

Additive read-only tool → no migration. Worker-side change → needs a worker rebuild + pin bump (per
the worker-change-validation-recipe) before the live gate exercises it. Reuses the ADR-085 ramdisk
import; no new execution. Merge stays **gated**.
