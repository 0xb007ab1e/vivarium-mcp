# Vivarium 0.14.0 — release notes (DRAFT)

> **Status: DRAFT.** Target version **0.14.0** (the v1.8 roadmap milestone). This is the candidate
> GitHub-release body; the release/tag is **gated** and cut only after PR #293 merges and the CI
> gates run green (currently pending the account-wide GitHub Actions billing lock). Finalize by
> stamping the date and promoting the CHANGELOG `[Unreleased]` section to `[0.14.0]`.

**Highlights:** broader Ghidra **loader coverage**, a batch of **read-only analysis tools**, and the
first **cross-binary** tools (two-program Version Tracking + cross-binary BSim). The Tier-1 tool
catalog grows **56 → 69**. No breaking changes; every addition is read-only or an opt-in/consent-gated
capability, and the containment model is unchanged.

---

## What's new

### Broader binary import (`session_import`)

Import the formats real firmware / mobile / Windows targets ship in. All loader hints are **additive
and opt-in** — with no hint set, import behaves byte-for-byte as before.

- **Headerless raw / firmware images** — `loader="binary"` with `processor` (a Ghidra `LanguageID`)
  + `base_addr` (and optional `entry`), for bare-metal MCU dumps. (ADR-045)
- **Intel-HEX / Motorola-SREC** hex-delivered firmware. (ADR-046)
- **Self-describing DEX / Mach-O / APK** — force the loader; the format carries its own layout.
  (ADR-047)
- **Fat / universal Mach-O** — select an arch slice by `processor`. (ADR-048)
- **Companion PDB symbols** — an optional `pdb_ref` (a second confined + size-capped path) applies a
  Microsoft PDB's function names/types to a freshly-loaded Windows PE **before analysis**, recovering
  the real symbols of a stripped binary. (ADR-061)

### Read-only analysis tools

- **`emulate`** — bounded p-code emulation (an interpreter; no native execution, syscalls, or I/O).
  (ADR-049)
- **`demangle`** — C++ symbol demangling (GNU/Itanium + MSVC), program-independent. (ADR-050)
- **`get_pcode` / `get_high_pcode`** — low and high (SSA) p-code listings. (ADR-052 / ADR-053)
- **`stack_frame`** — recovered stack-frame layout (locals/params with offsets, types, sizes).
  (ADR-054)
- **`basic_blocks`** — per-function control-flow graph (block ranges + successor edges). (ADR-055)
- **`list_data_types`** — paginated enumeration of the program's data types. (ADR-056)
- **`function_hash`** — Ghidra's exact function match-hashes (bytes / instructions / mnemonics) for
  duplicate detection. (ADR-057)
- **`bsim_similarity`** — fuzzy BSim cosine similarity between two functions. (ADR-058)
- **`find_similar_functions`** — whole-program BSim clone/variant search against a target. (ADR-059)

### Cross-binary tools (read-only w.r.t. the session)

These load their **own throwaway binaries** in the session's worker, analyze + compare them, then
wipe everything — the session's own program is never a participant, and there is **no persistent
store** (the stateless-worker guarantee is kept).

- **`version_track`** — two-program **Version Tracking**: correlate functions between two binaries
  (patch analysis / known-good comparison) via an allow-listed correlator. (ADR-060)
- **`bsim_search_corpus`** — cross-binary BSim search of a target's functions against an **ephemeral**
  corpus of reference binaries you pass in the call. (ADR-062)

### Structural write (consent-gated)

- **`apply_type_archive`** — apply a bundled Ghidra `.gdt` type archive (e.g. `generic_clib_64`) to
  set library prototypes. Gated by per-session write-consent, like every other mutation tool.
  (ADR-051)

---

## Security & containment

No change to the trust model: the server still never loads the JVM (ADR-001); one disposable worker
per session is verified-wiped on eviction (ADR-002); the worker runs rootless with gVisor, no egress,
read-only rootfs, dropped capabilities, and a wall-clock kill (ADR-004). New input surface — the
second/Nth binary for the cross-binary tools, the PDB parser, and the new loaders — is
**confined-root-resolved (CWE-22) and size-capped (CWE-400) before any byte reaches the JVM**, and
each is enumerated in a threat-model **TB3 delta**. All binary-derived output stays wrapped in the
untrusted-data envelope (ADR-005). No new egress, no new persistent store, no relaxed defaults.

## Upgrade notes

- **Backward-compatible.** No breaking changes; existing calls behave identically. The new loader
  hints and `pdb_ref` are opt-in — omitting them reproduces the prior import path exactly.
- The cross-binary tools (`version_track`, `bsim_search_corpus`) and PDB-companion import are gated
  like `session_import` (a capability: confined import root + size cap); they add **no** new
  write-consent surface — only `apply_type_archive` is a (consent-gated) structural write.
- Dependency bump: **cryptography 50.0.0** (PYSEC-2026-3552) and **mcp 1.28.1** (PYSEC-2026-3483) —
  both previously VEX not-affected, now upgraded.

## Deferred

- **DYLD shared-cache support** was scoped and **deferred** (ADR-063): the Ghidra loader is present
  and would work on a real cache, but there is no hermetic way to synthesize a test fixture (dyld
  caches can't be built off macOS, real ones are multi-gigabyte), and the ROI is low. To analyze a
  dylib from a shared cache today, extract it externally and import the Mach-O via `loader="macho"`.

## By the numbers

- Tier-1 tool catalog: **56 → 69**.
- ADRs: **ADR-045 … ADR-063** (each with a threat-model TB3 delta where it adds input surface).
- Every new tool proven live against a real hardened worker via a gated live-regression test.

_See [`CHANGELOG.md`](../CHANGELOG.md) for the itemized change list and
[`docs/roadmap-v1.8-findings.md`](roadmap-v1.8-findings.md) for the design/findings detail._
