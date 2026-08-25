# Vivarium 0.14.0 — release notes (2026-08-25)

> The v1.8 and v1.9 feature-milestone batches, plus rounds 11–12 of the security-hardening gap sweep,
> released together as **0.14.0**. (`v1.8`/`v1.9` are internal milestone labels, not package versions.)

**Highlights:** broader Ghidra **loader coverage**, two batches of **read-only analysis tools**, the
first **cross-binary** tools (two-program Version Tracking + cross-binary BSim), **data-flow slicing**,
**struct recovery**, **firmware secret/IOC scanning**, and **p-code emulation** with call/stub support.
The Tier-1 tool catalog grows **56 → 74** (58 read-only / 16 write). No breaking changes; every
addition is read-only or an opt-in/consent-gated capability, and the containment model is unchanged.

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

### v1.9 capability batch (ADR-064 … ADR-072)

A second batch closing capability gaps — all read-only or opt-in, same containment:

- **`data_flow_slice`** — bounded intra-function def-use slice over the decompiler SSA (backward =
  provenance, forward = uses); the missing primitive for vulnerability tracing. (ADR-064)
- **`recover_struct`** — propose a struct layout from access patterns off a base pointer
  (propose-only, never writes). (ADR-069)
- **`secret_scan`** — heuristic firmware secret scan, **redacted by construction** (masked preview +
  salted hash; the raw value never leaves the worker). (ADR-072)
- **`binary_diff`** — function-granularity two-program diff (`match_by` name / function_hash / BSim
  for stripped binaries; optional unchanged list). (ADR-067)
- **`deobfuscate_strings`** — recover stack-strings + in-place XOR-decoded strings (the decoder is
  emulated in the ADR-049 sandbox). (ADR-068)
- **Multi-region scatter-load** — `session_import` `regions=[…]` loads a headerless image into one
  program with N memory blocks at their bases. (ADR-065)
- **Container unwrap + detached debug info** — `container=` (gzip/xz/lzma/uImage, zip-bomb-capped) and
  `debug_format=` (linker/`nm` map or detached DWARF via `.gnu_debuglink`) on `session_import`.
  (ADR-070 / ADR-071)
- **`emulate` call/args/stubs** — call a function with argument placement + library-call stubs, so a
  self-contained routine runs to completion in the sandbox. (ADR-066)

### Hardening (gap-sweep rounds 11–12)

Rounds 11 and 12 of the adversarial gap sweep are folded in: a fixed `.gnu_debuglink` path-traversal
(CWE-22), bounded def-use/struct collection, a multi-region aggregate byte budget, sha256-verified
**fail-over mirrors** for the musl/zlib/openssl build fetches, the three hostile-input companion
parsers (`debuglink`/`uimage`/`debugmap`) promoted to the 100%-critical coverage set, a threat-model
STRIDE pass (§20) over the new parser/emulation/scanner surface, and assorted doc/contract
reconciliation. See the [CHANGELOG](../CHANGELOG.md) for the itemized list.

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

- Tier-1 tool catalog: **56 → 74** (58 read-only / 16 write).
- ADRs: **ADR-045 … ADR-072** (each with a threat-model TB3/TB4 delta where it adds input surface).
- Every new tool proven live against a real hardened worker via a gated live-regression test.

_See [`CHANGELOG.md`](../CHANGELOG.md) for the itemized change list and the archived
[v1.8 findings](archive/roadmap-v1.8-findings.md) for the design/findings detail._
