# ADR-063: DYLD shared-cache support — DEFERRED (fixture-blocked)

- **Status:** **Deferred** (2026-08-13). Scoped at the operator's request; **not built** — the
  capability is ready but a hermetic test fixture is not feasible, and the ROI is low. This ADR
  records the scoping so the decision is not re-litigated from scratch.
- **Date:** 2026-08-13
- **Deciders:** Human operator (asked to scope the DYLD fixture problem, then to record the deferral);
  assistant scoped the loader + fixture feasibility live against the pinned worker.

## Context

Apple's **dyld shared cache** (`dyld_shared_cache_*`) packs the system dylibs into one large file so
they load fast. Reverse-engineering an iOS/macOS system library usually means pulling it out of a
shared cache. DYLD was the last item in the v1.8 loader/analysis bucket (after the loader-coverage
work ADR-045…048, the two-program tools ADR-060, the PDB companion ADR-061, and the cross-binary BSim
corpus ADR-062).

Unlike every other bucket item — each of which was grounded and then shipped — DYLD is **blocked on
the test fixture**, not on the capability. This ADR records why, so a future revisit starts from the
findings rather than re-discovering them.

## Findings (grounded live against the pinned worker, 2026-08-13)

### The capability is READY (loader present)

Ghidra's DYLD machinery is fully present in the pinned worker image and would work on a real cache:
`ghidra.app.util.opinion.DyldCacheLoader`, `DyldCacheProgramBuilder`, `DyldCacheUtils`;
`ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader` / `DyldCacheImageInfo` /
`DyldCacheMappingInfo` / `DyldArchitecture`; and `ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem`
for component extraction. Recognition is by a **16-byte signature** — `DYLD_V1_SIGNATURE_PREFIX =
"dyld_v1"`, `DYLD_V1_SIGNATURE_LEN = 16` — i.e. `dyld_v1  <arch>\0` for the allow-listed architectures
(x86_64, x86_64h, arm64, arm64e, arm64_32, armv7/7f/7k/7s, armv6, armv8a/8ae, ppc). So Vivarium is
**not** capability-blocked: a `pdb`-/`macho`-style loader path would drive this on real input.

### The fixture is BLOCKED (no hermetic way to make a cache)

A `dyld_shared_cache` is a **container-of-containers with cross-referenced addresses**, far harder to
synthesize than the self-describing single-file fixtures (ELF/PE/PDB/Mach-O) the other increments use:

- a large `dyld_cache_header` (dozens of interdependent offset/count fields: `mappingOffset/Count`,
  `imagesOffset/Count` + `…Old` variants, `imagesTextOffset/Count`, `mappingWithSlideOffset/Count`,
  slide-info, …);
- ≥1 `DyldCacheMappingInfo` (address, size, fileOffset, maxProt, initProt) that must **cover** the
  referenced addresses;
- ≥1 `DyldCacheImageInfo` (address → an embedded Mach-O header, pathFileOffset → a dylib path string);
- ≥1 embedded `MH_DYLIB` Mach-O at the mapped **unslid** address, plus the slide-info the parser walks.

For `DyldCacheProgramBuilder` to actually extract/load a component, all of the mappings, image text
ranges, unslid addresses, and slide-info must be **self-consistent**.

No hermetic source for such a file exists in this environment:

- **No macOS host.** Apple's cache builder `update_dyld_shared_cache` is macOS-only — confirmed absent.
- **No Linux builder.** Linux dyld tools (`ktool`, `dyldextractor`, `dsc_extractor`, …) **read**
  caches; they do not build them — and none are installed.
- **Real caches are unusable as fixtures:** multi-GB, non-committable, non-hermetic, require network to
  fetch — violating the project's "tests build their own deterministic synthetic inputs; no real
  binary samples in the repo/CI" policy (CLAUDE.md, master §5).
- **Ghidra ships no test cache** in the release (its DYLD tests rely on source-tree test resources, not
  distributed with the binary release).
- **Hand-synthesizing a minimal cache is the only hermetic path** — and it is a multi-day, fragile
  binary-format effort (nested structures + cross-referenced addresses/offsets/mappings/slide-info),
  versus the ~1-hour single-file fixtures the other increments used.

### ROI is low

The genuinely useful capability — extract/analyze a **component dylib** from a cache — is meaningful
only against **real** system caches. A synthetic 2-dylib cache would prove **loader wiring only**, not
real-world utility. Recognition-only (magic + an empty header — cheap to fixture) is useless for RE.
So the effort (high) is disproportionate to the incremental value (low) relative to the shipped v1.8
tools.

## Decision

**Defer DYLD shared-cache support.** Do not build it in v1.8. The v1.8 loader/analysis bucket is
otherwise **complete** (raw/hex/self-describing/Mach-O-slice loaders, p-code emulate, demangle,
type-archive apply, low/high p-code, stack-frame, basic-block CFG, data-type listing, function
match-hash, BSim similarity, whole-program BSim search, Version Tracking, PDB companion symbols,
cross-binary BSim corpus). DYLD is the single deferred item, **fixture-blocked, not capability-blocked**.

## If revisited later — the two viable paths (each needs an operator decision)

1. **Commit a small real cache test resource** — accept a real (or curated-minimal) dyld cache as a
   binary test fixture. This **relaxes** the synthetic-only test policy (operator sign-off required),
   and dyld caches are not small; it also reintroduces a real (if benign) Apple binary into the repo.
2. **Invest the synthetic-cache-builder** — a multi-day effort to hand-author a minimal, self-consistent
   `dyld_shared_cache` (header + mapping + image + embedded MH_DYLIB + slide-info) that
   `DyldCacheProgramBuilder` will load. Highest fidelity to the no-external-binaries policy, highest cost.

Either path would then follow the standard increment shape (ADR + threat-model TB3 delta for a
component-of-a-cache input, confined + size-capped like `session_import`, a `loader="dyld"` or a
component-selection tool, a gated live-regression test).

## Consequences

- **Positive:** no half-built, untestable DYLD path lands; the decision + findings are recorded so a
  future revisit is cheap; the v1.8 bucket closes cleanly.
- **Negative:** iOS/macOS shared-cache reverse-engineering is not supported in v1.8. Users needing it
  must extract the target dylib with external tooling first, then import the extracted Mach-O via the
  existing `loader="macho"` path (ADR-047/048).

## References

- ADR-047 (self-describing loaders incl. Mach-O), ADR-048 (fat/universal Mach-O slice selection) — the
  existing Mach-O import path a caller falls back to.
- Ghidra `DyldCacheLoader` / `DyldCacheFileSystem` (present in the pinned worker; would drive real input).
