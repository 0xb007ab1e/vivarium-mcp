# ADR-086: DYLD shared-cache component import (`loader="dyld"` + `dyld_component`)

- **Status:** **Proposed** (drafted by the assistant 2026-11-05; **supersedes the deferral in ADR-063**
  now that the fixture blocker is solved — GH #369). Awaiting human ratification.
- **Date:** 2026-11-05
- **Deciders:** Human operator (asked to source a dyld fixture, then to build the loader); assistant
  cracked the hermetic synthetic-cache fixture live against the pinned worker and scoped the loader.
- **Context source:** ADR-063 deferred DYLD support as **fixture-blocked, not capability-blocked** —
  Ghidra's `DyldCacheFileSystem` is present and would work on a real cache, but no hermetic way to
  make a cache existed. That blocker is now **solved**: a pure, deterministic
  `synthetic_dyld_shared_cache` builder (`tests/_fixtures/binaries.py`) produces a minimal cache that
  Ghidra mounts and extracts a valid component Mach-O from (proven live). This ADR builds the loader.

## Context

Apple's dyld shared cache packs the system dylibs into one file; RE of an iOS/macOS library means
pulling the target dylib out of a cache. Ghidra models a cache as a **filesystem**
(`DyldCacheFileSystem`): mount → list component dylibs → extract one → it is a standalone Mach-O.
Vivarium analyzes one binary per session, so the dyld surface is **component selection**: the caller
names a component, the worker extracts it, and it is imported via the existing Mach-O path (ADR-047).

The fixture crack (recorded so it is not re-derived): Ghidra's `SplitDyldCache.getMacho` reads a
component at `imageAddress − cacheBaseAddress` — a **linear** address→file-offset model, *not* the
mapping's `fileOffset`. So a mountable synthetic cache needs one mapping covering the file from offset
0 at the base address, the image address = base + the embedded Mach-O's file offset, and the embedded
`MH_DYLIB` there. ADR-063's "multi-day, fragile, impossible" assessment is overturned.

## Decision

### D1 — `loader="dyld"` + `dyld_component`: extract one component, import it as Mach-O

Add `"dyld"` to the `session_import` `loader` enum and a `dyld_component` string field. With
`loader="dyld"` the worker mounts the (confined, size-capped) cache via `DyldCacheFileSystem`,
extracts the component named by `dyld_component`, and imports the extracted Mach-O via Ghidra's
Mach-O loader — producing one program for that dylib, analyzable with every existing read tool.

### D2 — Discovery: omitting `dyld_component` lists the components

`dyld_component` is optional. When omitted, the worker mounts the cache and fails closed with a
**category-safe listing** of the available component paths (bounded) — so a caller discovers the
contents without a separate tool, then re-imports with a chosen `dyld_component`. (A dedicated
read-only listing tool is a possible future refinement; the error-listing is the minimal surface.)

### D3 — Confinement + bounds (TB3, CWE-22/400)

The cache file is confined + size-capped **before the worker** exactly like every other
`session_import` input. `dyld_component` is validated against the **mounted filesystem's own listing**
(the caller cannot name an arbitrary host path — the lookup is inside the Ghidra GFileSystem, not the
host FS); a component not in the cache fails closed `not-found`. The component-listing is bounded
(`_DYLD_MAX_COMPONENTS`). All mounting/extraction/parsing of the hostile cache stays in the worker
(ADR-001/D4); the server never touches the bytes.

### D4 — Loader-hint rules (fail-closed, server-side)

`loader="dyld"` REQUIRES no `processor`/`base_addr`/`entry` (the extracted Mach-O carries its own
arch + layout — same as the self-describing `dex`/`macho`/`apk` loaders, ADR-047); those hints are
rejected. `dyld_component` is only valid with `loader="dyld"`. Mutually exclusive with `regions` and
`container`. Validated server-side before the worker (CWE-20).

### D5 — Contract delta (WS0, atomic)

Additive: `SessionImportIn.loader` enum += `"dyld"`; new `dyld_component?: str`. No tool-count
change (it is an import loader mode). `docs/contracts/tool-catalog.md` +
`docs/contracts/rpc-protocol.md` note the loader + the discovery/extract flow + constraints.

## Security / threat-model delta

- **New untrusted input (ADR-005 / TB3):** a dyld shared cache is hostile-origin like every import —
  confined + size-capped before the worker; mounted + parsed only in the worker container; a
  corrupt/hostile cache fails closed (`not-found`/category-safe). No new trust boundary (it is a
  `session_import` input).
- **Path confinement (CWE-22):** `dyld_component` resolves inside the Ghidra GFileSystem's own
  listing, never the host filesystem — it cannot escape to a host path; an unknown component is
  rejected.
- **DoS (CWE-400):** the cache size cap + the component-listing bound + the ADR-002 wall-clock kill
  bound the mount/extract. The extracted component is itself size-bounded by the cache.
- **No new execution surface:** the extracted Mach-O is loaded + analyzed by the existing Mach-O
  path; nothing is executed. The DYLD machinery is Ghidra's, present in the pinned worker.
- **Trust boundary unchanged:** mount + extract + Mach-O load are the TB3 worker edge; the server
  never parses the cache.

## Alternatives considered

- **Load the whole cache as one program** — rejected: Ghidra models a cache as a filesystem, not a
  single-program loader (`open_program` on a cache fails); component extraction is the supported +
  useful path (one target dylib, not the whole system).
- **A separate `list_cache_components` tool** — deferred: the omit-`dyld_component` error-listing is
  the minimal discovery surface; a dedicated tool can follow if a workflow needs it.
- **Keep deferring (ADR-063)** — rejected: the fixture blocker is solved, so the ROI calculus flips —
  a hermetic, gated-testable dyld path is now feasible.

## Consequences

- **Positive:** iOS/macOS shared-cache RE is supported — extract + analyze a component dylib — within
  the existing import model + the ratified Mach-O loader; the hermetic synthetic fixture makes it
  gated-testable (closing ADR-063's gap). No new execution surface.
- **Negative / cost:** a new JVM-edge mount/extract path (`# pragma: no cover`) validated via the
  gated live-regression (worker rebuild + pin bump). A real multi-subcache / slid cache has more
  structure than the synthetic fixture exercises (the fixture proves the wiring; real caches exercise
  the rest via Ghidra's own machinery).
- **Scope:** SemVer **minor** (additive loader mode). A dedicated component-listing tool + split-cache
  nuances are possible follow-ups.

## Testing (master §4)

- **Unit (hermetic):** `synthetic_dyld_shared_cache` builds deterministically with the right magic,
  single mapping (fileOffset 0 at base), one image at base+offset, and an embedded `MH_DYLIB`; schema
  — `loader="dyld"` accepts `dyld_component`, rejects `processor`/`base_addr`/`entry`, and is mutually
  exclusive with `regions`/`container`.
- **Integration (gated real worker, live-regression):** import `dyld_component="/usr/lib/libviv.dylib"`
  from the synthetic cache with `loader="dyld"` → assert the program loads as Mach-O (the component is
  analyzable); import with `dyld_component` omitted → assert the error lists the component. Added to
  the live-regression hard-gate list at the worker repin.
- **Abuse:** a `dyld_component` not in the cache fails closed (`not-found`); a corrupt/hostile cache
  fails closed category-safe; the mount/extract stays bounded (size cap + wall-clock kill).

## Rollout

Additive loader mode → no migration. Worker-side change → needs a worker rebuild + pin bump (per the
worker-change-validation-recipe) before the live gate exercises it. Reuses Ghidra's DYLD + Mach-O
machinery (present in the pinned worker); no new execution. Supersedes ADR-063's deferral. Merge
stays **gated**.
