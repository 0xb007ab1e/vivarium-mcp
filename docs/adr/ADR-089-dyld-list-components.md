# ADR-089: `list_cache_components` discovery tool + slid-cache coverage

- **Status:** **Proposed** (drafted 2026-11-05). Implements the ADR-086 follow-ups GH #418 + #419.
- **Date:** 2026-11-05
- **Deciders:** Human operator (asked to address the open ADR-086 follow-ups; chose the slid-variant +
  documented-multi-subcache scope for #419); assistant built the tool + the slid coverage.
- **Context source:** ADR-086 shipped `loader="dyld"` with discovery via the **omit-`dyld_component`
  error-listing** (#418 asked for a first-class tool) and validated extraction against a **single**
  hermetic cache (#419 asked for multi-subcache / slid coverage).

## Context

ADR-086's dyld discovery is error-as-control-flow: a caller imports with no `dyld_component`, catches
the `invalid-params` error, reads the listing from the message, then re-imports. A dedicated
read-only tool lists a cache's components cleanly, before any import, in the session the caller will
import into. Separately, the ADR-086 live gate exercises one hermetic single-mapping cache at the
default base; a non-zero ("slid") base should also be proven.

## Decision

### D1 — `list_cache_components`: a read-only cache-discovery tool (#418)

Add one Tier-1 **read-only** tool `list_cache_components(session_id, source_ref, offset?, limit?)` →
`CacheComponentsOut{components[path], total, truncated}`. It mounts the (server-confined, size-capped)
dyld shared cache with Ghidra's `DyldCacheFileSystem` in the session's worker, enumerates the
component dylib paths (bounded by `_DYLD_MAX_COMPONENTS`, paginated), and returns them — **no program
is loaded or mutated**. The mount/walk is the same code the ADR-086 import-discovery path uses,
factored into a shared `_dyld_walk_components` helper.

### D2 — Confinement + bounds (TB3, CWE-22/400)

`source_ref` is resolved + confined + size-capped **server-side before the worker**, exactly like
`session_import` (reusing `_resolve_and_cap`); the component paths come from the Ghidra GFileSystem's
own listing, never the host FS. A non-cache / corrupt input fails closed `not-found`; the listing is
bounded + paginated. Read-only, session-authorized (BOLA): the caller must own the session.

### D3 — Slid-cache coverage + documented multi-subcache deferral (#419)

The `synthetic_dyld_shared_cache` builder already parameterizes `base_address` — the extraction math
is base-relative (`getMacho` reads a component at `imageAddress − cacheBaseAddress`), so a non-zero
/"slid" base must still resolve. Add a hermetic **slid** case (a non-default base) proving the
extraction is slide-correct (not hardcoded to the default base). **Multi-subcache** (the sibling
`.1`/`.symbols` `SplitDyldCache` model) is **deferred**: it is Ghidra's own machinery (covered by
Ghidra's test suite), a hermetic sibling-file synthetic is fragile, and our wiring is proven by the
single-cache + slid hermetic gates; a real multi-subcache is a manual acceptance check (re-open if a
real target fails).

### D4 — Contract delta (WS0, additive)

New tool `list_cache_components` (catalog 80 → 81). New schemas `CacheComponentsIn` /
`CacheComponentsOut` — `path`/`components` are binary-derived → wrapped UNTRUSTED (ADR-005).
`docs/contracts/tool-catalog.md` gains the row + the count bump.

## Security / threat-model delta

- **Untrusted input (ADR-005 / TB3):** the cache is hostile — confined + size-capped before the
  worker, mounted/parsed only in the worker, listing bounded + fail-closed. No new trust boundary
  (a `session_import`-class input, read-only).
- **Path confinement (CWE-22):** `source_ref` is server-confined; component paths are inside the
  Ghidra GFileSystem, never a host path.
- **DoS (CWE-400):** size cap + `_DYLD_MAX_COMPONENTS` + pagination + the ADR-002 wall-clock kill.
- **No new execution / write surface:** read-only; no program is loaded; nothing is executed.

## Alternatives considered

- **Keep the error-listing only** — rejected by the operator (address #418): a clean tool beats
  error-as-control-flow.
- **A standalone (session-less) tool** — rejected: every tool is session-authorized; mounting in the
  session's worker reuses the lifecycle + confinement, and the caller imports into that session next.
- **Full multi-subcache synthetic (#419)** — deferred: fragile hermetic fixture for Ghidra-owned
  machinery; slid coverage + a documented manual real-cache check is the pragmatic scope.

## Consequences

- **Positive:** clean cache discovery before import; the extraction is proven slide-correct; the
  mount/walk is DRY (shared helper).
- **Negative / cost:** +1 tool; a new JVM-edge method (`# pragma: no cover`) validated via the gated
  live-regression (worker rebuild + pin bump).
- **Scope:** SemVer **minor** (additive read-only tool). Multi-subcache coverage remains a documented
  deferral.

## Testing (master §4)

- **Unit (hermetic):** schema (`list_cache_components` accepts `source_ref`; pagination bounds);
  the `synthetic_dyld_shared_cache` **slid** case (non-default base → `imageAddress − base` still
  equals the embedded Mach-O offset).
- **Integration (gated real worker, live-regression):** `list_cache_components` on the synthetic
  cache returns the component path; and an import from a **slid** cache loads the component. Added to
  the live-regression hard-gate list at the worker repin.
- **Abuse:** `list_cache_components` on a non-cache fails closed `not-found`.

## Rollout

Additive read-only tool → no migration. Worker-side change → needs a worker rebuild + pin bump before
the live gate exercises it. Reuses the ADR-086 mount + the existing `source_ref` confinement. Merge
stays **gated**.
