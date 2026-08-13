# ADR-048: `session_import` loader options — fat-Mach-O slice + DYLD-component selection

- **Status:** **Accepted** (ratified 2026-08-12). **D1/D2 (fat-Mach-O slice selection) IMPLEMENTED +
  live-proven.** **D3 (DYLD component selection) ratified in principle but IMPLEMENTATION-BLOCKED on a
  real fixture** — see D3. Increment 5 of the "expose more Ghidra loaders" program (after ADR-045
  raw, ADR-046 hex, ADR-047 self-describing).
- **Date:** 2026-08-12
- **Deciders:** Human operator (ratifies); assistant drafted + grounded.
- **Context source:** ADR-047 recorded that fat-Mach-O slice / DYLD-component selection was
  unreachable because `pyghidra.open_program` has no loader-options parameter. This ADR grounds the
  path that *does* work and designs the change.

## Context (grounded)

Two capabilities remain unreached:

- **Fat/universal Mach-O** loads only its **default (first) slice** via `loader="macho"`; there is no
  way to pick a specific arch slice.
- **DYLD shared cache** holds hundreds of dylibs; a useful load must select **one component by name**.

Neither is expressible through `pyghidra.open_program` (no options param; and its `language` arg is
**ignored** for Mach-O slice selection — verified: all three of default / x86 / aarch64 returned the
arm64 slice).

**What works (verified live in the worker):** `pyghidra.program_loader()` returns a
`ghidra.app.util.importer.ProgramLoader.Builder` with `.source()`, `.project()`, `.loaders(<Class>)`,
`.language()`, `.compiler()`, **`.addLoaderArg(name,val)` / `.loaderArgs(...)`**, `.monitor()`,
`.load()`. Driving it as
`program_loader().source(fat).project(proj).loaders(MachoLoader).language("x86:LE:64:default").load()`
**selected the x86_64 slice**, while `language("AARCH64:LE:64:AppleSilicon")` selected the arm64 slice
(two-slice fat fixture, in-container). So the builder **does** respect `language` for slice selection,
and `addLoaderArg` is the general option channel (DYLD component name, Intel-Hex base offset, …).

## Decision (proposed)

### D1 — Fat-Mach-O slice selection via an optional `processor` on `loader="macho"`

Allow `processor` (an allow-listed `LanguageID`) to be supplied with `loader="macho"`. Absent →
default slice (today's behavior, unchanged). Present → the worker loads the slice whose language
matches. This reuses the ADR-045 allow-list + server-side validation; no new field.

### D2 — Worker adopts the `ProgramLoader.Builder` for the slice/option path

`open_program` cannot do it, so the macho-with-processor path (and, later, any `addLoaderArg` path)
uses `pyghidra.program_loader()`. **This is the risky part:** `program_loader()` needs an explicit
project handle and returns a `LoadResults` (not the `open_program` context manager the worker retains
today as `self._project` and closes on evict). The change MUST preserve every existing guarantee:
the program/project handle is retained for reuse, and on eviction (TTL/idle/close/poison/timeout,
ADR-002) it is closed + the per-session store is **verifiably wiped** — no leaked JVM program, no
un-wiped project. This requires mapping the `LoadResults`/project lifecycle onto the launcher's
evict/close path and a live test that eviction still wipes the store. **This is why the ADR precedes
the code.**

### D3 — DYLD-component selection — ratified, but IMPLEMENTATION-BLOCKED on a real fixture

A DYLD load needs a component **name** (a new hint, e.g. `component: str`) passed as a loader arg to
`DyldCacheLoader` via the now-implemented `program_loader().addLoaderArg(...)` path (the mechanism D2
established). **Blocked (grounded 2026-08-12):** validating it needs a *real* dyld shared cache —
`DyldCacheLoader` requires valid mappings + an image array + slide-info to recognize the cache and
expose selectable components; a minimal hand-built header is rejected, and no real iOS cache is
available. Per the project's grounding discipline we do **not** ship an unvalidated JVM-edge path (the
class of bug ADR-045 F1 / `set_function_signature` cost). So D3 is **ratified in principle** and the
mechanism is ready, but implementation waits on a real dyld-cache fixture. Low near-term value (iOS
system libraries; zero for the current Android target).

### D4 — Security envelope unchanged, execution container-only

Server validates the closed `loader` enum + the `processor` allow-list before the worker (ADR-001).
**Loader args are NOT a free-form passthrough** — only the specific, validated options this ADR
introduces (a slice-selecting `processor`; later a validated `component` name) are ever turned into
`addLoaderArg` calls. Arbitrary client-supplied loader args are rejected (untrusted-input surface —
CWE-20). All parsing/loading stays in the hardened, ephemeral, network-isolated worker container,
never the host (standing operator directive).

## Alternatives considered

- **`open_program(language=…)` for slices** — rejected: verified it does NOT select the slice.
- **Generic `loader_args: dict` passthrough** — rejected: turning arbitrary client strings into Ghidra
  loader options is an untrusted-input hazard and a fuzzy contract. Expose specific validated options
  only.
- **Keep deferring** — rejected for fat slices (now grounded + reachable); kept for DYLD (ungrounded).

## Consequences

- **Positive:** fat/universal Mach-O becomes fully usable (pick any slice) — the iOS/macOS multi-arch
  case; establishes the `ProgramLoader.Builder` + validated-option pattern for future loaders.
- **Cost / risk:** a session/project-lifecycle change in the security-critical worker — needs careful
  implementation + an eviction/store-wipe regression test. DYLD remains open.

## Testing (planned)

- **Unit:** `processor` accepted with `loader="macho"` (allow-listed) and rejected otherwise; still
  forbidden for `dex`/`apk`.
- **Integration (gated real worker):** a two-slice fat Mach-O (arm64 + x86_64), select each slice via
  `processor` and assert the loaded architecture (the probe above is the proof-of-concept). **Plus** a
  lifecycle test: import via the builder path, then evict, and assert the store is wiped (D2 guarantee).

## Rollout

Additive + default-off (no `processor` ⇒ default slice, unchanged). Documented in
`vivarium://docs/importing`. Merge stays **gated**. Ratify D1/D2 before implementation; D3 (DYLD)
tracked separately pending a fixture.
