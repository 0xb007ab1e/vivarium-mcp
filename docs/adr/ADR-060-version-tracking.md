# ADR-060: Version Tracking — two-program function matching (`version_track`)

- **Status:** **Proposed** (2026-08-13). Design + threat-model FIRST, per the operator's decision;
  **no code lands until this ADR + the TB3 delta are reviewed.**
- **Date:** 2026-08-13
- **Deciders:** Human operator (chose "design + ADR first" over building it blind); assistant grounded
  the feasibility + drafted the design.
- **Context source:** Grounded live in the worker — the VT API is fully present
  (`VTSessionDB.createVTSession(name, source, dest, consumer)` + the correlator factories
  `ExactMatchInstructions/Bytes/Mnemonics`, `DuplicateFunctionMatch`, reference + symbol-name). Two
  raw programs load in one pyghidra instance with functions defined. Two constraints surfaced: (a)
  the **destination program must be writable** (VT writes match markup into it), and (b) VT's headless
  program lifecycle is **lock-sensitive** — `createVTSession` raised
  `LockException: domain object(s) are busy/locked` when the programs were held by open-program
  consumers/transactions. (a) shapes the design below; (b) is the open technical item to resolve
  during implementation.

## Context

Ghidra **Version Tracking** matches functions/data between **two** programs — the canonical use case
being "diff this binary against a known-good / earlier / reference build to find what changed or which
functions correspond." Vivarium's whole model is **single-program-per-worker** (one binary per
session, ADR-001/ADR-002), so VT is the one remaining flagship capability that does not fit the
existing shape: it needs a *second* program in play.

This ADR proposes how to get a second program into the picture **without** abandoning the
single-program session model or the containment guarantees — and enumerates the new trust-boundary
surface (a second hostile binary in the worker) so the threat-model delta can be reviewed before any
code.

## Decision (proposed)

### D1 — A `version_track` tool (Tier-1, read-only w.r.t. the session)

`version_track(session_id, other_source_ref, correlator?, min_confidence?, limit?)`:
- **`other_source_ref`** — a second binary, resolved through the **same confined import root** as
  `session_import` (CWE-22: no arbitrary path; size-capped identically).
- **`correlator`** — a **closed allow-list** of VT correlators (initial set:
  `exact_instructions` / `exact_bytes` / `exact_mnemonics` / `duplicate_function`).
- **`min_confidence`** / **`limit`** — bound which matches are returned and how many.

Returns the function matches between the session's program and the second binary — each as
`{source_address, destination_address, similarity, confidence}` — plus a `match_count` and a
`truncated` flag.

### D2 — The second program is a TRANSIENT load in the SAME worker; the session model is unchanged

The session still owns **one** persistent program. `version_track` confined-imports the second binary
into the session's **already-hardened, ephemeral, network-isolated worker**, analyzes it, runs one VT
correlator, extracts the matches, then **releases + wipes** the second program. It is never a second
session, never persisted, never reachable after the call. No cross-session program sharing (programs
in different workers are never joined — that would require moving a program between workers; rejected).

### D3 — Session program = SOURCE (read-only); second binary = DESTINATION (writable, throwaway)

VT writes match markup into the **destination**. So the **session's program is the SOURCE** (opened
read-only, byte-for-byte untouched) and the **transient second binary is the DESTINATION** (opened
writable). All VT markup lands in the throwaway program that is wiped at the end — **the session's
program is never mutated**, so `version_track` is read-only with respect to the session and needs **no
write-consent** on the session program.

### D4 — Correlator allow-list (closed set)

`correlator` is a `Literal` over a curated set of Ghidra correlator factories (start with the exact +
duplicate-function correlators; reference/symbol-name correlators can be added later). No arbitrary
correlator class is instantiated from client input.

### D5 — Bounds (two hostile binaries + a correlation is more expensive)

- The second binary is **size-capped** before load (reuse the `session_import` cap; CWE-400).
- Both programs' analysis + the correlation are backed by the worker's **wall-clock kill** (ADR-002)
  and the container **memory/pids/cpu caps** (ADR-004) — now covering *two* loaded programs.
- The match list is bounded by `limit`; `min_confidence` filters low-quality matches.
- **Open technical item:** the `createVTSession` **lock lifecycle** must be resolved (correct
  consumer/transaction/quiescent-program sequencing) so headless VT runs cleanly. This is the main
  implementation risk and is called out explicitly, not hidden.

### D6 — Output classification

`source_address` / `destination_address` are server-normalized (safe); `similarity` / `confidence` /
`match_count` are computed scalars (safe). If a match ever carries a **function name**, that name is
binary-derived and MUST be wrapped in the untrusted-data envelope (ADR-005). The initial cut returns
**addresses + scores only** (all safe) to keep the surface minimal.

### D7 — Gating

`version_track` **loads + analyzes a second binary** — a capability, gated exactly like
`session_import` (confined import root, size cap, worker-only per ADR-001). It does **not** get its
own write-consent gate because it does not mutate the session program (D3); the writable destination is
a throwaway.

## New trust-boundary surface (see the TB3 delta)

The second binary crosses the **binary → analyzer** boundary (**TB3**, the primary HOSTILE boundary)
into the **same** hardened worker. It does **not** create a new boundary class — it is a **second
input across TB3** — but it does add surface that the threat-model delta must state explicitly:
- **Two hostile binaries in one worker.** VT is **static correlation** (feature comparison) — there is
  **no cross-binary code execution**; both binaries are inert data. Neither can act on the other or
  escape (the ADR-004 isolation stack is unchanged).
- **Transient, wiped.** The second program + its derived matches are CONFIDENTIAL + hostile-origin
  (master §5 / ADR-005); the program is released + the store wiped at the end of the call, and the
  whole worker is killed + verified-wiped on evict (ADR-002).
- **Confined import.** The second binary is size-capped + confined-root-resolved (no arbitrary path).
- **No new egress / caps change.** The worker stays network-less, ro-rootfs, dropped-caps, gVisor
  (ADR-004) — a second program does not relax any of it.

## Alternatives considered

- **Cross-session VT (compare two existing sessions' programs)** — rejected: the programs live in
  **different workers**; joining them would mean moving a program across the process/container boundary
  (TB2), which is a far larger surface than a transient in-worker second load.
- **Make the session program the destination (writable) so VT markup is "in context"** — rejected: it
  would **mutate the session's program**, turning a diff into a write and pulling in the whole
  write-consent surface for no benefit; the throwaway-destination design keeps the session read-only.
- **Persist VT sessions / a VT database** — out of scope: Vivarium is stateless (ADR-002); a persistent
  VT store is a separate, much larger effort.

## Consequences (if accepted)

- **Positive:** unlocks the last flagship Ghidra capability — two-program function diff/matching (patch
  analysis, known-good comparison, correspondence between builds).
- **Cost / risk:** the largest increment of the v1.8 program — a second confined import + analyze, the
  VT session/correlator lifecycle (incl. the lock issue), match extraction, and a real trust-boundary
  delta (two hostile binaries). Adds one Tier-1 read-only tool.

## The VT program-lifecycle blocker — **RESOLVED** (2026-08-13 research)

The gating blocker (`createVTSession` / `new VTSessionDB(...)` raising `LockException: domain object(s)
are busy/locked`, or `ReadOnlyException` on the destination) is **solved**. Root cause + fix, grounded
live in the worker (a two-program VT run produced `match_count=1`, similarity 1.0):

- **Root cause:** `pyghidra.open_program` (and the `GhidraProject` it uses) holds a **perpetual open
  transaction** on the program for the lifetime of the handle. A probe showed `getCurrentTransactionInfo()`
  is **non-null** and `canLock()` is **False** even outside any explicit transaction — so VT (which must
  **lock** both programs to snapshot them into the session) cannot acquire the lock. The
  `program_loader()` builder avoids the transaction but returns a **read-only** program (the destination
  must be writable). Neither bare-load path yields a *writable + lockable* program.
- **The fix — open programs from project DOMAIN FILES via `getDomainObject`** (how Ghidra's own tool /
  `CreateAppliedExactMatchingSessionScript` holds them):
  1. `proj = pyghidra.open_project(dir, name, create=True)`; `root = proj.getProjectData().getRootFolder()`.
  2. Load the binary (builder), then **save it as a domain file**: `root.createFile(name, prog, monitor)`.
  3. **Close** the transient builder handle (`loaded.close()`).
  4. Reopen writable via the domain file: `df.getDomainObject(consumer, /*okToUpgrade*/True,
     /*okToRecover*/False, monitor)` → **no auto-transaction → `canLock()=True`**.
  5. Create the session with the **constructor** `new VTSessionDB(name, source, dest, consumer)` (NOT
     the static `createVTSession`); optionally place it in the project via `folder.createFile`.
  6. `correlator = factory.createCorrelator(src, srcAddrSet, dst, dstAddrSet, factory.createDefaultOptions())`;
     `matchSet = correlator.correlate(session, monitor)`; iterate `matchSet.getMatches()` →
     `getSourceAddress()` / `getDestinationAddress()` / `getSimilarityScore().getScore()` /
     `getConfidenceScore().getScore()`; `session.release(consumer)`.

## Design refinement from the research — VT loads BOTH binaries fresh (session program NOT reused)

The session's own program is loaded by the backend via `pyghidra.open_program` → it carries the
perpetual transaction (`canLock()=False`), so it **cannot be a VT participant**. Therefore
`version_track` loads **both** binaries **fresh** (via the lockable domain-file path above) in a
**throwaway VT project** inside the session's worker, correlates them, extracts the matches, then
releases + wipes both programs and the VT session. This **supersedes ADR-060 D3's "session program =
source"**: the session's program is now **completely untouched** — not even read by VT — which is
*stronger* for security (no risk of mutating or locking the live session program). Revised tool shape:

`version_track(session_id, source_ref_a, source_ref_b, correlator?, min_confidence?, limit?)` — both
`source_ref_a` and `source_ref_b` resolve through the **confined import root** (CWE-22) and are
size-capped (CWE-400); the `session_id` provides auth/scoping + the worker, not a program. Both binaries
are analyzed (correlators need functions defined) — bounded by the wall-clock kill + memory caps.

## Remaining open items (smaller)

1. **Two-binary import + analyze cost** — two fresh imports + analyses per call; bound with the
   `session_import` size cap + the wall-clock kill; consider a lighter analysis profile for VT loads.
2. **Correlator set** — confirm the initial allow-list (exact instructions/bytes/mnemonics +
   duplicate-function) vs. adding reference/symbol-name correlators in v1.
3. **Match volume** — bound the returned matches (`limit` + `min_confidence`); large programs can
   produce many.

> **Build status (2026-08-13):** the gating lifecycle blocker is **RESOLVED** (recipe above, grounded).
> No `version_track` code exists yet — the tool remains **Proposed** pending the go-ahead to build the
> (now de-risked) increment. The design is refined to the *both-fresh* model; the session program is no
> longer a participant, so ADR-060 D3 + the TB3 delta are updated accordingly.

## Testing (planned, master §4)

- **Unit:** schema — `other_source_ref` bounded; `correlator` closed `Literal`; `min_confidence ∈
  [0,1]`, `limit` bounded; result addresses/scores SAFE. Registry — the handler validates + dispatches
  (+ the import-gate path).
- **Integration (gated real worker):** two synthetic programs sharing a function — `version_track`
  returns the function match (source↔destination address) with a high score; a program with no shared
  function returns no matches. Abuse: an oversized second binary is rejected before load.

## Rollout

**None yet** — this is a Proposed design. On acceptance of this ADR + the TB3 delta, implementation
follows as its own gated increment. No behavior changes until then.
