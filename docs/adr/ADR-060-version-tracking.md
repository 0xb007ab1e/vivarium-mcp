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

## Open items to resolve before / during implementation

1. **VT lock lifecycle** (D5) — the concrete open-program/consumer/transaction sequence that lets
   `createVTSession` acquire both programs cleanly (the grounded blocker).
2. **Second-binary import path** — whether `version_track` reuses the `session_import` confined
   resolver + size machinery directly, or a dedicated bounded loader.
3. **Correlator set** — confirm the initial allow-list (exact + duplicate-function) vs. adding the
   reference/symbol-name correlators in v1.

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
