# ADR-067: Binary diff report — function-granularity two-program diff (`binary_diff`)

- **Status:** **Proposed** (awaiting human ratification; v1.9). Item 4 of the post-v1.8
  capability-gap batch (ADR-064..072).
- **Date:** 2026-08-13
- **Deciders:** Human operator (to ratify); drafted by the assistant from the post-v1.8
  capability-gap survey (the patch-diffing item).
- **Context source:** Vivarium can *match* two loaded programs (`version_track`, ADR-060) and *score*
  function similarity (BSim, ADR-058/059; corpus search, ADR-062), but has **no first-class "diff two
  builds" report**. The canonical RE/vuln workflow of **patch-diffing** — comparing two OTA firmware
  versions to spot which routines were patched, added, or removed — has to be assembled by hand today
  from `version_track` pairs plus per-function similarity calls. The primitives exist; the report that
  composes them into ADDED / REMOVED / CHANGED does not.

## Context

Given two builds A and B of the same firmware, an analyst wants one bounded answer: *which functions
are new in B, which were dropped from A, and which survived but changed (and how much).* `version_track`
(ADR-060) already pairs functions across two programs via Ghidra's correlators; BSim (ADR-058/059) and
`function_hash` (ADR-057) already yield a per-function change signal. What is missing is the
**composition**: run the pairing, then classify every function into ADDED (in B, unmatched), REMOVED
(in A, unmatched), or CHANGED (matched but not identical), and return that as a single structured,
bounded report.

This reuses the **ephemeral two-program session model** already established for `version_track` and
cross-binary BSim (ADR-062): both programs are loaded in one ephemeral session, diffed, and discarded —
**no persistent diff DB** (ADR-002 kept). It is a **read-only analysis** surface — no write, no
execution, no script — fitting the Tier-1 read-only catalog and the ADR-001 worker-only boundary.

## Decision

### D1 — `binary_diff`: bounded two-program function-granularity diff (the MVP)

Add a read-only Tier-1 tool `binary_diff`:

| Field | Type | Meaning |
|---|---|---|
| `program_a` | `str` | The baseline program (the ephemeral two-program session's first program, as with `version_track`/`bsim_search_corpus`). |
| `program_b` | `str` | The comparison program (the second program in the same ephemeral session). |
| `match_by` | `Literal["name","bsim","function_hash"]?` | The pairing primitive: symbol name, BSim similarity (ADR-058), or match-hash (ADR-057). Default `name` with a similarity fallback. |
| `min_similarity` | `float?` | For a similarity-based pairing, the threshold below which a matched pair is reported as CHANGED rather than unchanged (server-clamped to `[0,1]`). |
| `max_entries` | `int?` | Bound on the total diff entries returned (server-clamped to a hard cap). |
| `include_unchanged` | `bool?` | Default `false` — identical/high-similarity pairs are omitted from the report (only ADDED/REMOVED/CHANGED are returned). |

Returns a bounded structured diff:

- `added`: functions present in B with no pairing in A — `{address, name?, ...}`.
- `removed`: functions present in A with no pairing in B.
- `changed`: matched pairs that differ — `{address_a, address_b, name?, similarity?, change: Literal["signature","body","both"]?}` — a per-function **change indicator** derived from the pairing primitive (e.g. BSim/hash mismatch, differing size/instruction count).
- `summary`: counts per category (`added`, `removed`, `changed`) — honest even when the entry lists are `truncated`.
- `truncated`: `true` when `max_entries` clipped any list (ADR-005).

All name/text fields are binary-derived → wrapped in the **untrusted-data envelope** (ADR-005). The
diff is **function-granularity** for v1.9; basic-block / instruction-level diff of a single CHANGED
pair is a **deferred phase 2** (recorded out of scope in D2).

### D2 — Change indicator is a thin classification over existing primitives (MVP)

The per-function `change` indicator is a *classification*, not a new engine: pairing is delegated to
`version_track`'s correlators / BSim / `function_hash`, and CHANGED-ness is derived from the pairing
signal (unmatched → ADDED/REMOVED; matched with similarity `< min_similarity` or a hash mismatch →
CHANGED). Sub-function diff (which basic blocks / instructions changed within a CHANGED pair) multiplies
cost and needs its own bounds; it is **deferred phase 2**, out of scope here.

### D3 — Bounded before the worker (DoS)

`max_entries` (and `min_similarity` range) are validated + hard-clamped **server-side before the worker**
(CWE-400 / ADR-001 posture, mirroring every other bounded tool). The worker enforces the same caps and
sets `truncated`/`summary` honestly (ADR-005) — two large or adversarially-crafted programs can never
produce an unbounded report. The per-tool wall-clock (ADR-002) is the backstop.

### D4 — Ephemeral, no persistent diff store (ADR-002 kept)

Both programs live in one **ephemeral** two-program session (the ADR-062 posture); the diff is computed
and returned, and the session/store is wiped on close with the usual verified wipe. **No persistent diff
DB, no ADR-002 relaxation.**

### D5 — Contract delta (WS0, atomic)

Additive Tier-1 tool → `docs/contracts/tool-catalog.md` (new row) + `docs/contracts/rpc-protocol.md`
(new worker method). Catalog count +1. Lands atomically with the schema per the frozen-contract mandate.

## Security / threat-model delta

- **No new agency (ADR-001/LLM08):** read-only analysis; no write, no execution, no script. Pairing +
  classification only.
- **Untrusted output (ADR-005):** every returned name/text/change indicator is binary-derived →
  envelope-wrapped; the report is inert data, never instructions.
- **DoS (CWE-400):** `max_entries` bounds the report before + inside the worker; two-program load reuses
  the ADR-060/ADR-062 second-program size caps; the per-tool wall-clock (ADR-002) is the backstop.
- **Ephemeral (ADR-002):** no persistent diff store; the two-program session is wiped on close.
- **Trust boundary unchanged:** the JVM pairing/diff runs at the TB3 worker edge; the server never parses
  either binary.

## Alternatives considered

- **Leave it to the client** (compose `version_track` + N × `bsim_similarity` calls) — rejected: N+1
  round-trips, no honest bounded `truncated`, and every client re-implements the ADDED/REMOVED/CHANGED
  classification. The worker has both programs loaded already; one bounded pass is cheaper and consistent.
- **A persistent diff database across many builds** — rejected for v1.9: contradicts ADR-002 (the operator
  chose ephemeral for cross-binary BSim in ADR-062 for the same reason). A build-history diff store would be
  a separate, explicitly-decided ADR.
- **Instruction/basic-block-level diff as the MVP** — rejected: heavier, needs its own DoS bounds, and the
  function-granularity report is the 80% patch-diffing value at a fraction of the cost. Deferred (D2).
- **A new bespoke matching engine** — rejected: `version_track`/BSim/`function_hash` already pair functions;
  this tool composes them, it does not replace them.

## Consequences

- **Positive:** the missing first-class patch-diffing report (compare OTA firmware versions → spot patched /
  added / removed routines) — a core RE/vuln workflow, in one bounded call; reuses the ephemeral two-program
  model and the existing match/similarity primitives, so it is exact + cheap and adds no new trust surface.
- **Negative / cost:** a new JVM-edge worker method (`# pragma: no cover`) to validate via the gated
  live-regression; requires both programs analyzed (`session_analyze`) — an unanalyzed/undecompilable input
  fails closed (`analysis-failed`/`not-found`). Result quality inherits the chosen pairing primitive's
  limits (name-only pairing is weak against stripped/renamed binaries → BSim/hash fallback).
- **Scope:** SemVer **minor** (additive read-only capability). Sub-function diff + a build-history store =
  future ADRs.

## Testing (master §4)

- **Unit:** schema validation (`match_by` enum; `program_a`/`program_b` required; `max_entries` clamped;
  `min_similarity` clamped to `[0,1]`; unknown `match_by` rejected; `summary` counts consistent with returned
  lists). Server-side cap clamping proven.
- **Integration (gated real worker, live-regression):** analyze a known micro-binary as A, diff it against a
  **slightly-modified copy** of itself as B (one function added, one function's body changed) → assert the
  added function appears in `added`, the changed function appears in `changed` with a non-identical
  `similarity`/`change` indicator, and an unchanged function is *not* reported (with `include_unchanged=false`);
  assert `summary` counts match; assert `truncated=true` under a tiny `max_entries`. Add to the
  live-regression hard-gate list.
- **Abuse:** two large/degenerate programs must stay bounded (cap honored, `truncated=true`, `summary` honest);
  an unanalyzable second program fails closed category-safe; a name-only diff of a stripped binary degrades
  gracefully (no crash, honest empty/low-confidence report).

## Rollout

Additive + read-only → no migration. Worker-side change → needs a worker rebuild + `.github/worker-image.pin`
bump (per the worker-change-validation-recipe) before the live gate exercises it. Merge stays gated.
