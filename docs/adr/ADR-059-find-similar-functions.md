# ADR-059: Whole-program BSim search — read-only `find_similar_functions` tool

- **Status:** **Accepted** (2026-08-12). Builds directly on the BSim signature pipeline from ADR-058;
  part of the v1.8 "all Ghidra coverage" increment program.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("next"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — one `GenSignatures` scan of four functions
  (`f0`, an identical `f1`, an `f2` differing by one immediate, and an unrelated `f3`), then ranking
  by BSim similarity to `f0`, returned `f1`=1.0, `f2`=1.0, `f3`=0.378 — the correct clone/variant
  ranking, in a single bulk scan.

## Context

ADR-058 shipped `bsim_similarity(function_a, function_b)` — the two-function BSim primitive. The rich
RE use case is **whole-program clone/variant search**: "which functions in this binary are similar to
*this* one?" (find every statically-linked copy of a routine, every variant of a crypto function,
etc.). Doing that by calling `bsim_similarity` in a loop re-decompiles the target and re-builds the
factory on every call; doing it **server-side in one `GenSignatures` scan** is far more efficient.

## Decision

### D1 — A new `find_similar_functions` tool (Tier-1, read-only)

`find_similar_functions(session_id, function, min_similarity?, limit?, max_scan?)`:
- **`function`** — the target (name or entry address).
- **`min_similarity`** — minimum cosine similarity to report (`[0, 1]`, default 0.7).
- **`limit`** — maximum matches returned (top-K after sorting; default 20).
- **`max_scan`** — cap on candidate functions signature-scanned (default 500).

It runs **one** `GenSignatures` scan (the target + up to `max_scan` other functions), compares the
target's `LSHVector` to each candidate's (`vec.compare(other, VectorCompare())`), keeps those at or
above `min_similarity`, and returns them sorted high-to-low (top `limit`) — each as `{address, name,
similarity}` — plus `functions_scanned` and a `truncated` flag.

### D2 — Bounded cost (this is the one tool that decompiles many functions)

BSim signature generation **decompiles** each scanned function, so cost grows with `max_scan`. Two
guards bound it: `max_scan` (server-clamped) caps how many candidates are scanned (setting `truncated`
when more exist), and the worker's per-call **wall-clock kill** (ADR-002) backs the whole operation.
`limit` bounds the response size. The whole call runs in the ephemeral worker container.

### D3 — Read-only; reuses the ADR-058 pipeline

Same pipeline as `bsim_similarity`: `loadConfigurationTemplate("medium_64"/"medium_32")` (by address
size) → configured `LSHVectorFactory` → `GenSignatures` scan. Signature generation decompiles but does
**not** mutate the program DB; `GenSignatures` is disposed in a `finally` (ADR-002). Added to the
Tier-1 read allow-list; no write-consent.

### D4 — Collision-safe vector keying

Functions can share names (thunks, imports). Vectors are keyed by the signature description's
**address** (`int(desc.getAddress())` — a long offset), not by name, so duplicate names never collapse
two functions' vectors. The target is excluded from its own match list by entry-point offset.

### D5 — Output: name untrusted, everything else SAFE

Each match's `name` is Ghidra-recovered / binary-derived → wrapped in the **untrusted-data envelope**
(ADR-005). The `address`es, `similarity` scores, `functions_scanned`, `target_address`, and `truncated`
are server/worker scalars and stay bare.

## Alternatives considered

- **Loop `bsim_similarity` client-side** — rejected: re-decompiles the target and re-builds the vector
  factory per call; the server-side single-scan is dramatically cheaper and is the natural place for
  the bounded fan-out.
- **Scan the whole program unconditionally** — rejected: unbounded decompile cost on a large binary.
  `max_scan` + the wall-clock kill make the cost explicit and bounded (with an honest `truncated`).
- **A populated cross-binary BSim database** — out of scope: that needs a DB service and a
  multi-program model; this tool answers the *intra-program* question with no external state.

## Consequences

- **Positive:** delivers the rich BSim use case — whole-program clone/variant discovery — completing
  the similarity toolset (`function_hash` exact, `bsim_similarity` pairwise fuzzy, `find_similar_functions`
  one-to-many fuzzy, `identify_functions` FID library match).
- **Cost / risk:** the highest-cost read tool (a decompile per scanned function) — bounded by
  `max_scan` + the wall-clock kill, with `truncated` for honesty. Adds one Tier-1 read-only tool (the
  frozen catalog count increments 66 → 67; read-only 50 → 51).

## Testing (master §4)

- **Unit:** schema — target required; `min_similarity ∈ [0,1]`, `limit`/`max_scan` bounded; each match
  `name` is `Untrusted`, the rest bare. Registry — the handler validates the target name and
  dispatches.
- **Integration (gated real worker):** import a target, an identical copy, a one-immediate variant, and
  an unrelated function; `find_similar_functions(target, min_similarity=0.5)` and assert the identical +
  variant are returned above threshold (ranked high) while the unrelated one is excluded — the grounded
  proof-of-concept.

## Rollout

Additive — a new opt-in read-only tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is read-only and needs no write-consent.
