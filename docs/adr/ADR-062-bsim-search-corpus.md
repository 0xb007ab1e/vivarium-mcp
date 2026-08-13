# ADR-062: Cross-binary BSim search — ephemeral corpus (`bsim_search_corpus`)

- **Status:** **Accepted + Implemented** (2026-08-13). The persistence fork was put to the operator,
  who chose the **ephemeral per-call** shape (no ADR-002 relaxation); feasibility was then grounded
  live before wiring, and the tool built.
- **Date:** 2026-08-13
- **Deciders:** Human operator (chose ephemeral over a persistent BSim DB, explicitly keeping the
  stateless-worker mandate); assistant grounded the cross-binary mechanic + built the increment.

## Context

BSim (inc15/16, ADR-058/059) compares function feature-signatures **within one loaded program**
(`bsim_similarity` pairwise, `find_similar_functions` one-to-many). The canonical BSim use case is
**cross-binary**: "which functions in my binary match functions across a reference corpus" — identify
statically-linked library functions, cluster malware families, find known code.

The obvious realization is a **persistent BSim database** that accumulates signatures across binaries
and sessions. That **conflicts with the stateless-worker mandate (ADR-002)**: Vivarium's worker is
ephemeral and verified-wiped on evict, and every analyzed binary is CONFIDENTIAL + hostile-origin
(master §5). A persistent store outliving the worker and mixing hostile-origin data across sessions is
a new persistent trust store + confidentiality/isolation surface — a deliberate relaxation of a hard
mandate.

## Decision

### D0 — Ephemeral per-call, NOT a persistent DB (operator decision)

The operator chose the **ephemeral** shape: no persistent BSim database, no ADR-002 relaxation. The
"corpus" is **whatever the caller passes in one call**; it is built, queried, and wiped within the
call (VT-shaped, ADR-060). A persistent BSim corpus remains a separate, larger initiative gated on an
explicit relaxation of the stateless mandate — out of scope here.

### D1 — A `bsim_search_corpus` tool (Tier-1, read-only w.r.t. the session)

`bsim_search_corpus(session_id, target_ref, reference_refs[], min_similarity?, limit?, max_scan?)`:
- **`target_ref`** — the binary whose functions are searched.
- **`reference_refs`** — a bounded list (1..N) of reference binaries forming the corpus.
- All refs resolve through the **same confined import root** as `session_import` (CWE-22) and are
  **size-capped** identically (CWE-400).
- **`min_similarity`** (`[0,1]`, default 0.7) / **`limit`** / **`max_scan`** (functions signed per
  binary) bound the result and cost.

For each target function, the **best** reference-corpus match with similarity ≥ `min_similarity` is
returned as `{target_address, target_name, reference_index, reference_address, reference_name,
similarity}`, sorted high-to-low, capped at `limit`.

### D2 — In-memory sign→release→compare (no BSim DB machinery)

Grounded live: BSim `LSHVector`s **survive their source program's release** and **compare across
sequentially-loaded programs** when generated with the **same** `LSHVectorFactory` config. So the
worker loads each binary **fresh** (throwaway), auto-analyzes it (BSim needs defined functions), signs
its functions with `GenSignatures` + the bundled `medium_NN` weights, extracts each `(name, address,
LSHVector)`, and **releases the program before loading the next** — bounding memory to one loaded
program at a time. Then it compares each target vector to every retained reference vector
(`LSHVector.compare` → cosine). No `H2FileFunctionDatabase` / `QueryNearest` DB machinery is needed for
a bounded per-call corpus (it only earns its keep for persistence, which D0 rejects).

### D3 — Same address size across the corpus

BSim vectors are comparable only within one `medium_NN` template (32- vs 64-bit). The tool signs with
the **target's** template; a reference whose default address-space size differs is **skipped** (its
functions cannot be compared) rather than mis-signed. Skips are reflected in `corpus_functions_scanned`
(a skipped reference contributes zero).

### D4 — Bounds (N+1 hostile binaries + N+1 analyses)

- `reference_refs` is capped (`_MAX_CORPUS_REFS`) so the load/analyze cost is bounded; each ref is
  size-capped before load (CWE-400). `max_scan` bounds functions signed per binary.
- All N+1 loads + analyses + the comparison are backed by the worker **wall-clock kill** (ADR-002)
  and container **memory/pids/cpu caps** (ADR-004) — now covering a sequence of loaded programs (one
  at a time).
- The match list is bounded by `limit`; `min_similarity` filters low-quality matches.

### D5 — Gating & output classification

Loads + analyzes N+1 binaries — a capability, gated exactly like `session_import` (confined import
root, size cap, worker-only per ADR-001). It does **not** mutate the session program (all binaries are
fresh throwaways; the session program is not a participant), so **no write-consent**. `target_address`
/ `reference_address` / `reference_index` / `similarity` are computed/normalized scalars (SAFE);
`target_name` / `reference_name` are binary-derived → **untrusted-enveloped** (ADR-005).

## New trust-boundary surface (TB3 delta)

Like VT (ADR-060), this puts **multiple hostile binaries** (target + N references) into the same
hardened worker as **more inputs across TB3** — not a new boundary. BSim signing is **static feature
extraction** (decompile + LSH vector) — no cross-binary code execution; all binaries are inert data,
loaded one at a time, released, and the worker is wiped on evict. Both/all refs confined + size-capped
before the JVM. No new egress / caps change. See the threat-model TB3 delta.

## Alternatives considered

- **Persistent BSim DB (H2/Postgres) across sessions** — rejected by the operator (D0): breaks ADR-002
  statelessness; a separate large initiative.
- **Load all N+1 programs simultaneously + a real in-worker H2 BSim DB** — unnecessary: vectors survive
  release, so one-at-a-time sign+release bounds memory without DB machinery.

## Implementation record (2026-08-13)

- **Schema** (`schemas.py`): `BsimSearchCorpusIn{target_ref, reference_refs[1.._MAX_CORPUS_REFS],
  min_similarity, limit, max_scan}`; `CorpusMatch{target_address, target_name*, reference_index,
  reference_address, reference_name*, similarity}` (`*`=Untrusted); `BsimSearchCorpusOut{matches,
  target_functions_scanned, corpus_functions_scanned, truncated}`.
- **Server adapter** (`rpc_client.py`): `_resolve_and_cap(target_ref)` + one per reference (confine +
  size-cap + OOM-pre-flight, same helper as import), then the RPC bounded by the analysis timeout.
- **Worker** (`_jvm_bridge.py` `_gh_bsim_search_corpus` + `_bsim_sign_program`): load fresh →
  AutoAnalysisManager analyze → GenSignatures → extract `(name, addr, vector)` → release, per binary
  (target-size template; mismatched-arch references skipped); cross-compare, best-match-per-target,
  filter/sort/cap.
- **Tests:** unit schema (refs bounded 1..N; scores/limits bounded; names Untrusted) + registry
  dispatch (68→69); a gated live integration test (`test_bsim_search_corpus.py`) — a target ELF's
  function matches a reference ELF's copy at high similarity — added to `live-regression.yml`.

## Testing (master §4)

- **Unit:** `reference_refs` requires ≥1 and rejects > `_MAX_CORPUS_REFS`; `min_similarity ∈ [0,1]`;
  `limit`/`max_scan` bounded; result names Untrusted, addresses/scores SAFE.
- **Integration (gated real worker):** a target binary sharing a function with a reference binary →
  `bsim_search_corpus` returns that cross-binary match at high similarity; an unrelated corpus returns
  none. Abuse: an oversized reference is rejected before load (the shared cap).
