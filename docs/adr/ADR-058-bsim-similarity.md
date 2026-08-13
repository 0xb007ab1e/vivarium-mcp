# ADR-058: BSim fuzzy similarity — read-only `bsim_similarity` tool

- **Status:** **Accepted** (2026-08-12). The BSim flagship, delivered as a self-contained
  two-function similarity primitive; part of the v1.8 "all Ghidra coverage" increment program.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("do increment 15"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker after working out the config path — for three
  x86-64 functions (`f0`, an identical `f1`, an `f2` differing by one immediate, and an unrelated
  `f3`), the BSim cosine similarity was **1.0** (f0↔f1), **1.0** (f0↔f2 — operand-agnostic at the
  feature level), and **0.38** (f0↔f3). Confirms the end-to-end pipeline + the fuzzy semantics.

## Context

Finding **similar** functions — not just exact duplicates (`function_hash`, ADR-057) but *near*
duplicates and variant routines — is a core RE need and Ghidra's flagship capability: **BSim**. It was
deferred through increments 13–14 because its signature generation needs a configured LSH vector
factory. This increment worked that out:

1. `FunctionDatabase.loadConfigurationTemplate("medium_64")` (note: **no** `.xml`; the `.xml` form
   fails to resolve in headless) loads the bundled weights/config template.
2. `FunctionDatabase.generateLSHVectorFactory()` + `factory.set(config.weightfactory,
   config.idflookup, config.info.settings)` builds a configured factory.
3. `GenSignatures(false)` + `setVectorFactory` + `openProgram` + `scanFunction(func)` decompiles each
   function and produces its BSim feature signature.
4. `descriptionManager.listAllFunctions()` → `desc.getSignatureRecord().getLSHVector()` retrieves the
   `LSHVector`; `vecA.compare(vecB, new VectorCompare())` returns the cosine similarity in `[0, 1]`.

The bundled `medium_32` / `medium_64` weights ship in the pinned Ghidra install
(`Ghidra/Features/BSim/data`), so no external database or network is needed.

## Decision

### D1 — A new `bsim_similarity` tool (Tier-1, read-only), two functions

`bsim_similarity(session_id, function_a, function_b)` generates the BSim feature signature of each
function and returns their **cosine similarity** in `[0, 1]` (1.0 = identical/equivalent), plus each
function's entry address. This is deliberately the **self-contained two-function** primitive — no
database, no session-model change — the smallest useful BSim slice. (A future "find-similar-across-
the-program" tool would generate signatures for many functions and rank them; that is a heavier,
separate increment.)

### D2 — Fuzzy, complementing `function_hash`'s exact match

`function_hash` (ADR-057) gives **exact** equality at three granularities (bytes / operand-masked
instructions / mnemonics). `bsim_similarity` gives a **continuous** BSim score — so a caller can find
functions that are *close* but not identical (recompiled variants, small edits), which exact hashing
misses. The two are complementary: hash to cluster exact clones cheaply, BSim to score fuzzy matches.

### D3 — Read-only

Signature generation **decompiles** each function (via `GenSignatures`' internal decompiler) but does
**not** mutate the program DB. `GenSignatures` is disposed in a `finally` (ADR-002 memory discipline).
Added to the Tier-1 read allow-list; no write-consent.

### D4 — Bounds + architecture support

Bounded to exactly two functions per call; the two decompiles are backed by the worker's per-call
wall-clock kill (ADR-002). The config template is selected by the program's address size —
`medium_64` (64-bit) / `medium_32` (32-bit); an unsupported size fails closed with a clear
`analysis-failed` (the mainstream architectures are covered; exotic sizes are a documented gap).

### D5 — Output is all SAFE

`similarity` is a **computed scalar** (a cosine value, not binary content) and the addresses are
server-normalized — so, like `function_hash`, `bsim_similarity` carries **no** untrusted-envelope
fields.

## Alternatives considered

- **A bare `bsim_signature(function)` returning the raw vector** — rejected: an LSH vector is not
  directly comparable without the configured factory, so a bare signature is not useful to a caller;
  returning the *similarity* of two functions is the actionable primitive.
- **A whole-program "find similar functions" tool** — deferred: it generates a signature per function
  (a decompile each) and ranks — an O(n)-decompile operation worth its own bounded increment. The
  two-function primitive is the groundable, self-contained first step.
- **A populated BSim database + cross-binary query** — out of scope: that needs a DB service and a
  multi-program model; the bundled `medium` weights give intra-call similarity with no external state.

## Consequences

- **Positive:** delivers Ghidra's flagship similarity capability — fuzzy near-duplicate detection —
  with no external database, completing the similarity story alongside `function_hash` (exact) and
  `identify_functions` (FID library match).
- **Cost / risk:** moderate — two decompiles per call (bounded by the wall-clock kill); reuses the
  bundled BSim weights + the disposed-per-call `GenSignatures` lifecycle. Adds one Tier-1 read-only
  tool (the frozen catalog count increments 65 → 66; read-only 49 → 50).

## Testing (master §4)

- **Unit:** schema — both functions required; result is addresses + a score, all SAFE (nothing
  `Untrusted`). Registry — the handler validates both function names and dispatches.
- **Integration (gated real worker):** import three functions (two identical, one differing only in an
  immediate, and an unrelated one); `bsim_similarity` and assert identical → 1.0, the operand-diff →
  high (≈1.0), and the unrelated pair → clearly lower — the grounded proof-of-concept.

## Rollout

Additive — a new opt-in read-only tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is read-only and needs no write-consent.
