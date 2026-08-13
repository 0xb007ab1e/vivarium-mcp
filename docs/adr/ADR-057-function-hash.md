# ADR-057: Function match-hashes — read-only `function_hash` tool

- **Status:** **Accepted** (2026-08-12). A read-only function-similarity tool; part of the v1.8 "all
  Ghidra coverage" increment program.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("do increment 14"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — Ghidra's own ``ghidra.app.plugin.match`` hashers
  produced, for three functions (`mov eax,5;ret`, an identical copy, and `mov eax,9;ret`):
  ``ExactBytes`` matched the first two but NOT the third (different immediate byte);
  ``ExactInstructions`` matched **all three** (operands masked); ``ExactMnemonics`` matched all three
  (same mnemonic sequence). Confirms the API (``<Hasher>.FUNCTION_HASHER.hash(func, monitor)`` → a
  64-bit ``long``) and the exact semantics.

## Context

Finding **similar/duplicate functions** — statically-linked library copies, repeated crypto routines,
relocated/recompiled clones — is a core RE need Vivarium could not serve. The flagship path,
**BSim**, is installed but its signature *generation* needs a configured LSH vector factory + weights
+ per-function decompile (a multi-piece config effort, deferred to its own increment). Ghidra also
ships a simpler, self-contained primitive: the **function hashers** behind its function-match/diff
feature (``ghidra.app.plugin.match``). Those are exact (not fuzzy) but need no configuration and are
groundable directly.

## Decision

### D1 — A new `function_hash` tool (Tier-1, read-only)

`function_hash(session_id, function)` returns a function's Ghidra match-hashes at **three
granularities**, plus `address` (entry) and `instruction_count`:

- **`exact_bytes`** — hash of the raw bytes: matches identical code with identical operands.
- **`exact_instructions`** — hash with **operands masked**: matches the same code with different
  immediates/addresses (relocated/recompiled clones). The most useful for cross-binary dup detection.
- **`exact_mnemonics`** — hash of the mnemonic sequence only: the loosest of the three.

Two functions sharing a hash are duplicates **at that granularity**. Callers compare hashes across
functions (e.g. group a program's functions by `exact_instructions` to find clusters).

### D2 — Ghidra-native, exact (not fuzzy)

These are Ghidra's own hashers — the same ones its function-match/diff uses — so this is genuine
Ghidra coverage, not a bespoke metric. They do **exact** matching at each granularity; **fuzzy**
similarity (near-matches, partial overlap) is BSim's domain and remains a separate, heavier increment.

### D3 — Read-only

`function_hash` computes the hashes over the analyzed program; it does not decompile, execute, or
mutate the program DB. Added to the Tier-1 read allow-list; no write-consent.

### D4 — Output is all SAFE (opaque equality tokens)

Each hash is a Ghidra-computed 64-bit value rendered as a **decimal string** — an opaque equality
token, not echoed binary content, so it is a safe scalar (like a checksum / `binary_sha256`). No hash
digest, address, or count is attacker-controllable content, so — unusually for a tool over binary-
derived data — `function_hash` carries **no** untrusted-envelope fields. (Rendering as a string, not a
raw int, avoids any signed/unsigned 64-bit interpretation drift across the RPC.)

## Alternatives considered

- **BSim signature generation** — deferred: high value (fuzzy similarity) but its LSH vector-factory +
  weights + decompile config is a multi-probe effort warranting a dedicated increment. `function_hash`
  delivers the exact-match slice now with a clean, groundable API.
- **A bespoke structural hash** (hash the mnemonic sequence ourselves) — rejected: Ghidra already
  ships vetted hashers with well-defined semantics (including operand masking); reusing them is more
  correct and clearly "Ghidra coverage."
- **Return only one hash** — rejected: the three granularities answer different questions (exact code
  vs operand-agnostic clone vs mnemonic shape); returning all three is cheap and strictly more useful.

## Consequences

- **Positive:** enables duplicate/clone detection (statically-linked lib copies, repeated routines) via
  Ghidra's own matching primitive — a foundation a caller can also use to pre-filter before a heavier
  BSim pass later.
- **Cost / risk:** low — read-only, no decompile/execution/mutation; three cheap hasher calls + an
  instruction count. Adds one Tier-1 read-only tool (the frozen catalog count increments 64 → 65;
  read-only 48 → 49).

## Testing (master §4)

- **Unit:** schema — `function` required; all result fields are SAFE (nothing `Untrusted`). Registry —
  the handler validates the function name and dispatches.
- **Integration (gated real worker):** import a blob with two identical functions + one that differs
  only in an immediate; `function_hash` each and assert `exact_bytes` splits the differing one out
  while `exact_instructions` and `exact_mnemonics` match all three — the grounded proof-of-concept.

## Rollout

Additive — a new opt-in read-only tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is read-only and needs no write-consent.
