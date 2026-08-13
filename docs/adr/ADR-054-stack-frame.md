# ADR-054: Recovered stack-frame layout — read-only `stack_frame` tool

- **Status:** **Accepted** (2026-08-12). A read-only function-detail tool; part of the v1.8 "all
  Ghidra coverage" increment program.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("do increment 11"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — after full auto-analysis, a function built from
  `push rbp; mov rbp,rsp; mov [rbp-4],5; ...` exposed a recovered stack variable via
  `Function.getStackFrame().getStackVariables()`: `local_c` at offset `-12`, type `undefined4`,
  size 4. (Two earlier probes confirmed the decompiler's HighFunction symbol map is NOT the right
  source: it optimizes trivial locals away entirely — `return 5;` — whereas the Stack analyzer's
  frame retains them.)

## Context

A function's **stack frame** — its locals and stack-passed parameters with offsets, names, types,
and sizes — is a core RE artifact: it is how a reverser understands what a function does with its
data. Ghidra's Stack analyzer populates this frame during auto-analysis. Vivarium exposed
`get_function` (signature/basic detail), `decompile_function` (C), and the p-code tools, but no way
to read the recovered frame layout.

This is the tractable read-only slice this increment. The remaining bucket items (BSim /
Version-Tracking / PDB / DYLD) each need an external database, a second loaded program, or a real
fixture — none groundable here; `stack_frame` needs only the analysis Vivarium already runs.

## Decision

### D1 — A new `stack_frame` tool (Tier-1, read-only)

`stack_frame(session_id, function)` — a required `function` (name or entry address). It reads
`Function.getStackFrame()` and returns `frame_size` plus, for each stack variable, `{name,
stack_offset, data_type, size, is_parameter}` (the last derived from
`StackFrame.isParameterOffset(offset)`).

### D2 — Reads the analyzed frame; does not force analysis

The frame is populated by the **Stack analyzer** during `session_analyze`. `stack_frame` reads the
current frame state — it does **not** run analysis (that is a separate, heavier tool with its own
consent-free but bounded path). A function that has not been analyzed yet returns an **empty variable
list** — an honest empty result, not an error. The normal workflow is import → `session_analyze` →
inspect (decompile / `stack_frame` / …).

### D3 — Read-only

`stack_frame` reads the frame; it does not decompile (no `DecompInterface`), execute, or mutate the
program DB. It is added to the Tier-1 read allow-list (not a write tool); no write-consent.

### D4 — Output is binary/Ghidra-derived → untrusted envelope

Each variable's `name` (Ghidra-recovered, e.g. `local_c`) and `data_type` (binary-derived) are
wrapped in the **untrusted-data envelope** (ADR-005). The scalars — `frame_size`, `stack_offset`,
`size`, `is_parameter` — are server/worker-computed and stay bare.

## Alternatives considered

- **Read the decompiler's HighFunction local symbol map instead** — rejected (grounded): the
  decompiler optimizes trivial locals away, so its symbol map is often empty for simple functions;
  the Stack analyzer's frame is the stable, analysis-populated source. (The decompiler's *refined*
  view is already available through `get_high_pcode` / `decompile_function`.)
- **Have `stack_frame` run analysis when the frame is empty** — rejected: analysis is a heavy side
  effect; keep it explicit (`session_analyze`) and let `stack_frame` be a cheap, honest read.
- **Fold frame data into `get_function`** — rejected: `get_function` is a frozen contract; a separate
  tool keeps its shape stable and makes the (frame-specific) detail opt-in.
- **Ship a bucket item (BSim / Version-Tracking / PDB) instead** — not tractable this increment (each
  needs an external DB / a second program / a real fixture). `stack_frame` is the grounded slice.

## Consequences

- **Positive:** exposes the recovered stack layout — a core function-understanding artifact —
  complementing `get_function` and `decompile_function`.
- **Cost / risk:** low — read-only, no decompile, no execution, no mutation; a cheap frame read
  bounded by the function's variable count. Adds one Tier-1 read-only tool (the frozen catalog count
  increments 61 → 62; read-only 45 → 46).

## Testing (master §4)

- **Unit:** schema — `function` required; each variable's `name` + `data_type` are `Untrusted`,
  scalars bare. Registry — the handler validates the function name and dispatches.
- **Integration (gated real worker):** import a stack-using blob, `session_analyze`, then
  `stack_frame` and assert a recovered local at a negative offset with size 4 — the grounded
  proof-of-concept (an un-analyzed frame would be empty, so the test analyzes first).

## Rollout

Additive — a new opt-in read-only tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is read-only and needs no write-consent.
