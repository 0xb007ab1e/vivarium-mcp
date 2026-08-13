# ADR-055: Control-flow graph — read-only `basic_blocks` tool

- **Status:** **Accepted** (2026-08-12). A read-only function-detail tool; part of the v1.8 "all
  Ghidra coverage" increment program.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("do increment 12"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — walking ``BasicBlockModel`` over a branching
  function (`test eax,eax ; jz +2 ; inc eax ; ret`) returned three basic blocks with correct CFG:
  block `[401000-401003]` → successors `401006` (the jump target) + `401004` (fallthrough); block
  `[401004-401005]` → `401006`; block `[401006]` (ret) → no successors.

## Context

A function's **control-flow graph** — its basic blocks (straight-line code runs) and the edges
between them — is a core RE artifact for understanding branching, loops, and structure. Ghidra
already walks ``BasicBlockModel`` internally for `cyclomatic_complexity` (ADR-008), but that path
returns only **counts** (block/edge totals for the McCabe number). The actual CFG **structure** was
not exposed by any tool.

This is the tractable read-only slice this increment. The remaining bucket items (BSim /
Version-Tracking / PDB / DYLD) each need an external database, a second loaded program, or a real
fixture — none groundable here; `basic_blocks` needs only the analysis + block model Vivarium already
uses.

## Decision

### D1 — A new `basic_blocks` tool (Tier-1, read-only)

`basic_blocks(session_id, function, max_blocks?)` — a required `function` (name or entry address) and
a `max_blocks` cap (default 256, ≤ 10 000). It walks ``BasicBlockModel.getCodeBlocksContaining`` over
the function body and returns, per block: `{address (start), end_address (max), size (num addresses),
successors}`. `successors` are the start addresses of the block's **intraprocedural** successor blocks
— a flow that leaves the function (call/return/tail) is not counted as a CFG edge, matching the
convention `cyclomatic_complexity` already uses.

### D2 — Structure, not counts

This is the complement to `cyclomatic_complexity`: that tool returns the block/edge **counts** (the
complexity number); `basic_blocks` returns the block/edge **structure** (the graph itself). Both walk
the same ``BasicBlockModel``; they are distinct outputs for distinct questions.

### D3 — Read-only

`basic_blocks` reads the block model over the analyzed program; it does not decompile, execute, or
mutate the program DB. It is added to the Tier-1 read allow-list (not a write tool); no write-consent.

### D4 — Bounds

Bounded by `max_blocks` (server-clamped), with a `truncated` flag when clipped. The whole call runs
inside the ephemeral worker container.

### D5 — No untrusted content

Every field is a **server-normalized address or a count** (block start/end/size, successor
addresses). No instruction text or binary-derived content is returned (that is `disassemble` /
`get_pcode`), so — unlike most read tools — `basic_blocks` carries **no** untrusted-envelope fields.
Addresses are treated as safe scalars, consistent with `disassemble`'s bare `address`.

## Alternatives considered

- **Extend `cyclomatic_complexity` to also return the blocks** — rejected: it is a frozen
  count-only contract; a separate tool keeps its shape stable and makes the (heavier) structure
  opt-in.
- **Include each block's instructions/mnemonics** — rejected for this increment: that duplicates
  `disassemble` and would add untrusted content; the CFG structure (addresses + edges) is the
  distinct value. A caller can `disassemble` a block's range if it wants the instructions.
- **Ship a bucket item (BSim / Version-Tracking / PDB) instead** — not tractable this increment (each
  needs an external DB / a second program / a real fixture). `basic_blocks` is the grounded slice.

## Consequences

- **Positive:** exposes the CFG structure — a core function-understanding artifact — complementing
  `cyclomatic_complexity` (counts), `call_graph` (inter-function), and `decompile_function` (C).
- **Cost / risk:** low — read-only, no decompile, no execution, no mutation; a cheap block-model walk
  bounded by `max_blocks`; reuses the model already proven for complexity counts. Adds one Tier-1
  read-only tool (the frozen catalog count increments 62 → 63; read-only 46 → 47).

## Testing (master §4)

- **Unit:** schema — `function` required, `max_blocks` default + bounds; the result carries only SAFE
  address/count fields (nothing `Untrusted`). Registry — the handler validates the function name and
  dispatches.
- **Integration (gated real worker):** import a branching blob (`test eax,eax; jz; inc eax; ret`),
  create the function, `basic_blocks`, and assert ≥3 blocks with the entry block having two
  successors (jump target + fallthrough) — the grounded proof-of-concept.

## Rollout

Additive — a new opt-in read-only tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is read-only and needs no write-consent.
