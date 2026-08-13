# ADR-053: High (SSA) p-code — read-only `get_high_pcode` tool

- **Status:** **Accepted** (2026-08-12). A read-only IR-inspection tool; part of the v1.8 "all Ghidra
  coverage" increment program. Realizes the deferral in ADR-052 D5.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("do increment 10"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — decompiling `mov eax,5 ; add eax,3 ; ret` and
  iterating `HighFunction.getPcodeOps()` returned just **two** ops: `(register,0x0,8) COPY (const,
  0x8,8)` and `RETURN`. The decompiler **constant-folded** `5+3 → 8` and eliminated all the dead flag
  computations — vs. the ~14 raw ops `get_pcode` (ADR-052) returns for the same code.

## Context

Ghidra's decompiler builds a **high p-code** representation of a function: SSA form, dead-code
eliminated, constant-folded, with typed varnodes — the IR it actually reasons over to emit C. This is
distinct from the **low** p-code of `get_pcode` (ADR-052), which is the raw per-instruction SLEIGH
lifting (every flag write, no optimization). High p-code shows what a function *semantically does*
(the grounded example: two instructions collapse to `RAX = 8`), which is exactly what a reverser
wants when reasoning about data flow.

`get_pcode` (ADR-052 D5) explicitly deferred high p-code as "a later additive option." This is that
increment. The remaining bucket items (BSim / Version-Tracking / PDB / DYLD) all need an external
database, a second loaded program, or a real fixture — none groundable this increment; high p-code
needs only the decompiler Vivarium already runs.

## Decision

### D1 — A new `get_high_pcode` tool (Tier-1, read-only), function-scoped

`get_high_pcode(session_id, function, max_ops?)`. High p-code is **function-scoped** (a whole function
is decompiled to obtain its `HighFunction`), so — unlike `get_pcode` (which also accepts a raw address
range) — it takes a required `function` (name or entry address) and a `max_ops` cap (default 256, ≤
10 000). It returns the function's high p-code operations, each as `{address, op}` (the seqnum address
+ the rendered op text).

### D2 — Read-only; reuses the decompiler lifecycle

It decompiles via the same `DecompInterface` lifecycle as `decompile_function` (ADR-005 decompile
path) and iterates `HighFunction.getPcodeOps()`. **Nothing is executed** and the program DB is not
touched. The `DecompInterface` is **disposed in a `finally`** per call (ADR-002 memory discipline). It
is added to the Tier-1 read allow-list (not a write tool); no write-consent.

### D3 — Bounds

Bounded by `max_ops` (server-clamped), with a `truncated` flag when clipped. Decompilation is bounded
by the worker's per-call wall-clock kill (ADR-002). The whole call runs inside the ephemeral worker
container.

### D4 — Output is decompiler-derived → untrusted envelope

Each rendered op string is produced by decompiling a hostile binary, so it is wrapped in the
**untrusted-data envelope** (ADR-005) — inert text, never executed/rendered/followed — exactly like
`decompile_function`'s C and `get_pcode`'s low p-code. The seqnum `address` is a server-normalized
scalar and stays bare.

## Alternatives considered

- **Extend `get_pcode` with a `form: low|high` flag** — rejected: low p-code accepts a raw address
  range, but high p-code is inherently function-scoped (needs a decompiled function). Overloading one
  tool with two different input contracts is worse than a separate, honestly-shaped tool.
- **Emit the SSA varnode graph / data-flow edges** — out of scope: the rendered op list is the
  standard, compact high-p-code view; a full varnode/def-use graph is a heavier future option.
- **Ship a bucket item (BSim / Version-Tracking / PDB) instead** — not tractable this increment (each
  needs an external DB / a second program / a real fixture). High p-code is the grounded slice and
  completes the IR trio.

## Consequences

- **Positive:** exposes the decompiler's refined IR — completing the ladder `disassemble` (text) →
  `get_pcode` (raw IR) → **`get_high_pcode` (optimized SSA IR)** → `decompile_function` (C). The most
  useful IR view for data-flow reasoning (constant folding + dead-code elimination visible).
- **Cost / risk:** low — read-only, no execution, no mutation; bounded by `max_ops` + the decompile
  wall-clock kill; reuses the existing, disposed-per-call decompiler lifecycle. Adds one Tier-1
  read-only tool (the frozen catalog count increments 60 → 61; read-only 44 → 45).

## Testing (master §4)

- **Unit:** schema — `function` required, `max_ops` default + bounds; each `op` is `Untrusted`.
  Registry — the handler validates the function name and dispatches.
- **Integration (gated real worker):** import a blob, create a function, `get_high_pcode`, and assert
  the refined IR reflects the optimization (e.g. `mov eax,5; add eax,3` yields a folded `COPY 0x8` and
  a `RETURN`, far fewer ops than the low p-code) — the grounded proof-of-concept.

## Rollout

Additive — a new opt-in read-only tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is read-only and needs no write-consent.
