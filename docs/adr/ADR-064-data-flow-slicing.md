# ADR-064: Data-flow slicing (read-only def-use / taint reachability)

- **Status:** **Accepted** (ratified by the human operator 2026-08-13 — directed "start #1" of the
  post-v1.8 capability-gap set; v1.9). First of the ADR-064..072 gap batch.
- **Date:** 2026-08-13
- **Deciders:** Human operator (ratified); drafted by the assistant from the post-v1.8 capability-gap
  survey (the item flagged highest-value).
- **Context source:** Vivarium exposes program *structure* (functions, xrefs, call graph, decompiled
  C, raw + high p-code) but **no data-flow**. Reverse-engineering and vulnerability analysis
  routinely need *"where does this value come from / go to"* — a backward/forward **def-use slice**,
  and *"can an attacker-controlled source reach this sink"* — **taint reachability**. The real T19
  firmware RE settled the `APP&SK` gate by hand-tracing loads; a slice tool would have made it
  mechanical. Ghidra's decompiler already computes exactly this (an SSA `HighFunction` over
  `Varnode`s + `PcodeOp`s); Vivarium just doesn't surface it.

## Context

`get_pcode` (ADR-052) and `get_high_pcode` (ADR-053) **dump** p-code but do not **follow** it. To
answer "what defines register `r0` at `0x1000`?" a client today must pull the whole high-p-code and
re-implement Ghidra's data-flow walk client-side — heavy, error-prone, and duplicative of the
decompiler's own SSA. The data-flow graph is *in* the `HighFunction` (`Varnode.getDef()` /
`getDescendants()`, `PcodeOpAST` def-use edges); a bounded worker-side walk is cheap and exact.

This is a **read-only analysis** surface — no new agency, no write, no execution (unlike `emulate`,
ADR-049). It fits the Tier-1 read-only catalog and the ADR-001 worker-only boundary.

## Decision

### D1 — `data_flow_slice`: bounded intra-function def-use slice (the MVP)

Add a read-only Tier-1 tool `data_flow_slice`:

| Field | Type | Meaning |
|---|---|---|
| `function` | `str` | The containing function (address or name; resolved server→worker as elsewhere). |
| `seed` | `str` | The value to slice from: an address (a specific instruction/op) or a high-variable/register name within the function. |
| `direction` | `Literal["backward","forward"]` | `backward` = the defs feeding the seed (where it came from); `forward` = the uses the seed feeds (where it goes). |
| `max_nodes` | `int?` | Bound on returned slice nodes (server-clamped to a hard cap). |
| `max_depth` | `int?` | Bound on the def-use walk depth (server-clamped). |

Returns a bounded slice over the decompiler's `HighFunction`: a list of nodes
`{address, pcode_op, high_var?, role}` (the `PcodeOp`s + high-variables reachable from the seed in
`direction`), plus `truncated` when a cap was hit. All name/text fields are binary-derived → wrapped
in the untrusted-data envelope (ADR-005). The walk is **intra-function** — an input that comes from a
call/parameter is reported as a **boundary node** (`role="param"`/`"call_result"`), never silently
followed across the function edge.

### D2 — Taint reachability is a thin predicate over D1 (MVP: same-function)

Expose taint as a *reachability* query, not a second engine: `data_flow_slice` with a `sink` addition
answers "does a forward slice from `seed` reach `sink`?" For v1.9 the MVP is **intra-function**
(source and sink in the same function). Interprocedural taint (following the call graph) is a
**deferred phase 2** — it multiplies cost + needs a call-depth/blast-radius cap and careful DoS
bounds; recorded as out of scope here.

### D3 — Bounded before the worker (DoS)

`max_nodes`/`max_depth` are validated + hard-clamped **server-side before the worker** (CWE-400 /
ADR-001 posture, mirroring every other bounded tool). The worker enforces the same caps and sets
`truncated` honestly (ADR-005) — a large/adversarial function can never produce an unbounded walk.

### D4 — Contract delta (WS0, atomic)

Additive Tier-1 tool → `docs/contracts/tool-catalog.md` (new row) + `docs/contracts/rpc-protocol.md`
(new worker method). Catalog count +1 (69→70). Lands atomically with the schema per the frozen-
contract mandate.

## Security / threat-model delta

- **No new agency (ADR-001/LLM08):** read-only analysis; no write, no execution, no script.
- **Untrusted output (ADR-005):** every returned name/text is binary-derived → envelope-wrapped.
- **DoS (CWE-400):** the two caps bound the walk before + inside the worker; the per-tool wall-clock
  (ADR-002) is the backstop.
- **Trust boundary unchanged:** the JVM/HighFunction walk is the TB3 worker edge; the server never
  parses the binary.

## Alternatives considered

- **Client-side slicing over `get_high_pcode`** — rejected: re-implements Ghidra's data-flow, ships
  the whole p-code (bandwidth), and drifts from the decompiler's own SSA. The worker has the exact
  graph already.
- **A full standalone taint engine (interprocedural, path-sensitive)** — rejected for v1.9: research-
  and DoS-heavy; the intra-function slice is the 80% value at a fraction of the risk. Deferred (D2).
- **Emulation-based dynamic taint** — rejected here: `emulate` (ADR-049) is a separate dynamic tool;
  static slicing is cheaper and needs no execution.

## Consequences

- **Positive:** the missing analysis primitive for vuln hunting + provenance ("where did this
  value come from"); makes hand-tracing (the T19 SK gate) mechanical; reuses the decompiler's SSA so
  it's exact + cheap.
- **Negative / cost:** a new JVM-edge (`# pragma: no cover`) worker method to validate via the gated
  live-regression; the HighFunction must exist (requires prior `session_analyze` + a decompilable
  function) — a non-decompilable/undefined seed fails closed (`not-found`/`analysis-failed`).
- **Scope:** SemVer **minor** (additive read-only capability). Interprocedural taint = a future ADR.

## Testing (master §4)

- **Unit:** schema validation (direction enum; seed/function required; caps clamped; unknown
  direction rejected). Server-side cap clamping proven.
- **Integration (gated real worker, live-regression):** analyze a known micro-binary, take a backward
  slice from a function's return value → assert the defining ops appear + a param source is reported
  as a boundary node; a forward slice from a param → assert it reaches the return; assert `truncated`
  under a tiny `max_nodes`. Add to the live-regression hard-gate list.
- **Abuse:** an oversized/degenerate function must stay bounded (cap honored, `truncated=true`), and a
  non-decompilable seed fails closed category-safe.

## Rollout

Additive + read-only → no migration. Worker-side change → needs a worker rebuild + `.github/
worker-image.pin` bump (per the worker-change-validation-recipe) before the live gate exercises it.
Merge stays gated.
