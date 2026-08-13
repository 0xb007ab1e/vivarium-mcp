# ADR-069: Automatic struct / type recovery from access patterns (read-only inference)

- **Status:** **Proposed** (awaiting human ratification; v1.9). Item 6 of the post-v1.8
  capability-gap set (ADR-064..072).
- **Date:** 2026-08-13
- **Deciders:** Human operator (to ratify); drafted by the assistant from the post-v1.8 capability-gap
  survey — the item that closes the *creation-input* gap left by ADR-015.
- **Context source:** ADR-015 (Phase C) shipped `define_struct`/`define_union`, but **defining a
  struct is entirely manual** — a client must read the decompiled C, infer the layout by hand, and
  hand-author every `FieldSpec`. The T19 firmware RE hand-traced field accesses off a base pointer to
  reconstruct a config record; that inference is exactly what the decompiler's `HighFunction` already
  computes (offset/size/type per access off a base `Varnode`). Vivarium surfaces the *write* path
  (ADR-014/ADR-015) and now the *data-flow* (ADR-064) but has **no tool that proposes a layout** from
  how a pointer is used.

## Context

The structural-write arc (ADR-012 → ADR-013 → ADR-014 → ADR-015) is complete on the *write* side: a
client can `define_struct{fields:[...]}` then `apply_data_type`. But the client must **supply** the
field list. Recovering that list — "this pointer is accessed at `+0` (4-byte load), `+4`
(`char[32]`), `+36` (pointer store) ⇒ `struct {int; char[32]; void*;}`" — is mechanical pattern work
Ghidra's decompiler already does: the `HighFunction`'s SSA over `Varnode`s + `PcodeOp`s carries every
`PTRADD`/`PTRSUB`/`LOAD`/`STORE` off a base variable, with the accessed offset, the access size, and
the decompiler's inferred element type. A bounded worker-side walk of those accesses yields a
**candidate layout** directly.

This is a **read-only analysis** surface — it reads the same `HighFunction` ADR-064 reads, adds **no
agency, no write, no execution**. It fits the Tier-1 read-only catalog and the ADR-001 worker-only
boundary. Critically, it is a **suggestion engine feeding the existing gated write path**, not a new
write: the proposal it returns is consumed by the *already-gated* `define_struct`/`apply_data_type`
(ADR-014/ADR-015), so the structural-write consent + gate is preserved unchanged.

## Decision

### D1 — `recover_struct`: bounded read-only layout inference (the MVP)

Add a read-only Tier-1 tool `recover_struct`:

| Field | Type | Meaning |
|---|---|---|
| `function` | `str` | The containing function (address or name; resolved server→worker as elsewhere). |
| `base` | `str` | The base pointer/variable to infer a layout for: a high-variable/parameter/register name or an address within the function. |
| `max_fields` | `int?` | Bound on returned proposed fields (server-clamped to a hard cap). |
| `max_accesses` | `int?` | Bound on `HighFunction` accesses examined (server-clamped). |

Returns a **proposed** layout over the decompiler's `HighFunction`: a list of
`{offset, size, inferred_type, access: Literal["load","store","addr"], confidence}` for the accesses
seen off `base`, plus `truncated` when a cap was hit and `total_span` (the largest observed offset +
size). Every `inferred_type` / name / text field is binary-derived → wrapped in the untrusted-data
envelope (ADR-005). Overlapping or conflicting accesses at an offset are reported **as observed** (the
tool does not silently reconcile them) so the client — not the tool — decides. The walk is
**intra-function**; an access that flows in from a call/parameter is reported as a boundary field, not
followed across the function edge (mirrors ADR-064 D1).

### D2 — Propose only; NEVER write (the load-bearing boundary)

`recover_struct` **does not create a type, does not name a type, does not touch the
`DataTypeManager`.** It emits a candidate `{offset, size, inferred_type}` list and stops. To
*materialize* the proposal the client calls the **existing gated writes**:
`define_struct{name, fields:[FieldSpec]}` (ADR-015) then `apply_data_type{address, type:{named}}`
(ADR-014) — each of which independently requires `session_enable_writes{allow_structural:true}` +
`require_write_consent(structural=True)`. So the write-consent + structural-write gate (ADR-012/
ADR-014) is **preserved by construction**: `recover_struct` is on the read-only Tier-1 rung and never
appears in any write chokepoint. A malicious proposal (steered by an indirect injection, TB4) is
**inert** — it is data the client must then push through the gated write path, where it is
re-validated field-by-field (`validate_composite`, ADR-015 §4).

### D3 — Bounded before the worker (DoS)

`max_fields`/`max_accesses` are validated + hard-clamped **server-side before the worker** (CWE-400 /
ADR-001 posture, mirroring every bounded tool). The worker enforces the same caps and sets `truncated`
honestly (ADR-005) — a large/adversarial function (thousands of accesses off one base) can never
produce an unbounded proposal. The per-tool wall-clock (ADR-002) is the backstop.

### D4 — Contract delta (WS0, atomic)

Additive Tier-1 tool → `docs/contracts/tool-catalog.md` (new row) + `docs/contracts/rpc-protocol.md`
(new worker method `recover_struct`; params = tool schema minus `session_id`; worker returns plain
values, the server wraps the binary-derived `inferred_type`/name fields). Catalog count **+1**, landing
atomically with the schema per the frozen-contract mandate. No new `ErrorType` — reuses
`invalid-params` (bad base/shape/caps), `not-found` (function/base unresolvable), `analysis-failed`
(no `HighFunction` / undecompilable).

## Security / threat-model delta

- **No new agency (ADR-001/LLM08):** read-only analysis; **no write, no type creation, no execution,
  no script.** The one genuinely-new-risk surface (creating a type) stays behind the ADR-015 gate —
  this tool only *suggests* into it. Agency does **not** rise.
- **Untrusted output (ADR-005):** every returned `inferred_type`/name/text is binary-derived →
  envelope-wrapped; the whole proposal is inert data, never auto-applied.
- **Gate preserved (ADR-012/ADR-014):** the proposal is materialized **only** via the existing gated
  `define_struct`/`apply_data_type`, which re-validate it — the suggestion engine adds no bypass.
- **DoS (CWE-400):** the two caps bound the access walk before + inside the worker; wall-clock
  (ADR-002) backs it.
- **Trust boundary unchanged:** the JVM/`HighFunction` walk is the TB3 worker edge; the server never
  parses the binary.

## Alternatives considered

- **Make `recover_struct` create the type itself (one-shot infer-and-define):** ergonomic, but it
  would be a **write** tool that fuses inference with the type-universe mutation ADR-015 gated — moving
  attacker-influenced inferred layout *past* the structural-write consent. **Rejected** — the D2
  propose-only split keeps the gate load-bearing and the abuse matrix small (`std-owasp-llm` LLM07/
  LLM08).
- **Client-side inference over `get_high_pcode`/`data_flow_slice`:** re-implements the decompiler's
  access-pattern analysis client-side, ships the whole p-code (bandwidth), and drifts from Ghidra's
  own type inference. **Rejected** — the worker has the exact `HighFunction` accesses already (same
  reasoning as ADR-064).
- **Emulation-based dynamic layout recovery:** `emulate` (ADR-049) is a separate dynamic tool; static
  access-pattern inference is cheaper and needs no execution. **Rejected here.**
- **Silently reconcile overlapping/conflicting accesses into a single "best" field:** hides ambiguity
  the analyst needs to see and can mask a mis-inference. **Rejected** — report accesses as observed
  (D1); reconciliation is the client's call.

## Consequences

- **Positive:** closes the last *manual* step in the struct arc — the client no longer hand-authors
  `FieldSpec`s; makes the T19-style hand-tracing of a config record mechanical; reuses the
  decompiler's own type inference so proposals are exact + cheap; **preserves the ADR-015 write gate by
  construction** (propose-only), so it ships real capability with **zero new agency**.
- **Negative / cost:** a new JVM-edge (`# pragma: no cover`) worker method validated via the gated
  live-regression; a `HighFunction` must exist (requires prior `session_analyze` + a decompilable
  function) — an undecompilable/undefined base fails closed (`not-found`/`analysis-failed`). Inference
  is **best-effort** — a proposal can be wrong (union-vs-struct ambiguity, padding vs. field), which is
  why it is a *suggestion* the human/client reviews before the gated write, never an auto-apply.
- **Scope:** SemVer **minor** (additive read-only capability). Interprocedural layout recovery
  (following the base across calls) is a future ADR.

## Testing (master §4)

- **Unit:** schema validation (`function`/`base` required; caps clamped server-side; unknown/negative
  caps rejected; the result is proposal-only — no write path is reachable from this handler). Prove the
  server-side cap clamping.
- **Integration (gated real worker, live-regression):** analyze a known micro-binary whose function
  accesses distinct fields off a pointer parameter (e.g. `+0` int load, `+4` `char[16]`, `+20` pointer
  store) → assert the proposed layout has the **expected offsets** (`0/4/20`) with plausible sizes and
  `access` tags; assert `truncated=true` under a tiny `max_fields`; assert an undecompilable base fails
  closed. Add to the live-regression hard-gate list.
- **Abuse:** (a) an oversized/degenerate function (thousands of accesses off one base) stays bounded
  (cap honored, `truncated=true`); (b) an injection-steered call to `recover_struct` produces only
  **inert** proposal data — it defines **no** type and touches the `DataTypeManager` **not at all**
  (the propose-only invariant, D2); (c) a non-decompilable base fails closed category-safe; (d) the
  ADR-001 invariant holds — no JVM/PyGhidra import on the server-side handler. Benign/synthetic
  fixtures only (master §5); each deterministic + hermetic.

## Rollout

Additive + read-only → no migration. Worker-side change → needs a worker rebuild + `.github/
worker-image.pin` bump (per the worker-change-validation-recipe) before the live gate exercises it.
Merge stays gated.
