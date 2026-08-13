# ADR-052: P-Code (IR) listing — read-only `get_pcode` tool

- **Status:** **Accepted** (2026-08-12). A read-only IR-inspection tool; part of the v1.8 "all Ghidra
  coverage" increment program.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("do increment 9"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — `Instruction.getPcode()` returned the lifted low
  p-code per instruction (e.g. `mov eax,5` → `(register, 0x0, 8) COPY (const, 0x5, 8)`; `add eax,3`
  → a 10-op sequence incl. `INT_ADD` / carry / zext / flags). Confirms the API + output shape.

## Context

Ghidra lifts every machine instruction to **p-code** — its processor-independent intermediate
representation. Reversers inspect p-code to understand the exact semantics of an instruction
(especially unusual or obfuscated ones), and it is the same IR the `emulate` tool (ADR-049)
interprets. Vivarium exposed `disassemble` (mnemonic + operands) and `emulate` (run the IR) but no way
to *see* the lifted IR itself.

This is the tractable read-only slice of the remaining increment bucket. The heavier bucket items are
blocked without external inputs: **BSim** needs a populated similarity database, **Version-Tracking**
needs two loaded programs + a VT session (the model is single-program), and **PDB** is fixture-blocked
— each is a separate increment. `get_pcode` needs none of that.

## Decision

### D1 — A new `get_pcode` tool (Tier-1, read-only), shaped like `disassemble`

`get_pcode(session_id, start?, function?, max_instructions?)` — the exact input shape as
`disassemble`: a raw range from `start`, or a `function` by name/address, bounded by
`max_instructions` (default 256, ≤ 10 000). It lifts each instruction to its **raw low p-code ops**
(`Instruction.getPcode()`) and returns, per instruction: `address` (safe), `mnemonic`, and `pcode`
(the list of op texts). Same result as running the SLEIGH lifter that `disassemble`/`emulate` already
use — no decompiler, no analysis beyond what is loaded.

### D2 — Read-only, nothing executed

`get_pcode` **does not execute** anything (unlike `emulate`) and does not touch the program DB. It only
reads the lifted IR. It is added to the Tier-1 read allow-list (not a write tool); no write-consent.

### D3 — Bounds

Bounded exactly like `disassemble`: `max_instructions` caps the instruction count (server-clamped),
with a `truncated` flag when clipped. Each instruction's op list is additionally capped by a
**defensive per-instruction ceiling** (`_MAX_PCODE_OPS_PER_INSN = 256`) so a single instruction cannot
balloon the response (CWE-400). The whole call runs inside the ephemeral worker container.

### D4 — Output is binary-derived → untrusted envelope

`mnemonic` and every `pcode` op string are lifted from a hostile binary, so each is wrapped in the
**untrusted-data envelope** (ADR-005) — inert text, never executed/rendered/followed — exactly like
`disassemble`'s mnemonic/operands. `address` is a server-normalized scalar and stays bare.

### D5 — Low p-code, not high p-code (this increment)

This tool emits **low p-code** (`Instruction.getPcode()`) — raw, always available, no decompiler
required. **High p-code** (the decompiler's refined `PcodeOpAST` from a `HighFunction`) is a richer,
more expensive form that needs decompilation; it is deliberately out of scope here and could be a
later additive option (`decompile_function` already covers the decompiler's C output).

## Alternatives considered

- **Fold p-code into `disassemble`** (add a `pcode` field) — rejected: `disassemble` is a frozen
  contract; a separate tool keeps its shape stable and makes the (heavier) p-code opt-in.
- **High p-code from the decompiler** — deferred (D5): more expensive, needs a decompiled function;
  low p-code is the clean, always-available v1.
- **Ship a bucket item (BSim / Version-Tracking / PDB) instead** — not tractable this increment:
  each needs an external DB / a second program / a real fixture. `get_pcode` is the grounded slice.

## Consequences

- **Positive:** exposes the lifted IR for inspection — completes the trio `disassemble` (text) →
  `get_pcode` (IR) → `emulate` (run the IR). Useful for understanding unusual/obfuscated instructions.
- **Cost / risk:** low — read-only, no execution, no program mutation; bounded like `disassemble` with
  an extra per-instruction op cap. Adds one Tier-1 read-only tool (the frozen catalog count increments
  59 → 60; read-only 43 → 44).

## Testing (master §4)

- **Unit:** schema — `max_instructions` default + bounds (mirrors `disassemble`); `mnemonic` and each
  `pcode` op are `Untrusted`. Registry — the handler validates `start`/`function` and fails closed when
  neither is given.
- **Integration (gated real worker):** import a tiny blob, `get_pcode` over its range, and assert the
  lifted ops match the known lifting (e.g. `mov eax,5` → a `COPY` op; `add eax,3` → an `INT_ADD` op) —
  the grounded proof-of-concept.

## Rollout

Additive — a new opt-in read-only tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is read-only and needs no write-consent.
