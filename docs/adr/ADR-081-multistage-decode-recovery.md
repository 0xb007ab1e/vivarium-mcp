# ADR-081: Multi-stage / chained local decode recovery (`deobfuscate_strings` extension)

- **Status:** **Proposed** (drafted by the assistant 2026-11-04; closes the ADR-068 D4 "future ADR"
  deferral tracked as GH #379). Awaiting human ratification.
- **Date:** 2026-11-04
- **Deciders:** Human operator (ratification pending); drafted by the assistant from GH #379.
- **Context source:** ADR-068 (§D4) shipped the single-pass local XOR/ADD decoder MVP and explicitly
  deferred harder decoder classes to "a future ADR". #379 is that follow-up. This ADR extends
  `deobfuscate_strings` (`xor_decode`) to the **next tractable, in-envelope class: multi-stage /
  chained *local* decoders** — and keeps the rest deferred, fail-closed.

## Context

ADR-068 D3's `xor_decode` recovers a single-pass local decoder by **bounded p-code emulation of the
whole function** (ADR-049 sandbox) and reading back **one** buffer — `min(write_targets)`, the lowest
write-referenced address. Because the emulator already runs the *entire* function to completion, a
decoder that applies **several sequential passes within the same function** is already fully executed
— the limitation is **detection + readback, not emulation**:

- **Readback gap (the real recovery gap):** a chained decoder writes an **intermediate** buffer in an
  early stage and the **final plaintext** into a *different* buffer (e.g. `scratch = ct ^ k1` then
  `out = scratch ^ k2`, with `out` at a higher address). Today the worker reads only
  `min(write_targets)` — the intermediate scratch — finds non-printable bytes, and reports
  **not-recovered** (correct fail-closed per D4, but a miss).
- **Reporting gap:** a decoder with more than one constant key reports only the **first** `INT_XOR`
  key (`decode_key`), under-describing the chain even when the plaintext *is* recovered.

Both are fixable **within the existing execution envelope** — the emulation surface is unchanged
(still one bounded ADR-049 whole-function run, no native exec, no I/O, program DB untouched). Only the
**readback is widened** (read *every* distinct write buffer, bounded) and the **reporting is enriched**
(the ordered key chain). This is the 80%→90% increment on real firmware/malware decoders.

## Decision

### D1 — Recover chained *local* decoders by multi-buffer readback

Extend the `xor_decode` pass: after the (unchanged) bounded whole-function emulation, read back **every
distinct write-target buffer** (not just the minimum), bounded by a new `max_stages` cap, and report
the buffer whose decoded window yields the **longest printable leading run that CHANGED** vs its
original bytes. The before/after-change + printable-ratio gate (ADR-068 D3) is retained unchanged — it
is the honesty guarantee: a non-decoder or a stage that produced garbage yields no qualifying run and
is reported **not-recovered**, never guessed.

### D2 — Report the ordered decode-stage chain

Add an ordered `stages` list to each recovered `xor_decode` string: one `{op, key}` entry per detected
constant decode operation (`INT_XOR`/`INT_ADD` with a constant operand), in instruction order, bounded
by `max_stages`. The existing `encoding`/`decode_key` fields are retained and reflect the **first**
stage (backward-compatible — a single-stage decoder is `stages=[{op, key}]` with the same
`encoding`/`decode_key` as before). Every `key` is binary-derived → **untrusted-envelope-wrapped**
(ADR-005), like `decode_key`.

### D3 — `max_stages`: bound the chain (DoS)

Add `max_stages: int` to `DeobfuscateStringsIn` (`xor_decode` only), **server-clamped**
(`[1, 64]`, default `8`): the hard cap on both the number of stage entries reported *and* the number
of distinct write buffers read back after emulation. A pathological function with hundreds of write
targets can never trigger an unbounded readback. `max_bytes` still bounds each buffer window and
`max_steps` still bounds the emulation — `max_stages` only widens readback within those existing
bounds. Validated + clamped **before the worker** (CWE-400 / ADR-001), re-enforced in the worker, with
`truncated` set honestly when the cap clips the chain or the buffer set.

### D4 — Still deferred, still fail-closed (scope fence)

Explicitly **out of scope** for this ADR, unchanged from ADR-068 D4 and reported **not-recovered**
(never guessed), each tracked as its own follow-up:

- **Interprocedural** decoders (the loop calls out to other functions) — the whole-function emulation
  reaches a call it cannot satisfy and faults/halts; the before/after gate then yields nothing. A
  future ADR may add bounded call-emulation (ADR-066 `call`/`stubs`), scoped separately.
- **Self-modifying unpackers** — the ADR-049 emulator runs pre-translated p-code and does not
  re-decode bytes written to code space, so these inherently produce no plaintext and fail closed.
- **Stateful stream ciphers / key schedules** that need cross-call state — out of the local-loop model.

The guarantee is categorical: this ADR **widens readback of an already-run local emulation**; it adds
**no new execution capability** and no reach outside the single function.

### D5 — Contract delta (WS0, atomic)

Additive, backward-compatible fields only: `DeobfuscateStringsIn.max_stages` + `RecoveredString.stages`.
`docs/contracts/tool-catalog.md` (the `deobfuscate_strings` row: note `max_stages` + the `stages`
output field) + `docs/contracts/rpc-protocol.md` (the `deobfuscate_strings` method params/result).
**No catalog count change** (same tool, enriched). Lands atomically with the schema per the
frozen-contract mandate.

## Security / threat-model delta

- **No new agency / no new execution surface (ADR-001 / LLM08):** the emulation is the *same* single
  bounded ADR-049 whole-function run ADR-068 D3 already ratified. This ADR only reads back **more of
  the already-decoded memory** (bounded by `max_stages` × `max_bytes`) and reports the key chain. No
  additional `emulate` call, no call-following, no write, no script.
- **Untrusted output (ADR-005 / std-owasp-llm LLM01/LLM02):** recovered `text` and every stage `key`
  are binary-derived and of **hostile origin** — an attacker chooses the exact bytes reconstructed.
  All remain envelope-wrapped and inert; never auto-followed, executed, or rendered.
- **DoS (CWE-400):** `max_stages` bounds the readback buffer set and the stage list; `max_bytes`
  bounds each window; `max_steps` bounds the emulation; the ADR-002 per-tool wall-clock kill is the
  backstop. All clamped before + inside the worker; `truncated` honest.
- **Fail-closed scope fence (D4):** interprocedural / self-modifying / stateful decoders produce no
  qualifying printable-changed run and are reported **not-recovered** — never a guess.
- **Trust boundary unchanged:** the p-code walk + the emulator run are the TB3 worker edge; the server
  never parses the binary or loads the JVM.

## Alternatives considered

- **Emulate each stage separately / step the loop boundaries** — rejected: the whole-function run
  already executes every local stage; re-segmenting adds complexity and a larger step budget for no
  recovery gain. Widening readback is the minimal change.
- **Add bounded interprocedural call-emulation now** — rejected for this ADR: a materially larger
  execution surface (which callees, stub policy, recursion bounds) deserving its own ADR + threat
  model; kept deferred + fail-closed (D4).
- **Heuristic multi-key guessing without emulation** — rejected (same as ADR-068): brittle, risks
  confidently-wrong plaintext; running the actual local chain in the sandbox is exact.
- **Collapse multi-XOR to a single effective key** — rejected: only valid for commuting same-buffer
  XORs; breaks on mixed ops (xor-then-add) or multi-buffer chains, and loses the real stage chain the
  analyst wants.

## Consequences

- **Positive:** recovers the chained/multi-buffer local decoders real malware uses to defeat the
  single-pass MVP; reports the full decode chain for analyst confidence; stays entirely within the
  ratified ADR-049 execution envelope (no new agency).
- **Negative / cost:** a wider JVM-edge readback (`# pragma: no cover`) to validate via the gated
  live-regression (worker rebuild + `.github/worker-image.pin` bump per the
  worker-change-validation-recipe); the pure buffer-selection + stage-assembly logic is extracted to a
  testable core module (`core.multidecode`) with hermetic unit + property tests.
- **Scope:** SemVer **minor** (additive, backward-compatible). Interprocedural / self-modifying /
  stateful decoders remain a future ADR (D4).

## Testing (master §4)

- **Unit (hermetic, no JVM):** `core.multidecode.best_decoded_run` — picks the buffer with the longest
  printable-changed run; rejects all-unchanged / all-nonprintable / sub-`min_length`; honors the
  multi-buffer `max_stages`/`max_bytes` bounds. Stage-chain assembly preserves op order + caps at
  `max_stages`. Property/fuzz: arbitrary buffer sets never raise, never return a non-printable or
  unchanged run. Schema: `max_stages` clamp `[1,64]`; `stages` envelope-wrapped.
- **Integration (gated real worker, live-regression):** a micro-binary with a **two-buffer chained
  decoder** (`scratch = ct ^ k1` then `out = scratch ^ k2`, `out` at the higher address) → assert the
  plaintext is recovered from the final buffer with `technique="xor_decode"` and a 2-entry `stages`
  chain `[xor k1, xor k2]`; assert the single-pass fixture still recovers (regression) with
  `stages` length 1. Added to the live-regression hard-gate list.
- **Abuse:** a function with many write targets must stay bounded (`max_stages` honored,
  `truncated=true`); an **interprocedural** decoder (calls out) must fail closed (`not-recovered`),
  never a guess; a recovered string / stage key containing markup/URL/path bytes must arrive
  envelope-wrapped and inert.

## Rollout

Additive + read-only + backward-compatible → no migration. Worker-side change → needs a worker rebuild
+ `.github/worker-image.pin` bump (per the worker-change-validation-recipe) before the live gate
exercises it. Read-effect-only (reuses the ratified ADR-049 emulator); no write-consent. Merge stays
**gated**.
