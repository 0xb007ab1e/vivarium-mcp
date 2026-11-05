# ADR-082: Interprocedural local decode recovery (`deobfuscate_strings` cross-function detection)

- **Status:** **Proposed** (drafted by the assistant 2026-11-04; closes the ADR-081 D4 "interprocedural"
  deferral tracked as GH #398). Awaiting human ratification.
- **Date:** 2026-11-04
- **Deciders:** Human operator (ratification pending); drafted by the assistant from GH #398.
- **Context source:** ADR-068 D4 / ADR-081 D4 deferred decoders that "call out to other functions"
  as fail-closed, on the premise that the whole-function emulation "reaches a call it cannot satisfy
  and faults/halts." Investigating the ADR-049 emulator shows that premise is **pessimistic**: the
  emulator single-steps (`EmulatorHelper.step`) over the program's mapped memory, so a CALL to an
  **in-program** callee is *already* followed (the callee's code runs); the ADR-066 `stubs`
  mechanism exists precisely to substitute calls you do NOT want followed (external/library). The
  real gap is therefore **detection**, not execution.

## Context

`_gh_xor_decode_one` (ADR-068 D3 / ADR-081 / #401) recovers a local decoder by bounded
whole-function emulation plus a static scan of **the entry function's** p-code for the decode ops
(`INT_XOR`/value-feeding `INT_ADD`), the `STORE`-value varnodes, and the write-target buffers. When
the decode loop delegates the per-byte transform to a **helper function** (`for i: out[i] =
transform(in[i], key)`), the transform's `INT_XOR`/`INT_ADD` lives in the **callee**, which the scan
never visits — so detection finds no decode op, `select_decode_ops` is empty, and recovery returns
not-recovered, even though the emulation *would* have decoded the buffer (it steps into the callee).

So an interprocedural *local* decoder is recoverable with **no new execution capability** — the
emulation is already interprocedural within the program; only the **static detection** must span the
callees to find the decode op, its stored value, and the buffer.

## Decision

### D1 — Cross-function detection over a bounded callee set

Extend the decoder scan: starting from the entry function, also scan its resolved **in-program
callees** (via the existing `_iter_call_sites`), transitively to a bounded depth, merging across the
whole set the decode-op candidates (`INT_XOR`/`INT_ADD` const, with output varnode), the
`STORE`-value varnodes, the `COPY`/`SUBPIECE` link edges (#401), and the write-target buffers. The
pure filter (`core.multidecode.select_decode_ops` + `expand_value_feeders`) and the multi-buffer
readback (ADR-081) are unchanged — they now operate over the merged, cross-function signal. The
bounded whole-function emulation of the **entry** is unchanged and already runs the callees.

### D2 — Bounds (DoS): `max_callees` + `max_call_depth`

Two new `xor_decode` caps, **server-clamped**: `max_call_depth` (default `2`, range `[0, 8]`) bounds
how deep the callee walk recurses (`0` = the current entry-only behavior, fully backward-compatible),
and `max_callees` (default `16`, range `[1, 256]`) bounds the total number of distinct functions
scanned. The callee walk is breadth-first with a visited-set (cycle-safe) and stops at either cap. A
hostile deep/wide call graph can never trigger an unbounded static scan; the emulation stays bounded
by `max_steps` + the ADR-002 wall-clock kill as before.

### D3 — External / unresolved calls stay fail-closed

A CALL whose target is **not an in-program function** (an import/library thunk, or an
indirect/computed `call rax`) is *not* scanned (nothing to scan) and, at emulation time, stepping
into it faults → `stop_reason="fault"` → no printable-changed run → **not-recovered**. Recovering a
decoder that needs an external helper (`memcpy`, a ROM routine) requires client-supplied `stubs`
(ADR-066 D2), which `deobfuscate_strings` does not yet expose — a separate, tracked follow-up. This
ADR covers **in-program** interprocedural decoders only; everything else stays fail-closed, never
guessed.

### D4 — Honesty & scope fence (unchanged)

The before/after printable-changed gate (ADR-068 D3) is retained — the recovery honesty guarantee is
unchanged: a non-decoder across functions yields nothing. Self-modifying and stateful-stream
decoders (ADR-081 D4) remain deferred and fail-closed. This ADR **widens static detection across a
bounded in-program call graph**; it adds no new execution capability and no reach outside the
program the emulator already runs.

### D5 — Contract delta (WS0, atomic)

Additive, backward-compatible: `DeobfuscateStringsIn.max_call_depth` + `max_callees`. The output
shape is unchanged (the recovered string + `stages` chain; a stage key may now originate in a
callee, still untrusted-wrapped). `docs/contracts/tool-catalog.md` + `docs/contracts/rpc-protocol.md`
note the two caps and the cross-function detection. No catalog count change.

## Security / threat-model delta

- **No new execution surface (ADR-001 / LLM08):** the emulation is the *same* single bounded ADR-049
  whole-function run, which already steps into in-program callees. This ADR only **reads more static
  p-code** (a bounded call-graph walk) to locate the decode op/buffer. No additional `emulate` call,
  no new ability to run external code, no write, no script.
- **DoS (CWE-400):** `max_call_depth` + `max_callees` bound the static walk; `max_steps` /
  `max_bytes` / `max_stages` bound the emulation + readback; the ADR-002 wall-clock kill backstops.
  The walk is cycle-safe (visited-set) and breadth-first with a hard node cap.
- **Untrusted output (ADR-005):** recovered `text` and stage `key`s remain binary-derived, of hostile
  origin, envelope-wrapped and inert — a key may now come from a callee's p-code; the handling is
  identical.
- **Fail-closed fence (D3):** external/unresolved calls are not scanned and fault at emulation →
  not-recovered. No guessed plaintext.
- **Trust boundary unchanged:** the p-code walk + emulation are the TB3 worker edge; the server never
  parses the binary or loads the JVM.

## Alternatives considered

- **Add interprocedural call-*emulation* plumbing** — rejected as unnecessary: the emulator already
  follows in-program calls (that is why `stubs` exist). The gap was detection only; widening
  detection is the minimal, lowest-risk change.
- **Emulate each callee separately to catch the transform** — rejected: the entry emulation already
  runs the callees in-context; re-emulating them in isolation loses the caller's buffer/argument
  state and adds cost for no recovery gain.
- **Inline-only (no call-graph walk), rely on the decompiler to inline** — rejected: the raw-p-code
  scan deliberately avoids the decompiler's `HighFunction` (ADR-068 D2), and inlining is not
  guaranteed; an explicit bounded callee walk is deterministic.
- **Follow external calls by auto-stubbing** — rejected for this ADR (D3): guessing a library
  routine's effect risks confidently-wrong plaintext; client-supplied stubs are the safe path and a
  separate follow-up.

## Consequences

- **Positive:** recovers the common "decode loop calls a per-byte helper" pattern real firmware/
  malware uses, within the ratified ADR-049 execution envelope (no new agency); reuses the ADR-081
  multi-buffer readback + the #401 copy-chain filter over the merged cross-function signal.
- **Negative / cost:** a wider JVM-edge static walk (`# pragma: no cover`) to validate via the gated
  live-regression (worker rebuild + `.github/worker-image.pin` bump per the
  worker-change-validation-recipe); the pure filter/selection logic is unchanged and already
  hermetically tested. The callee-walk bounds are unit-tested at the schema level.
- **Scope:** SemVer **minor** (additive, backward-compatible; `max_call_depth=0` reproduces the prior
  entry-only behavior). External-helper (stub-assisted) decoders + self-modifying + stateful remain
  future work.

## Testing (master §4)

- **Unit (hermetic):** schema `max_call_depth` clamp `[0,8]` (default 2) + `max_callees` clamp
  `[1,256]` (default 16). The pure filter/expansion/selection/readback cores are unchanged (their
  existing tests hold); cross-function merge assembles the same candidate shape the pure functions
  already consume.
- **Integration (gated real worker, live-regression):** a micro-binary whose entry loop **calls a
  local per-byte XOR helper** (the `INT_XOR` + the store split across two functions) → assert
  `"Hello!"` is recovered with `technique="xor_decode"` and the key chain; assert the entry-only
  path (`max_call_depth=0`) does **not** recover it (proves the cross-function walk is what enables
  it). Added to the live-regression hard-gate list at the worker repin.
- **Abuse:** a deep/wide call graph stays bounded (`max_call_depth`/`max_callees` honored,
  `truncated` where applicable); a decoder calling an **external** function fails closed
  (not-recovered), never guessed; a recovered string/key containing markup/URL/path bytes arrives
  envelope-wrapped and inert.

## Rollout

Additive + read-only + backward-compatible (`max_call_depth=0` = prior behavior) → no migration.
Worker-side change → needs a worker rebuild + `.github/worker-image.pin` bump (per the
worker-change-validation-recipe) before the live gate exercises it. Reuses the ratified ADR-049
emulator; no write-consent. Merge stays **gated**.
