# ADR-068: String / constant deobfuscation (read-only stack-string + single-pass decode recovery)

- **Status:** **Proposed** (awaiting human ratification; v1.9). Item 5 of the post-v1.8 capability-gap
  batch (ADR-064..072).
- **Date:** 2026-08-13
- **Deciders:** Human operator (ratification pending); drafted by the assistant from the post-v1.8
  capability-gap survey (obfuscated-string recovery flagged as a common firmware/malware need).
- **Context source:** Vivarium surfaces only *plaintext* strings — `list_strings` / `search_strings`
  scan the binary for existing character runs. Firmware and malware routinely hide strings so those
  tools find nothing: (a) **stack-strings** built byte-by-byte by immediate stores
  (`mov [sp+0],'H'; mov [sp+1],'i'`), and (b) simple **XOR/ADD/rolling-decoded** blobs unpacked by a
  local decode loop at runtime. The T19 firmware work and standard RE triage both hit this — the
  interesting strings are the hidden ones.

## Context

`list_strings` / `search_strings` are pattern scanners over the program's bytes: they recover only
what is already sitting in memory as plaintext. Two obfuscation families defeat them completely:

- **Stack-strings** never exist as a contiguous run in the file — the plaintext only materializes on
  the stack at runtime, assembled by a sequence of constant immediate stores to adjacent stack slots.
  Statically the bytes are scattered across instruction immediates.
- **Encoded blobs** sit in `.data`/`.rodata` as ciphertext and are decoded in place (or into a local
  buffer) by a short loop (single-pass XOR/ADD with a constant or short key). Statically only the
  ciphertext is present.

Both are *recoverable without execution risk*: stack-strings by a bounded static scan of the
disassembly/p-code for constant-store runs, and encoded blobs by **bounded p-code emulation of the
decode loop** — reusing the ADR-049 `emulate` engine (a sandboxed p-code interpreter: **no native
exec, no syscalls, no I/O**). This is a **read-only analysis** surface (stack-string recovery adds no
new agency at all; the encoded-blob path reuses the already-ratified, already-bounded emulator). It
fits the Tier-1 read-only catalog and the ADR-001 worker-only boundary.

## Decision

### D1 — `deobfuscate_strings`: bounded recovery of hidden strings (the MVP)

Add a read-only Tier-1 tool `deobfuscate_strings`:

| Field | Type | Meaning |
|---|---|---|
| `function` | `str?` | Optional scope: a function (address or name) to search; omitted = a bounded whole-program scan (server-clamped). |
| `techniques` | `list[Literal["stack_string","xor_decode"]]?` | Which recovery passes to run; default = both. |
| `min_length` | `int?` | Minimum recovered-string length to report (server-clamped floor, suppresses noise). |
| `max_results` | `int?` | Bound on the number of recovered strings returned (server-clamped hard cap). |
| `max_bytes` | `int?` | Bound on the length of any single recovered string (server-clamped). |
| `max_steps` | `int?` | Only for `xor_decode`: p-code step budget for the decode-loop emulation, server-clamped and defaulted (inherits the ADR-049 clamp `[1, 1_000_000]`). |

Returns a bounded list of recovered strings
`{address, technique, text, length, encoding?, decode_key?}` plus `truncated` when any cap is hit.
Every recovered `text`/`decode_key` is binary-derived → wrapped in the **untrusted-data envelope**
(ADR-005). `technique` reports how each string was recovered so the caller can weight confidence.

### D2 — Stack-strings: static constant-store-run detection

For `stack_string`, the worker walks the function's disassembly / p-code and detects **runs of
constant stores to adjacent stack slots** (immediate → `[sp+k]`, `[sp+k+1]`, …), reassembles the byte
run in slot order, and reports it as a recovered string when it meets `min_length` and is
printable-enough (a bounded printable-ratio filter). This is **pure static analysis** — no execution,
no new agency. Non-constant / non-adjacent / gapped stores terminate a run honestly rather than
guessing.

### D3 — Encoded blobs: bounded emulation of the local decode loop (reuses ADR-049)

For `xor_decode`, the worker recovers plaintext by **bounded p-code emulation** of the local decode
loop via the ADR-049 `emulate` engine — seed the ciphertext buffer, run the loop under `max_steps`,
read back the decoded bytes. The full ADR-049 safety model applies unchanged: a **sandboxed p-code
interpreter** (no native exec, no syscalls, no I/O, program DB not mutated), bounded by `max_steps`
+ the per-call wall-clock kill (ADR-002) + the worker memory cap. No new execution surface is
introduced beyond what ADR-049 already ratified.

### D4 — Scope the MVP; defer complex/multi-stage decoders

The MVP is **stack-strings + single-pass XOR/ADD** — the 80% of real obfuscation. Explicitly
**out of scope for v1.9** (deferred to a future ADR): multi-stage / chained decoders, decoders that
call out to other functions (interprocedural), self-modifying unpackers, and stateful stream ciphers.
`xor_decode` targets a *local, self-contained* decode loop only; anything that leaves the function or
requires cross-call state is reported as *not-recovered*, never half-guessed.

### D5 — Bounded before the worker (DoS)

`max_results` / `max_bytes` / `min_length` / `max_steps` and the whole-program scan bound are
validated + **hard-clamped server-side before the worker** (CWE-400 / ADR-001 posture, mirroring
every other bounded tool). The worker enforces the same caps and sets `truncated` honestly (ADR-005)
— a large or adversarial binary can never produce an unbounded scan or an unbounded emulation.

### D6 — Contract delta (WS0, atomic)

Additive Tier-1 tool → `docs/contracts/tool-catalog.md` (new row) + `docs/contracts/rpc-protocol.md`
(new worker method) + the untrusted-envelope schema unchanged (reused). Catalog count +1 (additive).
Lands atomically with the schema per the frozen-contract mandate; the absolute count is set at merge
per the ADR-064..072 batch sequencing.

## Security / threat-model delta

- **No new agency for D2 (ADR-001/LLM08):** stack-string recovery is read-only static analysis — no
  write, no execution, no script.
- **D3 reuses ratified execution surface:** the `xor_decode` path introduces **no new execution
  capability** — it invokes the ADR-049 p-code interpreter (already accepted, already bounded, no
  native exec / no I/O / no host escape) inside the ADR-002 worker.
- **Untrusted output (ADR-005 / std-owasp-llm LLM01/LLM02):** recovered strings are binary-derived
  **and of HOSTILE origin** — an attacker chooses exactly the bytes this tool reconstructs. Every
  `text`/`decode_key` is envelope-wrapped and must **never** be auto-followed, executed, rendered as
  markup, or treated as an instruction/URL/path.
- **DoS (CWE-400):** the result/byte/length/step caps bound both the scan and the emulation before +
  inside the worker; the per-tool wall-clock kill (ADR-002) is the backstop.
- **Trust boundary unchanged:** the JVM disassembly/p-code walk and the emulator run are the TB3
  worker edge; the server never parses the binary or loads the JVM.

## Alternatives considered

- **Client-side reconstruction over `disassemble` / `get_pcode`** — rejected: forces the client to
  ship + re-parse whole functions and re-implement stack-slot tracking and loop emulation; the worker
  already has the disassembly, the p-code, and the ADR-049 emulator.
- **Emulate every function to catch all obfuscation** — rejected: hugely expensive on a hostile
  binary and outside the DoS envelope; the static stack-string pass + a *targeted* local-loop
  emulation is the 80% value at a fraction of the cost/risk.
- **A general unpacker / multi-stage decoder engine** — rejected for v1.9 (D4): research- and
  DoS-heavy, and a much larger execution surface; the single-pass MVP is deferred-expandable.
- **Signature/heuristic-only decoding (guess the key, no emulation)** — rejected: brittle and prone to
  emitting confidently-wrong plaintext; running the actual local loop in the sandbox is exact.

## Consequences

- **Positive:** recovers the strings that matter most (deliberately hidden ones) — the missing triage
  primitive for firmware/malware RE; makes stack-string and simple-XOR reversing mechanical instead of
  hand-traced; reuses the decompiler output + the ADR-049 emulator so it adds no new execution
  surface.
- **Negative / cost:** a new JVM-edge (`# pragma: no cover`) worker method to validate via the gated
  live-regression; the encoded-blob path depends on a decompilable/analyzable function (requires prior
  `session_analyze`) — a non-analyzable target or a decoder that escapes the MVP scope fails closed
  (`not-recovered` / `analysis-failed`), never a guess.
- **Scope:** SemVer **minor** (additive read-only capability). Multi-stage / interprocedural /
  self-modifying decoders = a future ADR.

## Testing (master §4)

- **Unit:** schema validation (`techniques` enum; caps clamped: `max_results` / `max_bytes` /
  `min_length` / `max_steps`; unknown technique rejected). Server-side cap clamping proven. Output
  carries the untrusted envelope.
- **Integration (gated real worker, live-regression):** a micro-binary that builds a **known
  stack-string** via constant immediate stores → assert the string is recovered with
  `technique="stack_string"`; a micro-binary with a **single-pass XOR blob + local decode loop** →
  assert the plaintext is recovered with `technique="xor_decode"` and the reported `decode_key`;
  assert `truncated=true` under a tiny `max_results`. Add to the live-regression hard-gate list.
- **Abuse:** an oversized/degenerate function and a hostile decode loop must stay bounded (caps
  honored, `truncated=true`, emulation hits `max-steps`); a decoder that escapes the MVP scope
  (interprocedural / multi-stage) must fail closed category-safe (`not-recovered`), never emit
  guessed plaintext; a recovered string containing markup/URL/path bytes must arrive envelope-wrapped
  and inert.

## Rollout

Additive + read-only → no migration. Worker-side change → needs a worker rebuild + `.github/
worker-image.pin` bump (per the worker-change-validation-recipe) before the live gate exercises it.
The tool is read-effect-only (D2 is pure static; D3 reuses the ratified read-effect-only emulator) and
needs no write-consent. Merge stays **gated**.
