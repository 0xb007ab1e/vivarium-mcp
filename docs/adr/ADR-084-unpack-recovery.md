# ADR-084: Self-modifying unpacker recovery (`deobfuscate_strings` opt-in `unpack`)

- **Status:** **Proposed** (drafted by the assistant 2026-11-05; closes the ADR-081 D4
  "self-modifying unpackers" deferral tracked as GH #399). Awaiting human ratification.
- **Date:** 2026-11-05
- **Deciders:** Human operator (ratification pending); drafted by the assistant from GH #399.
- **Context source:** ADR-068 D4 / ADR-081 D4 deferred "self-modifying unpackers" on the premise
  that the ADR-049 emulator runs pre-translated p-code and would not re-decode bytes written to code
  space. **An empirical probe disproved that premise:** Ghidra's `EmulatorHelper` *re-translates on
  execution* — a probe ran a self-modifying unpacker (a loop XOR-patches 25 bytes into the following
  code region, falls through, and executes the now-decoded instructions), which returned cleanly
  (`stop-address`), decoded the patch region to real instructions, and wrote the expected output
  (`"Hi!"`) into a data buffer. Self-modification is already handled **inside the existing sandbox**
  (still p-code only — no native execution).

## Context

A self-modifying unpacker decodes bytes into a writable (often executable) region at runtime and then
executes them; the recovered strings are produced by the **unpacked** code, not sitting in the static
image. The emulation already runs the whole thing. The gap is **output discovery**: the decode-loop
readback (ADR-081/ADR-082) reads the loop's *static* write targets — but an unpacker's final strings
land in a buffer whose address is a constant *inside the decoded code*, invisible to the static
pre-emulation scan. So the plaintext exists in the emulator's post-run memory but is never read back.

This is the same class as `stream_decode` (ADR-083): a mechanism the emulation already executes, that
only needs the right **detection + readback** — not a new execution capability.

## Decision

### D1 — A new OPT-IN technique `unpack`: run, then scan post-run memory

Add `unpack` to the `techniques` enum. It is **not** in the default and is **function-scoped only**
(a whole-program `unpack` is rejected, CWE-400 — emulating every function is prohibitive). For the
chosen function the worker runs the bounded ADR-049 whole-function emulation (which executes the
unpacker and the unpacked code — the probe proved this), then reads back a **bounded window of the
program's writable memory from the post-run state** and extracts every printable string that
**appeared** (changed vs the static file bytes). Each is reported as `technique="unpack"`.

### D2 — Output extraction (pure, testable)

The post-run readback window(s) are diffed against the original (static) bytes by the pure
`core.multidecode.extract_changed_strings(before, after, *, min_length, max_results)` — it scans
`after` for maximal printable-ASCII runs of at least `min_length` that are NOT byte-identical to the
same span of `before` (so only unpacker-produced content is reported, not pre-existing plaintext),
returning `(offset, text)` pairs, bounded by `max_results`. Deterministic + side-effect-free; the
JVM edge only supplies the before/after bytes.

### D3 — No key / no stages; `technique="unpack"`

An `unpack` recovery reports `technique="unpack"`, `encoding=null`, `decode_key=null`, `stages=null`
— an unpacker has no single key and the recovery is "what strings the unpacker produced in memory."
The recovered `text` is envelope-wrapped untrusted. The technique signals lower confidence (the
plaintext is the emulator's output of attacker-controlled code, executed only as sandboxed p-code).

### D4 — Bounds + fail-closed (self-contained only)

`max_bytes` bounds the post-run window read from each writable block; `max_results` bounds the
strings; `max_steps` bounds the emulation (an unpacker's loop may need a larger budget — the caller
raises it); `max_call_depth`/`max_callees` are not used by `unpack` (it reads memory, not call-graph
decode ops). The ADR-002 wall-clock kill backstops. **Scope fence:** `unpack` recovers only a
**self-contained** unpacker (seed/key baked in; the emulator starts from program memory + zeroed
registers). An unpacker keyed on external/runtime input, or one that faults before producing output,
yields no changed printable string → **not-recovered**, never a guess.

### D5 — Contract delta (WS0, atomic)

`techniques` enum += `"unpack"`; `RecoveredString.technique` enum += `"unpack"`. No new input fields
(reuses `function`/`max_bytes`/`max_results`/`max_steps`). `encoding`/`decode_key`/`stages` stay
`null` for `unpack`. `docs/contracts/tool-catalog.md` + `docs/contracts/rpc-protocol.md` note the
opt-in technique + its function-scoped + self-contained constraints. No catalog count change.

## Security / threat-model delta

- **No new execution surface (ADR-001 / LLM08):** the emulation is the *same* bounded ADR-049
  whole-function run. Ghidra's emulator already re-translates self-modified code (the probe proved
  it) — this is **not** a new capability introduced here; it is existing, sandboxed, p-code-only
  behavior (no native execution, no syscalls, no host escape; the program DB is not mutated — only
  the emulator's private memory state). `unpack` **relaxes detection** (no decode-op required — it
  reads memory after the run) and **requires a function scope**. No write, no script.
- **Executing attacker-decoded code (bounded):** the unpacked code runs **only as re-translated
  p-code in the ADR-049 interpreter** — the same sandbox that already runs the function's original
  code. It cannot make syscalls, perform I/O, or touch the host; it is bounded by `max_steps` + the
  wall-clock kill. The output is treated as untrusted (D3).
- **DoS (CWE-400):** the function-scope requirement + `max_steps`/`max_bytes`/`max_results` + the
  wall-clock kill bound the single emulation and the post-run scan. Opt-in keeps the default cheap.
- **Untrusted output (ADR-005):** recovered `text` is binary-derived, hostile-origin, envelope-
  wrapped, inert; lower confidence (emulator output of attacker code) — `technique="unpack"` signals
  it.
- **Fail-closed fence (D4):** external-keyed / faulting / non-self-contained unpackers produce no
  changed printable string → not-recovered. No guessed plaintext.
- **Trust boundary unchanged:** the emulation + memory read are the TB3 worker edge; the server never
  parses the binary or loads the JVM.

## Alternatives considered

- **Only surface the decoded CODE region (not a memory scan)** — rejected: the unpacker's *strings*
  are the value, and they land in a data buffer discovered only at runtime; surfacing the decoded
  instruction bytes would miss them and emit non-printable noise.
- **Statically trace the output buffer address** — rejected: the address is a constant inside the
  (encrypted) decoded code; recovering it statically means decoding the code by hand. Running the
  unpacker and scanning memory is exact and unpacker-agnostic.
- **Add `unpack` to the default techniques** — rejected: emulating every function on a whole-program
  scan is prohibitive; opt-in + function-scoped keeps the default cheap (same rationale as
  `stream_decode`).
- **Refuse self-modifying entirely (keep deferred)** — rejected now that the probe shows the
  emulation handles it safely within the existing sandbox; recovering the output is a real triage win.

## Consequences

- **Positive:** recovers strings from self-modifying unpackers — a common malware packer pattern —
  within the ratified ADR-049 execution envelope (no new capability); reuses the emulation and adds a
  pure post-run string-extraction core.
- **Negative / cost:** a new JVM-edge readback branch (`# pragma: no cover`) validated via the gated
  live-regression (worker rebuild + pin bump). Lowest-confidence output in the family (emulator
  output of attacker code) — signalled by the technique + null metadata. Only self-contained
  unpackers are in scope.
- **Scope:** SemVer **minor** (additive, opt-in, backward-compatible). External-keyed unpackers remain
  future work.

## Testing (master §4)

- **Unit (hermetic):** `extract_changed_strings` — finds printable runs ≥ `min_length` that changed
  vs before; ignores unchanged (pre-existing) plaintext; bounded by `max_results`; property/fuzz:
  arbitrary before/after never raise, every result is printable + changed. Schema: `techniques`
  accepts `"unpack"`; the result schema accepts `technique="unpack"` with null encoding/key/stages.
- **Integration (gated real worker, live-regression):** the self-modifying unpacker micro-binary (a
  loop XOR-patches a code region, falls through, executes the decoded instructions which write a
  string to a data buffer) → assert the string is recovered with `technique="unpack"`; assert the
  default `xor_decode` does **not** recover it (the output is not a static write target). Added to
  the live-regression hard-gate list at the worker repin.
- **Abuse:** a whole-program `unpack` request is rejected (function required); a function that
  produces no new printable string yields nothing (fail closed); a recovered string containing
  markup/URL/path bytes arrives envelope-wrapped and inert; the emulation stays bounded (`max_steps`).

## Rollout

Additive + opt-in + backward-compatible → no migration. Worker-side change → needs a worker rebuild +
`.github/worker-image.pin` bump (per the worker-change-validation-recipe) before the live gate
exercises it. Reuses the ratified ADR-049 emulator (which already re-translates self-modified code);
no write-consent. Merge stays **gated**.
