# ADR-083: Stateful / stream-cipher decode recovery (`deobfuscate_strings` opt-in `stream_decode`)

- **Status:** **Proposed** (drafted by the assistant 2026-11-05; closes the ADR-081 D4 "stateful
  stream-cipher / key-schedule" deferral tracked as GH #400). Awaiting human ratification.
- **Date:** 2026-11-05
- **Deciders:** Human operator (ratification pending); drafted by the assistant from GH #400.
- **Context source:** ADR-068 D4 / ADR-081 D4 deferred "stateful stream ciphers / key schedules." The
  `xor_decode` family (ADR-068/081/ADR-082, #401/#398) detects a decode op by its **constant** key
  operand; a stream cipher XORs the ciphertext with an evolving **keystream** (a register value, not
  an immediate), so it is never detected — even though the ADR-049 emulation *would* reproduce the
  keystream and decrypt the buffer when the cipher is self-contained in the binary.

## Context

A stateful/stream decoder (RC4-like PRGA, an LFSR/rolling keystream, a counter-derived key) computes
`out[i] = ct[i] ^ keystream_i`, where `keystream_i` comes from state carried across the loop (and
often across function calls — the key schedule). Two things differ from the `xor_decode` family:

1. **The key is variable.** The `INT_XOR`/`INT_ADD` operand is a register holding the keystream byte,
   not a constant. `xor_decode` detection requires `isConstant()`, so the decode op is never found.
2. **The "key" is not reportable.** There is no single byte to report as `decode_key`; the keystream
   is per-byte, produced by the state machine.

But the **emulation already handles the mechanism**: the ADR-049 sandbox runs the key schedule, the
PRGA, and the XOR (stepping into in-program callees per ADR-082), so a **self-contained** stream
decoder (seed/key baked into the binary) decrypts the buffer under emulation. The gap is **detection
+ cost control**: relaxing `xor_decode` to accept a variable key would make it emulate far more
functions (any XOR-into-store), inflating its cost on large binaries.

## Decision

### D1 — A new OPT-IN technique `stream_decode` (not in the default set)

Add `stream_decode` to the `techniques` enum. It is **not** in the default (`stack_string` +
`xor_decode` stay the default). It is **function-scoped only** — `stream_decode` requires an explicit
`function`; a whole-program `stream_decode` scan is rejected (fail-closed `invalid-argument`), because
the variable-key relaxation would otherwise emulate a large fraction of the program's functions
(CWE-400). The caller points it at a suspected decryptor.

### D2 — Variable-key decode detection + emulate-then-prove

For the chosen function, scan it and its in-program callees (reuse the ADR-082 bounded walk) for a
decode op — an `INT_XOR`/`INT_ADD` whose **output feeds a `STORE` value** (reusing the #401
value-feed filter + the COPY/SUBPIECE expansion), with the key operand **constant OR variable**. If
one exists (plus a `STORE` and a candidate buffer base), run the bounded ADR-049 whole-function
emulation (which executes the key schedule + keystream + XOR) and read back the write buffers; recover
the buffer that **became printable and changed** (ADR-068 D3 honesty gate). The before/after gate is
the proof: a non-decryptor, or a cipher whose key is NOT baked in (so emulation produces garbage from
the zero-initialised state), yields no printable-changed run → **not-recovered**.

### D3 — No per-byte key; `encoding="stream"`

A `stream_decode` recovery reports `encoding="stream"`, `decode_key=null`, and `stages=null` — a
stream cipher has no single reportable key. The recovered `text` is still envelope-wrapped untrusted.
`technique="stream_decode"` tells the caller how it was recovered (lower confidence than a keyed
`xor_decode`: the plaintext is the emulator's output, trustworthy only insofar as the cipher was
self-contained).

### D4 — Bounds + fail-closed (self-contained only)

`max_bytes` / `max_steps` (a stream cipher's key schedule may need a larger step budget — the caller
raises it) / `max_call_depth` / `max_callees` bound the scan + emulation as for `xor_decode`; the
ADR-002 wall-clock kill backstops. **Scope fence:** `stream_decode` recovers only a **self-contained**
decoder — the seed/key must be baked into the binary (the emulator starts from the program's initial
memory + zeroed registers). A decoder keyed on external/runtime input, or one that calls an external
helper (faults), produces no printable-changed run → **not-recovered**, never a guess. Self-modifying
unpackers (ADR-081 D4) remain out of scope.

### D5 — Contract delta (WS0, atomic)

`techniques` enum += `"stream_decode"`; `RecoveredString.technique` enum += `"stream_decode"`;
`encoding` enum += `"stream"`. No new input fields (reuses `function`/`max_bytes`/`max_steps`/
`max_call_depth`/`max_callees`). `docs/contracts/tool-catalog.md` + `docs/contracts/rpc-protocol.md`
note the opt-in technique + its function-scoped + self-contained constraints. No catalog count change.

## Security / threat-model delta

- **No new execution surface (ADR-001 / LLM08):** the emulation is the *same* bounded ADR-049
  whole-function run (already interprocedural for in-program callees, ADR-082). `stream_decode`
  **relaxes detection** (accepts a variable key) and **requires a function scope**; it adds no new
  execution capability, no external-code execution, no write, no script.
- **DoS (CWE-400):** the function-scope requirement is the primary cost control (no broad
  whole-program variable-key emulation); `max_steps`/`max_bytes`/`max_call_depth`/`max_callees` +
  the wall-clock kill bound the single emulation. Opt-in keeps `xor_decode`'s cost profile unchanged.
- **Untrusted output (ADR-005):** the recovered `text` is binary-derived, of hostile origin,
  envelope-wrapped, inert. Confidence is lower than keyed recovery — `technique="stream_decode"`
  signals that; the caller treats it as a lead, not ground truth.
- **Fail-closed fence (D4):** external-key / external-call / non-self-contained ciphers produce no
  printable-changed run → not-recovered. No guessed plaintext.
- **Trust boundary unchanged:** the p-code walk + emulation are the TB3 worker edge; the server never
  parses the binary or loads the JVM.

## Alternatives considered

- **Relax the default `xor_decode` to variable keys** — rejected: it would emulate every
  XOR-into-store function on a whole-program scan, a large cost/DoS regression; the opt-in,
  function-scoped technique keeps the default cheap.
- **Statically model the key schedule (reconstruct the keystream without emulation)** — rejected:
  cipher-specific, fragile, and prone to confidently-wrong output; running the actual schedule in the
  sandbox is exact and cipher-agnostic.
- **Report a synthesised "key"** — rejected: a stream cipher has no single key; `encoding="stream"` +
  `decode_key=null` is the honest shape.
- **Follow external key material** — rejected: a decoder keyed on runtime input cannot be statically
  emulated; it fails closed (D4), and a stub-assisted variant is separate future work.

## Consequences

- **Positive:** recovers self-contained stream/stateful decoders (embedded-key RC4-like / rolling-key
  / LFSR) that the keyed family cannot, within the ratified ADR-049 execution envelope; reuses the
  ADR-082 call-graph walk + the #401 value-feed filter + the ADR-081 multi-buffer readback.
- **Negative / cost:** a wider JVM-edge detection branch (`# pragma: no cover`) validated via the
  gated live-regression (worker rebuild + pin bump). Lower-confidence output (emulator-produced) —
  signalled by the technique + the null key. Only self-contained ciphers are in scope.
- **Scope:** SemVer **minor** (additive, opt-in, backward-compatible — default techniques unchanged).
  External-key / self-modifying decoders remain future work.

## Testing (master §4)

- **Unit (hermetic):** `techniques` accepts `"stream_decode"`; the result schema accepts
  `technique="stream_decode"` + `encoding="stream"` + null key/stages. The whole-program
  `stream_decode` rejection (function required) is asserted at the schema/dispatch boundary.
- **Integration (gated real worker, live-regression):** a micro-binary with a **self-contained
  rolling-keystream** decoder (`k` carried + updated per byte; `out[i] = ct[i] ^ k`) → assert
  `"Hello!"` is recovered with `technique="stream_decode"`, `encoding="stream"`, and no `decode_key`;
  assert the default `xor_decode` does **not** recover it (the key is variable). Added to the
  live-regression hard-gate list at the worker repin.
- **Abuse:** a whole-program `stream_decode` request is rejected (function required); a decoder keyed
  on an uninitialised/external value produces garbage → not-recovered (fail closed); a recovered
  string containing markup/URL/path bytes arrives envelope-wrapped and inert.

## Rollout

Additive + opt-in + backward-compatible (default techniques unchanged) → no migration. Worker-side
change → needs a worker rebuild + `.github/worker-image.pin` bump (per the
worker-change-validation-recipe) before the live gate exercises it. Reuses the ratified ADR-049
emulator; no write-consent. Merge stays **gated**.
