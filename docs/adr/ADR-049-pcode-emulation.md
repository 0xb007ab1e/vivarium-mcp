# ADR-049: P-Code emulation — bounded `emulate` tool

- **Status:** **Accepted** (ratified 2026-08-12). First tool that *executes* binary-derived code;
  scope + bounds set by the operator.
- **Date:** 2026-08-12
- **Deciders:** Human operator (ratified: registers + memory scope; step cap default 100k / max 1M);
  assistant grounded + implemented.
- **Context source:** Grounded live in the worker — `ghidra.app.emulator.EmulatorHelper` loaded a raw
  x86-64 blob (`mov eax,5; add eax,3; ret`), set PC/SP, stepped a bounded loop, and read back
  `RAX == 8`. Confirms feasibility + the safety model below.

## Context

Every Vivarium tool so far is read-only *inspection*: disassemble, decompile, xref, read bytes. A
recurring RE need — solving a routine's effect (a checksum, a key derivation, a deobfuscator) — needs
to **run** the code, which the tool set could not do. This is the sanctioned alternative to the
external angr/Unicorn route (see the open-pocket session-key notes): execute the recovered routine
and read the result.

**The safety model that makes this acceptable.** Ghidra's emulator is a **p-code interpreter**: it
steps the lifted intermediate representation, NOT native machine instructions on the host CPU. It
makes **no syscalls and no I/O**; a syscall/external p-code op (`CALLOTHER`) is unimplemented and
either halts or is inert — the emulator **cannot escape to the host**. State lives in the emulator's
own memory image, seeded from the program; the program DB is **not mutated** (still read-only). So
"executing untrusted code" here is a sandboxed IR interpreter, not native execution.

## Decision

### D1 — A new `emulate` tool (Tier-1, read-only-effect), registers + memory

`emulate(session_id, start, set_registers?, write_memory?, max_steps?, stop_at?, read_registers?,
read_memory?)`:
- **`start`** — hex address to begin execution (PC).
- **`set_registers`** — optional `{register_name: int}` presets (e.g. args, a stack pointer).
- **`write_memory`** — optional `[{address, data_hex}]` writes into the emulator image before running
  (stage arguments / buffers). Bounded total size.
- **`max_steps`** — p-code step budget, server-clamped to **[1, 1_000_000]**, **default 100_000**.
- **`stop_at`** — optional hex address; execution stops when reached.
- **`read_registers` / `read_memory`** — which registers / memory ranges to return after the run
  (bounded count/size).

Returns `steps_executed`, a closed-vocab `stop_reason` (`stop-address` / `max-steps` / `halted` /
`fault`), and the requested register values + memory bytes.

### D2 — Bounds (DoS on a hostile binary)

The emulated program is HOSTILE (a step could be an infinite loop). Three independent bounds:
`max_steps` (the hard step cap, server-clamped), the **existing per-call wall-clock kill** (ADR-002 —
SIGKILL the worker on timeout), and the worker **memory cap** (container). `write_memory` /
`read_memory` sizes + `read_registers` count are capped server-side (CWE-400). Emulation runs entirely
inside the hardened, ephemeral, network-isolated worker container — never the host (operator
directive).

### D3 — Output is binary-derived → untrusted envelope

Register/memory values produced by emulating a hostile binary are attacker-influenced. They are
returned wrapped in the **untrusted-data envelope** (ADR-005) — inert data, never executed/rendered/
followed — exactly like decompiled text or read bytes.

### D4 — Input validation, fail closed

`start`/`stop_at`/`write_memory[].address` parse as addresses; `register` names are validated by the
worker against the program's register set (unknown → fail closed `not-found`); `max_steps` clamped;
`data_hex` is valid hex within the size cap. Server validates shape/bounds before the worker (CWE-20);
the server never loads the JVM (ADR-001). No `set_registers`/`write_memory` can make the emulator do
I/O or escape — the interpreter has no such capability.

### D5 — No new agency / still read-only

`emulate` grants no write to the program, no host effect, no external call. It computes a function's
effect in a sandbox and returns values. It is added to the Tier-1 read allow-list (not a write tool);
the write-consent gate is unchanged.

## Alternatives considered

- **External Unicorn/angr** — rejected: brings native execution (Unicorn JITs to the host CPU) or a
  heavy dependency; the in-Ghidra p-code emulator is already present, sandboxed (no native exec), and
  needs no new dependency or attack surface.
- **Registers-only v1** — considered; operator chose registers + memory (staging/reading buffers is
  what makes solving real routines possible).
- **No step cap (wall-clock only)** — rejected: a tight, deterministic step cap is a better primary
  bound than wall-clock alone; wall-clock remains the backstop.

## Consequences

- **Positive:** unlocks "run the routine to solve it" (checksums, key derivations, deobfuscators)
  without leaving Vivarium or adding native execution. The sanctioned in-house alternative to
  angr/Unicorn.
- **Cost / risk:** first executing tool — the threat surface is a hostile p-code program; mitigated by
  the interpreter's inherent sandbox (no native exec / no I/O) + the three bounds + the container.
  Adds one Tier-1 tool (the frozen catalog count increments).

## Testing (master §4)

- **Unit:** schema — `max_steps` clamp/bounds; `write_memory`/`read_memory` size + count caps;
  `data_hex` validation; address fields. Output carries the untrusted envelope.
- **Integration (gated real worker):** emulate a raw `mov eax,5; add eax,3; ret` blob from its start
  with a step cap and assert the returned `RAX == 8`, `stop_reason` set, `steps_executed` bounded —
  the grounded proof-of-concept. Add an abuse case: a tight infinite loop hits `max-steps` (bounded).

## Rollout

Additive — a new opt-in tool; no existing behavior changes. Documented in the tool catalog +
`vivarium://docs/importing` is unaffected. Merge stays **gated**. The tool is read-effect-only and
needs no write-consent.
