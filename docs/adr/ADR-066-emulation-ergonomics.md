# ADR-066: Emulation ergonomics — call-a-function + library-call stubs over `emulate`

- **Status:** **Accepted** (ratified by the human operator 2026-08-13; v1.9). Item 3 of the post-v1.8
  capability-gap batch (ADR-064..072).
- **Date:** 2026-08-13
- **Deciders:** Human operator (to ratify); drafted by the assistant from the post-v1.8 capability-gap
  survey. Builds directly on the ratified `emulate` tool (ADR-049).
- **Context source:** The `emulate` tool (ADR-049) is a bounded p-code interpreter — grounded live in
  the worker (`EmulatorHelper` stepped `mov eax,5; add eax,3; ret` → `RAX == 8`). Using it today to
  solve a *function* still requires the client to hand-assemble the calling convention (which register
  or stack slot each argument lands in, where the return value comes back) and to route around any
  external call the routine makes. The parked T19 firmware session-key derivation (an app-side SHA-256
  over a token) and firmware checksum/CRC routines are exactly "run this pure function on these inputs,
  observe the output" — but they call `memcpy`/`strlen`/a ROM thunk mid-way, so a raw `emulate` halts.

## Context

`emulate` (ADR-049) exposes the primitive: seed PC/registers/memory, step a bounded loop, read back
registers/memory. It deliberately stops there. Two ergonomic gaps make it awkward for the most common
RE goal — *evaluate a routine's effect*:

1. **Manual calling-convention setup.** To "call `derive_key(token, len)`" the client must know the
   target's ABI, place each argument in the right register/stack slot, set up a return address, run,
   then read the ABI's return register. That's Ghidra-knowable (the decompiler already models the
   function's `prototype`/calling convention), so the client is re-deriving what the worker already has.
2. **External calls abort the run.** A self-contained checksum/derivation routine still calls
   `memcpy`/`memset`/`strlen` or a ROM thunk. Those targets are unresolved/external in the program
   image, so the emulator hits an unimplemented target and halts (ADR-049 D1 `stop_reason=halted`) —
   the routine never completes even though its *logic* is fully present.

Both are **convenience layered on the existing interpreter** — not a new execution model. This ADR
adds ergonomics **without weakening any ADR-049 safety property**: still a deterministic bounded p-code
interpreter, still worker-only (ADR-001), still no native execution, no syscalls, no real I/O, output
still binary-derived → untrusted envelope (ADR-005).

## Decision

### D1 — Call-a-function convenience (set up args, run bounded, read result)

Provide a "call this function with concrete arguments" convenience over `emulate`: given a function
and a positional argument list, the **worker** places arguments per the function's calling convention
(from the decompiler's `prototype`/`FunctionSignature`), sets a sentinel return address as the stop
target, runs the existing bounded emulator, and returns the ABI return value plus optionally any
caller-supplied output buffers read back.

| Field | Type | Meaning |
|---|---|---|
| `function` | `str` | The function to call (address or name; resolved server→worker as elsewhere). |
| `args` | `list` | Positional arguments — each an integer (register/stack scalar) or a staged buffer `{data_hex}` written to emulator memory with a pointer passed in the slot. Bounded count + total size. |
| `read_buffers` | `list?` | Optional `[{arg_index \| address, length}]` output ranges to read back after the run (bounded count/size), for routines that write through a pointer argument. |
| `max_steps` | `int?` | P-code step budget, server-clamped to ADR-049's `[1, 1_000_000]`, default `100_000`. |

Returns `return_value`, `steps_executed`, the closed-vocab `stop_reason` (ADR-049: `stop-address` /
`max-steps` / `halted` / `fault`, plus `stub-limit` — see D2), and any requested output buffers. The
calling convention is read from the decompiler, not guessed by the client; if the function has no
usable prototype the call fails closed (`analysis-failed`/`not-found`) rather than picking an ABI
silently.

### D2 — Optional library-call stubs / hooks (substitute a return value, never run real code)

Allow the caller to supply a **bounded stub table** so an external/unresolved call the routine makes
is *substituted* rather than followed:

| Field | Type | Meaning |
|---|---|---|
| `stubs` | `list?` | `[{target, action}]` where `target` is a callee (address or import name) and `action` is one of a **closed vocabulary**: `return_const:<int>` (set the ABI return register to a constant and continue past the call), or `skip` (advance past the call as a no-op / identity). Bounded count. |

When emulation reaches a call whose target matches a stub, the worker applies the stub's action —
sets the return register (`return_const`) or simply steps over the call (`skip`) — and resumes. **A
stub only substitutes a return value / skips the call frame; it never runs real library code, never
loads a host library, and never touches the host.** This keeps the ADR-049 sandbox intact: the
interpreter still makes no syscalls and cannot escape; a stub is purely a value the *client* asserts,
treated as untrusted like any other input. A call to an unresolved target with **no** matching stub
behaves exactly as today (halts — `stop_reason=halted`), so stubs are strictly opt-in. If the stub
budget is exhausted (more stubbed calls than the cap), the run stops with `stop_reason=stub-limit`.

### D3 — Bounds (DoS on a hostile binary — CWE-400)

The emulated program is HOSTILE (ADR-049 D2). All ADR-049 bounds carry over unchanged — `max_steps`
(server-clamped step cap), the per-call **wall-clock kill** (ADR-002 — SIGKILL the worker on timeout),
and the container **memory cap**. This ADR adds three server-clamped caps validated **before the
worker** (CWE-400): **arg count + total staged-buffer size**, **read-buffer count + total size**, and
**stub-table count**. A hostile routine that calls a stubbed function in a tight loop is still bounded
by `max_steps`/wall-clock; the stub-count cap bounds *distinct* stubbed targets and surfaces
`stub-limit` honestly. All caps are enforced server-side (the server never loads the JVM — ADR-001)
and re-enforced in the worker.

### D4 — Output is binary-derived → untrusted envelope (ADR-005)

`return_value`, `steps_executed`, and every read-back buffer are the effect of emulating a hostile
binary and are attacker-influenced. They are returned wrapped in the **untrusted-data envelope**
(ADR-005) — inert data, never executed / rendered / followed — exactly like `emulate`'s registers +
memory, decompiled text, or read bytes.

### D5 — No new agency / still read-effect-only

Neither D1 nor D2 grants any write to the program, any host effect, or any external call. Arguments,
buffers, and stubs seed a **sandboxed IR interpreter** that computes a function's effect and returns
values; the program DB is not mutated (still read-only). This is added to the Tier-1 read
allow-list alongside `emulate`; the write-consent gate is unchanged (LLM08 — no new autonomy: a stub
substitutes a value, it does not expand what the interpreter can *do*).

### D6 — Contract delta (WS0, atomic)

Extend the frozen contract atomically per the batch-atomicity mandate — either as additive optional
params on `emulate` (`args`/`read_buffers`/`stubs` with the calling-convention setup) **or** as a
sibling Tier-1 tool (e.g. `emulate_call`) that composes over the same worker method; the ratifying
decision picks one. Update `docs/contracts/tool-catalog.md` + `docs/contracts/rpc-protocol.md`
together; the catalog count increments only if a sibling tool is chosen. Lands atomically with the
schema (frozen-contract mandate — never edited ad hoc by a feature workstream).

## Security / threat-model delta

- **No new agency (ADR-001/LLM08):** convenience over the existing sandboxed interpreter; no write, no
  host effect, no external call. A stub substitutes a return value — it never runs real library code or
  touches the host, so it does not widen the interpreter's capability.
- **Sandbox unchanged (ADR-049):** still a bounded p-code interpreter — no native execution, no
  syscalls, no real I/O; a `CALLOTHER`/unresolved target with no stub still halts inertly. Runs only in
  the hardened, ephemeral, network-isolated worker container (operator directive), never the host.
- **Untrusted output (ADR-005):** return value + read-back buffers are binary-derived → envelope-wrapped.
- **DoS (CWE-400):** new caps (arg/buffer sizes, read-buffer count/size, stub-table count) validated
  server-side before the worker and re-enforced in it; `max_steps` + wall-clock (ADR-002) + container
  memory remain the backstops. `stub-limit` bounds stubbed-call fan-out honestly.
- **Input validation, fail closed (CWE-20):** `function` resolves + must have a usable prototype (else
  fail closed); `args`/`read_buffers`/`stubs` validated for shape, bounds, and closed-vocab `action`
  before the worker; unknown stub target is inert (no match → halt as today). The server never loads
  the JVM (ADR-001).
- **Trust boundary unchanged:** the JVM/emulator edge is the TB3 worker boundary; the server never
  parses the binary.

## Alternatives considered

- **Leave calling-convention setup + external-call routing to the client** — rejected: forces every
  client to re-model the ABI the decompiler already knows and to hand-patch around each external call;
  error-prone and duplicative, and the exact reason the parked T19 SK derivation stalled under raw
  `emulate`.
- **Stubs that actually execute a bundled libc (real `memcpy`/`strlen`)** — rejected: that would run
  real library code inside the emulator, expanding the sandbox surface and inviting the very
  native-execution/I-O risk ADR-049 forbids. Value-substitution stubs keep the interpreter inert; the
  common cases (`memcpy`/`memset`/`strlen`/ROM thunks) are covered by `return_const`/`skip`, and a
  routine that genuinely needs real library semantics is out of scope (use a real staged buffer, or
  defer to a future ADR).
- **External Unicorn/angr with a hooking framework** — rejected for the same reasons as ADR-049:
  brings native execution or a heavy dependency; the in-Ghidra p-code emulator is present, sandboxed,
  and needs no new dependency or attack surface.
- **Open-ended scripting hook (arbitrary stub callback)** — rejected: free-form execution on a hostile
  binary is exactly the agency ADR-001/LLM08 forbid; the closed-vocab `action` set is the least-power
  design that solves the motivating cases.

## Consequences

- **Positive:** turns `emulate` from a primitive into a usable "call this function on these inputs and
  read the result" tool; makes self-contained checksum/CRC/key-derivation routines (the T19 app-side
  SHA-256 gate) run to completion by stubbing their `memcpy`/`strlen`/thunk calls — mechanical instead
  of hand-assembled. Reuses the decompiler's own calling-convention model, so ABI setup is exact.
- **Negative / cost:** more surface on the first *executing* tool — argument staging, ABI resolution,
  and stub handling are new worker-side logic to validate via the gated live-regression; a function
  without a usable prototype or a routine needing real library semantics fails closed / is out of
  scope. New `stop_reason=stub-limit` value to document.
- **Scope:** SemVer **minor** (additive read-effect-only ergonomics over an existing tool). Executing
  real library code = a future ADR, if ever.

## Testing (master §4)

- **Unit:** schema validation — `args`/`read_buffers`/`stubs` shape + bounds; the closed-vocab stub
  `action` (`return_const`/`skip`; unknown rejected); server-side clamping of arg/buffer sizes,
  read-buffer count/size, and stub-table count proven with known-bad oversized inputs (the fixture must
  actually trip the cap, not be silently exempt — master §4). Output carries the untrusted envelope.
- **Integration (gated real worker, live-regression):** (a) build a tiny known arithmetic function
  (e.g. `int add3(int x){ return x + 3; }` or a small multiply), call it via D1 with a concrete
  argument, and assert the returned `return_value` matches the expected result, `stop_reason` set,
  `steps_executed` bounded — the D1 proof. (b) A routine that calls an external stub target (e.g. a
  `strlen`/`memcpy` thunk) with a `return_const`/`skip` stub runs to completion and returns the correct
  result, where the same call **without** the stub halts (`stop_reason=halted`) — the D2 proof. Add
  both to the live-regression hard-gate list.
- **Abuse:** a routine that loops on a stubbed call stays bounded (`max_steps`/`stub-limit` honored,
  bounded `steps_executed`); an oversized arg/buffer/stub table is rejected server-side (fail closed);
  a function with no usable prototype fails closed category-safe; an unresolved call with no matching
  stub halts inertly (no escape).

## Rollout

Additive + read-effect-only → no migration; existing `emulate` behavior is unchanged (all new fields
optional). Worker-side change (ABI setup + stub handling) → needs a worker rebuild + `.github/
worker-image.pin` bump (per the worker-change-validation-recipe) before the live gate exercises it.
The tool needs no write-consent. Merge stays **gated**.
