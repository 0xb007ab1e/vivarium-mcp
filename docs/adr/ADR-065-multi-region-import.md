# ADR-065: Multi-region / scatter-load raw import

- **Status:** **Accepted** (ratified by the human operator 2026-08-13; targets v1.9). Second of the ADR-064..072
  post-v1.8 capability-gap batch.
- **Date:** 2026-08-13
- **Deciders:** Human operator (to ratify); drafted by the assistant from the post-v1.8
  capability-gap survey (the ingestion item adjacent to ADR-045).
- **Context source:** ADR-045 unlocked headerless raw import but loads exactly **one** flat region at
  one base. Real devices ship **multiple** images at different bases in one system — e.g. the Actions/
  Telink "T19" firmware carries an ARM Cortex-M app at load `0x10000000`, a recovery image at
  `0x11000000`, and a Telink RISC-V image at `0x0`. Loading only one region at a time forces the
  operator to spin up disconnected sessions and loses the cross-region address relationships (xrefs,
  jump targets) that make the layout analyzable.

## Context

`session_import` with ADR-045 loader hints drives `BinaryLoader` for a single `{processor, base_addr,
entry?}` — one file, one block, one base. A scatter-loaded device firmware is several images that must
coexist in **one** address space so that a branch/pointer from the app region resolves into the
recovery region, strings/data in one block are xref'd from code in another, and the memory map reflects
the real device.

**A hard Ghidra constraint shapes the scope:** one Ghidra *program* has exactly **one**
processor/`Language`. So multiple **same-architecture** regions (e.g. several ARM Cortex-M blocks) map
cleanly into one program as distinct memory blocks. Genuinely **cross-architecture** regions (the ARM
app + the Telink RISC-V image) **cannot** share a program — they stay **separate sessions**, one per
Language. The MVP is therefore **same-language multi-region**; heterogeneous scatter-load is called out
and deferred (D5).

This is **ingestion**, additive on top of ADR-045 — no analysis change, no new agency, no write, no
execution (ADR-001). Once the blocks are mapped, the existing decompile/xref/export path works across
them unchanged.

## Decision

### D1 — Additive, opt-in `regions` list; single-region stays a byte-for-byte no-op

Extend `SessionImportIn` with one optional field, `regions`, a list of region descriptors. When
`regions` is absent, the RPC params and worker call are **identical to today** — the ADR-045
single-region path is untouched (the ADR-029/030/045 opt-in guarantee). `regions` is mutually exclusive
with the top-level single-region `base_addr`/`entry` hints (supplying both is ambiguous → rejected,
fail closed).

Each region descriptor:

| Field | Type | Meaning |
|---|---|---|
| `source_ref` | `str?` | The region's bytes as a confined source reference (as `session_import` today); **or** omit and use `offset`/`length` to carve from the top-level `source_ref`. |
| `offset` | `int?` | In-file byte offset into the parent `source_ref` when the region is a slice of one blob. |
| `length` | `int?` | Byte length of the carved slice (required with `offset`; each region independently size-capped). |
| `base_addr` | `int` | Load/base address for this region's memory block (required). |
| `entry` | `int?` | Optional per-region entry-point hint recorded as a disassembly seed. |

`loader="binary"` and a single top-level `processor` (Ghidra `LanguageID`) govern the whole set — **all
regions share the one program Language** (the constraint above). A per-region `processor` is **not**
accepted in the MVP; a differing architecture is a separate session, not a region (D5).

### D2 — One program, N memory blocks; overlap rejected

For `loader="binary"` with `regions`, the worker opens one program at the resolved `Language`, then
creates one initialized memory block per region at its `base_addr` (seeding disassembly at each
`entry`). The resulting `SessionInfo`/memory map reports every block. Region address ranges
`[base_addr, base_addr + length)` **must not overlap**; an overlapping pair is rejected **server-side
before the worker** (`validation`) — overlap is an operator error, not something to silently merge.

### D3 — Per-region confinement + size caps, pre-worker (DoS / untrusted input)

Every region is an untrusted input. **Each** region's bytes pass source-ref confinement and the
existing per-import **size cap before the worker** (ADR-045 posture, CWE-400/CWE-20); `offset`/`length`
slices are bounds-checked against the parent blob length. The number of regions is itself capped
(server-clamped hard cap) so a client cannot request thousands of blocks. Nothing unbounded reaches the
JVM edge; the per-analysis wall-clock kill (ADR-002) remains the backstop.

### D4 — Bounded per-region numeric hints, address-width checked

Each region's `base_addr` (and `entry` if given) is validated server-side: non-negative, within the
address width implied by the shared `processor` (32-bit Language → `< 2**32`), and `entry >= base_addr`.
Out-of-range → `validation` reject. These are plain config integers (low blast radius), validated
before the worker exactly as ADR-045 D3.

### D5 — Cross-architecture scatter-load is out of scope (explicit)

A firmware whose regions span **different** processors (ARM + RISC-V) **cannot** be one program
(Ghidra one-program-one-Language). The MVP does not attempt it: such a device is imported as **one
session per architecture** (each an ADR-045 or multi-region-same-arch import). A future ADR may add a
"session group" that federates cross-arch sessions for cross-image xrefs; recorded here as deferred, not
attempted.

### D6 — Contract delta routes through the frozen-contract process (WS0, atomic)

The `regions` field touches `docs/contracts/tool-catalog.md` (the `session_import` row) and
`docs/contracts/rpc-protocol.md` (the `import` params). Per the WS0 frozen-contract mandate this ADR
*proposes* the delta; the contract-file edits land **atomically** with the schema change as one reviewed
unit. No catalog count change (extends an existing tool, no new tool).

## Security / threat-model delta (`workflow-threat-model`, TB1 client→server + TB3 server→worker)

- **New untrusted inputs:** `regions[*].source_ref`/`offset`/`length` (bytes + bounded ints, each
  confined + size-capped before the worker, D3), `base_addr`/`entry` (bounded ints, address-width
  checked, D4). None are bytes reaching a shell/eval; the shared `processor` is still the ADR-045
  positive allow-list.
- **No new agency (ADR-001/LLM08):** multi-region only changes *how the existing import maps blocks* —
  no new tool, no write capability, no script execution. Read-only v1 posture intact.
- **DoS (CWE-400):** per-region size caps **and** a region-count cap before the worker; overlap
  rejection bounds the block layout; the per-analysis wall-clock kill (ADR-002) is the backstop. A
  pathological base can't allocate unbounded memory (each block is bounded by its capped region size).
- **Fail closed (ADR-005/CWE-20):** overlap, out-of-range base/entry, `offset`/`length` past the parent
  blob, a region-count over cap, or a mixed single-region/`regions` request each reject **pre-worker**,
  category-safe (no binary-derived detail to the client).
- **Trust boundary unchanged:** block creation is the TB3 worker/JVM edge; the server never parses the
  binary.

## Alternatives considered

- **Multiple independent single-region sessions (status quo)** — rejected for same-arch scatter-load:
  loses cross-region xrefs/branch resolution and the true memory map; forces the client to correlate by
  hand (the T19 layout is the motivating pain).
- **A per-region `processor` (heterogeneous one program)** — rejected: violates Ghidra's
  one-program-one-Language invariant; genuinely cross-arch regions must be separate sessions (D5).
- **A separate `import_scatter` tool** — rejected: duplicates confinement/size-cap/digest/loader-hint
  logic and widens the catalog; an additive optional `regions` field on the existing tool is smaller
  surface and matches the ADR-045 precedent.
- **Auto-detect region layout heuristically** — rejected: unreliable and surprising for headerless
  images; explicit operator-supplied bases are the correct model (ADR-045's own finding).
- **A cross-arch "session group" now** — rejected for the MVP: multiplies scope + needs a federation
  model; deferred to a future ADR (D5).

## Consequences

- **Positive:** unlocks realistic multi-image device firmware (the T19 scatter layout) as one coherent
  same-arch program with cross-region xrefs; additive + opt-in, so zero risk to the ADR-045
  single-region path; reuses the LanguageID allow-list, confinement, and size caps already in place.
- **Negative / cost:** a new worker branch that creates N blocks (`# pragma: no cover - JVM edge`,
  TB3) to validate via the gated live-regression; more schema validation surface (overlap, region
  count, per-region bounds). The one-Language constraint is a real limit operators must understand
  (documented in getting-started).
- **Scope:** SemVer **minor** (additive, opt-in ingestion capability). Cross-architecture scatter-load =
  a future ADR.

## Testing (master §4)

- **Unit:** schema validation — `regions` list validated (each `base_addr` required; `offset` requires
  `length`; per-region `base_addr`/`entry` within the shared processor's address width; `entry >=
  base_addr`); **overlapping** region ranges rejected; region count over the cap rejected; the
  single-region-and-`regions` conflict rejected; the no-`regions` path proven a byte-for-byte no-op
  (params identical to ADR-045 when the field is absent).
- **Integration (gated real worker, live-regression):** import **two same-arch** raw regions (e.g. two
  ARM Cortex-M blocks) at **different** bases into one session → analyze → assert **both** memory
  blocks exist in the memory map at their bases and a cross-region reference resolves. Add to the
  live-regression hard-gate list.
- **Abuse:** overlapping regions, a `base_addr` past the address width, an `offset`/`length` past the
  parent blob, and an over-cap region count must each reject **category-safe** (no binary-derived
  detail); an oversized region must hit the per-region size cap before the worker.

## Rollout

Additive + default-off → no migration. Ship behind the existing schema (no flag; absence of `regions` =
ADR-045 behavior). Worker-side change → needs a worker rebuild + `.github/worker-image.pin` bump (per
the worker-change-validation-recipe) before the live gate exercises it. Document the same-arch
constraint + the scatter-load workflow in `getting-started.md`. Merge stays **gated**.
