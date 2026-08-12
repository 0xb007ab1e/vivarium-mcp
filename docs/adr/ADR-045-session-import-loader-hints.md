# ADR-045: `session_import` loader hints — raw/headerless binary import

- **Status:** **Accepted** (ratified by the human operator 2026-08-12; targets v1.8). Implements
  finding **F1** in [`docs/roadmap-v1.8-findings.md`](../roadmap-v1.8-findings.md).
- **Date:** 2026-08-12
- **Deciders:** Human operator (ratified 2026-08-12 via direct Q&A: implement; allow-list scope =
  embedded-focused; include `entry`); drafted by the assistant from the v1.8 external-run findings
  (bare-metal firmware RE).
- **Context source:** A real external MCP client (Claude Code driving embedded-firmware RE) could not
  load **headerless MCU images** (ARM Cortex-M / Thumb, RISC-V RV32) — the dominant embedded-RE case
  — because `session_import` only drives Ghidra's auto-detecting container loaders (ELF/PE) and gives
  no way to specify processor + base address, so `ghidra.app.util.opinion.BinaryLoader` is
  unreachable. F1 is the headline v1.8 gap.

## Context

Today `session_import` takes `SessionImportIn{source_ref, expected_sha256?}` and the worker calls
`pyghidra.open_program(source_ref, …, analyze=False)` — the **auto-detect** path. For a raw MCU image
there is no ELF/PE header, no section table, no entry point, and Ghidra cannot guess the processor
(LanguageID) or the load/base address. The import fails with an unactionable `500` (also finding F4).

Embedded/bare-metal RE is a core reverse-engineering use case; supporting only auto-detectable
containers excludes it. The capability gap is **ingestion**, not analysis quality — once a raw image
is loaded at the right base with the right language, the existing decompile/rename/export path works.

**Two hard constraints shape the design:**

1. **ADR-001 — the server process never loads the JVM.** So the server *cannot* enumerate Ghidra's
   installed `LanguageID`s live to validate a client-supplied `processor`. The allow-list must exist
   server-side without touching Ghidra.
2. **Master §5 / ADR-005 — every input is hostile.** New fields are new untrusted inputs. They must
   be validated **before** the worker is touched (fail closed, CWE-20), and any failure must stay
   category-safe (no binary-derived detail to the client).

There is an established idiom for exactly this shape of change: **ADR-029** (analyze `profile`) and
**ADR-030** (`progress`) both added *optional, opt-in* fields to a frozen tool schema where the
default (field absent) is a **byte-for-byte no-op** reproducing today's behavior. F1 follows it.

## Decision

### D1 — Additive, opt-in loader hints; auto stays the default and a byte-for-byte no-op

Extend `SessionImportIn` with four optional fields:

| Field | Type | Meaning | Default |
|---|---|---|---|
| `loader` | `Literal["auto","binary"]` | `auto` = today's opinion/container loaders; `binary` = drive `BinaryLoader`. | `"auto"` |
| `processor` | `str \| None` | A Ghidra `LanguageID` string (e.g. `ARM:LE:32:Cortex`, `RISCV:LE:32:RV32GC`). | `None` |
| `base_addr` | `int \| None` | Image base / load address (raw images have no header to supply it). | `None` |
| `entry` | `int \| None` | Optional entry-point hint recorded as a disassembly seed. | `None` |

When `loader` is absent/`"auto"` **and** `processor`/`base_addr`/`entry` are all absent, the RPC
params and the worker call are **identical to today** — the same bare `pyghidra.open_program(…,
analyze=False)`. No new key crosses the wire; the auto path is untouched (the ADR-029/030 guarantee).

`loader="binary"` **requires** `processor` and `base_addr` (a raw image is meaningless without them);
the schema rejects the incomplete combination (fail closed). `processor`/`base_addr` supplied with
`loader="auto"` is also rejected (no silent ignoring — the client's intent is ambiguous).

### D2 — Server-side **curated static** LanguageID allow-list; worker re-validates (defense in depth)

Because the server can't ask Ghidra (D-constraint 1), it ships a **curated constant allow-list** of
supported `LanguageID`s (`vivarium/core/languages.py`). **v1.8 scope = embedded-focused** (operator
decision 2026-08-12): ARM/Thumb **LE+BE** Cortex, AARCH64, RISC-V **RV32/RV64** — the firmware cases
the finding hit. Desktop arches (x86/MIPS/PPC) are a later additive extension, not in this increment.
The server validates `processor` against this allow-list **before** spawning/calling the worker
(positive allow-list, CWE-20; unknown → `validation` reject naming the category).

The **worker re-validates** the (already allow-listed) `processor` against the *actually installed*
`LanguageService.getLanguageDescriptions()` and fails closed with a category-safe slug
(`not-found`/`unsupported`) if the language isn't present in that image build — so a drift between the
static list and the pinned Ghidra build can never silently mis-load. Two independent checks; neither
trusts the other.

### D3 — Bounded numeric hints, pre-worker

`base_addr` and `entry` are validated server-side: non-negative, within the address width implied by
the `processor` (e.g. 32-bit language → `< 2**32`), and `entry` (if given) `>= base_addr`. Out-of-range
→ `validation` reject. These are plain config integers, not bytes — low blast radius.

### D4 — Worker drives `BinaryLoader` with language + image base

For `loader="binary"` the worker opens the program via PyGhidra with the resolved `Language`, the
`BinaryLoader`, and sets the image base to `base_addr` (and seeds disassembly at `entry` when given),
then returns the same `SessionInfo` shape. The `# pragma: no cover - JVM edge` posture (TB3, ADR-001)
is unchanged; correctness is proven by the gated integration test (below), mirroring the
`set_function_signature` live-gate pattern.

### D5 — Contract delta routes through the frozen-contract process (WS0)

The new fields touch `docs/contracts/tool-catalog.md` (the `session_import` row) and
`docs/contracts/rpc-protocol.md` (the `import` params). Per the CLAUDE.md WS0 mandate those are
**frozen contracts** — this ADR *proposes* the delta; the actual contract-file edits land atomically
with the schema change as one reviewed unit, not ad hoc.

## Security / threat-model delta (`workflow-threat-model`, TB1 client→server + TB3 server→worker)

- **New untrusted inputs:** `loader` (closed enum), `processor` (string → positive allow-list, D2),
  `base_addr`/`entry` (bounded ints, D3). None are bytes; none reach a shell/eval. `processor`
  injection is neutralized by the allow-list (only exact known `LanguageID`s pass) — a client cannot
  smuggle an arbitrary string into the JVM language lookup.
- **No new agency (ADR-001/LLM08):** loader hints only change *how the existing import loads* — no new
  tool, no write capability, no script execution. Read-only v1 posture intact.
- **DoS:** a raw image still passes the size cap **before** the worker (unchanged); a pathological
  `base_addr` can't allocate unbounded memory (BinaryLoader maps the file, bounded by the capped file
  size). The per-analysis wall-clock kill (ADR-002) still bounds analysis.
- **Fail closed:** any invalid/incomplete hint combination is rejected pre-worker; the worker's
  re-validation is the second gate. Category-safe errors only (ADR-005).

## Alternatives considered

- **Live LanguageID enumeration in the server** — rejected: violates ADR-001 (would load the JVM in
  the server process). The curated list + worker re-validation gives the same safety without it.
- **A separate `import_raw` tool** — rejected: duplicates the confinement/size-cap/digest logic and
  widens the tool catalog; additive optional fields on the existing tool are smaller surface and
  match the ADR-029/030 precedent.
- **Free-form `processor` passthrough (validate only in the worker)** — rejected: pushes an untrusted
  string to the JVM edge with no server-side gate (defense-in-depth loss); the allow-list is cheap.
- **Auto-detect raw images heuristically** — rejected: unreliable and surprising; explicit operator
  control is the correct model for headerless firmware (the finding's own recommendation).

## Consequences

- **Positive:** unlocks embedded/bare-metal RE (the headline gap); additive + opt-in, so zero risk to
  the existing auto path; establishes the LanguageID allow-list other future features can reuse.
- **Negative / cost:** a curated allow-list is a **maintenance item** — it must track the pinned
  Ghidra build's languages (worker re-validation makes drift *safe*, not invisible; a CI check can
  assert the static list ⊆ installed languages). New validation + worker branch to test.
- **Scope:** SemVer **minor** (additive capability). F2–F4 (discoverability/observability) are
  independent and can land separately; **F5** (synthetic-ELF import bug) is partly mooted if raw
  loading covers the same arch, and otherwise unblocked once F4 surfaces the worker exception.

## Testing (master §4)

- **Unit:** schema validation — `loader="binary"` without `processor`/`base_addr` rejected; unknown
  `processor` rejected against the allow-list; out-of-range `base_addr`/`entry` rejected; the
  auto-default path proven a no-op (params byte-for-byte identical when hints absent).
- **Allow-list ⊆ installed:** a CI/worker check asserting every static `LanguageID` exists in the
  pinned Ghidra build (drift guard).
- **Integration (gated real worker, local real-worker recipe):** import a raw ARM Cortex-M image and
  a RISC-V RV32 image at a given base → analyze → assert functions recovered — the live happy-path
  gate (mirrors `test_set_function_signature.py`). Add a raw-image fixture to the acceptance harness.
- **Abuse:** a `processor` outside the allow-list, a `base_addr` past the address width, and an
  auto/`binary` field-conflict must each reject category-safe (no binary-derived detail).

## Rollout

Additive + default-off → no migration. Ship behind the existing schema (no flag needed; absence = old
behavior). Document in `getting-started.md` (ties to F2/F3 discoverability). Merge stays **gated**.
