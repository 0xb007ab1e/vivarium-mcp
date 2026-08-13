# ADR-051: Bundled type-archive application — `apply_type_archive` tool

- **Status:** **Accepted** (2026-08-12). First **mutation** tool of the v1.8 "all Ghidra coverage"
  increment program; scope + gate confirmed by the operator.
- **Date:** 2026-08-12
- **Deciders:** Human operator (chose GDT type-archive apply for increment 8 over read-only p-code
  listing); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — 16 `.gdt` archives ship in the pinned Ghidra
  install (`generic_clib`, `generic_clib_64`, `windows_vs12_32/64`, `mac_osx`, golang/rust, …). An
  end-to-end probe created a function named `strlen`, ran `ApplyFunctionDataTypesCmd` with
  `generic_clib_64`, and its prototype went from `undefined strlen(void)` to
  `size_t strlen(char * __s)` — confirming feasibility + the deterministic, verifiable effect.

## Context

Decompilation of a stripped binary that calls libc/Win32 shows untyped `undefined` prototypes for
library functions. Ghidra ships **Data Type archives** (`.gdt`) carrying the real prototypes; applying
one resolves same-named functions to their library signatures (and pulls in the referenced types),
materially improving decompilation. Vivarium had no tool to do this.

This is the first tool in the increment program that **mutates the program DB** — the earlier v1.8
additions (`emulate`, `demangle`) were read-only. It is not novel machinery: Vivarium already has a
structural-write path (write-consent + `allow_structural` gate + `session_undo`, ADR-012/013/014/015).
`apply_type_archive` is one more structural-write tool on that path.

## Decision

### D1 — A new `apply_type_archive` tool (structural write)

`apply_type_archive(session_id, archive)`:
- **`archive`** — which bundled type library to apply, a **closed allow-list**:
  `generic_clib` / `generic_clib_64` / `windows_vs12_32` / `windows_vs12_64` / `mac_osx`.

It runs `ApplyFunctionDataTypesCmd` over the whole program, applying each archive function prototype to
the same-named program function. Returns `archive`, `functions_updated` (a before/after prototype
diff), and `applied` — **all SAFE scalars**; no binary-derived value is echoed (the applied prototypes
live in the program DB, read back via the existing `get_function`/`decompile_function` tools).

### D2 — Closed allow-list, never a client path (CWE-22)

`archive` is a schema `Literal` (closed set); the worker maps the validated name to a `.gdt` **inside
the pinned Ghidra install** (`GHIDRA_INSTALL_DIR`). No client-supplied path is ever opened — the tool
cannot be steered to read an arbitrary file (path traversal). The worker re-validates the name against
its `_TYPE_ARCHIVES` map (defense in depth) and `not-found`s an unknown or missing archive.

### D3 — Gated structural write, one transaction, undoable

It is in `WRITE_TOOLS` and requires **write-consent + `allow_structural`** (`require_write_consent(
structural=True)`) — default-deny like every mutator. The apply is wrapped in **one program
transaction** (`_in_transaction`), so `session_undo` reverts the whole application atomically, and any
failure rolls back (fail closed — no partial application across the boundary).

### D4 — No new agency, no host effect

The tool applies **bundled, trusted** type data to the (untrusted) program; it makes no host effect, no
external call, and reads no client path. It only enriches types on the analyzed program. The bundled
archives are part of the pinned, digest-verified worker image (supply chain — `std-supplychain`).

## Alternatives considered

- **Read-only p-code (`get_pcode`) listing for increment 8** — considered; the operator chose the
  higher-RE-value type-archive apply. p-code inspection remains a candidate for a later increment.
- **Bulk-import ALL archive types into the program DTM** — rejected: copying ~20 k types bloats the
  program DB and is not the idiomatic Ghidra flow. `ApplyFunctionDataTypesCmd` pulls in only the types
  referenced by applied signatures.
- **Accept an arbitrary archive path from the client** — rejected: path traversal (CWE-22). A closed
  allow-list of bundled archives is the secure-by-default choice.
- **An `apply_signatures` flag** — dropped: applying function signatures *is* the tool's purpose; a
  flag adds config with no real value (least surface).

## Consequences

- **Positive:** resolves libc/Win32 API prototypes on a stripped binary → substantially better
  decompilation, without leaving Vivarium or adding a dependency. Complements `get_function` /
  `decompile_function`.
- **Cost / risk:** first mutating tool of the program — but it reuses the existing, tested
  structural-write gate + transaction/undo machinery; the only new surface is the archive allow-list
  (closed) and the whole-program apply (bounded by the program's function count, one transaction).
  Adds one Tier-1 (structural-write) tool (the frozen catalog count increments 58 → 59; `WRITE_TOOLS`
  15 → 16).

## Testing (master §4)

- **Unit:** schema — `archive` is a closed Literal (an arbitrary path / unknown name is rejected);
  result fields carry NO `Untrusted`. Registry/consent — the handler requires write-consent +
  `allow_structural` (denied for a read-only or non-structural session; fail closed, no port call).
- **Integration (gated real worker):** import a tiny blob, create a function named `strlen`, apply
  `generic_clib_64`, and assert its signature becomes `size_t strlen(char * __s)` with
  `functions_updated >= 1` — the grounded proof-of-concept.

## Rollout

Additive — a new opt-in **gated** tool; no existing behavior changes. Documented in the tool catalog +
RPC protocol. Merge stays **gated**. The tool is default-deny (write-consent + `allow_structural`) like
every mutator.
