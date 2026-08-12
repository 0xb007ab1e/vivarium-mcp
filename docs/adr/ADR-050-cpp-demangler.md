# ADR-050: C++ symbol demangling — read-only `demangle` tool

- **Status:** **Accepted** (2026-08-12). A read-only, program-independent name transform; part of the
  "all Ghidra coverage" increment program.
- **Date:** 2026-08-12
- **Deciders:** Human operator ("do increment 7"); assistant grounded + implemented.
- **Context source:** Grounded live in the worker — `ghidra.app.util.demangler.gnu.GnuDemangler`
  demangled `_ZN3foo3barEi` → `undefined foo::bar(int)` and
  `ghidra.app.util.demangler.microsoft.MicrosoftDemangler` demangled `?bar@foo@@QAEHH@Z` →
  `public int __thiscall foo::bar(int)`, both via `.demangle(mangled).getSignature()` with no program
  loaded. (`DemanglerUtil.demangle` returns a single object, not a list, in Ghidra 12.1.2 — the
  concrete demanglers are used directly.)

## Context

C++ symbols in a stripped-but-mangled binary appear as Itanium (`_ZN...`) or MSVC (`?...@@...`) mangled
names. Reversers routinely need the human-readable signature (`foo::bar(int)`) to understand a symbol.
Ghidra ships both demanglers; there was no Vivarium tool to invoke them. This is the smallest,
lowest-risk slice of increment 7's grab-bag (BSim / demanglers / PDB / GDT / Version-Tracking) — the
only one that is a **pure, read-only, no-fixture** capability shippable now.

## Decision

### D1 — A new `demangle` tool (Tier-1, read-only, program-independent)

`demangle(session_id, mangled, scheme?)`:
- **`mangled`** — the mangled symbol string (length-bounded; HOSTILE binary-derived input).
- **`scheme`** — `auto` (default; try GNU/Itanium then MSVC), `gnu`, or `msvc`.

Returns `demangled` (the demangled signature, or `None` if the string is not a mangled name in a tried
scheme — a non-mangled input is **not** an error) and `scheme` (which demangler matched, or `None`).

The tool loads **no program** and mutates nothing — each demangler is a pure string transform. It is
still session-scoped and authorized (BOLA): the caller must own the session the mangled symbol came
from, keeping the auth model uniform across the catalog.

### D2 — Bound (DoS on a hostile mangled name)

The mangled string is attacker-influenced (lifted from a hostile binary's symbols). A crafted,
deeply-nested template name could make a demangler do heavy work. Two independent bounds: the server
**length cap** (`mangled ≤ 8 KiB`, CWE-400/CWE-20) as the primary guard, and the existing per-call
**wall-clock kill** (ADR-002) as the backstop. Demangling runs entirely inside the hardened, ephemeral,
network-isolated worker container — never the host (operator directive).

### D3 — Output is binary-derived → untrusted envelope

The demangled name is derived from a hostile binary's symbol; it is returned wrapped in the
**untrusted-data envelope** (ADR-005) — inert data, never executed/rendered/followed — exactly like
decompiled text. `scheme` is a server-known closed-vocab scalar and stays bare.

### D4 — Input validation, fail closed

`scheme` is a closed `Literal` (unknown → rejected). `mangled` is length-bounded and non-empty. A
string the chosen demangler rejects yields `demangled=None` (caught in the worker, not surfaced as a
JVM error). The server validates shape/bounds before the worker (CWE-20); the server never loads the
JVM (ADR-001).

### D5 — No new agency / still read-only

`demangle` grants no write to the program, no host effect, no external call. It is added to the Tier-1
read allow-list (not a write tool); the write-consent gate is unchanged.

## Alternatives considered

- **A pure-Python demangler (e.g. `cxxfilt`/`demangle` libs)** — rejected: adds a dependency + a second
  code path, and MSVC demangling in particular is best handled by Ghidra's own implementation (the same
  one that names symbols in the program). Reusing Ghidra keeps parity with what the analysis produces.
- **Demangle a symbol *in the program* (by address) instead of a raw string** — considered; the raw
  string form is strictly more general (works for any name the client extracted, e.g. from
  `list_symbols`) and program-independent, so it needs no loaded program.
- **Bundle the rest of increment 7 (BSim / PDB / GDT / Version-Tracking) here** — rejected: BSim needs a
  populated similarity DB, Version-Tracking needs two loaded programs + a VT session (the model is
  single-program), PDB is fixture-blocked, and GDT-apply is a *structural mutation* (gated) — each is a
  separate increment with its own ADR/fixture. Demangling is the one clean read-only slice.

## Consequences

- **Positive:** turns mangled C++ symbols into readable signatures without leaving Vivarium or adding a
  dependency; complements `list_symbols`/`get_symbol`.
- **Cost / risk:** low — read-only, no program, no host effect; the only surface is a hostile mangled
  string, bounded by the length cap + the wall-clock backstop + the container. Adds one Tier-1 tool (the
  frozen catalog count increments 57 → 58).

## Testing (master §4)

- **Unit:** schema — `scheme` closed-set; `mangled` non-empty + length cap; default `scheme=auto`.
  Output carries the untrusted envelope; a no-match yields `demangled=None`/`scheme=None`. Registry —
  the handler authorizes then dispatches.
- **Integration (gated real worker):** demangle a GNU/Itanium name (`_ZN3foo3barEi` → `foo::bar(int)`),
  an MSVC name (`?bar@foo@@QAEHH@Z` → `foo::bar(int)`), and assert `auto` resolves each to the right
  scheme; a non-mangled string returns `demangled=None` (not an error) — the grounded proof-of-concept.

## Rollout

Additive — a new opt-in tool; no existing behavior changes. Documented in the tool catalog. Merge stays
**gated**. The tool is read-only and needs no write-consent.
