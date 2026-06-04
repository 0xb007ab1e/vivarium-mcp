# ADR-005: Untrusted-data envelope for all binary-derived output

- **Status:** Accepted (locked by PLAN.md v2 / red-team F3)
- **Date:** 2026-06-03
- **Deciders:** Human + red-team + PM; recorded by Software Architect (WS0)

## Context

Ghidra's output is derived from a hostile binary and flows to an **LLM** (trust boundary 4).
Strings, symbol/function names, comments, decompiled C, and disassembly can contain **indirect
prompt-injection** payloads (`std-owasp-llm` LLM01/02) or content crafted to be auto-executed,
rendered as active markup, or followed as links/paths. Returning such content as bare strings
invites the client/LLM to treat hostile data as instructions.

## Decision

**Every** piece of binary-derived content returned by a tool is wrapped in a typed
**untrusted-data envelope** (`core.envelope.Untrusted[T]`):

- It records **provenance** (`origin`), whether it was **`truncated`**, the **`encoding`** of any
  embedded bytes, and safe server-generated **`notes`**.
- It is a **typing + provenance control**: "this came from a hostile binary" is un-ignorable at the
  type level, and the envelope is the single chokepoint for **defensive normalization** (WS4 —
  neutralize/annotate control characters and bidi/zero-width Unicode used for injection/spoofing).
- It carries a **client rendering contract** (documented in `docs/contracts/untrusted-envelope.md`):
  consumers MUST NOT execute, evaluate, deserialize, render as HTML/markdown, or follow URLs/paths
  found in the value — display as inert text only.

Server-controlled scalars we computed ourselves (addresses we normalized, counts, sizes) stay bare;
only **content originating from the binary** is wrapped. The schemas in `tools/schemas.py` encode
this distinction in their field types and are part of the frozen contract.

## Consequences

- **Positive:** makes the trust boundary explicit and enforced by the type system; one place to
  harden injection defenses; clients get unambiguous handling guidance; auditable provenance.
- **Negative:** more verbose schemas and a wrapping step on every binary-derived field; clients
  must understand the envelope (documented contract). Wrapping is not a *guarantee* against
  injection (the LLM may still be tricked) — it is layered with abuse tests (WS4) and the "never
  auto-execute" rule, per defense-in-depth.
- **Rejected:** returning raw strings with only documentation warnings — too easy to ignore; not
  type-enforced.
