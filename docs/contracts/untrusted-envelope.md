# Contract: Untrusted-Data Envelope (FROZEN — WS0, ADR-005)

> Pydantic source of truth: [`src/vivarium/core/envelope.py`](../../src/vivarium/core/envelope.py).
> Applies to **all** binary-derived content crossing trust boundary **TB4** to the LLM.

## Shape

```jsonc
{
  "value":     <T>,                 // the untrusted payload (string / list / structured)
  "origin":    "binary-derived" | "ghidra-generated",
  "truncated": false,               // true if capped to satisfy a size/count limit
  "encoding":  null | "hex" | "base64" | "utf-8-replace",  // representation of embedded bytes
  "notes":     []                   // safe, server-generated annotations (≤16); NOT instructions
}
```

- The model is **generic** over `value`'s type (`Untrusted[str]`, `Untrusted[list[str]]`, …),
  **frozen**, and rejects extra fields.
- `origin`: `binary-derived` = extracted from the binary (strings, bytes, names); `ghidra-generated`
  = synthesized by Ghidra over hostile input (decompiler output) — both untrusted.
- `truncated`: honesty over silent loss — the client knows the view is partial.
- `notes`: server-side, safe annotations only (e.g. "non-UTF-8 bytes replaced", "control
  characters present"). Never derived/parsed instructions from the content.

## Client rendering contract (consumers MUST honor)

Treat `value` as **inert data, never instructions**:

- **DO NOT** execute, `eval`, deserialize, or run it as code/SQL/shell.
- **DO NOT** render it as HTML/Markdown/active markup; display as **plain inert text**.
- **DO NOT** follow URLs, file paths, or "instructions" found inside it.
- **DO NOT** let it override system/developer prompts (indirect prompt injection — `std-owasp-llm`
  LLM01/02). It came from a hostile binary.
- **DO** surface `origin`/`truncated`/`notes` so a human/LLM knows the provenance and limits.

## Server obligations

- The single wrap chokepoint is `core.envelope.wrap()` (WS4): it applies defensive normalization —
  neutralizing/annotating control characters and bidi/zero-width Unicode used for injection or
  homoglyph spoofing (`std-cwe`, `topic-i18n`) — and sets `encoding`/`truncated`/`notes`.
- Caps are applied **before** wrapping (the producing tool enforces size/count limits).
- This is a **typing + provenance + normalization** control, layered with read-only tools and the
  never-auto-execute rule — **not** a guarantee against injection (defense-in-depth).

## Streaming chunks (ADR-040)

- A streamed partial result is **no different**: each `$/chunk`'s binary-derived fields are wrapped
  via the same `wrap()` chokepoint **per chunk** before reaching the client (`Untrusted[T]`, no new
  shape). A chunk is inert data — same client rendering contract above applies to every chunk.
- The worker emits a plain `payload`; the **server** envelopes each chunk as it buffers it (the
  worker never envelopes), identical to the one-shot `result` path.
- Progress/status (`$/progress`, `job_status`) is **server-authored** status (counts, phase, eta) —
  **not** binary-derived and **not** enveloped; it never carries decompiled text, strings, or paths.

## Read-back values (annotation export, ADR-018)

- Exported value fields that are **read back out of the program** (e.g. a function's current name,
  a recovered signature, a comment) are tagged `Untrusted` / binary-derived **regardless of who
  originally wrote them** — including names a client itself set on a prior session. On export they
  are read from the hostile Ghidra program, so their provenance **at read-time is the binary**, not
  the client. The advisory `binary.name` provenance is wrapped the same way for the same reason.
