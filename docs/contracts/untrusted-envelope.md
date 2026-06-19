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
