r"""(C) allow-list projection — the consumer-agnostic neutralization control (ADR-078, TB10).

This is the **keystone** of ADR-078's rendering-safety model: the only control that holds in a
renderer Vivarium does not own (a raw ``.md`` opened on GitHub/mkdocs, a VS Code preview, or an
LLM reading the document). Layers (A) CSP + ``<iframe sandbox>`` and (B) auto-escaping protect the
HTML path *we* emit; projection makes the binary-derived bytes themselves non-markup in **any**
consumer, so the "no active markup anywhere" guarantee does not depend on who renders the artifact.

Every function here takes hostile-origin, binary-derived content (symbol names, strings,
addresses — all ``CONFIDENTIAL`` and of ``HOSTILE ORIGIN`` per the data-classification) and
projects it to an inert form:

- :func:`project_identifier` — a name is reduced to the write-name charset ``[A-Za-z0-9_$.]`` (the
  same allow-list :mod:`vivarium.core.validation` enforces for *write* targets); any other byte
  becomes an inert ``\xNN`` / ``\uXXXX`` escape. ``<img ...>`` cannot survive. (Of the retained
  charset only ``_`` is markup-adjacent — Markdown emphasis — but intra-word underscores are inert
  in CommonMark and a flanking ``_x_`` can at worst italicize, never execute/link/beacon; the HTML
  path escapes it via (B) regardless. Strings use the stricter preview set below, ``_`` escaped.)
- :func:`project_string` — a string becomes a lossless **hex dump** plus a **positive-allow-list
  preview**: only obviously-inert characters pass literally; every markup/Markdown/LLM-active byte
  (and every control/non-ASCII byte) is escaped. A deny-list could miss a byte; an allow-list can't.
- :func:`project_address` — an address is rendered as canonical ``0x`` hex (always safe).

Projection is **lossy for human reading** (mangled names, escaped previews) — the accepted ADR-078
cost; the paired hex dump is the lossless record and layer (B) provides the trusted view.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from vivarium.core.validation import _WRITE_NAME_REST

__all__ = [
    "PROJECTION_NAME_CHARSET",
    "PROJECTION_PREVIEW_SAFE",
    "ProjectedString",
    "project_address",
    "project_identifier",
    "project_string",
]

# The identifier projection charset — IDENTICAL to the write-name charset
# (:data:`vivarium.core.validation._WRITE_NAME_REST`, i.e. ``[A-Za-z0-9_$.]``). We reuse that frozen
# set so a name that would be *rejected* as a write target is, on the read/report side, *projected*
# to the same safe shape rather than rejected. A unit test asserts these stay equal (anti-drift).
PROJECTION_NAME_CHARSET: frozenset[str] = _WRITE_NAME_REST

# The string-preview POSITIVE allow-list: the only bytes that pass a preview literally. Deliberately
# narrow — alphanumerics, space, and a little punctuation inert in HTML, Markdown, and as an LLM
# instruction. Everything else (all HTML/Markdown-active bytes — ``< > & " ' [ ] ( ) : ! * _ ~ |``
# backslash/backtick/``#``/``{ }`` — plus every control / non-ASCII byte) is escaped. An allow-list
# cannot miss an active byte the way a deny-list can; that is why the guarantee holds in a renderer
# we don't control. ``_ * ~`` (Markdown emphasis/strike), ``:`` (``javascript:``/autolink) and
# ``/`` are intentionally NOT safe.
PROJECTION_PREVIEW_SAFE: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,-=+@"
)

# Bounds (CWE-400) — the caller also bounds upstream, but project defensively.
_MAX_NAME_CHARS = 1024  # mirrors schemas._MAX_NAME; a projected name can grow ~6x under escaping
_MAX_PREVIEW_CHARS = 256  # characters of a string rendered in the human preview
_MAX_HEX_BYTES = 256  # bytes of a string rendered in the hex dump
_HEX_COLS = 16  # bytes per hex-dump row


def _escape_char(ch: str) -> str:
    r"""Return an inert escape for one character — ``\xNN`` for a byte, ``\uXXXX`` otherwise.

    The escape is composed only of ``\``, ``x``/``u`` and hex digits — none markup-active. A literal
    backslash in the *input* is never passed through; it is escaped to ``\x5c``, so the output
    cannot form active markup.
    """
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def project_identifier(name: str, *, max_chars: int = _MAX_NAME_CHARS) -> str:
    r"""Project a binary-derived identifier to the inert write-name charset (ADR-078 (C)).

    Each character is kept literally only if it is in :data:`PROJECTION_NAME_CHARSET`
    (``[A-Za-z0-9_$.]``); every other byte — markup (``<>&"'``), path/space, control, bidi,
    zero-width, or non-ASCII — becomes an inert ``\xNN`` / ``\uXXXX`` escape. The result therefore
    never carries a byte that can be active markup in any consumer.

    Args:
        name: The hostile-origin identifier (a symbol/function/type name read out of the binary).
        max_chars: Cap on the *input* characters considered (DoS guard — the projected output is
            longer under escaping). Excess input is dropped and an elision marker appended.

    Returns:
        The projected identifier (ASCII, inert). Empty input yields ``""``.
    """
    if not name:
        return ""
    truncated = len(name) > max_chars
    body = "".join(
        ch if ch in PROJECTION_NAME_CHARSET else _escape_char(ch) for ch in name[:max_chars]
    )
    return body + ("\\u2026" if truncated else "")  # inert escaped ellipsis marker


def project_address(address: int) -> str:
    """Project an address to canonical ``0x`` hex (always inert).

    Args:
        address: A non-negative address/offset. A negative value is rendered with a leading ``-``.

    Returns:
        Canonical lowercase hex, e.g. ``"0x401000"``.
    """
    if address < 0:
        return f"-0x{-address:x}"
    return f"0x{address:x}"


class ProjectedString(BaseModel):
    """The projected (inert) view of a binary-derived string — ADR-078 (C).

    Pairs a lossless :attr:`hex` dump with a lossy, allow-list-escaped :attr:`preview`. Neither
    field can carry active markup in any consumer: the hex dump is only ``[0-9a-f ]`` + offsets, and
    the preview passes only :data:`PROJECTION_PREVIEW_SAFE` bytes literally (all else escaped).

    Attributes:
        preview: A human-readable, allow-list-escaped rendering (lossy; capped).
        hex: A canonical hex dump of the raw bytes (lossless to the byte cap; the record of truth).
        byte_len: The true byte length of the source (so a truncated view is honest).
        truncated: Whether either rendering was capped below the full source.
    """

    model_config = ConfigDict(frozen=True)

    preview: str
    hex: str
    byte_len: int = Field(ge=0)
    truncated: bool = False


def _preview(raw: bytes, *, max_chars: int) -> tuple[str, bool]:
    """Render the positive-allow-list preview of ``raw`` (latin-1 decoded for 1:1 byte mapping)."""
    # 1:1 byte->codepoint; projection decides what survives, not the codec.
    text = raw.decode("latin-1")
    truncated = len(text) > max_chars
    out = "".join(
        ch if ch in PROJECTION_PREVIEW_SAFE else _escape_char(ch) for ch in text[:max_chars]
    )
    return out, truncated


def _hex_dump(raw: bytes, *, max_bytes: int, cols: int) -> tuple[str, bool]:
    """Render a canonical ``offset: hh hh ... |ascii|`` hex dump; the ascii gutter is dot-masked."""
    truncated = len(raw) > max_bytes
    data = raw[:max_bytes]
    lines: list[str] = []
    for off in range(0, len(data), cols):
        chunk = data[off : off + cols]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        # ascii gutter: only preview-safe printable bytes show; all else is a dot (never markup).
        gutter = "".join(chr(b) if chr(b) in PROJECTION_PREVIEW_SAFE else "." for b in chunk)
        lines.append(f"{off:08x}: {hexpart:<{cols * 3 - 1}} |{gutter}|")
    return "\n".join(lines), truncated


def project_string(
    raw: str | bytes,
    *,
    max_preview: int = _MAX_PREVIEW_CHARS,
    max_hex_bytes: int = _MAX_HEX_BYTES,
) -> ProjectedString:
    """Project a binary-derived string to an inert :class:`ProjectedString` (ADR-078 (C)).

    Produces a lossless hex dump plus an allow-list-escaped preview. ``](javascript:evil)``,
    ``<script>``, an embedded SVG, or a Markdown beacon image all survive only as escaped,
    non-active text — in a browser, in raw Markdown, and to an LLM alike.

    Args:
        raw: The hostile-origin string (``str`` is encoded UTF-8; ``bytes`` used as-is).
        max_preview: Character cap on the preview rendering.
        max_hex_bytes: Byte cap on the hex dump.

    Returns:
        The inert projected view, with ``truncated`` set if either rendering was capped.
    """
    data = raw.encode("utf-8", "surrogatepass") if isinstance(raw, str) else bytes(raw)
    preview, p_trunc = _preview(data, max_chars=max_preview)
    hexdump, h_trunc = _hex_dump(data, max_bytes=max_hex_bytes, cols=_HEX_COLS)
    return ProjectedString(
        preview=preview,
        hex=hexdump,
        byte_len=len(data),
        truncated=p_trunc or h_trunc,
    )
