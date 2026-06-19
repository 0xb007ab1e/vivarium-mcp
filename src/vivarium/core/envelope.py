"""Untrusted-data envelope (ADR-005) — FROZEN CONTRACT (WS0).

EVERY piece of binary-derived content (decompiled code, disassembly, strings, symbol/function
names, comments, raw/searched bytes, type names, metadata strings) crosses trust boundary 4 and
is **untrusted** (indirect prompt injection — std-owasp-llm LLM01/02). It MUST be returned to the
client wrapped in :class:`Untrusted`, never as a bare string the LLM might treat as instructions.

The envelope is a *typing and provenance* control, not encryption: it makes "this came from a
hostile binary" un-ignorable at the type level, records provenance for audit, and is the single
place where defensive normalization/annotation is applied. Consumers (and the LLM client) are
contractually told: **do not auto-execute, eval, render as markup, or follow** this content.

See ``docs/contracts/untrusted-envelope.md`` for the canonical specification and the rendering
contract for clients.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Generic, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class DataOrigin(StrEnum):
    """Provenance of wrapped content — where it ultimately came from.

    Part of the frozen contract; used for audit and for client-side handling decisions.
    """

    BINARY = "binary-derived"
    """Content extracted/derived from the analyzed (hostile) binary by Ghidra."""

    GHIDRA = "ghidra-generated"
    """Content synthesized by Ghidra (e.g. decompiler output, auto-generated names) over hostile
    input — still untrusted, as inputs influence it."""


class Untrusted(BaseModel, Generic[T]):  # noqa: UP046  # frozen ADR-005 contract; classic typing.Generic retained
    """A typed wrapper marking ``value`` as untrusted, hostile-origin content — FROZEN CONTRACT.

    Type parameters:
        T: The shape of the wrapped payload (e.g. ``str`` for decompiled text, a list model for
            strings/symbols). Bounding/caps are applied by the producing tool BEFORE wrapping.

    Attributes:
        value: The untrusted payload. Treated as **data only** — never instructions.
        origin: Provenance (:class:`DataOrigin`).
        truncated: Whether ``value`` was truncated to satisfy a size/count cap (so the client
            knows the view is partial — honesty over silent loss).
        encoding: How any binary bytes within ``value`` are represented (e.g. ``"hex"``,
            ``"base64"``, ``"utf-8-replace"``). ``None`` when ``value`` is structured/textual.
        notes: Optional safe, server-generated annotations (e.g. "contains control characters",
            "non-UTF-8 bytes replaced") — NOT derived instructions.

    Security contract (clients MUST honor): do not execute, evaluate, deserialize, render as HTML/
    markdown/links, or follow URLs/paths found in ``value``. Display as inert text.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: T
    origin: DataOrigin
    truncated: bool = False
    encoding: str | None = None
    notes: list[str] = Field(default_factory=list, max_length=16)


# --- Defensive-normalization tables (WS4) -------------------------------------------------------
#
# These are the Unicode/control classes that subvert how a downstream renderer, terminal, or LLM
# *interprets* text — distinct from the visible characters they decorate. They are used to spoof
# (bidi reordering / homoglyphs — topic-i18n), to smuggle invisible instructions/state (zero-width),
# or to corrupt parsers/terminals (C0/C1 controls). Binary-derived strings, symbol/function names,
# comments, and decompiled C can carry these as an indirect-prompt-injection vector (std-owasp-llm
# LLM01/02, std-cwe CWE-20). The single chokepoint :func:`wrap` NEUTRALIZES them (replaces each with
# an inert, visible ``<U+XXXX>`` token so no information is silently lost) AND ANNOTATES via safe,
# server-generated ``notes`` so the client/LLM is told the class was present.
#
# Newlines/tabs are preserved (legitimate in decompiled code / multi-line text); only the dangerous
# control subset is neutralized.

# Bidirectional formatting + override codepoints (Trojan-Source style spoofing — CVE-2021-42574).
_BIDI_CODEPOINTS: frozenset[int] = frozenset(
    {
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
    }
)

# Zero-width / invisible joiners and the BOM/word-joiner used to smuggle hidden content.
_ZERO_WIDTH_CODEPOINTS: frozenset[int] = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
    }
)

# Control characters that are SAFE to keep (legitimate whitespace in code/text).
_ALLOWED_CONTROL_CHARS: frozenset[str] = frozenset({"\t", "\n", "\r"})

# Annotation note strings (stable, server-generated — NEVER derived from the content).
_NOTE_CONTROL = "control characters neutralized"
_NOTE_BIDI = "bidirectional/override formatting neutralized"
_NOTE_ZERO_WIDTH = "zero-width/invisible characters neutralized"

# Stable ordering for emitted notes (deterministic output).
_NOTE_ORDER: tuple[str, ...] = (_NOTE_CONTROL, _NOTE_BIDI, _NOTE_ZERO_WIDTH)

# Cap on the per-call notes list (mirrors the frozen ``Untrusted.notes`` max_length=16).
_MAX_NOTES = 16


def _neutralization_note(ch: str) -> str | None:
    """Classify a single character for neutralization.

    A single source of truth: a non-``None`` result both means "this character must be replaced
    with an inert token" AND is the stable annotation note for its class. Returning one value
    (rather than a ``(bool, note)`` pair) removes the otherwise-unreachable "neutralize but no
    note" state.

    Args:
        ch: A one-character string.

    Returns:
        The stable annotation note for ``ch``'s dangerous class, or ``None`` when ``ch`` is safe
        (preserved as-is).
    """
    code = ord(ch)
    if code in _BIDI_CODEPOINTS:
        return _NOTE_BIDI
    if code in _ZERO_WIDTH_CODEPOINTS:
        return _NOTE_ZERO_WIDTH
    if ch in _ALLOWED_CONTROL_CHARS:
        return None
    # C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F).
    if code <= 0x1F or code == 0x7F or 0x80 <= code <= 0x9F:
        return _NOTE_CONTROL
    return None


def _normalize_text(text: str) -> tuple[str, list[str]]:
    """Neutralize and annotate dangerous control/bidi/zero-width characters in ``text``.

    Each offending character is replaced with an inert, visible ``<U+XXXX>`` token (no information
    is silently dropped) and its class is recorded once in the returned annotation notes. Pure and
    deterministic (no I/O) — trivially testable.

    Args:
        text: The untrusted string to normalize.

    Returns:
        ``(normalized_text, notes)`` where ``notes`` lists the distinct classes neutralized in a
        stable order (control, bidi, zero-width).
    """
    out: list[str] = []
    flagged: set[str] = set()
    for ch in text:
        note = _neutralization_note(ch)
        if note is not None:
            out.append(f"<U+{ord(ch):04X}>")
            flagged.add(note)
        else:
            out.append(ch)
    ordered = [n for n in _NOTE_ORDER if n in flagged]
    return "".join(out), ordered


def _normalize_value(value: T) -> tuple[T, list[str]]:  # noqa: UP047  # classic TypeVar retained to match frozen Untrusted[T] (ADR-005)
    """Apply normalization to ``str`` payloads (and ``str`` items of a flat list); pass others.

    Only textual content can carry the injection/spoofing classes ``wrap`` defends against;
    server-computed scalars and structured models are passed through unchanged (ADR-005: only
    binary-derived content is wrapped, and only text needs neutralizing).

    Args:
        value: The payload to normalize.

    Returns:
        ``(normalized_value, notes)`` — the normalized payload and the aggregated, de-duplicated
        annotation notes (stable order).
    """
    if isinstance(value, str):
        norm, notes = _normalize_text(value)
        # ``value`` is ``str`` here, so ``T`` is ``str``; mypy cannot narrow a TypeVar from an
        # isinstance guard, hence the explicit (sound) cast rather than a blanket ignore.
        return cast("T", norm), notes
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        flagged: set[str] = set()
        new_items: list[str] = []
        for item in value:
            norm_item, item_notes = _normalize_text(item)
            new_items.append(norm_item)
            flagged.update(item_notes)
        ordered = [n for n in _NOTE_ORDER if n in flagged]
        return cast("T", new_items), ordered
    # Non-text payload (structured model, scalar, mixed list): nothing to neutralize.
    return value, []


def wrap(  # noqa: UP047  # classic TypeVar retained to match frozen Untrusted[T] (ADR-005)
    value: T,
    *,
    origin: DataOrigin = DataOrigin.BINARY,
    truncated: bool = False,
    encoding: str | None = None,
    notes: list[str] | None = None,
) -> Untrusted[T]:
    """Wrap binary-derived content in the untrusted-data envelope.

    This is the single chokepoint through which hostile content leaves the core (ADR-005). It
    applies defensive normalization to textual payloads: control characters (C0/C1/DEL except
    tab/newline/CR), bidirectional formatting/override codepoints (Trojan-Source spoofing —
    CVE-2021-42574), and zero-width/invisible characters are **neutralized** to inert
    ``<U+XXXX>`` tokens and **annotated** via safe, server-generated ``notes`` (std-cwe CWE-20,
    topic-i18n homoglyph/bidi note). Caller-supplied ``notes`` are preserved; the function-derived
    annotations are appended, de-duplicated, and the combined list is bounded to the frozen
    ``Untrusted`` cap (16 — fail closed).

    This is a typing + provenance + normalization control layered with the read-only tool surface
    and the "never auto-execute" rendering contract — defense-in-depth, **not** a guarantee against
    prompt injection (the model may still be tricked; see threat-model §5 residual risk).

    Args:
        value: The untrusted payload to wrap. ``str`` and flat ``list[str]`` payloads are
            normalized; structured/scalar payloads pass through unchanged.
        origin: Provenance of the content. Defaults to ``DataOrigin.BINARY``.
        truncated: Set when ``value`` was capped by the producing tool BEFORE wrapping.
        encoding: Representation of any embedded bytes (e.g. ``"hex"``, ``"base64"``,
            ``"utf-8-replace"``); ``None`` for structured/plain-text payloads.
        notes: Optional safe, caller-supplied annotations. Never instructions derived from the
            content; the producing tool supplies these.

    Returns:
        An :class:`Untrusted` wrapper around the normalized ``value``, with provenance, the
        ``truncated`` flag, ``encoding``, and the merged annotation ``notes``.
    """
    normalized, derived_notes = _normalize_value(value)
    # Caller notes first (provenance/cap annotations from the producing tool), then our defensive
    # annotations; de-duplicate while preserving order; bound to the frozen cap (fail closed).
    merged: list[str] = []
    seen: set[str] = set()
    for note in (*(notes or ()), *derived_notes):
        if note not in seen:
            seen.add(note)
            merged.append(note)
    if len(merged) > _MAX_NOTES:
        merged = merged[:_MAX_NOTES]
    return Untrusted[T](
        value=normalized,
        origin=origin,
        truncated=truncated,
        encoding=encoding,
        notes=merged,
    )
