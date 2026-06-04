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
from typing import Generic, TypeVar

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


class Untrusted(BaseModel, Generic[T]):
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


def wrap(
    value: T,
    *,
    origin: DataOrigin = DataOrigin.BINARY,
    truncated: bool = False,
    encoding: str | None = None,
    notes: list[str] | None = None,
) -> Untrusted[T]:
    """Wrap binary-derived content in the untrusted-data envelope.

    This is the single chokepoint through which hostile content leaves the core. WS4 hardens it
    with defensive normalization (e.g. neutralizing/annotating control characters and bidi/zero-
    width Unicode used for prompt-injection or spoofing — std-cwe, topic-i18n homoglyph note).

    Args:
        value: The untrusted payload to wrap.
        origin: Provenance of the content. Defaults to ``DataOrigin.BINARY``.
        truncated: Set when ``value`` was capped.
        encoding: Representation of any embedded bytes.
        notes: Safe server-generated annotations.

    Returns:
        An :class:`Untrusted` wrapper around ``value``.

    Note:
        STUB (WS4) — the WS0 stub will construct the wrapper directly; WS4 adds the normalization
        and annotation pass. Signature is frozen.
    """
    raise NotImplementedError("WS4: implement normalization/annotation; construct Untrusted")
