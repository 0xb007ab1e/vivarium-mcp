"""Curated allow-list of Ghidra ``LanguageID``s accepted by ``session_import`` loader hints.

ADR-045 (F1, raw/headerless binary import). The MCP server process **must not load the JVM**
(ADR-001), so it cannot enumerate Ghidra's installed languages live to validate a client-supplied
``processor`` hint. Instead the server ships this **curated static allow-list** and validates
``processor`` against it *before* the worker is contacted (positive allow-list, CWE-20). The worker
independently re-validates the (already allow-listed) id against the languages actually installed in
the pinned image and fails closed if absent — so drift between this list and the pinned Ghidra build
is *safe*, never silent (ADR-045 §D2).

**v1.8 scope is embedded-focused** (operator decision 2026-08-12): ARM/Thumb (LE+BE) Cortex,
AARCH64 (LE+BE), and RISC-V RV32/RV64 — the bare-metal firmware cases the v1.8 external run hit.
Desktop architectures (x86/MIPS/PPC) are a later additive extension, deliberately out of this
increment.

This module is pure (no I/O, no JVM) — part of the functional core; the values are plain strings and
integers validated at the boundary.
"""

from __future__ import annotations

#: Supported Ghidra ``LanguageID`` → address width in **bits**. The width is the third colon-field
#: of the id (e.g. ``ARM:LE:32:Cortex`` → 32); it is stored explicitly (not parsed) so the mapping
#: is the single source of truth and a malformed id can never yield a bogus width. Keep sorted.
_SUPPORTED_LANGUAGES: dict[str, int] = {
    # ARM Cortex-M / Thumb (the dominant MCU firmware case), both endiannesses.
    "ARM:BE:32:Cortex": 32,
    "ARM:LE:32:Cortex": 32,
    # AArch64 (64-bit ARM), both endiannesses.
    "AARCH64:BE:64:v8A": 64,
    "AARCH64:LE:64:v8A": 64,
    # RISC-V, 32- and 64-bit (little-endian — the deployed firmware convention).
    "RISCV:LE:32:RV32GC": 32,
    "RISCV:LE:64:RV64GC": 64,
}

#: Public, sorted tuple of supported ids — for schema-error messages and docs (the reject reason
#: names the allowed set so a client can self-correct).
SUPPORTED_LANGUAGE_IDS: tuple[str, ...] = tuple(sorted(_SUPPORTED_LANGUAGES))


def is_supported_language(language_id: str) -> bool:
    """Return whether ``language_id`` is in the curated embedded allow-list (exact match).

    Args:
        language_id: A candidate Ghidra ``LanguageID`` string (untrusted client input).

    Returns:
        ``True`` iff the id is an exact member of the allow-list. No normalization/casefolding is
        applied — Ghidra ``LanguageID``s are case-sensitive and an inexact match must be rejected
        (fail closed), not coerced.
    """
    return language_id in _SUPPORTED_LANGUAGES


def address_bits(language_id: str) -> int:
    """Return the address width in bits for a supported ``language_id``.

    Args:
        language_id: A Ghidra ``LanguageID`` string that MUST already be allow-listed (call
            :func:`is_supported_language` first).

    Returns:
        The address width in bits (32 or 64) — used to bound ``base_addr``/``entry`` server-side.

    Raises:
        KeyError: If ``language_id`` is not in the allow-list (a programmer error: callers validate
            membership before asking for the width).
    """
    return _SUPPORTED_LANGUAGES[language_id]
