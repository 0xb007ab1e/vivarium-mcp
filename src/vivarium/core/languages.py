"""Allow-list of Ghidra ``LanguageID``s accepted by ``session_import`` loader hints.

ADR-045 (F1, raw/headerless binary import). The MCP server process **must not load the JVM**
(ADR-001), so it cannot enumerate Ghidra's installed languages live to validate a client-supplied
``processor`` hint. Instead the server ships this **static allow-list** and validates ``processor``
against it *before* the worker is contacted (positive allow-list, CWE-20). The worker independently
re-validates the (already allow-listed) id against the languages actually installed in the pinned
image and fails closed if absent — so drift between this list and the pinned Ghidra build is *safe*,
never silent (ADR-045 §D2).

**This list is the FULL set of languages installed in the pinned worker's Ghidra** (generated, not
hand-curated). Regenerate on a Ghidra version bump by enumerating
``DefaultLanguageService.getLanguageService().getLanguageDescriptions(False)`` in the worker and
emitting ``{getLanguageID(): getSize()}``; a CI check should assert this list equals the installed
set (the ADR-045 §D2 drift guard). Keeping the full set (rather than a hand-picked subset) maximizes
raw-import coverage — x86, MIPS, PowerPC, AVR, 8051/PIC, MSP430, Xtensa, SuperH, tricore, 68k, and
every ARM/AARCH64/RISC-V variant Ghidra ships — while preserving the positive-validation property.

This module is pure (no I/O, no JVM) — part of the functional core; the values are plain strings and
integers validated at the boundary.
"""

from __future__ import annotations

#: Supported Ghidra ``LanguageID`` -> address width in **bits** (the address size Ghidra reports for
#: that language: 16/24/32/64). Stored explicitly (not parsed from the id) so a malformed id can
#: never yield a bogus width; the width bounds ``base_addr``/``entry`` server-side. Generated from
#: the pinned worker's Ghidra install (see the module docstring). Keep sorted.
_SUPPORTED_LANGUAGES: dict[str, int] = {
    "6502:LE:16:default": 16,
    "65C02:LE:16:default": 16,
    "68000:BE:32:Coldfire": 32,
    "68000:BE:32:MC68020": 32,
    "68000:BE:32:MC68030": 32,
    "68000:BE:32:default": 32,
    "6805:BE:16:default": 16,
    "6809:BE:16:default": 16,
    "80251:BE:24:default": 16,
    "80390:BE:24:default": 16,
    "8048:LE:16:default": 16,
    "8051:BE:16:default": 16,
    "8051:BE:24:cip-51": 24,
    "8051:BE:24:mx51": 16,
    "8085:LE:16:default": 16,
    "AARCH64:BE:32:ilp32": 32,
    "AARCH64:BE:64:v8A": 64,
    "AARCH64:LE:32:ilp32": 32,
    "AARCH64:LE:64:AppleSilicon": 64,
    "AARCH64:LE:64:v8A": 64,
    "ARM:BE:32:Cortex": 32,
    "ARM:BE:32:v4": 32,
    "ARM:BE:32:v4t": 32,
    "ARM:BE:32:v5": 32,
    "ARM:BE:32:v5t": 32,
    "ARM:BE:32:v6": 32,
    "ARM:BE:32:v7": 32,
    "ARM:BE:32:v8": 32,
    "ARM:BE:32:v8-m": 32,
    "ARM:BE:32:v8T": 32,
    "ARM:LE:32:Cortex": 32,
    "ARM:LE:32:v4": 32,
    "ARM:LE:32:v4t": 32,
    "ARM:LE:32:v5": 32,
    "ARM:LE:32:v5t": 32,
    "ARM:LE:32:v6": 32,
    "ARM:LE:32:v7": 32,
    "ARM:LE:32:v8": 32,
    "ARM:LE:32:v8-m": 32,
    "ARM:LE:32:v8T": 32,
    "ARM:LEBE:32:v7LEInstruction": 32,
    "ARM:LEBE:32:v8LEInstruction": 32,
    "BPF:LE:32:default": 32,
    "CP1600:BE:16:default": 16,
    "CR16C:LE:16:default": 16,
    "DATA:BE:64:default": 64,
    "DATA:LE:64:default": 64,
    "Dalvik:LE:32:DEX_Android10": 32,
    "Dalvik:LE:32:DEX_Android11": 32,
    "Dalvik:LE:32:DEX_Android12": 32,
    "Dalvik:LE:32:DEX_Android13": 32,
    "Dalvik:LE:32:DEX_Base": 32,
    "Dalvik:LE:32:DEX_KitKat": 32,
    "Dalvik:LE:32:DEX_Lollipop": 32,
    "Dalvik:LE:32:DEX_Nougat": 32,
    "Dalvik:LE:32:DEX_Oreo": 32,
    "Dalvik:LE:32:DEX_Pie": 32,
    "Dalvik:LE:32:Marshmallow": 32,
    "Dalvik:LE:32:ODEX_KitKat": 32,
    "H6309:BE:16:default": 16,
    "HC-12:BE:16:default": 16,
    "HC05:BE:16:M68HC05TB": 16,
    "HC05:BE:16:default": 16,
    "HC08:BE:16:MC68HC908QY4": 16,
    "HC08:BE:16:default": 16,
    "HCS-12:BE:24:default": 24,
    "HCS-12X:BE:24:default": 24,
    "HCS08:BE:16:MC9S08GB60": 16,
    "HCS08:BE:16:default": 16,
    "Hexagon:LE:32:default": 32,
    "JVM:BE:32:default": 32,
    "Loongarch:LE:32:ilp32d": 32,
    "Loongarch:LE:32:ilp32f": 32,
    "Loongarch:LE:64:lp64d": 64,
    "Loongarch:LE:64:lp64f": 64,
    "M16C/60:LE:16:default": 16,
    "M16C/80:LE:16:default": 16,
    "M8C:BE:16:default": 16,
    "MCS96:LE:16:default": 16,
    "MIPS:BE:32:16e": 32,
    "MIPS:BE:32:R6": 32,
    "MIPS:BE:32:default": 32,
    "MIPS:BE:32:micro": 32,
    "MIPS:BE:64:16e": 64,
    "MIPS:BE:64:64-32R6addr": 32,
    "MIPS:BE:64:64-32addr": 32,
    "MIPS:BE:64:R6": 64,
    "MIPS:BE:64:default": 64,
    "MIPS:BE:64:micro": 64,
    "MIPS:BE:64:micro64-32addr": 32,
    "MIPS:LE:32:16e": 32,
    "MIPS:LE:32:R6": 32,
    "MIPS:LE:32:default": 32,
    "MIPS:LE:32:micro": 32,
    "MIPS:LE:64:16e": 64,
    "MIPS:LE:64:64-32R6addr": 32,
    "MIPS:LE:64:64-32addr": 32,
    "MIPS:LE:64:R6": 64,
    "MIPS:LE:64:default": 64,
    "MIPS:LE:64:micro": 64,
    "MIPS:LE:64:micro64-32addr": 32,
    "NDS32:BE:32:default": 32,
    "NDS32:LE:32:default": 32,
    "PIC-12:LE:16:PIC-12C5xx": 16,
    "PIC-16:LE:16:PIC-16": 16,
    "PIC-16:LE:16:PIC-16C5x": 16,
    "PIC-16:LE:16:PIC-16F": 16,
    "PIC-17:LE:16:PIC-17C7xx": 16,
    "PIC-18:LE:24:PIC-18": 24,
    "PIC-24E:LE:24:default": 24,
    "PIC-24F:LE:24:default": 24,
    "PIC-24H:LE:24:default": 24,
    "PowerPC:BE:32:4xx": 32,
    "PowerPC:BE:32:MPC8270": 32,
    "PowerPC:BE:32:QUICC": 32,
    "PowerPC:BE:32:default": 32,
    "PowerPC:BE:32:e500": 32,
    "PowerPC:BE:32:e500mc": 32,
    "PowerPC:BE:64:64-32addr": 32,
    "PowerPC:BE:64:A2-32addr": 32,
    "PowerPC:BE:64:A2ALT": 64,
    "PowerPC:BE:64:A2ALT-32addr": 32,
    "PowerPC:BE:64:VLE-32addr": 32,
    "PowerPC:BE:64:VLEALT-32addr": 32,
    "PowerPC:BE:64:default": 64,
    "PowerPC:LE:32:4xx": 32,
    "PowerPC:LE:32:QUICC": 32,
    "PowerPC:LE:32:default": 32,
    "PowerPC:LE:32:e500": 32,
    "PowerPC:LE:32:e500mc": 32,
    "PowerPC:LE:64:64-32addr": 32,
    "PowerPC:LE:64:A2-32addr": 32,
    "PowerPC:LE:64:A2ALT": 64,
    "PowerPC:LE:64:A2ALT-32addr": 32,
    "PowerPC:LE:64:default": 64,
    "RISCV:LE:32:AndeStar_v5": 32,
    "RISCV:LE:32:default": 32,
    "RISCV:LE:64:default": 64,
    "SuperH4:BE:32:default": 32,
    "SuperH4:LE:32:default": 32,
    "SuperH:BE:32:SH-1": 32,
    "SuperH:BE:32:SH-2": 32,
    "SuperH:BE:32:SH-2A": 32,
    "TI_MSP430:LE:16:default": 16,
    "TI_MSP430X:LE:32:default": 32,
    "V850:LE:32:default": 32,
    "Xtensa:BE:32:default": 32,
    "Xtensa:LE:32:default": 32,
    "avr32:BE:32:default": 32,
    "avr8:LE:16:atmega256": 24,
    "avr8:LE:16:default": 16,
    "avr8:LE:24:xmega": 24,
    "dsPIC30F:LE:24:default": 24,
    "dsPIC33C:LE:24:default": 24,
    "dsPIC33E:LE:24:default": 24,
    "dsPIC33F:LE:24:default": 24,
    "eBPF:BE:64:default": 64,
    "eBPF:LE:64:default": 64,
    "pa-risc:BE:32:default": 32,
    "sparc:BE:32:default": 32,
    "sparc:BE:64:default": 64,
    "tricore:LE:32:default": 32,
    "tricore:LE:32:tc172x": 32,
    "tricore:LE:32:tc176x": 32,
    "tricore:LE:32:tc29x": 32,
    "x86:LE:16:Protected Mode": 16,
    "x86:LE:16:Real Mode": 16,
    "x86:LE:32:System Management Mode": 32,
    "x86:LE:32:default": 32,
    "x86:LE:64:compat32": 64,
    "x86:LE:64:default": 64,
    "z180:LE:16:default": 16,
    "z182:LE:16:default": 16,
    "z80:LE:16:default": 16,
    "z8401x:LE:16:default": 16,
}

#: Public, sorted tuple of supported ids (for drift checks/docs). NOTE: this is large (the full
#: installed set) — do NOT dump it verbatim into client-facing error text; name the count + point at
#: the ``vivarium://docs/importing`` resource instead.
SUPPORTED_LANGUAGE_IDS: tuple[str, ...] = tuple(sorted(_SUPPORTED_LANGUAGES))


def is_supported_language(language_id: str) -> bool:
    """Return whether ``language_id`` is in the allow-list (exact, case-sensitive match).

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
        The address width in bits (16/24/32/64) — used to bound ``base_addr``/``entry``.

    Raises:
        KeyError: If ``language_id`` is not in the allow-list (a programmer error: callers validate
            membership before asking for the width).
    """
    return _SUPPORTED_LANGUAGES[language_id]
