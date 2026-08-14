"""Pure (JVM-free) parser for a name→address symbol map (ADR-071, ``debug_format="map"``).

Part of the functional core (ADR-001): turns the text of a linker/``nm``/IDA ``.map`` symbol dump
into ``(name, address)`` pairs the worker applies as labels. No I/O, no JVM — deterministic and
unit-testable. The map file is HOSTILE input (a companion the operator paired with the binary); this
parser is linear + bounded (ReDoS-safe, CWE-1333) and never trusts the content beyond extracting a
hex address + an identifier per line.

Supported line shapes (the common flat-address forms):
    * ``nm``:            ``0000000000001149 T main``
    * bare pair:         ``0x1149 main`` / ``00001149  handler``
    * linker assignment: ``main = 0x1149 ;``
Segment-relative IDA ``.map`` lines (``0001:00001149 _main``) are intentionally NOT interpreted
(the segment base is unknown here) — such lines yield no symbol rather than a wrong address.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Hard cap on characters of any single line examined (pathological-input defense).
_MAX_LINE_LEN = 1024

# ``name = 0xADDR`` linker-assignment form (checked first; unambiguous).
_ASSIGN = re.compile(r"^\s*([A-Za-z_.$][A-Za-z0-9_.$@]{0,255})\s*=\s*(?:0x)?([0-9A-Fa-f]{1,16})\b")

# ``ADDR [type] NAME`` form: a leading hex address then, later on the line, an identifier as the
# last such token. Linear, anchored, no nested quantifiers.
_LEADING_ADDR = re.compile(r"^\s*(?:0x)?([0-9A-Fa-f]{1,16})\b")
_IDENT = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$@]{0,255}")


@dataclass(frozen=True, slots=True)
class MapSymbol:
    """One recovered symbol from a map file.

    Attributes:
        name: The symbol name (binary/companion-derived — treated as untrusted downstream).
        address: The absolute address (non-negative int).
    """

    name: str
    address: int


def parse_symbol_map(text: str, *, max_symbols: int) -> list[MapSymbol]:
    """Parse ``text`` into ``(name, address)`` symbols, bounded by ``max_symbols``.

    Deterministic + side-effect-free. Lines that do not carry both a hex address and an identifier
    are skipped (never guessed). Stops once ``max_symbols`` is reached (the caller learns of the cap
    via a ``truncated`` flag computed against this bound).

    Args:
        text: The map-file contents.
        max_symbols: Hard cap on the number of symbols returned (already server-clamped).

    Returns:
        Ordered, de-duplicated-by-(name,address) :class:`MapSymbol` list (first occurrence wins).
    """
    out: list[MapSymbol] = []
    seen: set[tuple[str, int]] = set()
    for raw_line in text.splitlines():
        if len(out) >= max_symbols:
            break
        line = raw_line[:_MAX_LINE_LEN]
        assign = _ASSIGN.match(line)
        if assign is not None:
            name, addr_hex = assign.group(1), assign.group(2)
        else:
            leading = _LEADING_ADDR.match(line)
            if leading is None:
                continue
            addr_hex = leading.group(1)
            # The symbol name is the last identifier after the address (skips the nm type letter).
            idents = _IDENT.findall(line[leading.end() :])
            if not idents:
                continue
            name = idents[-1]
        address = int(addr_hex, 16)
        key = (name, address)
        if key in seen:
            continue
        seen.add(key)
        out.append(MapSymbol(name=name, address=address))
    return out
