#!/usr/bin/env python3
"""Extract a call-graph GROUND TRUTH from an unstripped ELF (e2e fixtures, WS5).

Given a binary built **with DWARF** (`-g`) and a **non-PIE** layout (`-no-pie`, so symbol
addresses equal the addresses Ghidra reports for the stripped copy), emit a JSON ground truth that
the e2e suite compares Ghidra's recovery against:

  * **functions** — the tool's OWN functions only. We read them from DWARF `DW_TAG_subprogram`
    DIEs that have a `DW_AT_low_pc` and whose declaring compilation unit is one of the tool's
    source files (NOT a system header / statically-linked libc — those carry no DWARF in a normal
    release build, and we additionally drop CUs under system include roots). Each is recorded as
    ``{name, low_pc, high_pc, size}`` with **absolute** addresses.
  * **edges** — direct call edges `caller -> callee` between those functions, recovered by
    disassembling each function's byte range (capstone) and resolving direct ``call``/tail-``jmp``
    immediate targets that land inside another known function. This is the *true* static call
    graph at the granularity Ghidra can also see (direct calls; indirect/virtual calls are out of
    scope for both, so excluding them keeps the comparison fair).

The analyzed fixture is the STRIPPED copy of the same binary, so Ghidra invents ``FUN_<addr>``
names; the e2e maps truth ``low_pc`` -> recovered function and asserts recall of functions + edges
+ a valid leaf-first order. Ground truth is intentionally a *subset oracle*: everything here is
real, but it does not claim completeness (so the e2e uses recall thresholds, not exact equality).

Hermeticity: this runs in the GATED fixtures-build job (which already has the toolchain + pinned
source), never in the hermetic test job. Output is committed nowhere — it ships in the build
artifact alongside the stripped binary.

Usage:
    extract_ground_truth.py --binary <unstripped.elf> --tool <name> --version <v> \
        [--source-root <dir>] [--out <truth.json>]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Any

from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - capstone is a fixtures-build dependency
    Cs = None

#: Compilation-unit name prefixes we treat as NOT-the-tool (system/libc/compiler runtime). A CU
#: whose name starts with one of these is excluded even if it carries DWARF.
_SYSTEM_CU_PREFIXES = ("/usr/include", "/usr/lib", "/build/glibc", "<built-in>", "../sysdeps")


@dataclass(frozen=True)
class TruthFunction:
    """One ground-truth function: real name + absolute address range."""

    name: str
    low_pc: int
    high_pc: int

    @property
    def size(self) -> int:
        """Byte size of the function body (``high_pc - low_pc``)."""
        return max(0, self.high_pc - self.low_pc)


def _is_tool_cu(cu_name: str) -> bool:
    """Return whether a DWARF compilation-unit name belongs to the tool (not a system source)."""
    return not any(cu_name.startswith(p) for p in _SYSTEM_CU_PREFIXES)


def _collect_functions(elf: ELFFile) -> list[TruthFunction]:
    """Collect the tool's own functions from DWARF subprogram DIEs (with a low_pc), deduped."""
    if not elf.has_dwarf_info():
        msg = "binary has no DWARF info — build the fixture with -g"
        raise SystemExit(msg)
    dwarf = elf.get_dwarf_info()
    out: dict[int, TruthFunction] = {}
    for cu in dwarf.iter_CUs():
        top = cu.get_top_DIE()
        cu_name = ""
        if "DW_AT_name" in top.attributes:
            cu_name = top.attributes["DW_AT_name"].value.decode("utf-8", "replace")
        if cu_name and not _is_tool_cu(cu_name):
            continue
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram":
                continue
            low = die.attributes.get("DW_AT_low_pc")
            name_attr = die.attributes.get("DW_AT_name")
            if low is None or name_attr is None:
                continue  # declaration-only / inlined-without-range / anonymous
            low_pc = int(low.value)
            high_attr = die.attributes.get("DW_AT_high_pc")
            # DWARF4+: high_pc may be an offset (form class 'constant') or an absolute address.
            if high_attr is None:
                high_pc = low_pc
            elif high_attr.form in ("DW_FORM_addr",):
                high_pc = int(high_attr.value)
            else:
                high_pc = low_pc + int(high_attr.value)  # offset form
            raw_name = name_attr.value
            name = raw_name.decode("utf-8") if isinstance(raw_name, bytes) else str(raw_name)
            if low_pc:
                out[low_pc] = TruthFunction(name=name, low_pc=low_pc, high_pc=high_pc)
    return sorted(out.values(), key=lambda f: f.low_pc)


def _text_bytes(elf: ELFFile) -> tuple[int, bytes]:
    """Return (vaddr, data) for the .text section (where the function bodies live)."""
    sec = elf.get_section_by_name(".text")
    if sec is None:
        msg = "no .text section"
        raise SystemExit(msg)
    return int(sec["sh_addr"]), sec.data()


def _collect_edges(funcs: list[TruthFunction], text_vaddr: int, text: bytes) -> list[list[str]]:
    """Recover direct call/tail-jmp edges between known functions by disassembling each body."""
    if Cs is None:
        return []  # capstone absent — edges optional; functions alone still gate recovery
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    by_range = sorted(funcs, key=lambda f: f.low_pc)

    def owner(addr: int) -> str | None:
        for f in by_range:
            if f.low_pc <= addr < f.high_pc:
                return f.name
        return None

    edges: set[tuple[str, str]] = set()
    text_end = text_vaddr + len(text)
    for f in funcs:
        if not (text_vaddr <= f.low_pc < text_end):
            continue
        start = f.low_pc - text_vaddr
        end = min(f.high_pc - text_vaddr, len(text))
        for insn in md.disasm(text[start:end], f.low_pc):
            if insn.mnemonic not in ("call", "jmp"):
                continue
            op = insn.op_str.strip()
            if not (op.startswith("0x") or op.lstrip("-").isdigit()):
                continue  # indirect (register/memory) — not a resolvable static edge
            try:
                target = int(op, 0)
            except ValueError:
                continue
            callee = owner(target)
            if callee and callee != f.name:
                edges.add((f.name, callee))
    return sorted([list(e) for e in edges])


def extract(binary: str, tool: str, version: str) -> dict[str, Any]:
    """Build the ground-truth dict for ``binary`` (unstripped, -g, -no-pie)."""
    with open(binary, "rb") as fh:  # noqa: PTH123 - simple CLI read
        elf = ELFFile(fh)
        if elf.header["e_type"] != "ET_EXEC":
            # -no-pie yields ET_EXEC with absolute addresses; ET_DYN (PIE) would need rebasing.
            sys.stderr.write(
                f"WARNING: {binary} is {elf.header['e_type']} (expected ET_EXEC from -no-pie); "
                "addresses may not match Ghidra without rebasing.\n"
            )
        funcs = _collect_functions(elf)
        text_vaddr, text = _text_bytes(elf)
        edges = _collect_edges(funcs, text_vaddr, text)
        entry = int(elf.header["e_entry"])
    return {
        "schema": "vivarium/e2e-groundtruth/1",
        "tool": tool,
        "version": version,
        "entry": entry,
        "functions": [asdict(f) for f in funcs],
        "edges": edges,
        "counts": {"functions": len(funcs), "edges": len(edges)},
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry: parse args, extract, write JSON (stdout or --out)."""
    ap = argparse.ArgumentParser(
        description="Extract call-graph ground truth from an unstripped ELF."
    )
    ap.add_argument("--binary", required=True, help="path to the UNSTRIPPED, -g -no-pie ELF")
    ap.add_argument("--tool", required=True, help="tool name (e.g. cjson)")
    ap.add_argument("--version", required=True, help="tool version (e.g. 1.7.18)")
    ap.add_argument("--out", default="-", help="output JSON path ('-' = stdout)")
    ns = ap.parse_args(argv)
    truth = extract(ns.binary, ns.tool, ns.version)
    text = json.dumps(truth, indent=2, sort_keys=True)
    if ns.out == "-":
        sys.stdout.write(text + "\n")
    else:
        with open(ns.out, "w", encoding="utf-8") as fh:  # noqa: PTH123
            fh.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
