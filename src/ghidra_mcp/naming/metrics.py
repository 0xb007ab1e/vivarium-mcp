"""Naming-quality eval metrics (ADR-010, decision #3 — MEASURED, not guaranteed).

Scores a :class:`~ghidra_mcp.naming.loop.RenamedProgram` on quality signals:

- **name_coverage** — fraction of inferred (non-external) functions that got a *meaningful* name,
  i.e. renamed away from Ghidra's ``FUN_xxxxxxxx`` placeholder. Pure, no compiler needed.
- **compiles / compile_diagnostics** — does the assembled translation unit compile? Requires an
  injected :class:`CompileRunner`. The renamed C is **untrusted-derived** (it came, via the namer,
  from a hostile binary's decompilation), so a real runner MUST compile it **sandboxed** — that
  step is a separate gated increment (ADR-010 §Security); here it is a port with fakes in tests.
- **behavioral_equivalence** — does the rebuilt artifact behave like the original on test inputs?
  Research-hard / generally unachievable from decompiler output; **explicitly best-effort** and
  deferred (field present, ``None`` until the sandboxed differential-run harness lands).

Compilability and behavioral equivalence are honest *metrics to track*, never guarantees: turning
decompiler pseudo-C into a recompilable, equivalent program is not solvable in general (decision 3).
This module is pure given its ports — the compiler/runner are injected, so scoring is hermetic.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from ghidra_mcp.naming.loop import RenamedProgram

#: Ghidra's default placeholder names for un-named functions/data. A function whose assigned name
#: still matches one of these was NOT meaningfully renamed (does not count toward coverage).
_PLACEHOLDER = re.compile(r"^(FUN|SUB|LAB|DAT|UNK)_[0-9a-fA-F]+$")


@dataclass(frozen=True, slots=True)
class CompileResult:
    """Outcome of compiling a translation unit.

    Attributes:
        ok: Whether compilation succeeded.
        diagnostics: Compiler stderr/notes, truncated + safe (no host paths/secrets) — for triage.
    """

    ok: bool
    diagnostics: str = ""


#: A compile runner takes C source and returns a :class:`CompileResult`. THE INPUT IS UNTRUSTED
#: (binary-derived); a real implementation MUST sandbox the compiler (no network, read-only, dropped
#: caps — worker-style isolation, ADR-004/ADR-010 §Security). Tests inject a deterministic fake.
CompileRunner = Callable[[str], CompileResult]


@dataclass(frozen=True, slots=True)
class NamingMetrics:
    """Measured quality of a naming pass (best-effort signals; see module docstring).

    Attributes:
        total_functions: All functions in the pass (inferred + external + skipped externals).
        inferred_functions: Functions a namer actually named (the coverage denominator).
        external_functions: Imported/external functions (kept their known name, not inferred).
        named_functions: Inferred functions whose assigned name is meaningful (not a placeholder).
        name_coverage: ``named_functions / inferred_functions`` (``0.0`` when none inferred).
        compiles: Whether the translation unit compiled, or ``None`` if no compiler was run.
        compile_diagnostics: Compiler diagnostics when a runner ran, else ``None``.
        behavioral_equivalence: Measured equivalence rate, or ``None`` (deferred — research-hard).
    """

    total_functions: int
    inferred_functions: int
    external_functions: int
    named_functions: int
    name_coverage: float
    compiles: bool | None = None
    compile_diagnostics: str | None = None
    behavioral_equivalence: float | None = None


def _is_meaningful(name: str) -> bool:
    """Whether ``name`` is a real semantic identifier (not a Ghidra ``FUN_``-style placeholder)."""
    return bool(name) and _PLACEHOLDER.match(name) is None


def name_coverage(program: RenamedProgram) -> float:
    """Fraction of inferred functions renamed to a meaningful (non-placeholder) identifier.

    Args:
        program: The naming pass result.

    Returns:
        ``named / inferred`` in ``[0, 1]``; ``0.0`` when no functions were inferred.
    """
    inferred = [f for f in program.functions if f.inferred]
    if not inferred:
        return 0.0
    named = sum(1 for f in inferred if _is_meaningful(f.assigned_name))
    return named / len(inferred)


def score(program: RenamedProgram, *, compile_runner: CompileRunner | None = None) -> NamingMetrics:
    """Compute :class:`NamingMetrics` for a naming pass.

    Args:
        program: The naming pass result to score.
        compile_runner: Optional SANDBOXED compiler (ADR-010 §Security). When ``None`` (default,
            hermetic), compilability is not measured (``compiles=None``) — name coverage still is.

    Returns:
        The measured (best-effort) metrics.
    """
    inferred = [f for f in program.functions if f.inferred]
    externals = [f for f in program.functions if f.is_external]
    named = sum(1 for f in inferred if _is_meaningful(f.assigned_name))

    compiles: bool | None = None
    diagnostics: str | None = None
    if compile_runner is not None:
        result = compile_runner(program.translation_unit)
        compiles, diagnostics = result.ok, result.diagnostics

    return NamingMetrics(
        total_functions=len(program.functions),
        inferred_functions=len(inferred),
        external_functions=len(externals),
        named_functions=named,
        name_coverage=(named / len(inferred)) if inferred else 0.0,
        compiles=compiles,
        compile_diagnostics=diagnostics,
        behavioral_equivalence=None,
    )
