"""Leaf-first naming orchestration core (pure functional core — ADR-010).

Given a leaf-first ``analysis_order`` (sinks first; SCCs already condensed by ``core/callgraph``)
and a per-function :class:`~ghidra_mcp.tools.schemas.FunctionContext` bundle, walk the functions
**bottom-up** and, for each, ask an injected :data:`Namer` to propose a semantic name + renamed
pseudo-C. Names are **carried forward**: when a caller is processed, its already-named callees'
assigned names are passed to the namer (the whole point of leaf-first — a caller is named with its
callees' meanings in hand). External/imported functions keep their **known** name and are never
re-inferred (locked decision #1).

Purely functional and deterministic: no I/O, no JVM, no LLM — the ``Namer`` (the client LLM in
production, a deterministic stub in tests/eval) and all bounds are injected, so the walk is
trivially unit-testable (functional core / imperative shell). Binary-derived input is ``Untrusted``
(ADR-005) and is treated as inert data — this module never executes the decompiled or renamed C;
the eval's compile/run step is a separate sandboxed increment (ADR-010 §Security).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from ghidra_mcp.tools.schemas import AnalysisOrderOut, FunctionContext

#: Default cap on the number of functions named in one pass (DoS / cost bound — a hostile or huge
#: binary must not drive an unbounded client loop; surfaced honestly via ``RenamedProgram.notes``).
_DEFAULT_MAX_FUNCTIONS = 5_000


@dataclass(frozen=True, slots=True)
class ProposedName:
    """A namer's proposal for one function.

    Attributes:
        new_name: The inferred semantic identifier (the client/LLM's renamed function name).
        new_c: The renamed pseudo-C for this function (names applied). Untrusted-derived and NEVER
            executed by this module; carried into the assembled translation unit as inert text.
    """

    new_name: str
    new_c: str


#: A namer maps (this function's context, {callee_address: assigned_name} for already-named callees)
#: to a :class:`ProposedName`. In production this is the client LLM; tests/eval inject a
#: deterministic stub. From this core's perspective it is called once per non-external function.
Namer = Callable[[FunctionContext, Mapping[str, str]], ProposedName]


@dataclass(frozen=True, slots=True)
class FunctionNaming:
    """The naming outcome for one function (in leaf-first processing order).

    Attributes:
        address: Function entry address (hex) — safe.
        original_name: The pre-naming Ghidra name (``Untrusted.value``) — recorded for the eval.
        assigned_name: The name carried forward to callers: the namer's ``new_name`` for inferred
            functions, or the KNOWN name for externals.
        is_external: Whether this is an imported/external/thunk function (known name, not inferred).
        inferred: Whether a namer produced this (``False`` for externals / missing-context skips).
        renamed_c: The renamed pseudo-C, or ``None`` for externals (no body to synthesize).
    """

    address: str
    original_name: str
    assigned_name: str
    is_external: bool
    inferred: bool
    renamed_c: str | None = None


@dataclass(frozen=True, slots=True)
class RenamedProgram:
    """The result of a leaf-first naming pass.

    Attributes:
        functions: Per-function outcomes in leaf-first processing order.
        translation_unit: The assembled renamed C (inferred bodies concatenated leaf-first, with an
            external-declaration header). Untrusted-derived inert text — feed only to a SANDBOXED
            compiler in the eval (ADR-010 §Security); never exec/eval it.
        notes: Honest caveats (missing contexts, truncation, unresolved indirect/virtual calls) so
            the caller knows the output is partial — the recovery substrate is best-effort.
    """

    functions: tuple[FunctionNaming, ...]
    translation_unit: str
    notes: tuple[str, ...] = field(default_factory=tuple)


def orchestrate(
    order: AnalysisOrderOut,
    contexts: Mapping[str, FunctionContext],
    namer: Namer,
    *,
    max_functions: int = _DEFAULT_MAX_FUNCTIONS,
) -> RenamedProgram:
    """Walk ``order`` leaf-first, naming each function with its callees' names already assigned.

    Args:
        order: Leaf-first components (sinks first) from the ``analysis_order`` tool.
        contexts: ``function_context`` bundles keyed by entry address (hex).
        namer: Injected name+C proposer (client LLM in prod; deterministic stub in tests/eval).
        max_functions: Cap on inferred functions (DoS/cost bound); excess is skipped + noted.

    Returns:
        A :class:`RenamedProgram` with per-function outcomes (leaf-first), the assembled renamed
        translation unit, and honesty notes.
    """
    assigned: dict[str, str] = {}  # address -> name carried forward to callers
    results: list[FunctionNaming] = []
    notes: list[str] = []
    inferred_count = 0
    truncated = False

    for component in order.components:
        for address in component.members:
            ctx = contexts.get(address)
            if ctx is None:
                # The plan referenced a function we have no context for — record, don't guess.
                notes.append(f"missing context for {address}")
                continue

            if ctx.is_external:
                # Known name (import/thunk) — never re-infer (locked decision #1). Carry it forward
                # so callers see the real library name in their callee context.
                known = ctx.name.value
                assigned[address] = known
                results.append(
                    FunctionNaming(
                        address=address,
                        original_name=known,
                        assigned_name=known,
                        is_external=True,
                        inferred=False,
                    )
                )
                continue

            if inferred_count >= max_functions:
                truncated = True
                continue

            # Names already assigned to this function's direct callees (leaf-first guarantees they
            # were processed first, unless they sit in an unresolved/un-analyzed corner — absent).
            callee_names = {
                c.address: assigned[c.address] for c in ctx.callees if c.address in assigned
            }
            proposed = namer(ctx, callee_names)
            assigned[address] = proposed.new_name
            results.append(
                FunctionNaming(
                    address=address,
                    original_name=ctx.name.value,
                    assigned_name=proposed.new_name,
                    is_external=False,
                    inferred=True,
                    renamed_c=proposed.new_c,
                )
            )
            inferred_count += 1

            if ctx.has_unresolved_calls:
                notes.append(f"{address}: named with unresolved indirect/virtual call(s) — partial")

    if truncated:
        notes.append(f"naming truncated at max_functions={max_functions}")
    if order.truncated:
        notes.append("analysis_order was truncated — call graph is partial")

    return RenamedProgram(
        functions=tuple(results),
        translation_unit=_assemble(results),
        notes=tuple(notes),
    )


def _assemble(results: list[FunctionNaming]) -> str:
    """Assemble a single renamed translation unit from leaf-first results.

    Externals become a forward-declaration header (known names only, no bodies); inferred functions
    contribute their renamed pseudo-C in leaf-first order (callees before callers — a natural,
    mostly-forward-declared layout). This is inert text for the SANDBOXED eval compiler, not a
    correctness guarantee (ADR-010 §Security, decision #3).
    """
    extern_decls = [
        f"extern void {r.assigned_name}(void); /* external/imported */"
        for r in results
        if r.is_external
    ]
    bodies = [r.renamed_c for r in results if r.inferred and r.renamed_c is not None]
    header = "/* ghidra-mcp semantic-naming reference output (best-effort; NOT a guarantee) */\n"
    parts = [header]
    if extern_decls:
        parts.append("\n".join(extern_decls))
    parts.extend(bodies)
    return "\n\n".join(parts) + "\n"
