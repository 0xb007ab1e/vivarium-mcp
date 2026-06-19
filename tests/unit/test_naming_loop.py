"""Unit tests for the leaf-first naming orchestration core (ADR-010).

Pure, hermetic: a deterministic stub namer stands in for the client LLM. Cover the leaf-first walk,
carry-forward of callee names, external-name preservation, missing-context + truncation + unresolved
notes, and translation-unit assembly.
"""

from __future__ import annotations

from collections.abc import Mapping

from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.naming.loop import Namer, ProposedName, orchestrate
from vivarium.tools.schemas import (
    AnalysisOrderOut,
    CallGraphNode,
    FunctionContext,
    OrderedComponent,
)


def _u(text: str) -> Untrusted[str]:
    return Untrusted(value=text, origin=DataOrigin.GHIDRA)


def _node(addr: str, name: str, *, external: bool = False) -> CallGraphNode:
    return CallGraphNode(
        address=addr, name=_u(name), is_external=external, has_unresolved_calls=False
    )


def _ctx(
    addr: str,
    name: str,
    *,
    external: bool = False,
    callees: list[CallGraphNode] | None = None,
    refstrings: list[str] | None = None,
    unresolved: bool = False,
) -> FunctionContext:
    return FunctionContext(
        address=addr,
        name=_u(name),
        signature=_u("undefined4 " + name + "(void)"),
        is_external=external,
        decompilation=_u(f"/* {name} */ int {name}(void) {{ return 0; }}"),
        callees=callees or [],
        callers=[],
        referenced_strings=[_u(s) for s in (refstrings or [])],
        has_unresolved_calls=unresolved,
    )


def _order(*components: tuple[list[str], bool], truncated: bool = False) -> AnalysisOrderOut:
    return AnalysisOrderOut(
        components=[OrderedComponent(members=m, is_recursive=r) for m, r in components],
        unresolved_callers=[],
        self_recursive=[],
        truncated=truncated,
    )


def _record_namer() -> tuple[Namer, list[tuple[str, dict[str, str]]]]:
    """A deterministic namer that records each (address, callee_names) it was asked to name."""
    seen: list[tuple[str, dict[str, str]]] = []

    def namer(ctx: FunctionContext, callee_names: Mapping[str, str]) -> ProposedName:
        seen.append((ctx.address, dict(callee_names)))
        # Use a referenced string if present (the real semantic signal), else a stable synthetic.
        base = (
            ctx.referenced_strings[0].value if ctx.referenced_strings else f"fn_{ctx.address[-4:]}"
        )
        return ProposedName(new_name=base, new_c=f"int {base}(void) {{ return 0; }}")

    return namer, seen


def test_leaf_first_carries_callee_names_forward() -> None:
    """A caller is named AFTER its callee, and the namer sees the callee's assigned name."""
    a = _ctx("0x401000", "FUN_00401000", refstrings=["parse_header"])
    b = _ctx("0x401100", "FUN_00401100", callees=[_node("0x401000", "FUN_00401000")])
    contexts = {a.address: a, b.address: b}
    namer, seen = _record_namer()
    # Leaf-first: A (sink) before B (root).
    result = orchestrate(_order((["0x401000"], False), (["0x401100"], False)), contexts, namer)

    assert [f.address for f in result.functions] == ["0x401000", "0x401100"]
    assert result.functions[0].assigned_name == "parse_header"
    # When B was named, the namer received A's already-assigned name.
    b_seen = dict(seen)["0x401100"]
    assert b_seen == {"0x401000": "parse_header"}
    assert all(f.inferred for f in result.functions)


def test_external_keeps_known_name_and_is_not_inferred() -> None:
    """Imported/external functions keep their known name and are never sent to the namer."""
    ext = _ctx("0x402000", "puts", external=True)
    namer, seen = _record_namer()
    result = orchestrate(_order((["0x402000"], False)), {ext.address: ext}, namer)

    (fn,) = result.functions
    assert fn.is_external and not fn.inferred
    assert fn.assigned_name == "puts" and fn.renamed_c is None
    assert seen == []  # namer never called for an external
    assert "extern void puts(void); /* external/imported */" in result.translation_unit


def test_missing_context_is_noted_not_guessed() -> None:
    namer, _ = _record_namer()
    result = orchestrate(_order((["0xdeadbeef"], False)), {}, namer)
    assert result.functions == ()
    assert any("missing context for 0xdeadbeef" in n for n in result.notes)


def test_max_functions_truncates_and_notes() -> None:
    ctxs = {f"0x40{i}000": _ctx(f"0x40{i}000", f"FUN_{i}") for i in range(3)}
    order = _order(*[([a], False) for a in ctxs])
    namer, _ = _record_namer()
    result = orchestrate(order, ctxs, namer, max_functions=2)
    assert sum(f.inferred for f in result.functions) == 2
    assert any("truncated at max_functions=2" in n for n in result.notes)


def test_unresolved_and_order_truncation_notes() -> None:
    c = _ctx("0x401000", "FUN_x", unresolved=True)
    namer, _ = _record_namer()
    result = orchestrate(_order((["0x401000"], False), truncated=True), {c.address: c}, namer)
    assert any("unresolved indirect/virtual" in n for n in result.notes)
    assert any("analysis_order was truncated" in n for n in result.notes)


def test_translation_unit_assembles_externs_then_bodies() -> None:
    ext = _ctx("0x402000", "memcpy", external=True)
    leaf = _ctx("0x401000", "FUN_a", refstrings=["copy_block"])
    contexts = {ext.address: ext, leaf.address: leaf}
    namer, _ = _record_namer()
    result = orchestrate(_order((["0x402000"], False), (["0x401000"], False)), contexts, namer)
    tu = result.translation_unit
    assert "best-effort; NOT a guarantee" in tu
    assert "extern void memcpy(void)" in tu
    assert "int copy_block(void)" in tu
