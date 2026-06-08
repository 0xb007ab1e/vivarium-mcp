"""Unit tests for the pure call-graph ordering core (ADR-007) — critical path (100% target).

Exercises :func:`ghidra_mcp.core.callgraph.compute_analysis_order` over every shape the algorithm
must handle: empty, single node, linear chain, branching DAG, disconnected components, self-loop
(direct recursion), a multi-node cycle (mutual recursion), nested cycles, unknown callee ids
(leaves with no own adjacency entry), and unresolved (indirect/virtual) edges. The ordering
invariant (every resolved edge points from a later component to an earlier one — leaf-first) is
asserted structurally, plus a graph-bomb robustness check that a deep chain does not recurse.
"""

from __future__ import annotations

import pytest

from ghidra_mcp.core.callgraph import (
    AnalysisOrder,
    Component,
    compute_analysis_order,
)


def _order_index(order: AnalysisOrder) -> dict[str, int]:
    """Map each node id to the index of its component in the leaf-first order.

    Args:
        order: The computed analysis order.

    Returns:
        A node-id -> component-index mapping.
    """
    index: dict[str, int] = {}
    for i, comp in enumerate(order.components):
        for member in comp.members:
            index[member] = i
    return index


def _assert_leaf_first(adjacency: dict[str, list[str]], order: AnalysisOrder) -> None:
    """Assert every resolved edge points from a later component to an earlier-or-same one.

    Leaf-first means a callee's component must be ordered before (or equal to, within a cycle) its
    caller's component. Equivalently: for an edge ``u -> v``, ``index[v] <= index[u]``.

    Args:
        adjacency: The input adjacency map.
        order: The computed analysis order.
    """
    index = _order_index(order)
    for caller, callees in adjacency.items():
        for callee in callees:
            assert index[callee] <= index[caller], (
                f"edge {caller}->{callee} violates leaf-first: "
                f"{index[callee]} (callee) > {index[caller]} (caller)"
            )


def test_empty_graph_yields_empty_order() -> None:
    """An empty adjacency map produces an empty, total result (no crash)."""
    order = compute_analysis_order({})
    assert order.components == ()
    assert order.unresolved_callers == ()
    assert order.self_recursive == ()


def test_single_node_no_edges() -> None:
    """A single function that calls nothing is one non-recursive component."""
    order = compute_analysis_order({"a": []})
    assert order.components == (Component(members=("a",), is_recursive=False),)


def test_linear_chain_is_leaf_first() -> None:
    """A -> B -> C orders leaf C first, root A last."""
    adjacency = {"a": ["b"], "b": ["c"], "c": []}
    order = compute_analysis_order(adjacency)
    names = [comp.members for comp in order.components]
    assert names == [("c",), ("b",), ("a",)]
    _assert_leaf_first(adjacency, order)


def test_branching_dag_leaf_first_invariant() -> None:
    """A diamond (a->b, a->c, b->d, c->d) respects the leaf-first edge invariant."""
    adjacency = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    order = compute_analysis_order(adjacency)
    _assert_leaf_first(adjacency, order)
    # d must be first (pure sink); a must be last (pure source).
    index = _order_index(order)
    assert index["d"] == 0
    assert index["a"] == len(order.components) - 1


def test_disconnected_components_each_appear() -> None:
    """Two unconnected functions each become their own singleton component."""
    order = compute_analysis_order({"x": [], "y": []})
    members = sorted(comp.members for comp in order.components)
    assert members == [("x",), ("y",)]
    assert all(not comp.is_recursive for comp in order.components)


def test_unknown_callee_becomes_leaf_node() -> None:
    """A callee with no adjacency key of its own (e.g. an external import) is ordered as a leaf."""
    adjacency = {"a": ["ext"]}  # 'ext' has no own entry
    order = compute_analysis_order(adjacency)
    index = _order_index(order)
    assert "ext" in index
    assert index["ext"] < index["a"]  # external leaf named/handled before its caller
    _assert_leaf_first(adjacency, order)


def test_self_loop_is_recursive_and_reported() -> None:
    """A function that calls itself is a single recursive component and listed in self_recursive."""
    adjacency = {"r": ["r", "leaf"], "leaf": []}
    order = compute_analysis_order(adjacency)
    assert "r" in order.self_recursive
    comp_r = next(c for c in order.components if c.members == ("r",))
    assert comp_r.is_recursive is True
    # The self-edge must NOT be reported as a separate successor making a 2-node component.
    assert all(len(c.members) == 1 for c in order.components)
    _assert_leaf_first({"r": ["leaf"], "leaf": []}, order)  # resolved (non-self) edges leaf-first


def test_mutual_recursion_condensed_into_one_component() -> None:
    """A<->B mutual recursion condenses into a single recursive component."""
    adjacency = {"a": ["b"], "b": ["a"]}
    order = compute_analysis_order(adjacency)
    assert len(order.components) == 1
    comp = order.components[0]
    assert comp.members == ("a", "b")  # sorted members
    assert comp.is_recursive is True
    assert order.self_recursive == ()  # mutual, not direct self-recursion


def test_cycle_with_entry_and_leaf_orders_around_the_cycle() -> None:
    """root -> (a<->b) -> leaf: leaf first, cycle in the middle, root last."""
    adjacency = {"root": ["a"], "a": ["b", "leaf"], "b": ["a"], "leaf": []}
    order = compute_analysis_order(adjacency)
    index = _order_index(order)
    # leaf is a pure sink -> earliest; root is a pure source -> latest.
    assert index["leaf"] == 0
    assert index["root"] == len(order.components) - 1
    # a and b share one recursive component.
    assert index["a"] == index["b"]
    cycle_comp = next(c for c in order.components if set(c.members) == {"a", "b"})
    assert cycle_comp.is_recursive is True
    _assert_leaf_first(adjacency, order)


def test_unresolved_edges_surfaced_not_dropped() -> None:
    """Functions with unresolved indirect/virtual calls are reported and present as nodes."""
    adjacency: dict[str, list[str]] = {"dispatch": [], "helper": []}
    order = compute_analysis_order(adjacency, unresolved=["dispatch"])
    assert "dispatch" in order.unresolved_callers
    index = _order_index(order)
    assert "dispatch" in index  # still a node in the order


def test_unresolved_only_node_with_no_adjacency_entry() -> None:
    """An unresolved-flagged node that never appears in the adjacency is still ordered."""
    order = compute_analysis_order({}, unresolved=["mystery"])
    assert order.unresolved_callers == ("mystery",)
    assert order.components == (Component(members=("mystery",), is_recursive=False),)


def test_duplicate_edges_are_deduplicated() -> None:
    """Repeated callee edges do not change the result (de-duplicated)."""
    adjacency = {"a": ["b", "b", "b"], "b": []}
    order = compute_analysis_order(adjacency)
    assert [c.members for c in order.components] == [("b",), ("a",)]


def test_deep_chain_does_not_recurse() -> None:
    """A very deep linear chain is handled iteratively (no Python recursion / stack overflow)."""
    depth = 10_000
    adjacency: dict[str, list[str]] = {f"n{i}": [f"n{i + 1}"] for i in range(depth)}
    adjacency[f"n{depth}"] = []
    order = compute_analysis_order(adjacency)
    assert len(order.components) == depth + 1
    # Leaf-first: the deepest node n{depth} is first, n0 is last.
    assert order.components[0].members == (f"n{depth}",)
    assert order.components[-1].members == ("n0",)


def test_large_cycle_does_not_recurse() -> None:
    """A long single cycle condenses to one recursive component without recursion."""
    size = 5_000
    adjacency: dict[str, list[str]] = {f"c{i}": [f"c{(i + 1) % size}"] for i in range(size)}
    order = compute_analysis_order(adjacency)
    assert len(order.components) == 1
    assert order.components[0].is_recursive is True
    assert len(order.components[0].members) == size


def test_result_is_frozen_immutable() -> None:
    """The result dataclasses are frozen (immutable) — safe to share."""
    import dataclasses

    order = compute_analysis_order({"a": []})
    comp = order.components[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        comp.is_recursive = True  # type: ignore[misc]
