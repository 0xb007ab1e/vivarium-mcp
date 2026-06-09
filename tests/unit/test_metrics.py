"""Unit tests for the pure Tier-2 metric cores (ADR-008): complexity + call-graph metrics."""

from __future__ import annotations

import pytest

from ghidra_mcp.core.metrics import (
    CallGraphMetricsResult,
    FanEntry,
    compute_call_graph_metrics,
    cyclomatic_complexity,
)


@pytest.mark.parametrize(
    ("blocks", "edges", "expected"),
    [
        (1, 0, 1),  # straight-line: max(1, 0-1+2)=1
        (4, 5, 3),  # 5-4+2
        (5, 10, 7),  # 10-5+2
        (3, 2, 1),  # max(1, 2-3+2)=1 (clamp)
        (0, 5, 1),  # degenerate/empty CFG -> 1
        (-2, 9, 1),  # negative block count -> 1
    ],
)
def test_cyclomatic_complexity(blocks: int, edges: int, expected: int) -> None:
    """McCabe E-N+2 with a floor of 1, robust to degenerate CFGs."""
    assert cyclomatic_complexity(blocks, edges) == expected


def test_call_graph_metrics_full() -> None:
    """Fan-in/out, leaf/root, recursion, unresolved, and ranked hotspots over a mixed graph."""
    adjacency = {
        "0x1": ["0x2", "0x3", "0x2"],  # dup edge -> deduped; fan-out 2
        "0x2": ["0x3"],
        "0x3": [],  # leaf
        "0xa": ["0xb"],
        "0xb": ["0xa"],  # mutual recursion (one recursive component)
        "0xc": ["0xc"],  # self-loop
    }
    m = compute_call_graph_metrics(adjacency, unresolved=("0x1",), top_n=2)
    assert isinstance(m, CallGraphMetricsResult)
    assert m.function_count == 6
    assert m.edge_count == 6  # (1,2)(1,3)(2,3)(a,b)(b,a)(c,c)
    assert m.leaf_count == 1  # only 0x3
    assert m.root_count == 1  # only 0x1
    assert m.recursive_component_count == 2  # {a,b} cycle + {c} self-loop
    assert m.self_recursive_count == 1  # 0xc
    assert m.unresolved_caller_count == 1
    # top fan-in: 0x3 has in-degree 2; then count-1 tie broken by address -> 0x2
    assert m.top_fan_in == (FanEntry("0x3", 2), FanEntry("0x2", 1))
    # top fan-out: 0x1 has out-degree 2; then count-1 tie -> 0x2
    assert m.top_fan_out == (FanEntry("0x1", 2), FanEntry("0x2", 1))


def test_call_graph_metrics_empty_and_topn_zero() -> None:
    """Empty graph yields zeroed metrics; top_n<=0 yields empty rankings."""
    m = compute_call_graph_metrics({}, unresolved=(), top_n=0)
    assert m.function_count == 0
    assert m.edge_count == 0
    assert m.leaf_count == 0
    assert m.root_count == 0
    assert m.recursive_component_count == 0
    assert m.top_fan_in == ()
    assert m.top_fan_out == ()


def test_call_graph_metrics_unknown_callee_counts_as_node() -> None:
    """A callee with no adjacency entry of its own still counts as a node (a leaf)."""
    m = compute_call_graph_metrics({"0x1": ["0x9"]}, top_n=5)
    assert m.function_count == 2  # 0x1 + 0x9
    assert m.edge_count == 1
    assert m.leaf_count == 1  # 0x9
    assert m.root_count == 1  # 0x1
    assert m.top_fan_in == (FanEntry("0x9", 1),)
    assert m.top_fan_out == (FanEntry("0x1", 1),)
