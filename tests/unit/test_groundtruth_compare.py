"""Unit tests for the pure ground-truth comparison core (WS5; hermetic, no Ghidra).

Exercises :mod:`tests.e2e._groundtruth` with synthetic truth + simulated Ghidra recovery: perfect
recovery passes; a missed function lowers function-recall and is reported; a missed edge lowers
edge-recall over the fair (both-endpoints-recovered) denominator; a callee ranked after its caller
is a leaf-first violation. Deterministic, no I/O.
"""

from __future__ import annotations

import pytest

from tests.e2e._groundtruth import GroundTruth, Thresholds, compare

# A synthetic call graph (addresses are arbitrary but stable):
#   leaf_a@0x10, leaf_b@0x20  (leaves)
#   helper@0x30 -> leaf_a, leaf_b
#   compute@0x40 -> helper, leaf_a
#   main@0x50 -> compute, leaf_b
_TRUTH_DOC = {
    "schema": "ghidra-mcp/e2e-groundtruth/1",
    "tool": "synth",
    "version": "0",
    "functions": [
        {"name": "leaf_a", "low_pc": 0x10, "high_pc": 0x20},
        {"name": "leaf_b", "low_pc": 0x20, "high_pc": 0x30},
        {"name": "helper", "low_pc": 0x30, "high_pc": 0x40},
        {"name": "compute", "low_pc": 0x40, "high_pc": 0x50},
        {"name": "main", "low_pc": 0x50, "high_pc": 0x60},
    ],
    "edges": [
        ["helper", "leaf_a"],
        ["helper", "leaf_b"],
        ["compute", "helper"],
        ["compute", "leaf_a"],
        ["main", "compute"],
        ["main", "leaf_b"],
    ],
}

# Leaf-first SCC order (each its own singleton component), leaves first:
_GOOD_ORDER = [[0x10], [0x20], [0x30], [0x40], [0x50]]
_ALL_FUNCS = [0x10, 0x20, 0x30, 0x40, 0x50]
_ALL_EDGES = [(0x30, 0x10), (0x30, 0x20), (0x40, 0x30), (0x40, 0x10), (0x50, 0x40), (0x50, 0x20)]


@pytest.fixture
def truth() -> GroundTruth:
    """Parsed synthetic ground truth."""
    return GroundTruth.from_json(_TRUTH_DOC)


def test_from_json_rejects_bad_schema() -> None:
    """A document without the expected schema tag is rejected."""
    with pytest.raises(ValueError, match="schema"):
        GroundTruth.from_json({"schema": "nope", "functions": [], "edges": []})


def test_perfect_recovery_passes(truth: GroundTruth) -> None:
    """Exact recovery → recall 1.0, no violations, passed."""
    r = compare(
        truth,
        recovered_function_addrs=_ALL_FUNCS,
        recovered_edges=_ALL_EDGES,
        analysis_order=_GOOD_ORDER,
    )
    assert r.function_recall == 1.0
    assert r.edge_recall == 1.0
    assert r.leaf_first_consistent is True
    assert r.passed is True
    assert r.missing_functions == ()
    assert r.missing_edges == ()


def test_missing_function_lowers_recall_and_is_reported(truth: GroundTruth) -> None:
    """Dropping helper@0x30 → 4/5 functions, and its edges leave the fair denominator."""
    funcs = [a for a in _ALL_FUNCS if a != 0x30]
    edges = [e for e in _ALL_EDGES if 0x30 not in e]
    r = compare(
        truth,
        recovered_function_addrs=funcs,
        recovered_edges=edges,
        analysis_order=[[a] for a in funcs],
    )
    assert r.function_recall == pytest.approx(4 / 5)
    assert "helper" in r.missing_functions
    # edges touching the missing endpoint are excluded from the denominator, so among the
    # remaining (main->compute, compute->leaf_a, main->leaf_b) recovery is still complete:
    assert r.edge_recall == 1.0
    # 4/5 = 0.80 is below the default 0.90 function-recall threshold → overall fail.
    assert r.passed is False


def test_missing_edge_lowers_edge_recall(truth: GroundTruth) -> None:
    """All functions recovered but one edge (main->compute) missing → edge_recall 5/6."""
    edges = [e for e in _ALL_EDGES if e != (0x50, 0x40)]
    r = compare(
        truth,
        recovered_function_addrs=_ALL_FUNCS,
        recovered_edges=edges,
        analysis_order=_GOOD_ORDER,
    )
    assert r.function_recall == 1.0
    assert r.edge_recall == pytest.approx(5 / 6)
    assert ("main", "compute") in r.missing_edges
    assert r.passed is True  # 5/6 ≈ 0.83 ≥ 0.80 default


def test_edge_recall_below_threshold_fails(truth: GroundTruth) -> None:
    """Dropping enough edges pushes edge_recall under the threshold → fail."""
    edges = [(0x30, 0x10)]  # keep only 1 of 6
    r = compare(
        truth,
        recovered_function_addrs=_ALL_FUNCS,
        recovered_edges=edges,
        analysis_order=_GOOD_ORDER,
    )
    assert r.edge_recall == pytest.approx(1 / 6)
    assert r.passed is False


def test_leaf_first_violation_detected(truth: GroundTruth) -> None:
    """An order placing a callee AFTER its caller is a leaf-first violation → fail."""
    bad_order = [[0x50], [0x40], [0x30], [0x20], [0x10]]  # reversed: sources first (wrong)
    r = compare(
        truth,
        recovered_function_addrs=_ALL_FUNCS,
        recovered_edges=_ALL_EDGES,
        analysis_order=bad_order,
    )
    assert r.leaf_first_consistent is False
    assert r.leaf_first_violations  # non-empty
    assert r.passed is False


def test_same_component_cycle_is_not_a_violation(truth: GroundTruth) -> None:
    """Endpoints in the same SCC component (a cycle) don't count as a leaf-first violation."""
    # compute+helper share one component (as if mutually recursive); order still leaf-first.
    order = [[0x10], [0x20], [0x30, 0x40], [0x50]]
    r = compare(
        truth,
        recovered_function_addrs=_ALL_FUNCS,
        recovered_edges=_ALL_EDGES,
        analysis_order=order,
    )
    assert r.leaf_first_consistent is True


def test_thresholds_are_configurable(truth: GroundTruth) -> None:
    """A stricter function-recall threshold flips a borderline pass to fail."""
    funcs = [a for a in _ALL_FUNCS if a != 0x30]  # 4/5 = 0.8
    r = compare(
        truth,
        recovered_function_addrs=funcs,
        recovered_edges=[e for e in _ALL_EDGES if 0x30 not in e],
        analysis_order=[[a] for a in funcs],
        thresholds=Thresholds(function_recall=0.95),
    )
    assert r.passed is False
