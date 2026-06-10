"""Pure ground-truth comparison for the OSS e2e (WS5) — no I/O, no Ghidra, no JVM.

The e2e harness runs a real binary through the MCP server → worker → Ghidra and collects what
Ghidra RECOVERED from the *stripped* fixture:

  * the set of recovered function entry addresses,
  * the recovered direct call edges (caller_addr -> callee_addr), and
  * the leaf-first ``analysis_order`` (a list of SCC components, each a list of addresses).

It then loads the GROUND TRUTH JSON (produced by ``extract_ground_truth.py`` from the unstripped,
``-no-pie`` build, so truth addresses == Ghidra addresses) and calls :func:`compare`. This module
is the pure scoring core — deterministic, side-effect-free, and unit-tested with synthetic inputs
(``tests/unit/test_groundtruth_compare.py``); the heavy, gated e2e merely feeds it real data.

Why recall + tolerances (not exact equality): Ghidra's recovery legitimately varies by version and
misses/merges a few thunks, and the truth is a deliberate *subset oracle* (real, not complete). So
we assert that Ghidra recovered **most** of the known functions, **most** of the known edges (among
recovered endpoints), and that the leaf-first order is **consistent** with the known partial order —
the substrate the (client-driven) semantic-naming walk depends on.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True)
class GroundTruth:
    """Parsed ground truth: name<->address maps and edges by name (absolute addresses)."""

    tool: str
    version: str
    addr_by_name: Mapping[str, int]
    name_by_addr: Mapping[int, str]
    edges_by_name: frozenset[tuple[str, str]]

    @classmethod
    def from_json(cls, doc: Mapping[str, object]) -> GroundTruth:
        """Build from a ``extract_ground_truth.py`` JSON document (validates the schema tag)."""
        schema = str(doc.get("schema", ""))
        if not schema.startswith("ghidra-mcp/e2e-groundtruth/"):
            msg = f"unexpected ground-truth schema: {schema!r}"
            raise ValueError(msg)
        funcs = doc.get("functions") or []
        if not isinstance(funcs, list):
            msg = "ground truth 'functions' must be a list"
            raise ValueError(msg)
        addr_by_name: dict[str, int] = {}
        name_by_addr: dict[int, str] = {}
        for f in funcs:
            name = str(f["name"])
            addr = int(f["low_pc"])
            addr_by_name[name] = addr
            name_by_addr[addr] = name
        raw_edges = doc.get("edges") or []
        if not isinstance(raw_edges, list):
            msg = "ground truth 'edges' must be a list"
            raise ValueError(msg)
        edges = frozenset((str(a), str(b)) for a, b in raw_edges)
        return cls(
            tool=str(doc.get("tool", "")),
            version=str(doc.get("version", "")),
            addr_by_name=addr_by_name,
            name_by_addr=name_by_addr,
            edges_by_name=edges,
        )


@dataclass(frozen=True)
class Thresholds:
    """Pass/fail tolerances (fractions in [0,1]). Defaults are conservative-but-real."""

    function_recall: float = 0.90
    edge_recall: float = 0.80
    require_leaf_first_consistent: bool = True


@dataclass(frozen=True)
class ComparisonResult:
    """Outcome of comparing recovered data to ground truth."""

    function_recall: float
    edge_recall: float
    leaf_first_consistent: bool
    missing_functions: tuple[str, ...]
    missing_edges: tuple[tuple[str, str], ...]
    leaf_first_violations: tuple[tuple[str, str], ...]
    passed: bool
    notes: tuple[str, ...] = field(default_factory=tuple)

    def summary(self) -> str:
        """One-line human summary (for assert messages / logs)."""
        return (
            f"func_recall={self.function_recall:.2f} edge_recall={self.edge_recall:.2f} "
            f"leaf_first={'ok' if self.leaf_first_consistent else 'VIOLATED'} "
            f"passed={self.passed}"
        )


def _component_index(order: Sequence[Sequence[int]]) -> dict[int, int]:
    """Map each address to its position in the leaf-first SCC ordering (component index)."""
    idx: dict[int, int] = {}
    for i, comp in enumerate(order):
        for addr in comp:
            idx[addr] = i
    return idx


def compare(
    truth: GroundTruth,
    *,
    recovered_function_addrs: Iterable[int],
    recovered_edges: Iterable[tuple[int, int]],
    analysis_order: Sequence[Sequence[int]],
    thresholds: Thresholds | None = None,
) -> ComparisonResult:
    """Score Ghidra's recovery against the ground truth (pure).

    Args:
        truth: Parsed ground truth (absolute addresses).
        recovered_function_addrs: Entry addresses of functions Ghidra recovered.
        recovered_edges: Direct call edges Ghidra recovered, as (caller_addr, callee_addr).
        analysis_order: Leaf-first SCC components (each a list of addresses).
        thresholds: Pass/fail tolerances (defaults if omitted).

    Returns:
        A :class:`ComparisonResult` with recall metrics, the specific misses, and pass/fail.
    """
    th = thresholds or Thresholds()
    rec_funcs = set(recovered_function_addrs)
    rec_edges = {(int(a), int(b)) for a, b in recovered_edges}

    # --- function recall: truth functions whose entry addr Ghidra also recovered ---
    truth_addrs = set(truth.name_by_addr)
    found = {a for a in truth_addrs if a in rec_funcs}
    missing_fn = tuple(sorted(truth.name_by_addr[a] for a in truth_addrs - found))
    function_recall = (len(found) / len(truth_addrs)) if truth_addrs else 1.0

    # --- edge recall: only over edges whose BOTH endpoints were recovered (fair denominator) ---
    considered: list[tuple[str, str]] = []
    missing_edges: list[tuple[str, str]] = []
    for caller, callee in sorted(truth.edges_by_name):
        ca = truth.addr_by_name.get(caller)
        ce = truth.addr_by_name.get(callee)
        if ca is None or ce is None or ca not in rec_funcs or ce not in rec_funcs:
            continue  # endpoint not recovered → not counted for/against edge recall
        considered.append((caller, callee))
        if (ca, ce) not in rec_edges:
            missing_edges.append((caller, callee))
    edge_recall = (len(considered) - len(missing_edges)) / len(considered) if considered else 1.0

    # --- leaf-first consistency: for every truth edge present in recovery, the callee's
    #     component must come at-or-before the caller's (leaves first). Same component = a cycle
    #     (order within is undefined) → not a violation. ---
    comp_idx = _component_index(analysis_order)
    violations: list[tuple[str, str]] = []
    for caller, callee in considered:
        ca, ce = truth.addr_by_name[caller], truth.addr_by_name[callee]
        if (ca, ce) not in rec_edges:
            continue
        ci, ei = comp_idx.get(ca), comp_idx.get(ce)
        if ci is None or ei is None:
            continue  # not in the returned order slice
        if ei > ci:  # callee ranked AFTER caller → not leaf-first
            violations.append((caller, callee))
    leaf_first_consistent = not violations

    passed = (
        function_recall >= th.function_recall
        and edge_recall >= th.edge_recall
        and (leaf_first_consistent or not th.require_leaf_first_consistent)
    )
    notes = (
        f"truth: {len(truth_addrs)} fns / {len(truth.edges_by_name)} edges; "
        f"recovered endpoints for {len(considered)} edges",
    )
    return ComparisonResult(
        function_recall=function_recall,
        edge_recall=edge_recall,
        leaf_first_consistent=leaf_first_consistent,
        missing_functions=missing_fn,
        missing_edges=tuple(missing_edges),
        leaf_first_violations=tuple(violations),
        passed=passed,
        notes=notes,
    )
