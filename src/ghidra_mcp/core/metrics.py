"""Pure (JVM-free) metric computations for the Tier-2 reporting tools (ADR-008).

This module is part of the **functional core** (ADR-001): it derives metrics from already-extracted,
plain facts (CFG block/edge counts; a resolved call-graph adjacency) with no I/O, no JVM, and no
binary parsing — so it is deterministic and 100%-unit-testable. The worker extracts the raw counts;
the server computes the metrics here; the adapter wraps any binary-derived labels (function names)
in the untrusted envelope (ADR-005) when shaping the typed output.
"""

from __future__ import annotations

from dataclasses import dataclass

from ghidra_mcp.core.callgraph import AdjacencyMap, compute_analysis_order


def cyclomatic_complexity(block_count: int, edge_count: int) -> int:
    """Return the McCabe cyclomatic complexity of a single procedure.

    ``M = E - N + 2`` for one connected procedure (``P = 1``): ``edge_count - block_count + 2``.
    The result is clamped to a minimum of 1 — a straight-line function (one block, no branch edges)
    has complexity 1, and a degenerate/empty CFG must never report < 1 or a negative value.

    Args:
        block_count: Number of basic blocks (CFG nodes) in the function. Non-positive is treated as
            an empty/degenerate CFG (complexity 1).
        edge_count: Number of control-flow edges between basic blocks.

    Returns:
        The cyclomatic complexity, an integer ``>= 1``.
    """
    if block_count <= 0:
        return 1
    return max(1, edge_count - block_count + 2)


@dataclass(frozen=True, slots=True)
class FanEntry:
    """One node ranked by fan-in or fan-out degree (addresses only — no names in the pure core).

    Attributes:
        address: The function node id (a server-normalized entry address).
        count: The degree (number of distinct callers for fan-in, distinct callees for fan-out).
    """

    address: str
    count: int


@dataclass(frozen=True, slots=True)
class CallGraphMetricsResult:
    """Structural metrics over a resolved call graph (pure; addresses only).

    Attributes:
        function_count: Distinct nodes (callers, callees, and unresolved-flagged nodes).
        edge_count: Distinct resolved ``caller -> callee`` edges (deduped; self-loops counted).
        leaf_count: Nodes with no outgoing resolved edges (fan-out 0).
        root_count: Nodes with no incoming resolved edges (fan-in 0).
        recursive_component_count: Strongly-connected components that represent recursion
            (multi-member cycles, or single members with a self-loop).
        self_recursive_count: Nodes with a direct self-loop.
        unresolved_caller_count: Nodes with >=1 unresolved (indirect/virtual) outgoing call.
        top_fan_in: Highest in-degree nodes (descending count, ties broken by address).
        top_fan_out: Highest out-degree nodes (descending count, ties broken by address).
    """

    function_count: int
    edge_count: int
    leaf_count: int
    root_count: int
    recursive_component_count: int
    self_recursive_count: int
    unresolved_caller_count: int
    top_fan_in: tuple[FanEntry, ...]
    top_fan_out: tuple[FanEntry, ...]


def _ranked(degrees: dict[str, int], top_n: int) -> tuple[FanEntry, ...]:
    """Return the ``top_n`` nodes by degree (desc), ties broken by address (asc), as ``FanEntry``.

    Args:
        degrees: Node id -> degree count.
        top_n: Maximum entries to return (non-positive yields an empty tuple).

    Returns:
        The deterministically-ordered top entries.
    """
    if top_n <= 0:
        return ()
    ranked = sorted(degrees.items(), key=lambda kv: (-kv[1], kv[0]))
    return tuple(FanEntry(address=addr, count=count) for addr, count in ranked[:top_n])


def compute_call_graph_metrics(
    adjacency: AdjacencyMap,
    *,
    unresolved: tuple[str, ...] = (),
    top_n: int = 10,
) -> CallGraphMetricsResult:
    """Compute structural call-graph metrics from a resolved adjacency map (PURE, no JVM, no I/O).

    Fan-out/fan-in are computed over **distinct** resolved edges; recursion stats come from the same
    SCC machinery as :func:`ghidra_mcp.core.callgraph.compute_analysis_order`, so a single graph
    extraction feeds both the leaf-first order (semantic-naming) and these metrics (ADR-007 reuse).

    Args:
        adjacency: Resolved ``caller-node-id -> [callee-node-ids]`` map (may contain duplicate or
            unknown-target callees; both are normalized here).
        unresolved: Node ids with at least one unresolved outgoing call edge.
        top_n: How many hotspots to return in ``top_fan_in`` / ``top_fan_out``.

    Returns:
        The :class:`CallGraphMetricsResult`.
    """
    # All node ids: callers, every callee target, and any unresolved-flagged node.
    nodes: set[str] = set(adjacency)
    for callees in adjacency.values():
        nodes.update(callees)
    nodes.update(unresolved)

    fan_out: dict[str, int] = dict.fromkeys(nodes, 0)
    fan_in: dict[str, int] = dict.fromkeys(nodes, 0)
    seen_edges: set[tuple[str, str]] = set()
    for caller, callees in adjacency.items():
        for callee in callees:
            edge = (caller, callee)
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            fan_out[caller] = fan_out.get(caller, 0) + 1
            fan_in[callee] = fan_in.get(callee, 0) + 1

    order = compute_analysis_order(adjacency, unresolved=unresolved)
    recursive = sum(1 for c in order.components if c.is_recursive)

    return CallGraphMetricsResult(
        function_count=len(nodes),
        edge_count=len(seen_edges),
        leaf_count=sum(1 for n in nodes if fan_out.get(n, 0) == 0),
        root_count=sum(1 for n in nodes if fan_in.get(n, 0) == 0),
        recursive_component_count=recursive,
        self_recursive_count=len(order.self_recursive),
        unresolved_caller_count=len(set(unresolved)),
        top_fan_in=_ranked({n: d for n, d in fan_in.items() if d > 0}, top_n),
        top_fan_out=_ranked({n: d for n, d in fan_out.items() if d > 0}, top_n),
    )
