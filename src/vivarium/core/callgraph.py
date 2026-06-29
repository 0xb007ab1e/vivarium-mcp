"""Pure call-graph ordering core (ADR-007) — critical path (100% target).

This is the algorithmic heart of the semantic-naming feature: given a function call-graph
*adjacency map* (extracted by the worker — ADR-001), it computes a **leaf-first reverse-topological
ordering** so a client can name/analyze the lowest-level callees first and carry assigned names
forward as it walks toward the entry roots ("start at the lowest call site, work backwards").

Why this lives in the pure server-side core (ADR-001, topic-architecture-patterns):

- Graph *extraction* (which function calls which) is a JVM/Ghidra operation and belongs in the
  worker (``_gh_call_graph``). The *ordering* over that extracted adjacency is pure graph theory
  with **no JVM, no I/O, no binary parsing** — so it is a functional-core computation that is
  trivially 100%-testable without Ghidra.

The graph is a DAG only in the absence of recursion. Real binaries contain recursion and
mutual-recursion cycles, so a naive topological sort does not exist. We therefore:

1. Condense each **strongly-connected component (SCC)** — a maximal set of mutually-reachable
   functions (a recursion cycle, or a single self-recursive / acyclic function) — into one node.
   The condensation of any directed graph is a DAG (Tarjan's theorem).
2. Topologically order the condensed DAG and **reverse** it so leaves (sinks: functions that call
   nothing further) come first and roots (entry points) come last.

Honesty over silent loss (ADR-005 ethos, threat-model TB4):

- **Unresolved edges** (indirect/virtual/computed calls Ghidra could not resolve to a concrete
  callee) are surfaced explicitly via :attr:`AnalysisOrder.unresolved_callers`, never silently
  dropped. A function whose real callees are hidden behind a vtable/function-pointer is flagged so
  the client knows its inferred purpose rests on incomplete information.
- **Self-loops** (direct self-recursion) are recorded, not discarded.

All inputs are treated as untrusted (the adjacency was derived from a hostile binary): node ids are
opaque strings, edges to unknown nodes are tolerated, and the algorithms are iterative (no Python
recursion) so a pathologically deep/cyclic graph cannot blow the interpreter stack (DoS — the
node/edge *count* caps live at the tool boundary; this module is robust regardless of size).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

# An adjacency map: caller node id -> the callee node ids it directly calls (resolved edges only).
# Node ids are opaque, untrusted strings (typically a function entry address in canonical hex).
AdjacencyMap = Mapping[str, Iterable[str]]


@dataclass(frozen=True, slots=True)
class Component:
    """One node of the condensed DAG: a strongly-connected component of the call graph.

    A component with more than one member is a recursion cycle (mutual recursion); a single-member
    component may still be self-recursive (see :attr:`is_recursive`).

    Attributes:
        members: The function node ids in this component, in a deterministic (sorted) order. A
            single-element tuple for a non-cyclic function.
        is_recursive: ``True`` when the component represents recursion — either a multi-member
            cycle (mutual recursion) or a single member with a self-loop (direct recursion). The
            client treats a recursive component as a unit (name its members together; there is no
            strict leaf-first order *within* a cycle).
    """

    members: tuple[str, ...]
    is_recursive: bool


@dataclass(frozen=True, slots=True)
class AnalysisOrder:
    """The leaf-first analysis plan over a call graph (the ``analysis_order`` tool result, pure).

    Attributes:
        components: Strongly-connected components in **leaf-first reverse-topological order** —
            sinks (call nothing further) first, entry roots last. Naming/analyzing in this order
            lets a client carry resolved callee names forward into each caller.
        unresolved_callers: Node ids that have at least one *unresolved* outgoing call edge
            (indirect/virtual/computed — the worker could not resolve the concrete callee). Their
            inferred purpose rests on incomplete call information; surfaced, never dropped
            (ADR-005 honesty; threat-model TB4).
        self_recursive: Node ids with a direct self-loop (function calls itself). A subset of the
            members of recursive components; recorded explicitly for the client.
    """

    components: tuple[Component, ...]
    unresolved_callers: tuple[str, ...]
    self_recursive: tuple[str, ...] = field(default_factory=tuple)


def _collect_nodes(adjacency: AdjacencyMap, unresolved: set[str]) -> list[str]:
    """Collect every node id appearing anywhere, in deterministic order (sorted).

    A node is any id that is a caller (a key), a resolved callee (a value), or flagged unresolved.
    Callees referencing an id with no adjacency entry of its own (a leaf with no recorded outgoing
    edges, e.g. an imported/external function) are still nodes and must appear in the order.

    Args:
        adjacency: The resolved caller -> callees map.
        unresolved: Node ids known to have unresolved outgoing edges (still real nodes; may be
            empty).

    Returns:
        All distinct node ids, sorted for determinism.
    """
    nodes: set[str] = set(unresolved)
    for caller, callees in adjacency.items():
        nodes.add(caller)
        nodes.update(callees)
    return sorted(nodes)


def _normalize(adjacency: AdjacencyMap, nodes: list[str]) -> tuple[dict[str, list[str]], set[str]]:
    """Build a clean adjacency over ``nodes`` and detect direct self-loops.

    Edges are de-duplicated and ordered deterministically (sorted). A self-loop (``n`` calls ``n``)
    is recorded separately and **excluded** from the SCC successor edges, so it does not by itself
    force ``n`` into a "recursive" multi-node component — direct recursion is reported via
    :attr:`AnalysisOrder.self_recursive` and the single-member component's ``is_recursive`` flag.

    Args:
        adjacency: The raw resolved caller -> callees map (may contain dupes / unknown targets).
        nodes: The full, sorted node set.

    Returns:
        ``(succ, self_loops)`` where ``succ`` maps every node to its sorted, de-duplicated,
        non-self successor ids, and ``self_loops`` is the set of self-recursive node ids.
    """
    succ: dict[str, list[str]] = {n: [] for n in nodes}
    self_loops: set[str] = set()
    for caller, callees in adjacency.items():
        seen: set[str] = set()
        for callee in callees:
            if callee == caller:
                self_loops.add(caller)
                continue
            if callee in seen:
                continue
            seen.add(callee)
        succ[caller] = sorted(seen)
    return succ, self_loops


# C901: Tarjan's SCC is a standard iterative algorithm — splitting it would obscure its invariant.
def _tarjan_sccs(nodes: list[str], succ: dict[str, list[str]]) -> list[list[str]]:  # noqa: C901
    """Compute strongly-connected components iteratively (Tarjan's algorithm).

    Iterative (explicit work stack) rather than recursive so a deeply nested or long cyclic graph
    from a hostile binary cannot exhaust the Python call stack (robustness / DoS resistance). The
    returned SCCs are in **reverse topological order of the condensation** (Tarjan emits sinks
    first), which is exactly the leaf-first order this feature wants — callers preserve it.

    Args:
        nodes: All node ids (sorted, for deterministic component membership/order).
        succ: Node -> sorted successor ids (self-loops already removed).

    Returns:
        A list of SCCs (each a list of node ids); SCCs are ordered leaf-first (sinks before
        sources), and members within each SCC are sorted.
    """
    index_of: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []
    counter = 0

    for root in nodes:
        if root in index_of:
            continue
        # Each work-stack entry is (node, next_successor_index_to_visit).
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, succ_i = work[-1]
            if succ_i == 0:
                index_of[node] = counter
                lowlink[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)

            successors = succ[node]
            if succ_i < len(successors):
                work[-1] = (node, succ_i + 1)
                child = successors[succ_i]
                if child not in index_of:
                    work.append((child, 0))
                elif child in on_stack:
                    lowlink[node] = min(lowlink[node], index_of[child])
                continue

            # All successors processed: if ``node`` is an SCC root, pop its component.
            if lowlink[node] == index_of[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                sccs.append(sorted(component))
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
    return sccs


def compute_analysis_order(
    adjacency: AdjacencyMap,
    *,
    unresolved: Iterable[str] | None = None,
) -> AnalysisOrder:
    """Compute the leaf-first reverse-topological analysis order over a call graph.

    This is the pure algorithmic core behind the ``analysis_order`` tool. It condenses recursion /
    mutual-recursion cycles into single :class:`Component` nodes and orders the resulting DAG so
    leaves (functions that call nothing further) come first and entry roots come last — the order a
    client walks to name callees before their callers and carry assigned names forward.

    The computation is total and deterministic: an empty graph yields an empty order; disconnected
    nodes each form their own singleton component; unknown callee ids are treated as real leaf
    nodes; self-loops and cycles are reported rather than dropped; unresolved (indirect/virtual)
    call sites are surfaced in :attr:`AnalysisOrder.unresolved_callers`. It performs no I/O and uses
    no Python recursion (hostile-graph robust).

    Args:
        adjacency: A resolved caller-node-id -> directly-called callee-node-ids map. Node ids are
            opaque, untrusted strings (typically function entry addresses in canonical hex). Edges
            to ids with no key of their own are tolerated (they become leaf nodes).
        unresolved: Optional node ids that have at least one *unresolved* outgoing call edge
            (indirect/virtual/computed). They are included as nodes and reported, so the client
            knows the call information for them is incomplete.

    Returns:
        An :class:`AnalysisOrder` whose ``components`` are in leaf-first reverse-topological order.
    """
    unresolved_set = set(unresolved) if unresolved is not None else set()
    nodes = _collect_nodes(adjacency, unresolved_set)
    succ, self_loops = _normalize(adjacency, nodes)
    sccs = _tarjan_sccs(nodes, succ)

    components: list[Component] = []
    for scc in sccs:
        is_recursive = len(scc) > 1 or (len(scc) == 1 and scc[0] in self_loops)
        components.append(Component(members=tuple(scc), is_recursive=is_recursive))

    return AnalysisOrder(
        components=tuple(components),
        unresolved_callers=tuple(sorted(unresolved_set)),
        self_recursive=tuple(sorted(self_loops)),
    )
