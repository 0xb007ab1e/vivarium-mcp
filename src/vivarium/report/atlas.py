"""Whole-program atlas composition (ADR-078 Tier-1, TB10) — model (B) over (C)-projected leaves.

Composes the outputs of the existing read-only tools — ``program_summary``, ``call_graph``
(whole-program, bounded), and ``list_functions`` — into a bounded ``AtlasData`` structure (see
:mod:`vivarium.tools.schemas`). No new worker capability and no new analysis path (ADR-001/078): the
handler fetches these by reusing the sibling tool handlers (like Tier-0 reused the export tool), and
this module only projects + bounds their already-``Untrusted``-wrapped outputs.

The (C)-projection surface is small and uniform: every binary-derived ``name`` leaf
(``CallGraphNode``/``FunctionSummary``) and the format-reported ``compiler`` are projected and
re-wrapped ``Untrusted`` (ADR-005). Addresses, counts, and closed-vocabulary strings (format,
architecture, endianness) are server-safe scalars and pass through. Runs server-side at the output
edge, never in the worker, never a write primitive.
"""

from __future__ import annotations

from vivarium.core.envelope import DataOrigin, Untrusted, wrap
from vivarium.report.projection import project_identifier, project_string
from vivarium.tools.schemas import (
    AtlasData,
    AtlasEdge,
    AtlasFunction,
    AtlasNode,
    AtlasSummary,
    CallGraphOut,
    FunctionListOut,
    ProgramSummary,
)

__all__ = ["compose_atlas"]


def _wname(name: Untrusted[str]) -> Untrusted[str]:
    """Project a binary-derived identifier leaf (C) and re-wrap ``Untrusted`` (ADR-005)."""
    return wrap(project_identifier(name.value), origin=DataOrigin.GHIDRA)


def _wcompiler(compiler: Untrusted[str] | None) -> Untrusted[str] | None:
    """Project the free-text compiler string to its escaped preview and re-wrap, or ``None``."""
    if compiler is None:
        return None
    return wrap(project_string(compiler.value).preview, origin=DataOrigin.GHIDRA)


def compose_atlas(
    summary: ProgramSummary,
    graph: CallGraphOut,
    functions: FunctionListOut,
    *,
    max_nodes: int,
    max_edges: int,
    max_functions: int,
) -> AtlasData:
    """Compose a bounded whole-program atlas from reused read-only tool outputs (ADR-078 Tier-1).

    Args:
        summary: The ``program_summary`` output (cover-page metadata + counts + metrics).
        graph: The whole-program ``call_graph`` output (bounded adjacency).
        functions: The ``list_functions`` inventory output.
        max_nodes: Cap on call-graph nodes rendered (DoS guard — CWE-400).
        max_edges: Cap on call-graph edges rendered.
        max_functions: Cap on function-inventory rows rendered.

    Returns:
        The projected, bounded :class:`AtlasData`; ``truncated`` is set if any source was capped
        (here or already in the tool outputs).
    """
    md = summary.metadata
    metrics = summary.call_graph_metrics
    atlas_summary = AtlasSummary(
        program_sha256=md.sha256,
        format=md.format,
        architecture=md.architecture,
        endianness=md.endianness,
        size_bytes=md.size_bytes,
        entry_point=md.entry_point,
        compiler=_wcompiler(md.compiler),
        function_count=summary.function_count,
        import_count=summary.import_count,
        export_count=summary.export_count,
        string_count=summary.string_count,
        leaf_count=metrics.leaf_count if metrics is not None else None,
        root_count=metrics.root_count if metrics is not None else None,
        recursive_component_count=(
            metrics.recursive_component_count if metrics is not None else None
        ),
        unresolved_caller_count=(metrics.unresolved_caller_count if metrics is not None else None),
    )

    nodes = [
        AtlasNode(
            address=n.address,
            name=_wname(n.name),
            is_external=n.is_external,
            has_unresolved_calls=n.has_unresolved_calls,
        )
        for n in graph.nodes[:max_nodes]
    ]
    edges = [
        AtlasEdge(from_address=e.from_address, to_address=e.to_address)
        for e in graph.edges[:max_edges]
    ]
    atlas_functions = [
        AtlasFunction(address=f.address, name=_wname(f.name), size=f.size)
        for f in functions.functions[:max_functions]
    ]

    truncated = (
        graph.truncated
        or functions.truncated
        or len(graph.nodes) > max_nodes
        or len(graph.edges) > max_edges
        or len(functions.functions) > max_functions
    )
    return AtlasData(
        summary=atlas_summary,
        nodes=nodes,
        edges=edges,
        functions=atlas_functions,
        truncated=truncated,
    )
