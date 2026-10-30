"""Export a Vivarium reverse-engineering session to the ``memory-graph`` knowledge graph (ADR-079).

Client-side only: the Vivarium server never calls out (ADR-001). This package is a pure consumer of
the existing read-only tools — a functional-core mapper (:mod:`vivarium.graph_export.mapper`) over
the tool output models, driven by the imperative shell (:mod:`vivarium.graph_export.driver`) through
the :class:`~vivarium.graph_export.ports.ToolCaller` /
:class:`~vivarium.graph_export.ports.GraphSink` ports. All binary-derived content crosses the
boundary as inert data tagged with hostile provenance
(ADR-005); secret findings stay redacted (ADR-072).
"""

from vivarium.graph_export.driver import ExportOptions, ExportStats, export_session
from vivarium.graph_export.ports import EdgeSpec, GraphSink, NodeSpec, ToolCaller

__all__ = [
    "EdgeSpec",
    "ExportOptions",
    "ExportStats",
    "GraphSink",
    "NodeSpec",
    "ToolCaller",
    "export_session",
]
