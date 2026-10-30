"""Ports and value objects for the memory-graph exporter (ADR-079).

The exporter is ports & adapters (``topic-architecture-patterns``): the pure mapper emits
:class:`NodeSpec` / :class:`EdgeSpec` value objects; the driver pushes them through a
:class:`GraphSink` and pulls source facts through a :class:`ToolCaller`. The adapters (live MCP
clients) and the tests (in-memory fakes) implement the two protocols.

The memory-graph vocabulary (node kinds, edge types, provenance, layers) is mirrored here as frozen
allow-lists so the mapper **fails closed** on an out-of-vocabulary emission rather than letting an
invalid node/edge reach the store (CWE-20 at the boundary).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# --- memory-graph vocabulary (mirror of mg_schema; the exporter's allow-lists) ------------------

#: Node kinds the exporter emits (a subset of the memory-graph ``kinds`` vocabulary).
NODE_KINDS: frozenset[str] = frozenset(
    {
        "PROGRAM",
        "FUNCTION",
        "STRING",
        "IMPORT",
        "EXPORT",
        "IOC",
        "CONSTANT",
        "SECRET",
        "VULN",
        "COMMENT",
        "STRUCT",
        "UNION",
    }
)

#: Edge types the exporter emits (a subset of the memory-graph ``edge_types`` vocabulary).
EDGE_TYPES: frozenset[str] = frozenset(
    {
        "CONTAINS",
        "CALLS",
        "XREF",
        "REFERENCES",
        "IMPORTS",
        "EXPORTS",
        "ANNOTATES",
    }
)

#: Provenance labels (mg ``provenance``): where the fact ultimately came from.
PROVENANCE: frozenset[str] = frozenset({"BINARY", "GHIDRA", "INFERRED", "USER"})

#: Layers (mg ``layers``): ``raw`` = direct extraction, ``inferred`` = heuristic scanner leads,
#: ``curated`` = analyst annotations (ADR-079 §3.1).
LAYERS: frozenset[str] = frozenset({"raw", "inferred", "curated"})

#: Sentinel local-id kind meaning "resolve this endpoint against the address index, not the
#: local-id index" — used for CALLS / XREF edges whose endpoints are referenced purely by address.
ADDR_REF: str = "@ADDR"

#: A node's stable local identity within one export: ``(kind, address_int | value_str)``. The driver
#: maps it to the memory-graph key returned by the upsert, so edges never guess key derivation.
LocalId = tuple[str, int | str]


@dataclass(frozen=True, slots=True)
class NodeSpec:
    """One memory-graph node to upsert — a pure value object (no I/O).

    Attributes:
        kind: memory-graph node kind (must be in :data:`NODE_KINDS`).
        name: The node name. For binary-derived nodes this is hostile content stored as inert data;
            ``provenance`` marks it so no consumer executes/renders/follows it (ADR-005).
        provenance: One of :data:`PROVENANCE`.
        layer: One of :data:`LAYERS`.
        address: Integer address for addressable nodes (functions, strings, …), else ``None``.
        attrs: Extra scalar attributes (also inert data when binary-derived).
    """

    kind: str
    name: str
    provenance: str
    layer: str
    address: int | None = None
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def local_id(self) -> LocalId:
        """Stable within-export identity: by address when addressable, else by (kind, name)."""
        if self.address is not None:
            return (self.kind, self.address)
        return (self.kind, self.name)


@dataclass(frozen=True, slots=True)
class EdgeSpec:
    """One memory-graph edge to upsert — a pure value object (no I/O).

    Endpoints are :data:`LocalId` references the driver resolves to memory-graph keys after the
    nodes are upserted. An endpoint whose ``kind`` is :data:`ADDR_REF` resolves against the address
    index
    (any node at that address); otherwise it resolves against the local-id index. An endpoint that
    resolves to nothing causes the edge to be skipped (counted, never fabricated).

    Attributes:
        type: memory-graph edge type (must be in :data:`EDGE_TYPES`).
        src: Source endpoint local id.
        dst: Destination endpoint local id.
        provenance: One of :data:`PROVENANCE`.
        attrs: Extra scalar attributes for the edge.
    """

    type: str
    src: LocalId
    dst: LocalId
    provenance: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GraphBatch:
    """The mapped result of a session: nodes then edges, de-duplicated by identity.

    Nodes are de-duplicated by :attr:`NodeSpec.local_id` (last write wins, so a USER rename overlay
    applied after the GHIDRA node updates its name — ADR-079 §3.1). Edges are de-duplicated by
    ``(type, src, dst)``.
    """

    nodes: list[NodeSpec] = field(default_factory=list)
    edges: list[EdgeSpec] = field(default_factory=list)


@runtime_checkable
class ToolCaller(Protocol):
    """The Vivarium read-only source port: name a tool, pass validated args, get its typed result.

    Adapters: the live ADR-076 ``McpToolCaller`` (an MCP client to a Vivarium server); tests use an
    in-memory fake backed by canned ``*Out`` models. The driver depends only on this protocol, never
    on a concrete transport (ADR-001: the server stays a pure source).
    """

    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """Invoke a read-only Vivarium tool and return its raw result payload."""
        ...


@runtime_checkable
class GraphSink(Protocol):
    """The memory-graph destination port: open/resolve a project, upsert nodes and edges.

    Adapters: a live MCP client to the ``memory-graph`` server; tests use an in-memory fake. Writing
    is a gated, outward action (ADR-079 §5 / ``workflow-gated-actions``) — the adapter is only
    constructed once that gate is cleared.
    """

    def ensure_project(self, name: str, description: str) -> str:
        """Resolve the project named ``name`` (create if absent); return its id. Idempotent."""
        ...

    def upsert_nodes(self, project_id: str, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Upsert nodes; return per-node ``{"key": ...}`` records in input order."""
        ...

    def upsert_edges(self, project_id: str, edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Upsert edges keyed by ``src_key`` / ``dst_key``; return per-edge records."""
        ...
