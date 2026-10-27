"""Pure mapping: Vivarium ``*Out`` models → memory-graph nodes/edges (ADR-079 §3).

Functional core — no I/O, no SDK, no server. :func:`build_graph` takes a :class:`SessionSources`
bundle (everything the driver pulled from the read-only tools) and returns a de-duplicated
:class:`~vivarium.graph_export.ports.GraphBatch`. Every binary-derived value is unwrapped from its
:class:`~vivarium.core.envelope.Untrusted` wrapper and stored as inert node data tagged with hostile
provenance (``BINARY``/``GHIDRA``/``INFERRED``); secret findings are stored REDACTED (ADR-072),
never the raw value. An out-of-vocabulary emission fails closed with :class:`GraphMapError`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vivarium.core.envelope import Untrusted
from vivarium.graph_export.ports import (
    ADDR_REF,
    EDGE_TYPES,
    LAYERS,
    NODE_KINDS,
    PROVENANCE,
    EdgeSpec,
    GraphBatch,
    LocalId,
    NodeSpec,
)
from vivarium.tools import schemas as s


class GraphMapError(ValueError):
    """A node/edge could not be mapped to a valid memory-graph shape — fail closed, never emit."""


@dataclass(slots=True)
class SessionSources:
    """Everything the driver pulled from one Vivarium session, for the pure mapper to project.

    Every collection defaults empty / ``None`` so the mapper maps exactly what was gathered; a tool
    that was skipped or returned nothing simply contributes no nodes. Per-tool ``truncated`` flags
    are OR-ed onto the ``PROGRAM`` node (honest partial view — ADR-005).
    """

    metadata: s.ProgramMetadata
    fingerprint: s.ProgramFingerprintOut | None = None
    functions: list[s.FunctionSummary] = field(default_factory=list)
    function_details: dict[str, s.FunctionDetail] = field(default_factory=dict)
    complexities: dict[str, int] = field(default_factory=dict)
    function_hashes: dict[str, str] = field(default_factory=dict)
    call_nodes: list[s.CallGraphNode] = field(default_factory=list)
    call_edges: list[s.CallEdge] = field(default_factory=list)
    xrefs: list[s.Xref] = field(default_factory=list)
    imports: list[s.ImportedSymbol] = field(default_factory=list)
    exports: list[s.ExportedSymbol] = field(default_factory=list)
    strings: list[s.DefinedString] = field(default_factory=list)
    iocs: list[s.IocMatch] = field(default_factory=list)
    crypto_constants: list[s.CryptoConstantFinding] = field(default_factory=list)
    crypto_indicators: list[s.CryptoIndicator] = field(default_factory=list)
    secrets: list[s.SecretFinding] = field(default_factory=list)
    capabilities: list[s.CapabilityMatch] = field(default_factory=list)
    family: s.FamilyMatchOut | None = None
    #: Analyst renames, address(hex) → new name (USER/curated overlay).
    renames: dict[str, str] = field(default_factory=dict)
    #: Analyst comments, ``(address_hex, slot, text)`` (USER/curated).
    comments: list[tuple[str, str, str]] = field(default_factory=list)
    #: Analyst composite types, ``(kind, name, fields)`` where ``kind`` is ``"struct"``/``"union"``.
    types: list[tuple[str, str, list[dict[str, Any]]]] = field(default_factory=list)
    #: Per-source truncation flags, OR-ed onto the PROGRAM node.
    truncated: dict[str, bool] = field(default_factory=dict)


# --- helpers ------------------------------------------------------------------------------------


def _addr(value: str | None) -> int | None:
    """Parse a Vivarium hex address (``"0x1000"`` / bare hex) to ``int``; ``None`` if unparsable."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _raw(value: Untrusted[str] | str | None) -> str | None:
    """Unwrap an ``Untrusted[str]`` (or plain str) to its inert payload; ``None`` passes through.

    The dangerous control/bidi/zero-width subset was already neutralized at the ``wrap`` chokepoint
    (ADR-005); the returned text is hostile *data* and is only ever stored as a node name/attr with
    hostile provenance — never executed, rendered, or followed.
    """
    if value is None:
        return None
    if isinstance(value, Untrusted):
        return value.value
    return value


class _Builder:
    """Accumulator that de-duplicates nodes (by local id, merging attrs) and edges (by identity)."""

    def __init__(self) -> None:
        self._nodes: dict[LocalId, NodeSpec] = {}
        self._edges: dict[tuple[str, LocalId, LocalId], EdgeSpec] = {}

    def node(
        self,
        kind: str,
        name: str,
        provenance: str,
        layer: str,
        *,
        address: int | None = None,
        attrs: dict[str, Any] | None = None,
    ) -> NodeSpec:
        """Add or merge a node; later attrs win, a USER/curated name overrides an earlier one."""
        if kind not in NODE_KINDS:
            raise GraphMapError(f"invalid node kind: {kind!r}")
        if provenance not in PROVENANCE:
            raise GraphMapError(f"invalid provenance: {provenance!r}")
        if layer not in LAYERS:
            raise GraphMapError(f"invalid layer: {layer!r}")
        spec = NodeSpec(
            kind=kind,
            name=name,
            provenance=provenance,
            layer=layer,
            address=address,
            attrs=dict(attrs or {}),
        )
        existing = self._nodes.get(spec.local_id)
        if existing is None:
            self._nodes[spec.local_id] = spec
            return spec
        merged_attrs = {**existing.attrs, **spec.attrs}
        # A curated (USER) layer overrides the name; otherwise keep the first name, merge attrs.
        name_out = spec.name if layer == "curated" else existing.name
        prov_out = provenance if layer == "curated" else existing.provenance
        layer_out = layer if layer == "curated" else existing.layer
        merged = NodeSpec(
            kind=existing.kind,
            name=name_out,
            provenance=prov_out,
            layer=layer_out,
            address=existing.address,
            attrs=merged_attrs,
        )
        self._nodes[spec.local_id] = merged
        return merged

    def edge(
        self,
        edge_type: str,
        src: LocalId,
        dst: LocalId,
        provenance: str,
        *,
        attrs: dict[str, Any] | None = None,
    ) -> None:
        """Add an edge, de-duplicated by ``(type, src, dst)``."""
        if edge_type not in EDGE_TYPES:
            raise GraphMapError(f"invalid edge type: {edge_type!r}")
        if provenance not in PROVENANCE:
            raise GraphMapError(f"invalid provenance: {provenance!r}")
        self._edges[(edge_type, src, dst)] = EdgeSpec(
            type=edge_type, src=src, dst=dst, provenance=provenance, attrs=dict(attrs or {})
        )

    def finish(self) -> GraphBatch:
        """Return the accumulated nodes (first-seen order) and edges."""
        return GraphBatch(nodes=list(self._nodes.values()), edges=list(self._edges.values()))


# --- the mapping --------------------------------------------------------------------------------


def build_graph(src: SessionSources) -> GraphBatch:
    """Project a session's gathered facts to a de-duplicated memory-graph batch (ADR-079 §3)."""
    b = _Builder()
    sha = src.metadata.sha256
    program_id: LocalId = ("PROGRAM", sha)
    _add_program(b, src)
    _add_functions(b, src, program_id)
    _add_call_graph(b, src)
    _add_xrefs(b, src)
    _add_imports_exports(b, src, program_id)
    _add_strings(b, src, program_id)
    _add_iocs(b, src)
    _add_crypto(b, src)
    _add_secrets(b, src)
    _add_capabilities(b, src)
    _add_annotations(b, src, program_id)
    return b.finish()


def _add_program(b: _Builder, src: SessionSources) -> None:
    m = src.metadata
    attrs: dict[str, Any] = {
        "sha256": m.sha256,
        "size_bytes": m.size_bytes,
        "format": m.format,
        "architecture": m.architecture,
        "endianness": m.endianness,
        "entry_point": m.entry_point,
        "function_count": m.function_count,
        "analysis_complete": m.analysis_complete,
        "compiler": _raw(m.compiler),  # format-reported → untrusted
        "truncated": any(src.truncated.values()),
    }
    if src.fingerprint is not None:
        fp = src.fingerprint
        attrs["structure_digest"] = fp.structure_digest
        attrs["import_digest"] = fp.import_digest
        attrs["code_ratio"] = fp.coverage.code_ratio
        attrs["data_ratio"] = fp.coverage.data_ratio
    if src.family is not None and src.family.candidates:
        # Cross-binary family links are deferred (ADR-079 §7); store the leads as a PROGRAM attr.
        attrs["family_candidates"] = [
            {"family": c.family, "confidence": c.confidence, "basis": c.basis}
            for c in src.family.candidates
        ]
        attrs["corpus_version"] = src.family.corpus_version
    # PROGRAM name is the sha256 — a safe, server-computed digest (not hostile content).
    b.node("PROGRAM", m.sha256, "BINARY", "raw", attrs=attrs)


def _add_functions(b: _Builder, src: SessionSources, program_id: LocalId) -> None:
    for fn in src.functions:
        addr = _addr(fn.address)
        if addr is None:
            continue  # a function with no parseable entry address cannot be address-keyed — skip
        ghidra_name = _raw(fn.name) or ""
        attrs: dict[str, Any] = {"size": fn.size, "ghidra_name": ghidra_name}
        detail = src.function_details.get(fn.address)
        if detail is not None:
            attrs["signature"] = _raw(detail.signature)
            attrs["is_thunk"] = detail.is_thunk
            attrs["calling_convention"] = _raw(detail.calling_convention)
        if fn.address in src.complexities:
            attrs["complexity"] = src.complexities[fn.address]
        if fn.address in src.function_hashes:
            # The future cross-binary SAME_AS join key (ADR-079 §7) — stored, not yet linked.
            attrs["function_hash"] = src.function_hashes[fn.address]
        rename = src.renames.get(fn.address)
        if rename is not None:
            attrs["renamed"] = True
            b.node("FUNCTION", rename, "USER", "curated", address=addr, attrs=attrs)
        else:
            b.node("FUNCTION", ghidra_name, "GHIDRA", "raw", address=addr, attrs=attrs)
        b.edge("CONTAINS", program_id, ("FUNCTION", addr), "GHIDRA")


def _add_call_graph(b: _Builder, src: SessionSources) -> None:
    # Call-graph nodes may include external/thunk functions not in the list_functions page.
    for node in src.call_nodes:
        addr = _addr(node.address)
        if addr is None:
            continue
        b.node(
            "FUNCTION",
            _raw(node.name) or "",
            "GHIDRA",
            "raw",
            address=addr,
            attrs={"is_external": node.is_external},
        )
    for edge in src.call_edges:
        fr, to = _addr(edge.from_address), _addr(edge.to_address)
        if fr is None or to is None:
            continue
        b.edge("CALLS", (ADDR_REF, fr), (ADDR_REF, to), "GHIDRA")


def _add_xrefs(b: _Builder, src: SessionSources) -> None:
    for xref in src.xrefs:
        fr, to = _addr(xref.from_address), _addr(xref.to_address)
        if fr is None or to is None:
            continue
        b.edge("XREF", (ADDR_REF, fr), (ADDR_REF, to), "GHIDRA", attrs={"ref_type": xref.ref_type})


def _add_imports_exports(b: _Builder, src: SessionSources, program_id: LocalId) -> None:
    for imp in src.imports:
        name = _raw(imp.name) or ""
        addr = _addr(imp.address)
        attrs: dict[str, Any] = {"library": _raw(imp.library)}
        node = b.node("IMPORT", name, "GHIDRA", "raw", address=addr, attrs=attrs)
        b.edge("IMPORTS", program_id, node.local_id, "GHIDRA")
    for exp in src.exports:
        addr = _addr(exp.address)
        node = b.node("EXPORT", _raw(exp.name) or "", "GHIDRA", "raw", address=addr)
        b.edge("EXPORTS", program_id, node.local_id, "GHIDRA")


def _add_strings(b: _Builder, src: SessionSources, program_id: LocalId) -> None:
    for st in src.strings:
        addr = _addr(st.address)
        node = b.node(
            "STRING",
            _raw(st.value) or "",
            "BINARY",
            "raw",
            address=addr,
            attrs={"length": st.length},
        )
        b.edge("CONTAINS", program_id, node.local_id, "BINARY")


def _add_iocs(b: _Builder, src: SessionSources) -> None:
    for ioc in src.iocs:
        value = _raw(ioc.value) or ""
        node = b.node("IOC", value, "INFERRED", "inferred", attrs={"category": ioc.category})
        addr = _addr(ioc.source_address)
        if addr is not None:
            b.edge("REFERENCES", node.local_id, (ADDR_REF, addr), "INFERRED")


def _add_crypto(b: _Builder, src: SessionSources) -> None:
    for cc in src.crypto_constants:
        addr = _addr(cc.address)
        if addr is None:
            continue
        b.node(
            "CONSTANT",
            cc.algorithm,
            "INFERRED",
            "inferred",
            address=addr,
            attrs={"algorithm": cc.algorithm, "kind": cc.kind, "source": "constant_scan"},
        )
    for ind in src.crypto_indicators:
        addr = _addr(ind.address)
        detail = _raw(ind.detail) or ""
        attrs = {
            "kind": ind.kind,
            "source": ind.source,
            "detail": detail,
            "confidence": ind.confidence,
        }
        if addr is not None:
            b.node("CONSTANT", ind.kind, "INFERRED", "inferred", address=addr, attrs=attrs)
        else:
            # Addressless indicator (e.g. api_name with no address) — key by detail string.
            b.node("CONSTANT", f"{ind.kind}:{detail}", "INFERRED", "inferred", attrs=attrs)


def _add_secrets(b: _Builder, src: SessionSources) -> None:
    for sec in src.secrets:
        # REDACTED (ADR-072): never the raw value — masked preview + salted hash only. Fail closed.
        attrs = {
            "category": sec.category,
            "pattern_id": sec.pattern_id,
            "masked_preview": _raw(sec.masked_preview),
            "preview_hash": sec.preview_hash,
            "entropy": sec.entropy,
        }
        addr = _addr(sec.address)
        if addr is not None:
            b.node("SECRET", sec.pattern_id, "INFERRED", "inferred", address=addr, attrs=attrs)
        else:
            b.node(
                "SECRET",
                f"{sec.pattern_id}:{sec.preview_hash}",
                "INFERRED",
                "inferred",
                attrs=attrs,
            )


def _add_capabilities(b: _Builder, src: SessionSources) -> None:
    for cap in src.capabilities:
        attrs: dict[str, Any] = {
            "rule_id": cap.rule_id,
            "name": cap.name,
            "namespace": cap.namespace,
            "confidence": cap.confidence,
            "attack": [{"tactic": t.tactic, "technique_id": t.technique_id} for t in cap.attack],
        }
        node = b.node("VULN", cap.name, "INFERRED", "inferred", attrs=attrs)
        for ev in cap.evidence:
            addr = _addr(ev.address)
            if addr is not None:
                b.edge(
                    "REFERENCES",
                    node.local_id,
                    (ADDR_REF, addr),
                    "INFERRED",
                    attrs={"where": ev.where, "detail": _raw(ev.detail)},
                )


def _add_annotations(b: _Builder, src: SessionSources, program_id: LocalId) -> None:
    for address, slot, text in src.comments:
        addr = _addr(address)
        if addr is None:
            continue
        # Comment identity is addr+slot; its text is analyst-authored (USER), stored as data.
        node = b.node(
            "COMMENT",
            f"{address}:{slot}",
            "USER",
            "curated",
            attrs={"slot": slot, "text": text, "address": address},
        )
        b.edge("ANNOTATES", node.local_id, (ADDR_REF, addr), "USER")
    for kind, name, fields in src.types:
        node_kind = "UNION" if kind == "union" else "STRUCT"
        b.node(node_kind, name, "USER", "curated", attrs={"fields": fields})
        b.edge("CONTAINS", program_id, (node_kind, name), "USER")
