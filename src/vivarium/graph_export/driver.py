"""Imperative shell: pull a Vivarium session, map it, push to memory-graph (ADR-079 §2).

Holds no mapping logic — it gathers the read-only tool output into a
:class:`~vivarium.graph_export.mapper.SessionSources`, calls the pure
:func:`~vivarium.graph_export.mapper.build_graph`, then resolves and upserts the batch through a
:class:`~vivarium.graph_export.ports.GraphSink`. Edge endpoints are resolved to memory-graph keys
*after* the nodes are upserted (never by guessing key derivation); an endpoint that resolves to no
node skips its edge (counted, never fabricated). Every source tool is already bounded; the driver
walks pagination to an explicit per-kind ceiling and surfaces truncation onto the PROGRAM node.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from vivarium.graph_export.mapper import SessionSources, build_graph
from vivarium.graph_export.ports import ADDR_REF, GraphBatch, GraphSink, ToolCaller
from vivarium.tools import schemas as s

_log = logging.getLogger("vivarium.graph_export")

#: memory-graph upsert chunk size (bounds a single write — CWE-400).
_CHUNK = 500


@dataclass(slots=True)
class ExportOptions:
    """Per-kind ceilings and toggles bounding one export (ADR-079 §4)."""

    page_size: int = 1000
    max_functions: int = 50_000
    max_strings: int = 50_000
    max_imports: int = 10_000
    max_exports: int = 10_000
    max_iocs: int = 20_000
    max_crypto: int = 20_000
    max_secrets: int = 10_000
    max_capabilities: int = 10_000
    max_call_nodes: int = 50_000
    max_call_edges: int = 200_000
    max_xref_targets: int = 256
    max_xrefs_per_target: int = 256
    #: Per-function deep enrichment (get_function + complexity + function_hash) is N calls per
    #: function — off by default, bounded by ``max_enrich_functions`` when on.
    enrich_functions: bool = False
    max_enrich_functions: int = 2000


@dataclass(slots=True)
class ExportStats:
    """Outcome of one export — safe scalars only (no binary-derived content)."""

    project_id: str
    project_name: str
    nodes_total: int = 0
    nodes_created: int = 0
    edges_total: int = 0
    edges_created: int = 0
    edges_skipped: int = 0
    failed_tools: list[str] = field(default_factory=list)


# --- gather (pull) ------------------------------------------------------------------------------


def gather_sources(
    caller: ToolCaller, session_id: str, opts: ExportOptions
) -> tuple[SessionSources, list[str]]:
    """Pull every read-only tool for ``session_id`` into a :class:`SessionSources` bundle.

    ``program_metadata`` is mandatory (identifies the binary); every other tool is best-effort — a
    failure is logged and returned in the ``failed`` list (also recorded in
    :attr:`ExportStats.failed_tools`), never fatal, so a partial graph still lands. Each list tool
    is walked to its per-kind ceiling. Returns the bundle and the list of tools that failed.
    """
    failed: list[str] = []
    meta = _parse(caller, "program_metadata", {"session_id": session_id}, s.ProgramMetadata)
    src = SessionSources(metadata=meta)

    fp = _safe(
        caller, "program_fingerprint", {"session_id": session_id}, s.ProgramFingerprintOut, failed
    )
    src.fingerprint = fp
    if fp is not None:
        src.truncated["coverage"] = False

    src.functions = _paginate(
        caller,
        "list_functions",
        {"session_id": session_id},
        "functions",
        s.FunctionSummary,
        opts.max_functions,
        opts,
        failed,
        src.truncated,
        "functions",
    )

    cg = _safe(
        caller,
        "call_graph",
        {
            "session_id": session_id,
            "max_nodes": opts.max_call_nodes,
            "max_edges": opts.max_call_edges,
        },
        s.CallGraphOut,
        failed,
    )
    if cg is not None:
        src.call_nodes = cg.nodes
        src.call_edges = cg.edges
        src.truncated["call_graph"] = cg.truncated

    _gather_xrefs(caller, session_id, opts, src, failed)

    src.imports = _paginate(
        caller,
        "list_imports",
        {"session_id": session_id},
        "imports",
        s.ImportedSymbol,
        opts.max_imports,
        opts,
        failed,
        src.truncated,
        "imports",
    )
    src.exports = _paginate(
        caller,
        "list_exports",
        {"session_id": session_id},
        "exports",
        s.ExportedSymbol,
        opts.max_exports,
        opts,
        failed,
        src.truncated,
        "exports",
    )
    src.strings = _paginate(
        caller,
        "list_strings",
        {"session_id": session_id},
        "strings",
        s.DefinedString,
        opts.max_strings,
        opts,
        failed,
        src.truncated,
        "strings",
    )
    src.iocs = _paginate(
        caller,
        "ioc_scan",
        {"session_id": session_id},
        "matches",
        s.IocMatch,
        opts.max_iocs,
        opts,
        failed,
        src.truncated,
        "iocs",
    )
    src.crypto_constants = _paginate(
        caller,
        "crypto_constant_scan",
        {"session_id": session_id},
        "findings",
        s.CryptoConstantFinding,
        opts.max_crypto,
        opts,
        failed,
        src.truncated,
        "crypto_constants",
    )
    src.crypto_indicators = _paginate(
        caller,
        "crypto_detect",
        {"session_id": session_id},
        "indicators",
        s.CryptoIndicator,
        opts.max_crypto,
        opts,
        failed,
        src.truncated,
        "crypto_indicators",
    )
    src.secrets = _paginate(
        caller,
        "secret_scan",
        {"session_id": session_id},
        "findings",
        s.SecretFinding,
        opts.max_secrets,
        opts,
        failed,
        src.truncated,
        "secrets",
    )
    src.capabilities = _paginate(
        caller,
        "capability_scan",
        {"session_id": session_id},
        "capabilities",
        s.CapabilityMatch,
        opts.max_capabilities,
        opts,
        failed,
        src.truncated,
        "capabilities",
    )
    src.family = _safe(caller, "family_match", {"session_id": session_id}, s.FamilyMatchOut, failed)

    if opts.enrich_functions:
        _enrich_functions(caller, session_id, opts, src, failed)
    _gather_annotations(caller, session_id, src, failed)

    src.truncated["_failed_tools"] = bool(failed)
    _log.info(
        "graph_export.gather",
        extra={
            "session": session_id,
            "functions": len(src.functions),
            "strings": len(src.strings),
            "failed_tools": failed,
        },
    )
    return src, failed


def _gather_xrefs(
    caller: ToolCaller,
    session_id: str,
    opts: ExportOptions,
    src: SessionSources,
    failed: list[str],
) -> None:
    """Pull xrefs for the most-referenced functions (bounded — ADR-078 atlas pattern)."""
    metrics = _safe(
        caller,
        "call_graph_metrics",
        {"session_id": session_id, "top_n": opts.max_xref_targets},
        s.CallGraphMetricsOut,
        failed,
    )
    if metrics is None:
        return
    xrefs: list[s.Xref] = []
    for ranking in metrics.top_fan_in[: opts.max_xref_targets]:
        page = _safe(
            caller,
            "xrefs_to",
            {
                "session_id": session_id,
                "target": ranking.address,
                "limit": opts.max_xrefs_per_target,
            },
            s.XrefsOut,
            failed,
        )
        if page is not None:
            xrefs.extend(page.xrefs)
    src.xrefs = xrefs


def _enrich_functions(
    caller: ToolCaller,
    session_id: str,
    opts: ExportOptions,
    src: SessionSources,
    failed: list[str],
) -> None:
    """Per-function deep enrichment (detail + complexity + hash), bounded by the enrich cap."""
    for fn in src.functions[: opts.max_enrich_functions]:
        args = {"session_id": session_id, "function": fn.address}
        detail = _safe(caller, "get_function", args, s.FunctionDetail, failed)
        if detail is not None:
            src.function_details[fn.address] = detail
        cx = _safe(caller, "cyclomatic_complexity", args, s.CyclomaticComplexity, failed)
        if cx is not None:
            src.complexities[fn.address] = cx.complexity
        fh = _safe(caller, "function_hash", args, s.FunctionHashOut, failed)
        if fh is not None:
            # Operand-masked hash = the cross-binary clone / SAME_AS key (ADR-079 §7, deferred).
            src.function_hashes[fn.address] = fh.exact_instructions


def _gather_annotations(
    caller: ToolCaller,
    session_id: str,
    src: SessionSources,
    failed: list[str],
) -> None:
    """Pull user annotations and project them into renames / comments / types."""
    try:
        payload = caller.call("session_export_annotations", {"session_id": session_id})
    except Exception as exc:
        _log.warning(
            "graph_export.tool_failed",
            extra={"tool": "session_export_annotations", "error": str(exc)},
        )
        failed.append("session_export_annotations")
        return
    document = payload.get("document", payload) if isinstance(payload, dict) else {}
    entries = document.get("entries", []) if isinstance(document, dict) else []
    for entry in entries:
        if isinstance(entry, dict):
            _apply_annotation_entry(entry, src)


def _apply_annotation_entry(entry: dict[str, Any], src: SessionSources) -> None:
    """Project one exported-annotation entry into the renames / comments / types collections."""
    kind = entry.get("kind")
    if kind in ("rename_function", "rename_symbol"):
        addr = entry.get("function" if kind == "rename_function" else "identifier")
        if isinstance(addr, str):
            src.renames[addr] = _unwrap(entry.get("new_name")) or ""
    elif kind == "set_comment":
        addr = entry.get("address")
        if isinstance(addr, str):
            src.comments.append(
                (addr, str(entry.get("comment_type", "")), _unwrap(entry.get("text")) or "")
            )
    elif kind == "define_types":
        for spec in entry.get("types", []) or []:
            if isinstance(spec, dict) and isinstance(spec.get("name"), str):
                src.types.append(
                    (str(spec.get("kind", "struct")), spec["name"], list(spec.get("fields", [])))
                )


# --- push (map + resolve + upsert) --------------------------------------------------------------


def push_batch(
    sink: GraphSink,
    batch: GraphBatch,
    *,
    program_sha256: str,
    binary_label: str,
) -> ExportStats:
    """Upsert a mapped batch into the per-binary memory-graph project (idempotent).

    Nodes are upserted first (chunked); their returned keys build a local-id index and an address
    index, against which edge endpoints are resolved (``ADDR_REF`` endpoints via the address index).
    Edges whose endpoints do not both resolve are skipped and counted — never fabricated.
    """
    name = f"vivarium-{program_sha256[:12]}"
    project_id = sink.ensure_project(
        name, f"Vivarium RE export of {binary_label} ({program_sha256})"
    )
    stats = ExportStats(project_id=project_id, project_name=name)

    id_index, addr_index = _upsert_nodes(sink, project_id, batch, stats)
    edge_payloads = _resolve_edges(batch, id_index, addr_index, stats)
    for chunk in _chunks(edge_payloads, _CHUNK):
        for result in sink.upsert_edges(project_id, chunk):
            stats.edges_total += 1
            if result.get("created"):
                stats.edges_created += 1
    _log.info(
        "graph_export.push",
        extra={
            "project": name,
            "nodes": stats.nodes_total,
            "edges": stats.edges_total,
            "skipped": stats.edges_skipped,
        },
    )
    return stats


def export_session(
    caller: ToolCaller,
    sink: GraphSink,
    session_id: str,
    *,
    binary_label: str = "",
    opts: ExportOptions | None = None,
) -> ExportStats:
    """Gather, map, and push one Vivarium session to its memory-graph project (ADR-079)."""
    options = opts or ExportOptions()
    src, failed = gather_sources(caller, session_id, options)
    batch = build_graph(src)
    stats = push_batch(
        sink,
        batch,
        program_sha256=src.metadata.sha256,
        binary_label=binary_label or src.metadata.format,
    )
    stats.failed_tools = failed
    return stats


def _upsert_nodes(
    sink: GraphSink, project_id: str, batch: GraphBatch, stats: ExportStats
) -> tuple[dict[tuple[str, int | str], str], dict[int, str]]:
    """Upsert nodes (chunked) and build the local-id + address indexes from the returned keys."""
    id_index: dict[tuple[str, int | str], str] = {}
    addr_index: dict[int, str] = {}
    for chunk in _chunks(batch.nodes, _CHUNK):
        payload = [_node_dict(n) for n in chunk]
        results = sink.upsert_nodes(project_id, payload)
        for node, result in zip(chunk, results, strict=False):
            key = result.get("key")
            if not isinstance(key, str):
                continue
            id_index[node.local_id] = key
            if node.address is not None:
                addr_index[node.address] = key
            stats.nodes_total += 1
            if result.get("created"):
                stats.nodes_created += 1
    return id_index, addr_index


def _resolve_edges(
    batch: GraphBatch,
    id_index: dict[tuple[str, int | str], str],
    addr_index: dict[int, str],
    stats: ExportStats,
) -> list[dict[str, Any]]:
    """Resolve each edge's endpoints to keys; skip (and count) any that does not fully resolve."""
    payloads: list[dict[str, Any]] = []
    for edge in batch.edges:
        src_key = _resolve(edge.src, id_index, addr_index)
        dst_key = _resolve(edge.dst, id_index, addr_index)
        if src_key is None or dst_key is None:
            stats.edges_skipped += 1
            continue
        payloads.append(
            {
                "type": edge.type,
                "src_key": src_key,
                "dst_key": dst_key,
                "provenance": edge.provenance,
                "attrs": edge.attrs,
            }
        )
    return payloads


# --- helpers ------------------------------------------------------------------------------------


def _node_dict(node: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "kind": node.kind,
        "name": node.name,
        "provenance": node.provenance,
        "layer": node.layer,
        "attrs": node.attrs,
    }
    if node.address is not None:
        out["address"] = node.address
    return out


def _resolve(
    endpoint: tuple[str, int | str],
    id_index: dict[tuple[str, int | str], str],
    addr_index: dict[int, str],
) -> str | None:
    if endpoint[0] == ADDR_REF:
        raw = endpoint[1]
        return addr_index.get(raw) if isinstance(raw, int) else None
    return id_index.get(endpoint)


def _chunks[T](items: list[T], size: int) -> Iterator[list[T]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _unwrap(value: Any) -> str | None:
    """Unwrap an exported-document value field (``{"value": ...}`` or a bare str)."""
    if isinstance(value, dict):
        inner = value.get("value")
        return inner if isinstance(inner, str) else None
    return value if isinstance(value, str) else None


def _parse[M: BaseModel](caller: ToolCaller, tool: str, args: dict[str, Any], model: type[M]) -> M:
    """Call a (mandatory) tool and validate its payload into ``model``."""
    return model.model_validate(caller.call(tool, args))


def _safe[M: BaseModel](
    caller: ToolCaller,
    tool: str,
    args: dict[str, Any],
    model: type[M],
    failed: list[str],
) -> M | None:
    """Best-effort call: validate on success; on any error log, record, and return ``None``."""
    try:
        return model.model_validate(caller.call(tool, args))
    except Exception as exc:
        _log.warning("graph_export.tool_failed", extra={"tool": tool, "error": str(exc)})
        failed.append(tool)
        return None


def _paginate[M: BaseModel](
    caller: ToolCaller,
    tool: str,
    base_args: dict[str, Any],
    list_key: str,
    item: type[M],
    cap: int,
    opts: ExportOptions,
    failed: list[str],
    truncated: dict[str, bool],
    trunc_key: str,
) -> list[M]:
    """Walk a paginated list tool to ``cap``; set ``truncated[trunc_key]`` if the cap clipped it."""
    out: list[M] = []
    offset = 0
    while len(out) < cap:
        limit = min(opts.page_size, cap - len(out))
        args = {**base_args, "offset": offset, "limit": limit}
        try:
            payload = caller.call(tool, args)
        except Exception as exc:
            _log.warning("graph_export.tool_failed", extra={"tool": tool, "error": str(exc)})
            failed.append(tool)
            break
        rows = payload.get(list_key, []) if isinstance(payload, dict) else []
        if not rows:
            break
        out.extend(item.model_validate(r) for r in rows[:limit])
        if len(rows) < limit:
            if payload.get("truncated"):
                truncated[trunc_key] = True
            break
        offset += limit
    else:
        truncated[trunc_key] = True
    return out
