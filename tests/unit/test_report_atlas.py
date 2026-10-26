"""Unit tests for ADR-078 Tier-1 atlas composition (``vivarium.report.atlas``)."""

from __future__ import annotations

from typing import TypedDict

from vivarium.core.envelope import DataOrigin, Untrusted, wrap
from vivarium.report.atlas import compose_atlas
from vivarium.tools import schemas as s


class _Caps(TypedDict):
    max_nodes: int
    max_edges: int
    max_functions: int


def _u(value: str) -> Untrusted[str]:
    return wrap(value, origin=DataOrigin.BINARY)


def _meta(compiler: str | None = None) -> s.ProgramMetadata:
    return s.ProgramMetadata(
        sha256="a" * 64,
        size_bytes=1024,
        format="ELF",
        architecture="x86:LE:64:default",
        endianness="little",
        compiler=_u(compiler) if compiler is not None else None,
        entry_point="0x401000",
        function_count=3,
        analysis_complete=True,
    )


def _metrics() -> s.CallGraphMetricsOut:
    return s.CallGraphMetricsOut(
        function_count=3,
        edge_count=2,
        leaf_count=1,
        root_count=1,
        recursive_component_count=0,
        self_recursive_count=0,
        unresolved_caller_count=2,
        top_fan_in=[],
        top_fan_out=[],
    )


def _summary(
    metrics: s.CallGraphMetricsOut | None = None, compiler: str | None = None
) -> s.ProgramSummary:
    return s.ProgramSummary(
        metadata=_meta(compiler),
        function_count=3,
        import_count=1,
        export_count=0,
        string_count=5,
        call_graph_metrics=metrics,
    )


def _node(addr: str, name: str, ext: bool = False, unres: bool = False) -> s.CallGraphNode:
    return s.CallGraphNode(address=addr, name=_u(name), is_external=ext, has_unresolved_calls=unres)


def _graph(
    nodes: list[s.CallGraphNode], edges: list[s.CallEdge], truncated: bool = False
) -> s.CallGraphOut:
    return s.CallGraphOut(nodes=nodes, edges=edges, unresolved_callers=[], truncated=truncated)


def _funcs(funcs: list[s.FunctionSummary], truncated: bool = False) -> s.FunctionListOut:
    return s.FunctionListOut(functions=funcs, total=len(funcs), truncated=truncated)


_CAPS: _Caps = {"max_nodes": 100, "max_edges": 100, "max_functions": 100}


def test_summary_counts_and_metrics_surfaced() -> None:
    atlas = compose_atlas(_summary(_metrics()), _graph([], []), _funcs([]), **_CAPS)
    assert atlas.summary.program_sha256 == "a" * 64
    assert atlas.summary.function_count == 3
    assert atlas.summary.leaf_count == 1
    assert atlas.summary.unresolved_caller_count == 2


def test_metrics_absent_leaves_none() -> None:
    atlas = compose_atlas(_summary(None), _graph([], []), _funcs([]), **_CAPS)
    assert atlas.summary.leaf_count is None
    assert atlas.summary.root_count is None


def test_node_and_function_names_projected_and_wrapped() -> None:
    graph = _graph([_node("0x401000", "<img src=x onerror=alert(1)>")], [])
    funcs = _funcs([s.FunctionSummary(address="0x401000", name=_u("](javascript:evil)"), size=16)])
    atlas = compose_atlas(_summary(), graph, funcs, **_CAPS)
    # leaves are Untrusted-wrapped AND (C)-projected (no active markup bytes survive)
    assert isinstance(atlas.nodes[0].name, Untrusted)
    assert "<" not in atlas.nodes[0].name.value and ">" not in atlas.nodes[0].name.value
    fn_name = atlas.functions[0].name.value
    for ch in "]():":
        assert ch not in fn_name


def test_compiler_projected() -> None:
    atlas = compose_atlas(_summary(compiler="gcc<b>"), _graph([], []), _funcs([]), **_CAPS)
    assert atlas.summary.compiler is not None
    assert "<" not in atlas.summary.compiler.value


def test_edges_pass_through_addresses() -> None:
    edges = [s.CallEdge(from_address="0x401000", to_address="0x401100")]
    atlas = compose_atlas(_summary(), _graph([], edges), _funcs([]), **_CAPS)
    assert atlas.edges[0].from_address == "0x401000"
    assert atlas.edges[0].to_address == "0x401100"


def test_caps_bound_and_flag_truncation() -> None:
    nodes = [_node(f"0x{i:x}", f"fn_{i}") for i in range(10)]
    edges = [s.CallEdge(from_address="0x0", to_address=f"0x{i:x}") for i in range(10)]
    funcs = [s.FunctionSummary(address=f"0x{i:x}", name=_u(f"fn_{i}"), size=4) for i in range(10)]
    atlas = compose_atlas(
        _summary(), _graph(nodes, edges), _funcs(funcs), max_nodes=3, max_edges=4, max_functions=2
    )
    assert len(atlas.nodes) == 3
    assert len(atlas.edges) == 4
    assert len(atlas.functions) == 2
    assert atlas.truncated is True


def test_source_truncation_propagates() -> None:
    atlas = compose_atlas(_summary(), _graph([], [], truncated=True), _funcs([]), **_CAPS)
    assert atlas.truncated is True


def _xref(frm: str, to: str, ref_type: str = "CALL") -> s.Xref:
    return s.Xref(from_address=frm, to_address=to, ref_type=ref_type)


def test_xrefs_absent_default_empty() -> None:
    atlas = compose_atlas(_summary(), _graph([], []), _funcs([]), **_CAPS)
    assert atlas.xrefs == []


def test_xrefs_pass_through_server_safe_scalars() -> None:
    xrefs = [_xref("0x401000", "0x401100", "CONDITIONAL_CALL")]
    atlas = compose_atlas(
        _summary(), _graph([], []), _funcs([]), xrefs=xrefs, max_xrefs=100, **_CAPS
    )
    assert atlas.xrefs[0].from_address == "0x401000"
    assert atlas.xrefs[0].to_address == "0x401100"
    assert atlas.xrefs[0].ref_type == "CONDITIONAL_CALL"


def test_xrefs_capped_and_flag_truncation() -> None:
    xrefs = [_xref(f"0x{i:x}", "0x401000") for i in range(10)]
    atlas = compose_atlas(_summary(), _graph([], []), _funcs([]), xrefs=xrefs, max_xrefs=3, **_CAPS)
    assert len(atlas.xrefs) == 3
    assert atlas.truncated is True
