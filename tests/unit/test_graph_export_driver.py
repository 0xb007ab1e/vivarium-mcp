"""Unit tests for the memory-graph export driver (ADR-079 §6) — fakes, no live transport.

Exercises the imperative shell's testable logic: gathering the read-only tools into a
``SessionSources``, pagination + per-kind ceilings, edge-key resolution (address index + local-id
index), dangling-edge skip-and-count, best-effort tool failure (recorded, never fatal), and
idempotent re-export. The live ``McpToolCaller`` / ``McpGraphSink`` adapters are not exercised here.
"""

from __future__ import annotations

from typing import Any, cast

from vivarium.graph_export import driver as d
from vivarium.graph_export.ports import ADDR_REF


def _u(value: str, origin: str = "binary-derived") -> dict[str, Any]:
    return {"value": value, "origin": origin}


def _empty(sha: str) -> dict[str, Any]:
    """Valid-empty payloads for every tool ``gather_sources`` calls (tests override selectively)."""
    return {
        "program_metadata": {
            "sha256": sha,
            "size_bytes": 100,
            "format": "ELF",
            "architecture": "x86:LE:64",
            "endianness": "little",
            "compiler": None,
            "entry_point": "0x1000",
            "function_count": 0,
            "analysis_complete": True,
        },
        "program_fingerprint": {
            "structure_digest": "d0",
            "import_digest": None,
            "function_count": 0,
            "import_count": 0,
            "coverage": {
                "total_bytes": 100,
                "defined_code_bytes": 0,
                "defined_data_bytes": 0,
                "undefined_bytes": 100,
                "code_ratio": 0.0,
                "data_ratio": 0.0,
                "function_count": 0,
            },
        },
        "list_functions": {"functions": [], "total": 0, "truncated": False},
        "call_graph": {"nodes": [], "edges": [], "unresolved_callers": [], "truncated": False},
        "call_graph_metrics": {
            "function_count": 0,
            "edge_count": 0,
            "leaf_count": 0,
            "root_count": 0,
            "recursive_component_count": 0,
            "self_recursive_count": 0,
            "unresolved_caller_count": 0,
            "top_fan_in": [],
            "top_fan_out": [],
            "truncated": False,
        },
        "list_imports": {"imports": [], "total": 0, "truncated": False},
        "list_exports": {"exports": [], "total": 0, "truncated": False},
        "list_strings": {"strings": [], "total": 0, "truncated": False},
        "ioc_scan": {"matches": [], "total": 0, "truncated": False},
        "crypto_constant_scan": {"findings": [], "total": 0, "truncated": False},
        "crypto_detect": {"indicators": [], "total": 0, "truncated": False},
        "secret_scan": {"findings": [], "total": 0, "truncated": False},
        "capability_scan": {
            "capabilities": [],
            "total": 0,
            "truncated": False,
            "rule_pack_version": "0",
        },
        "family_match": {"candidates": [], "corpus_version": "0", "truncated": False},
        "session_export_annotations": {"document": {"schema_version": 1, "entries": []}},
    }


class FakeToolCaller:
    """Returns canned payloads by tool; raises for tools in ``errors`` (best-effort path)."""

    def __init__(self, responses: dict[str, Any], errors: set[str] | None = None) -> None:
        self.responses = responses
        self.errors = errors or set()
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, args))
        if tool in self.errors:
            raise RuntimeError("boom")
        resp = self.responses[tool]
        result = resp(args) if callable(resp) else resp
        return cast("dict[str, Any]", result)


class FakeGraphSink:
    """Records upserts; returns stable keys mimicking memory-graph's derivation + created flags."""

    def __init__(self) -> None:
        self.projects: dict[str, str] = {}
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self._seen: set[Any] = set()

    def ensure_project(self, name: str, description: str) -> str:
        self.projects[name] = f"proj_{name}"
        return self.projects[name]

    def upsert_nodes(self, project_id: str, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for n in nodes:
            addr = n.get("address")
            key = (
                f"{n['kind'].lower()}:@{addr}"
                if addr is not None
                else f"{n['kind'].lower()}:{n['name']}"
            )
            created = key not in self._seen
            self._seen.add(key)
            self.nodes.append(n)
            out.append({"key": key, "created": created})
        return out

    def upsert_edges(self, project_id: str, edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for e in edges:
            ident = (e["type"], e["src_key"], e["dst_key"])
            created = ident not in self._seen
            self._seen.add(ident)
            self.edges.append(e)
            out.append({"created": created})
        return out


_SHA = "b" * 64


def _paged(list_key: str, rows: list[Any], *, truncated: bool = False) -> Any:
    """A paginated payload that returns ``rows`` at offset 0 and an empty page after."""

    def _resp(args: dict[str, Any]) -> dict[str, Any]:
        if args.get("offset", 0) > 0:
            return {list_key: [], "total": len(rows), "truncated": truncated}
        return {list_key: rows, "total": len(rows), "truncated": truncated}

    return _resp


# --- end to end ---------------------------------------------------------------------------------


def test_export_session_builds_project_and_resolves_edges() -> None:
    responses = _empty(_SHA)
    responses["program_metadata"]["function_count"] = 1
    responses["list_functions"] = _paged(
        "functions", [{"address": "0x1000", "name": _u("main", "ghidra-generated"), "size": 20}]
    )
    responses["call_graph"] = {
        "nodes": [
            {
                "address": "0x1000",
                "name": _u("main", "ghidra-generated"),
                "is_external": False,
                "has_unresolved_calls": False,
            },
            {
                "address": "0x2000",
                "name": _u("strcpy", "ghidra-generated"),
                "is_external": True,
                "has_unresolved_calls": False,
            },
        ],
        "edges": [{"from_address": "0x1000", "to_address": "0x2000"}],
        "unresolved_callers": [],
        "truncated": False,
    }
    responses["list_strings"] = _paged(
        "strings", [{"address": "0x6000", "value": _u("/bin/sh"), "length": 7}]
    )
    responses["ioc_scan"] = _paged(
        "matches", [{"category": "path", "value": _u("/bin/sh"), "source_address": "0x6000"}]
    )

    caller = FakeToolCaller(responses)
    sink = FakeGraphSink()
    stats = d.export_session(caller, sink, "sess-1", binary_label="sample.elf")

    assert stats.project_name == f"vivarium-{_SHA[:12]}"
    assert stats.failed_tools == []
    kinds = {n["kind"] for n in sink.nodes}
    assert {"PROGRAM", "FUNCTION", "STRING", "IOC"} <= kinds
    # CALLS edge resolved both endpoints via the address index.
    calls = [e for e in sink.edges if e["type"] == "CALLS"]
    assert (
        calls
        and calls[0]["src_key"] == "function:@4096"
        and calls[0]["dst_key"] == "function:@8192"
    )
    # IOC REFERENCES resolved to the string node at 0x6000.
    assert any(e["type"] == "REFERENCES" and e["dst_key"] == "string:@24576" for e in sink.edges)
    assert stats.nodes_created == stats.nodes_total and stats.nodes_total >= 4


def test_dangling_edge_is_skipped_and_counted() -> None:
    responses = _empty(_SHA)
    responses["list_functions"] = _paged(
        "functions", [{"address": "0x1000", "name": _u("main"), "size": 1}]
    )
    responses["call_graph_metrics"] = {
        **_empty(_SHA)["call_graph_metrics"],
        "top_fan_in": [{"address": "0x1000", "name": _u("main"), "count": 1}],
    }
    # xref from a real node (0x1000) to an address with no node (0xdead) → must be skipped.
    responses["xrefs_to"] = {
        "xrefs": [{"from_address": "0x1000", "to_address": "0xdead", "ref_type": "DATA"}],
        "total": 1,
        "truncated": False,
    }
    stats = d.export_session(FakeToolCaller(responses), FakeGraphSink(), "s")
    assert stats.edges_skipped >= 1
    # No XREF edge should have been upserted (its dst did not resolve).


def test_pagination_walks_pages_until_short_page() -> None:
    rows_page0 = [{"address": f"0x{i:x}", "name": _u("f"), "size": 1} for i in range(1, 6)]

    def functions(args: dict[str, Any]) -> dict[str, Any]:
        off = args.get("offset", 0)
        if off == 0:
            return {"functions": rows_page0, "total": 7, "truncated": False}
        if off == 5:
            return {
                "functions": [{"address": "0x100", "name": _u("g"), "size": 1}],
                "total": 7,
                "truncated": False,
            }
        return {"functions": [], "total": 7, "truncated": False}

    responses = _empty(_SHA)
    responses["list_functions"] = functions
    opts = d.ExportOptions(page_size=5)
    src, failed = d.gather_sources(FakeToolCaller(responses), "s", opts)
    assert len(src.functions) == 6 and failed == []


def test_ceiling_truncates_and_flags() -> None:
    responses = _empty(_SHA)
    responses["list_functions"] = _paged(
        "functions",
        [{"address": f"0x{i:x}", "name": _u("f"), "size": 1} for i in range(1, 4)],
    )
    opts = d.ExportOptions(page_size=1, max_functions=1)
    src, _ = d.gather_sources(FakeToolCaller(responses), "s", opts)
    assert len(src.functions) == 1
    assert src.truncated["functions"] is True


def test_tool_failure_is_recorded_not_fatal() -> None:
    responses = _empty(_SHA)
    caller = FakeToolCaller(responses, errors={"ioc_scan", "secret_scan"})
    stats = d.export_session(caller, FakeGraphSink(), "s")
    assert "ioc_scan" in stats.failed_tools and "secret_scan" in stats.failed_tools
    assert stats.project_name == f"vivarium-{_SHA[:12]}"  # export still completed


def test_idempotent_reexport_reports_zero_created_second_time() -> None:
    responses = _empty(_SHA)
    responses["list_functions"] = _paged(
        "functions", [{"address": "0x1000", "name": _u("main"), "size": 1}]
    )
    sink = FakeGraphSink()
    first = d.export_session(FakeToolCaller(responses), sink, "s")
    second = d.export_session(FakeToolCaller(responses), sink, "s")
    assert first.nodes_created > 0 and second.nodes_created == 0


def test_annotations_rename_overlay_reaches_graph() -> None:
    responses = _empty(_SHA)
    responses["list_functions"] = _paged(
        "functions", [{"address": "0x1000", "name": _u("FUN_1000", "ghidra-generated"), "size": 1}]
    )
    responses["session_export_annotations"] = {
        "document": {
            "schema_version": 1,
            "entries": [
                {"kind": "rename_function", "function": "0x1000", "new_name": _u("decrypt")},
                {
                    "kind": "set_comment",
                    "address": "0x1000",
                    "comment_type": "EOL",
                    "text": _u("decrypts config"),
                },
            ],
        }
    }
    sink = FakeGraphSink()
    d.export_session(FakeToolCaller(responses), sink, "s")
    fn = next(n for n in sink.nodes if n["kind"] == "FUNCTION")
    assert fn["name"] == "decrypt" and fn["provenance"] == "USER" and fn["layer"] == "curated"
    assert any(n["kind"] == "COMMENT" for n in sink.nodes)


def test_enrich_functions_pulls_detail_complexity_hash() -> None:
    responses = _empty(_SHA)
    responses["list_functions"] = _paged(
        "functions", [{"address": "0x1000", "name": _u("main", "ghidra-generated"), "size": 20}]
    )
    responses["get_function"] = {
        "address": "0x1000",
        "name": _u("main", "ghidra-generated"),
        "signature": _u("int main(void)", "ghidra-generated"),
        "size": 20,
        "is_thunk": False,
        "calling_convention": _u("__cdecl", "ghidra-generated"),
    }
    responses["cyclomatic_complexity"] = {
        "address": "0x1000",
        "name": _u("main", "ghidra-generated"),
        "complexity": 9,
        "block_count": 5,
        "edge_count": 6,
        "incomplete": False,
    }
    responses["function_hash"] = {
        "address": "0x1000",
        "exact_bytes": "11",
        "exact_instructions": "22",
        "exact_mnemonics": "33",
        "instruction_count": 12,
    }
    opts = d.ExportOptions(enrich_functions=True)
    src, failed = d.gather_sources(FakeToolCaller(responses), "s", opts)
    assert failed == []
    assert src.complexities["0x1000"] == 9
    assert src.function_hashes["0x1000"] == "22"
    assert src.function_details["0x1000"].is_thunk is False


def test_annotation_failure_is_recorded() -> None:
    responses = _empty(_SHA)
    caller = FakeToolCaller(responses, errors={"session_export_annotations"})
    stats = d.export_session(caller, FakeGraphSink(), "s")
    assert "session_export_annotations" in stats.failed_tools


def test_nonpaginated_tool_failure_recorded_via_safe() -> None:
    responses = _empty(_SHA)
    caller = FakeToolCaller(
        responses, errors={"family_match", "program_fingerprint", "call_graph_metrics"}
    )
    stats = d.export_session(caller, FakeGraphSink(), "s")
    assert {"family_match", "program_fingerprint", "call_graph_metrics"} <= set(stats.failed_tools)
    # Export still produced the program node despite the optional-tool failures.
    assert stats.nodes_total >= 1


def test_define_types_annotation_becomes_struct_node() -> None:
    responses = _empty(_SHA)
    responses["session_export_annotations"] = {
        "document": {
            "schema_version": 1,
            "entries": [
                {
                    "kind": "define_types",
                    "types": [
                        {
                            "kind": "struct",
                            "name": "Config",
                            "fields": [{"name": "k", "type": "int"}],
                        },
                        {"kind": "union", "name": "U", "fields": []},
                        {"kind": "struct", "name": None},  # malformed — skipped, never fatal
                    ],
                },
            ],
        }
    }
    sink = FakeGraphSink()
    d.export_session(FakeToolCaller(responses), sink, "s")
    names = {n["name"] for n in sink.nodes if n["kind"] in ("STRUCT", "UNION")}
    assert names == {"Config", "U"}


# --- helpers ------------------------------------------------------------------------------------


def test_resolve_addr_ref_and_local_id() -> None:
    id_index: dict[tuple[str, int | str], str] = {("PROGRAM", "sha"): "program:sha"}
    addr_index = {0x1000: "func:@4096"}
    assert d._resolve((ADDR_REF, 0x1000), id_index, addr_index) == "func:@4096"
    assert d._resolve((ADDR_REF, "nope"), id_index, addr_index) is None
    assert d._resolve((ADDR_REF, 0x2000), id_index, addr_index) is None
    assert d._resolve(("PROGRAM", "sha"), id_index, addr_index) == "program:sha"
    assert d._resolve(("PROGRAM", "other"), id_index, addr_index) is None


def test_unwrap_handles_wrapped_bare_and_missing() -> None:
    assert d._unwrap({"value": "x", "origin": "binary-derived"}) == "x"
    assert d._unwrap("plain") == "plain"
    assert d._unwrap({"nope": 1}) is None
    assert d._unwrap(None) is None
    assert d._unwrap(42) is None


def test_node_dict_omits_absent_address() -> None:
    from vivarium.graph_export.ports import NodeSpec

    with_addr = d._node_dict(NodeSpec("FUNCTION", "f", "GHIDRA", "raw", address=16, attrs={"a": 1}))
    without = d._node_dict(NodeSpec("PROGRAM", "sha", "BINARY", "raw"))
    assert with_addr["address"] == 16 and with_addr["attrs"] == {"a": 1}
    assert "address" not in without
