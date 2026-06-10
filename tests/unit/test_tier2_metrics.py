"""Behavior tests for the v1.1 Tier-2 reporting/metrics adapter methods (ADR-008).

The worker exposes four new extraction primitives (``function_cfg`` / ``imports`` / ``exports`` /
``coverage`` — ADR-001); the metric *derivation* is JVM-free. These tests fake the worker RPC
(:meth:`RpcGhidraAdapter._tool_call`) and exercise the server-side logic — pure-core wiring, the
untrusted-data wrap (ADR-005), pagination, and ``truncated`` honesty — with no JVM/Ghidra:

- ``cyclomatic_complexity`` runs the pure ``E - N + 2`` over worker CFG counts and wraps the name;
- ``list_imports`` / ``list_exports`` wrap names (and import library) and paginate;
- ``coverage`` computes ratios + ``undefined_bytes`` server-side (divide-by-zero guarded);
- ``ioc_scan`` runs the pure scanner over ``list_strings`` and wraps each match value (BINARY);
- ``crypto_constant_scan`` composes one ``search_bytes`` per signature and shapes the addresses;
- ``call_graph_metrics`` runs the pure metric core over the ``call_graph`` adjacency;
- ``program_summary`` aggregates the above into one bounded triage report.

The worker-only ``_gh_*`` JVM bindings are coverage-omitted edges validated only by the real-worker
integration suite (a gated image build).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.core.iocscan import CRYPTO_SIGNATURES
from ghidra_mcp.ghidra import rpc_client as rc
from ghidra_mcp.tools import schemas as s

_SID = "sid1"

#: A faked worker response: a callable taking the request params and returning a plain result dict.
_Responder = Callable[[dict[str, Any]], dict[str, Any]]


class _DeadWorker:
    """An inert worker handle (the faked ``_tool_call`` never dials a real socket)."""

    def kill(self) -> None:
        """No-op kill."""

    def is_alive(self) -> bool:
        """Report not alive."""
        return False


class _FakeAdapter(rc.RpcGhidraAdapter):
    """Adapter whose ``_tool_call`` returns canned per-method responses (no worker)."""

    responses: dict[str, _Responder]
    calls: list[tuple[str, dict[str, Any]]]

    def _tool_call(self, sid: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, params))
        return self.responses[method](params)


def _make(responses: dict[str, _Responder]) -> _FakeAdapter:
    """Build a fake adapter wired with the given per-method responders."""
    adapter = _FakeAdapter(
        launcher=lambda _sid, _path: _DeadWorker(),
        socket_dir="/run/x",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=1 << 20,
    )
    adapter.responses = responses
    adapter.calls = []
    return adapter


# --- cyclomatic_complexity --------------------------------------------------------------------
def test_cyclomatic_complexity_computes_mccabe_and_wraps_name() -> None:
    """``cyclomatic_complexity`` derives ``E - N + 2`` from worker counts and wraps the name."""
    adapter = _make(
        {
            "function_cfg": lambda _p: {
                "address": "0x1000",
                "name": "main",
                "block_count": 4,
                "edge_count": 6,
                "incomplete": False,
            }
        }
    )
    out = adapter.cyclomatic_complexity(
        _SID, s.CyclomaticComplexityIn(session_id=_SID, function="main")
    )
    assert out.complexity == 4  # 6 - 4 + 2
    assert out.block_count == 4
    assert out.address == "0x1000"
    assert isinstance(out.name, Untrusted) and out.name.origin is DataOrigin.BINARY
    assert adapter.calls[0] == ("function_cfg", {"function": "main"})


def test_cyclomatic_complexity_clamps_and_flags_incomplete() -> None:
    """A degenerate/unresolved CFG never reports < 1 and preserves the ``incomplete`` flag."""
    adapter = _make(
        {
            "function_cfg": lambda _p: {
                "address": "0x1000",
                "name": "stub",
                "block_count": 1,
                "edge_count": 0,
                "incomplete": True,
            }
        }
    )
    out = adapter.cyclomatic_complexity(
        _SID, s.CyclomaticComplexityIn(session_id=_SID, function="stub")
    )
    assert out.complexity == 1  # max(1, 0 - 1 + 2)
    assert out.incomplete is True


# --- list_imports / list_exports --------------------------------------------------------------
def test_list_imports_wraps_name_and_library() -> None:
    """``list_imports`` wraps name + library (BINARY); address bare; missing library = None."""
    adapter = _make(
        {
            "imports": lambda _p: {
                "imports": [
                    {"name": "recv", "library": "ws2_32.dll", "address": "0x4010"},
                    {"name": "puts"},
                ],
                "total": 2,
                "truncated": False,
            }
        }
    )
    out = adapter.list_imports(_SID, s.ListImportsIn(session_id=_SID))
    assert isinstance(out.imports[0].name, Untrusted)
    assert out.imports[0].library is not None and isinstance(out.imports[0].library, Untrusted)
    assert out.imports[0].address == "0x4010"
    assert out.imports[1].library is None and out.imports[1].address is None
    assert out.total == 2


def test_list_exports_forwards_pagination_and_wraps() -> None:
    """``list_exports`` forwards offset/limit to the worker and wraps export names."""
    adapter = _make(
        {
            "exports": lambda _p: {
                "exports": [{"name": "DllMain", "address": "0x1500"}],
                "total": 5,
                "truncated": True,
            }
        }
    )
    out = adapter.list_exports(_SID, s.ListExportsIn(session_id=_SID, offset=2, limit=1))
    assert isinstance(out.exports[0].name, Untrusted)
    assert out.exports[0].address == "0x1500"
    assert out.truncated is True
    assert adapter.calls[0][1] == {"offset": 2, "limit": 1}


# --- coverage ---------------------------------------------------------------------------------
def test_coverage_computes_ratios_and_undefined() -> None:
    """``coverage`` derives ratios + ``undefined_bytes`` from worker byte counts."""
    adapter = _make(
        {
            "coverage": lambda _p: {
                "total_bytes": 1000,
                "defined_code_bytes": 400,
                "defined_data_bytes": 100,
                "function_count": 7,
            }
        }
    )
    out = adapter.coverage(_SID, s.CoverageIn(session_id=_SID))
    assert out.undefined_bytes == 500
    assert out.code_ratio == 0.4
    assert out.data_ratio == 0.1
    assert out.function_count == 7


def test_coverage_guards_divide_by_zero() -> None:
    """An empty program (0 total bytes) yields 0.0 ratios, not a ZeroDivisionError."""
    adapter = _make(
        {
            "coverage": lambda _p: {
                "total_bytes": 0,
                "defined_code_bytes": 0,
                "defined_data_bytes": 0,
                "function_count": 0,
            }
        }
    )
    out = adapter.coverage(_SID, s.CoverageIn(session_id=_SID))
    assert out.code_ratio == 0.0
    assert out.data_ratio == 0.0
    assert out.undefined_bytes == 0


# --- ioc_scan ---------------------------------------------------------------------------------
def _strings(*rows: tuple[str, str], truncated: bool = False) -> _Responder:
    """A ``list_strings`` responder for ``(address, value)`` rows."""
    return lambda _p: {
        "strings": [
            {"address": addr, "value": value, "length": len(value)} for addr, value in rows
        ],
        "total": len(rows),
        "truncated": truncated,
    }


def test_ioc_scan_finds_and_wraps_values() -> None:
    """``ioc_scan`` runs the pure scanner over strings and wraps each match value BINARY-origin."""
    adapter = _make(
        {
            "list_strings": _strings(
                ("0x1", "connect to 10.0.0.1 now"),
                ("0x2", "visit http://evil.example/c2"),
            )
        }
    )
    out = adapter.ioc_scan(_SID, s.IocScanIn(session_id=_SID))
    found = {(m.category, m.value.value) for m in out.matches}
    assert ("ipv4", "10.0.0.1") in found
    assert ("url", "http://evil.example/c2") in found
    assert all(isinstance(m.value, Untrusted) for m in out.matches)
    assert all(m.value.origin is DataOrigin.BINARY for m in out.matches)
    # the scan pulls a bounded page of strings before scanning
    assert adapter.calls[0][0] == "list_strings"
    assert adapter.calls[0][1]["limit"] == rc._IOC_STRING_BUDGET


def test_ioc_scan_filters_by_category_and_paginates() -> None:
    """``categories`` restricts the scan and ``offset``/``limit`` paginate matches (truncation)."""
    adapter = _make(
        {
            "list_strings": _strings(
                ("0x1", "10.0.0.1"),
                ("0x2", "10.0.0.2"),
                ("0x3", "10.0.0.3"),
                ("0x4", "ignore-me@example.com"),  # email — excluded by category filter
            )
        }
    )
    out = adapter.ioc_scan(
        _SID, s.IocScanIn(session_id=_SID, categories=["ipv4"], offset=1, limit=1)
    )
    assert out.total == 3  # three ipv4 matches, email filtered out
    assert len(out.matches) == 1  # one page
    assert out.matches[0].category == "ipv4"
    assert out.truncated is True  # offset+limit < total


def test_ioc_scan_propagates_string_truncation() -> None:
    """A truncated string set marks the scan ``truncated`` even if the match page is not clipped."""
    adapter = _make({"list_strings": _strings(("0x1", "10.0.0.1"), truncated=True)})
    out = adapter.ioc_scan(_SID, s.IocScanIn(session_id=_SID))
    assert out.truncated is True


# --- crypto_constant_scan ---------------------------------------------------------------------
def test_crypto_constant_scan_composes_searches_and_shapes() -> None:
    """``crypto_constant_scan`` issues one ``search_bytes`` per signature and shapes the hits."""
    aes = "637c777bf26b6fc53001672bfed7ab76"

    def _search(params: dict[str, Any]) -> dict[str, Any]:
        # crypto_constant_scan composes the fail-closed search_bytes adapter method, which builds
        # full ByteMatch rows — so the worker shape must carry context_hex (the real worker does).
        if params["pattern_hex"] == aes:
            return {
                "matches": [{"address": "0x8000", "context_hex": aes}],
                "total": 1,
                "truncated": False,
            }
        return {"matches": [], "total": 0, "truncated": False}

    adapter = _make({"search_bytes": _search})
    out = adapter.crypto_constant_scan(_SID, s.CryptoConstantScanIn(session_id=_SID))
    # one search issued per known signature
    assert len(adapter.calls) == len(CRYPTO_SIGNATURES)
    assert out.total == 1
    finding = out.findings[0]
    assert finding.algorithm == "AES"
    assert finding.kind == "sbox"
    assert finding.address == "0x8000"


def test_crypto_constant_scan_truncates_on_search() -> None:
    """A truncated per-signature ``search_bytes`` propagates to the aggregate ``truncated``."""
    adapter = _make({"search_bytes": lambda _p: {"matches": [], "total": 0, "truncated": True}})
    out = adapter.crypto_constant_scan(_SID, s.CryptoConstantScanIn(session_id=_SID))
    assert out.truncated is True


# --- call_graph_metrics -----------------------------------------------------------------------
def _graph() -> dict[str, Any]:
    """main(0x1000) -> helper(0x2000) -> puts(0x3000, external); main also calls puts."""
    return {
        "nodes": [
            {
                "address": "0x1000",
                "name": "main",
                "is_external": False,
                "has_unresolved_calls": True,
            },
            {
                "address": "0x2000",
                "name": "helper",
                "is_external": False,
                "has_unresolved_calls": False,
            },
            {
                "address": "0x3000",
                "name": "puts",
                "is_external": True,
                "has_unresolved_calls": False,
            },
        ],
        "edges": [
            {"from_address": "0x1000", "to_address": "0x2000"},
            {"from_address": "0x1000", "to_address": "0x3000"},
            {"from_address": "0x2000", "to_address": "0x3000"},
        ],
        "unresolved_callers": ["0x1000"],
        "truncated": False,
    }


def test_call_graph_metrics_computes_structure_and_wraps_hotspot_names() -> None:
    """``call_graph_metrics`` runs the pure core over the adjacency, reusing wrapped node names."""
    adapter = _make({"call_graph": lambda _p: _graph()})
    out = adapter.call_graph_metrics(_SID, s.CallGraphMetricsIn(session_id=_SID))
    assert out.function_count == 3
    assert out.edge_count == 3
    assert out.leaf_count == 1  # puts has no outgoing edge
    assert out.root_count == 1  # main has no incoming edge
    assert out.unresolved_caller_count == 1
    # puts is the most-called (fan-in 2) and its hotspot name is untrusted-wrapped
    top_in = out.top_fan_in[0]
    assert top_in.address == "0x3000"
    assert top_in.count == 2
    assert isinstance(top_in.name, Untrusted) and top_in.name.origin is DataOrigin.BINARY


def test_call_graph_metrics_honors_top_n() -> None:
    """``top_n`` bounds the hotspot rankings."""
    adapter = _make({"call_graph": lambda _p: _graph()})
    out = adapter.call_graph_metrics(_SID, s.CallGraphMetricsIn(session_id=_SID, top_n=1))
    assert len(out.top_fan_in) == 1
    assert len(out.top_fan_out) == 1


# --- program_summary --------------------------------------------------------------------------
def _summary_responses() -> dict[str, _Responder]:
    """Responders covering every RPC ``program_summary`` aggregates."""
    return {
        "program_metadata": lambda _p: {
            "sha256": "ab" * 32,
            "size_bytes": 2048,
            "format": "ELF",
            "architecture": "x86:LE:64:default",
            "endianness": "little",
            "compiler": "gcc",
            "entry_point": "0x1000",
            "function_count": 2,
            "analysis_complete": True,
        },
        "imports": lambda _p: {"imports": [{"name": "recv"}], "total": 3, "truncated": False},
        "exports": lambda _p: {
            "exports": [{"name": "main", "address": "0x1000"}],
            "total": 1,
            "truncated": False,
        },
        "list_strings": _strings(("0x9", "http://c2.example/x")),
        "coverage": lambda _p: {
            "total_bytes": 2048,
            "defined_code_bytes": 1024,
            "defined_data_bytes": 256,
            "function_count": 2,
        },
        "call_graph": lambda _p: _graph(),
        "list_functions": lambda _p: {
            "functions": [
                {"address": "0x1000", "name": "main", "size": 32},
                {"address": "0x2000", "name": "helper", "size": 16},
            ],
            "total": 2,
            "truncated": False,
        },
        "function_cfg": lambda p: {
            "address": p["function"],
            "name": "fn",
            "block_count": 2 if p["function"] == "0x1000" else 5,
            "edge_count": 3 if p["function"] == "0x1000" else 9,
            "incomplete": False,
        },
        "search_bytes": lambda _p: {"matches": [], "total": 0, "truncated": False},
    }


def test_program_summary_aggregates_everything() -> None:
    """``program_summary`` assembles totals, coverage, metrics, complexity, and IOC counts."""
    adapter = _make(_summary_responses())
    out = adapter.program_summary(_SID, s.ProgramSummaryIn(session_id=_SID))
    assert out.import_count == 3
    assert out.export_count == 1
    assert out.string_count == 1
    assert out.function_count == 2
    assert out.coverage is not None and out.coverage.undefined_bytes == 768
    assert out.call_graph_metrics is not None and out.call_graph_metrics.function_count == 3
    # top-by-complexity: helper (9-5+2=6) ranks above main (3-2+2=3)
    assert [c.complexity for c in out.top_complex_functions] == [6, 3]
    assert any(c.category == "url" for c in out.ioc_counts)
    assert isinstance(out.metadata.compiler, Untrusted)


def test_program_summary_skips_call_graph_when_disabled() -> None:
    """``include_call_graph=False`` omits the metrics and never extracts the call graph."""
    adapter = _make(_summary_responses())
    out = adapter.program_summary(
        _SID, s.ProgramSummaryIn(session_id=_SID, include_call_graph=False)
    )
    assert out.call_graph_metrics is None
    assert not any(method == "call_graph" for method, _ in adapter.calls)


def test_program_summary_skips_complexity_and_iocs_when_capped_to_zero() -> None:
    """Zero caps skip the complexity pass and IOC scan entirely (no wasted round-trips)."""
    adapter = _make(_summary_responses())
    out = adapter.program_summary(
        _SID,
        s.ProgramSummaryIn(session_id=_SID, max_complex_functions=0, max_iocs=0),
    )
    assert out.top_complex_functions == []
    assert out.ioc_counts == []
    # the complexity pass is skipped entirely (no CFG extraction)
    assert not any(method == "function_cfg" for method, _ in adapter.calls)
    # string_count still calls list_strings (limit=1), but the IOC scan's bounded budget never runs
    list_strings_limits = [p["limit"] for m, p in adapter.calls if m == "list_strings"]
    assert list_strings_limits == [1]


# --- fail-closed on malformed worker result (ADR-008 review Low-2; topic-error-handling) -------
def test_malformed_worker_result_in_builder_maps_to_worker_unavailable() -> None:
    """A builder method fails CLOSED (WORKER_UNAVAILABLE) when the worker omits a required key.

    Proves the ``_fail_closed`` guard fires on a known-bad result rather than letting a raw
    ``KeyError`` escape the adapter (which the server shell would mislabel as a generic internal
    error). The untrusted worker detail is never surfaced — only the safe mapped type.
    """
    # decompile_function builds via _build_decompiled, which requires c_code/signature.
    adapter = _make({"decompile_function": lambda _p: {"address": "0x1", "name": "f"}})
    with pytest.raises(GhidraMcpError) as excinfo:
        adapter.decompile_function(_SID, s.DecompileFunctionIn(session_id=_SID, function="f"))
    assert excinfo.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_malformed_worker_result_on_validate_path_maps_too() -> None:
    """The ``model_validate`` path (xrefs) also fails closed on a wrong-typed worker result."""
    adapter = _make({"xrefs_to": lambda _p: {"xrefs": [], "total": "not-an-int"}})
    with pytest.raises(GhidraMcpError) as excinfo:
        adapter.xrefs_to(_SID, s.XrefsIn(session_id=_SID, target="main"))
    assert excinfo.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_malformed_function_cfg_maps_to_worker_unavailable() -> None:
    """The Tier-2 ``cyclomatic_complexity`` builder fails closed on a malformed CFG result."""
    adapter = _make({"function_cfg": lambda _p: {"address": "0x1", "name": "f"}})  # no counts
    with pytest.raises(GhidraMcpError) as excinfo:
        adapter.cyclomatic_complexity(_SID, s.CyclomaticComplexityIn(session_id=_SID, function="f"))
    assert excinfo.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
