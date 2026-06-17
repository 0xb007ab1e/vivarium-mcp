"""Behavior tests for the v1.1 semantic-naming adapter methods + pure seam (ADR-007).

The worker exposes two extraction primitives (``call_graph`` / ``referenced_strings``, ADR-001);
everything else is computed/aggregated JVM-free in the adapter. These tests fake the worker RPC
(:meth:`RpcGhidraAdapter._tool_call`) and exercise the server-side logic without a JVM/Ghidra:

- ``call_graph`` wires the worker call + wraps node names (untrusted, ADR-005);
- ``analysis_order`` runs the pure leaf-first ordering core over the extracted adjacency;
- ``callees`` / ``callers`` are one-hop projections (dedup, pagination, unresolved honesty flag);
- ``function_context`` aggregates get_function + call_graph + decompile + referenced_strings,
  taking the function's own ``is_external`` / ``has_unresolved_calls`` from its graph node and
  wrapping every binary-derived field.

The worker-only ``_gh_call_graph`` / ``_gh_referenced_strings`` JVM bindings are coverage-omitted
edges validated only by the real-worker integration suite (a gated image build).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ghidra_mcp.core.envelope import DataOrigin, Untrusted
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

    def exit_diagnosis(self) -> str:
        """Report an unknown exit (inert worker; never queried in these tests)."""
        return "unknown"


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


# --- fixtures (plain worker-shaped dicts) -----------------------------------------------------
# main(0x1000) -> helper(0x2000) -> puts(0x3000, external). 0x1000 also has an UNRESOLVED call and
# a DUPLICATE edge to helper (to prove edge/neighbor de-duplication).
def _graph(*, truncated: bool = False) -> dict[str, Any]:
    """A small worker-shaped call-graph dict used across the adapter tests."""
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
            {"from_address": "0x1000", "to_address": "0x2000"},  # duplicate → must dedup
            {"from_address": "0x2000", "to_address": "0x3000"},
        ],
        "unresolved_callers": ["0x1000"],
        "truncated": truncated,
    }


def _func(address: str, name: str, *, is_thunk: bool = False) -> _Responder:
    """A ``get_function`` responder for one function."""
    return lambda _p: {
        "address": address,
        "name": name,
        "signature": f"int {name}(void)",
        "size": 16,
        "is_thunk": is_thunk,
    }


# --- call_graph -------------------------------------------------------------------------------
def test_call_graph_forwards_bounds_and_wraps_names() -> None:
    """``call_graph`` forwards the bounds and returns wrapped node names (addresses bare)."""
    adapter = _make({"call_graph": lambda _p: _graph(truncated=True)})
    out = adapter.call_graph(_SID, s.CallGraphIn(session_id=_SID, root="main", max_nodes=5))
    assert isinstance(out, s.CallGraphOut)
    assert isinstance(out.nodes[0].name, Untrusted)
    assert out.nodes[0].address == "0x1000"
    assert out.truncated is True
    # the worker received the bounded params (root + caps)
    _method, params = adapter.calls[0]
    assert params["root"] == "main"
    assert params["max_nodes"] == 5


# --- analysis_order ---------------------------------------------------------------------------
def test_analysis_order_is_leaf_first() -> None:
    """``analysis_order`` orders sinks first (0x3000) → roots last (0x1000) via the pure core."""
    adapter = _make({"call_graph": lambda _p: _graph()})
    order = adapter.analysis_order(_SID, s.AnalysisOrderIn(session_id=_SID))
    members = [c.members for c in order.components]
    assert members == [["0x3000"], ["0x2000"], ["0x1000"]]
    assert order.unresolved_callers == ["0x1000"]
    assert order.self_recursive == []


# --- callees / callers ------------------------------------------------------------------------
def test_callees_dedups_and_flags_unresolved() -> None:
    """``callees`` of main returns helper once (dedup) and surfaces the unresolved-calls flag."""
    adapter = _make({"call_graph": lambda _p: _graph(), "get_function": _func("0x1000", "main")})
    out = adapter.callees(_SID, s.CalleesIn(session_id=_SID, function="main"))
    assert [n.address for n in out.neighbors] == ["0x2000"]
    assert out.total == 1
    assert out.unresolved is True  # main has an unresolved outgoing call


def test_callees_paginates() -> None:
    """``callees`` honors offset/limit and marks ``truncated`` when a page clips."""
    wide = {
        "nodes": [
            {"address": a, "name": a, "is_external": False, "has_unresolved_calls": False}
            for a in ("0x1000", "0xa", "0xb", "0xc")
        ],
        "edges": [
            {"from_address": "0x1000", "to_address": "0xa"},
            {"from_address": "0x1000", "to_address": "0xb"},
            {"from_address": "0x1000", "to_address": "0xc"},
        ],
        "unresolved_callers": [],
        "truncated": False,
    }
    adapter = _make({"call_graph": lambda _p: wide, "get_function": _func("0x1000", "main")})
    out = adapter.callees(_SID, s.CalleesIn(session_id=_SID, function="main", offset=1, limit=1))
    assert [n.address for n in out.neighbors] == ["0xb"]
    assert out.total == 3
    assert out.truncated is True
    assert out.unresolved is False


def test_callers_reverses_edges() -> None:
    """``callers`` of helper(0x2000) returns its caller main(0x1000); unresolved is False."""
    adapter = _make({"call_graph": lambda _p: _graph(), "get_function": _func("0x2000", "helper")})
    out = adapter.callers(_SID, s.CallersIn(session_id=_SID, function="helper"))
    assert [n.address for n in out.neighbors] == ["0x1000"]
    assert out.total == 1
    assert out.unresolved is False


def test_callers_empty_for_entry_root() -> None:
    """A function nothing calls (main) has no callers."""
    adapter = _make({"call_graph": lambda _p: _graph(), "get_function": _func("0x1000", "main")})
    out = adapter.callers(_SID, s.CallersIn(session_id=_SID, function="main"))
    assert out.neighbors == []
    assert out.total == 0


# --- function_context -------------------------------------------------------------------------
def _context_responses() -> dict[str, _Responder]:
    """Responders covering every RPC ``function_context`` aggregates (for ``main``)."""
    return {
        "get_function": _func("0x1000", "main"),
        "call_graph": lambda _p: _graph(),
        "decompile_function": lambda _p: {
            "address": "0x1000",
            "name": "main",
            "c_code": "int main(void){return helper();}",
            "signature": "int main(void)",
        },
        "referenced_strings": lambda _p: {"strings": ["/etc/passwd", "%s\n"], "truncated": False},
    }


def test_function_context_aggregates_and_wraps() -> None:
    """``function_context`` assembles the bundle, wraps binary-derived fields, uses node facts."""
    adapter = _make(_context_responses())
    ctx = adapter.function_context(_SID, s.FunctionContextIn(session_id=_SID, function="main"))
    assert ctx.address == "0x1000"
    assert isinstance(ctx.name, Untrusted)
    assert isinstance(ctx.signature, Untrusted)
    assert ctx.is_external is False  # taken from the graph node, not just is_thunk
    assert ctx.has_unresolved_calls is True  # graph-node honesty flag
    assert ctx.decompilation is not None and isinstance(ctx.decompilation, Untrusted)
    assert [n.address for n in ctx.callees] == ["0x2000"]
    assert ctx.callers == []  # nothing calls main in the fixture
    assert [str(rsv.value) for rsv in ctx.referenced_strings] == ["/etc/passwd", "%s\n"]
    assert all(rsv.origin is DataOrigin.BINARY for rsv in ctx.referenced_strings)
    assert ctx.truncated is False


def test_function_context_omits_decompilation_when_disabled() -> None:
    """``include_decompilation=False`` yields no pseudo-C and never calls the decompiler."""
    adapter = _make(_context_responses())
    ctx = adapter.function_context(
        _SID,
        s.FunctionContextIn(session_id=_SID, function="main", include_decompilation=False),
    )
    assert ctx.decompilation is None
    assert not any(method == "decompile_function" for method, _ in adapter.calls)


def test_function_context_skips_callers_when_capped_to_zero() -> None:
    """``max_callers=0`` skips the reverse-hop whole-graph fetch and returns no callers."""
    adapter = _make(_context_responses())
    ctx = adapter.function_context(
        _SID, s.FunctionContextIn(session_id=_SID, function="main", max_callers=0)
    )
    assert ctx.callers == []


def test_function_context_skips_strings_when_capped_to_zero() -> None:
    """``max_strings=0`` skips the referenced-strings RPC entirely (no empty round-trip)."""
    adapter = _make(_context_responses())
    ctx = adapter.function_context(
        _SID, s.FunctionContextIn(session_id=_SID, function="main", max_strings=0)
    )
    assert ctx.referenced_strings == []
    assert not any(method == "referenced_strings" for method, _ in adapter.calls)


def test_function_context_propagates_truncation() -> None:
    """A truncated referenced-strings result propagates to the bundle's ``truncated`` flag."""
    responses = _context_responses()
    responses["referenced_strings"] = lambda _p: {"strings": ["x"], "truncated": True}
    adapter = _make(responses)
    ctx = adapter.function_context(_SID, s.FunctionContextIn(session_id=_SID, function="main"))
    assert ctx.truncated is True


# --- pure shaping seam (carried forward; exercised directly) ----------------------------------
def test_build_call_graph_wraps_names_untrusted() -> None:
    """``_build_call_graph`` wraps node names in the untrusted envelope; addresses stay bare."""
    out = rc._build_call_graph(_graph(truncated=True))
    assert isinstance(out.nodes[0].name, Untrusted)
    assert out.nodes[0].address == "0x1000"
    assert out.nodes[2].is_external is True
    assert out.edges[0].from_address == "0x1000"
    assert out.unresolved_callers == ["0x1000"]
    assert out.truncated is True


def test_build_analysis_order_condenses_cycle() -> None:
    """A mutual-recursion cycle condenses into one recursive component in the shaped output."""
    graph = s.CallGraphOut(
        nodes=[
            s.CallGraphNode(
                address=a,
                name=Untrusted(value=a, origin=DataOrigin.BINARY),
                is_external=False,
                has_unresolved_calls=False,
            )
            for a in ("0xa", "0xb")
        ],
        edges=[
            s.CallEdge(from_address="0xa", to_address="0xb"),
            s.CallEdge(from_address="0xb", to_address="0xa"),
        ],
        unresolved_callers=[],
        truncated=True,
    )
    order = rc._build_analysis_order(graph)
    assert len(order.components) == 1
    assert order.components[0].is_recursive is True
    assert sorted(order.components[0].members) == ["0xa", "0xb"]
    assert order.truncated is True
