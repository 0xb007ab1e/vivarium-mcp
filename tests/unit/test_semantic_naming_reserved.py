"""Guard tests for the v1.1 semantic-naming reserved stubs + the implemented pure seam (ADR-007).

Two jobs:

1. **Reserved-stub guards.** The worker-dependent extraction methods (``call_graph``/``callees``/
   ``callers``/``analysis_order``/``function_context`` on the RPC adapter, and ``_gh_call_graph``
   on the JVM bridge) are intentionally stubbed until WS2 builds them against the pinned Ghidra
   image (a GATED supply-chain action). These tests assert each raises ``NotImplementedError`` with
   the reserved label, so the seam is locked and a real implementation is an obvious diff.
2. **Implemented pure seam.** ``rpc_client._build_analysis_order`` (adjacency → leaf-first order via
   the pure :mod:`ghidra_mcp.core.callgraph`) and ``_build_call_graph`` (worker dict → wrapped
   model) are implemented now and unit-tested here — only the worker RPC hop is reserved.
"""

from __future__ import annotations

import pytest

from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.ghidra import rpc_client as rc
from ghidra_mcp.tools import schemas as s


def _adapter() -> rc.RpcGhidraAdapter:
    """Build an adapter with inert collaborators (no worker is spawned for the stub guards)."""
    return rc.RpcGhidraAdapter(
        launcher=lambda _sid, _path: _DeadWorker(),
        socket_dir="/run/x",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=4096,
    )


class _DeadWorker:
    """A worker handle that is never actually used by the reserved-stub paths."""

    def kill(self) -> None:
        """No-op kill."""

    def is_alive(self) -> bool:
        """Report not alive."""
        return False


_SID = "sid1"


def test_call_graph_is_reserved_stub() -> None:
    """``call_graph`` extraction is reserved (NotImplementedError) until WS2 builds it."""
    with pytest.raises(NotImplementedError, match="RESERVED"):
        _adapter().call_graph(_SID, s.CallGraphIn(session_id=_SID))


def test_callees_is_reserved_stub() -> None:
    """``callees`` extraction is reserved until WS2 builds it."""
    with pytest.raises(NotImplementedError, match="RESERVED"):
        _adapter().callees(_SID, s.CalleesIn(session_id=_SID, function="main"))


def test_callers_is_reserved_stub() -> None:
    """``callers`` extraction is reserved until WS2 builds it."""
    with pytest.raises(NotImplementedError, match="RESERVED"):
        _adapter().callers(_SID, s.CallersIn(session_id=_SID, function="main"))


def test_analysis_order_extraction_hop_is_reserved_stub() -> None:
    """``analysis_order``'s extraction hop is reserved; the ordering itself is the pure core."""
    with pytest.raises(NotImplementedError, match="RESERVED"):
        _adapter().analysis_order(_SID, s.AnalysisOrderIn(session_id=_SID))


def test_function_context_is_reserved_stub() -> None:
    """``function_context`` assembly is reserved until WS2 builds it."""
    with pytest.raises(NotImplementedError, match="RESERVED"):
        _adapter().function_context(_SID, s.FunctionContextIn(session_id=_SID, function="main"))


def test_jvm_bridge_gh_call_graph_is_reserved_stub() -> None:
    """The worker-only ``_gh_call_graph`` JVM binding is reserved (built by WS2; ADR-001)."""
    from ghidra_mcp.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    with pytest.raises(NotImplementedError, match="RESERVED"):
        backend.call_graph({"max_nodes": 10, "max_edges": 10, "max_depth": 2})


# --- implemented pure seam --------------------------------------------------------------------
def test_build_call_graph_wraps_names_untrusted() -> None:
    """``_build_call_graph`` wraps node names in the untrusted envelope; addresses stay bare."""
    out = rc._build_call_graph(
        {
            "nodes": [
                {
                    "address": "0x1000",
                    "name": "main",
                    "is_external": False,
                    "has_unresolved_calls": False,
                },
                {
                    "address": "0x2000",
                    "name": "puts",
                    "is_external": True,
                    "has_unresolved_calls": False,
                },
            ],
            "edges": [{"from_address": "0x1000", "to_address": "0x2000"}],
            "unresolved_callers": ["0x1000"],
            "truncated": True,
        }
    )
    assert isinstance(out, s.CallGraphOut)
    assert isinstance(out.nodes[0].name, Untrusted)
    assert out.nodes[0].address == "0x1000"  # server-normalized scalar stays bare
    assert out.nodes[1].is_external is True
    assert out.edges[0].from_address == "0x1000"
    assert out.unresolved_callers == ["0x1000"]
    assert out.truncated is True


def test_build_analysis_order_uses_pure_core_leaf_first() -> None:
    """``_build_analysis_order`` produces a leaf-first order via the pure callgraph core."""
    graph = s.CallGraphOut(
        nodes=[
            s.CallGraphNode(
                address=a,
                name=Untrusted(value=a, origin=DataOrigin.BINARY),
                is_external=False,
                has_unresolved_calls=(a == "0x1000"),
            )
            for a in ("0x1000", "0x2000", "0x3000")
        ],
        edges=[
            s.CallEdge(from_address="0x1000", to_address="0x2000"),
            s.CallEdge(from_address="0x2000", to_address="0x3000"),
        ],
        unresolved_callers=["0x1000"],
        truncated=False,
    )
    order = rc._build_analysis_order(graph)
    members = [c.members for c in order.components]
    # Leaf-first: 0x3000 (sink) first, 0x1000 (root) last.
    assert members == [["0x3000"], ["0x2000"], ["0x1000"]]
    assert order.unresolved_callers == ["0x1000"]
    assert order.self_recursive == []


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
    assert order.truncated is True  # propagated from the (capped) graph
