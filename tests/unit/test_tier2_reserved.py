"""Guard tests for the v1.1 Tier-2 reserved stubs (ADR-008).

The 8 Tier-2 adapter methods and the 4 worker-only ``_gh_*`` extraction bindings are intentionally
reserved until the build fan-out wires them (adapter → pure cores + the new worker RPCs; the JVM
extraction → the pinned Ghidra image). These tests lock the seam: each raises
``NotImplementedError`` with the ``RESERVED`` label, so a real impl is an obvious diff. The cores
(``core.metrics`` / ``core.iocscan``) are already implemented and 100%-tested.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from ghidra_mcp.ghidra import rpc_client as rc
from ghidra_mcp.tools import schemas as s

_SID = "sid1"


class _DeadWorker:
    """Inert worker handle — the reserved paths never dial a socket."""

    def kill(self) -> None:
        """No-op."""

    def is_alive(self) -> bool:
        """Report not alive."""
        return False


def _adapter() -> rc.RpcGhidraAdapter:
    """Build an adapter with inert collaborators (no worker spawned for the stub guards)."""
    return rc.RpcGhidraAdapter(
        launcher=lambda _sid, _path: _DeadWorker(),
        socket_dir="/run/x",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=4096,
    )


_TIER2_CALLS: list[Callable[[rc.RpcGhidraAdapter], object]] = [
    lambda a: a.cyclomatic_complexity(
        _SID, s.CyclomaticComplexityIn(session_id=_SID, function="main")
    ),
    lambda a: a.list_imports(_SID, s.ListImportsIn(session_id=_SID)),
    lambda a: a.list_exports(_SID, s.ListExportsIn(session_id=_SID)),
    lambda a: a.coverage(_SID, s.CoverageIn(session_id=_SID)),
    lambda a: a.ioc_scan(_SID, s.IocScanIn(session_id=_SID)),
    lambda a: a.crypto_constant_scan(_SID, s.CryptoConstantScanIn(session_id=_SID)),
    lambda a: a.call_graph_metrics(_SID, s.CallGraphMetricsIn(session_id=_SID)),
    lambda a: a.program_summary(_SID, s.ProgramSummaryIn(session_id=_SID)),
]


@pytest.mark.parametrize("call", _TIER2_CALLS)
def test_tier2_adapter_methods_are_reserved(call: Callable[[rc.RpcGhidraAdapter], object]) -> None:
    """Each Tier-2 adapter method is reserved (NotImplementedError) until the build fan-out."""
    with pytest.raises(NotImplementedError, match="RESERVED"):
        call(_adapter())


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("function_cfg", {"function": "main"}),
        ("imports", {"offset": 0, "limit": 10}),
        ("exports", {"offset": 0, "limit": 10}),
        ("coverage", {}),
    ],
)
def test_tier2_jvm_extraction_is_reserved(method: str, params: dict[str, object]) -> None:
    """The 4 worker-only Tier-2 ``_gh_*`` extraction bindings are reserved (built in fan-out)."""
    from ghidra_mcp.ghidra._jvm_bridge import PyGhidraBackend

    backend = PyGhidraBackend()
    with pytest.raises(NotImplementedError, match="RESERVED"):
        getattr(backend, method)(params)
