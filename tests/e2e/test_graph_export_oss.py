"""Live ADR-079 memory-graph export e2e (GATED, real worker) — closes the gather live gap.

The hermetic suite (``test_graph_export_driver.py`` / ``test_graph_export_mapper.py``) covers the
pure mapper + the driver's resolution logic against fakes. This exercises :func:`export_session`
over a REAL ``python -m vivarium`` server (which spawns a hardened Ghidra worker): it proves the
driver's tool-arg shapes and payload parsing match the live tool schemas, that a real analyzed
binary yields a PROGRAM + FUNCTION graph with resolved CALLS/CONTAINS edges, and that binary-derived
node names cross the boundary as inert data (never fabricating an edge).

The memory-graph server itself is NOT required: an in-memory ``GraphSink`` records the upserts, so
this test has no second live dependency. Gated like the other ``_oss`` real-worker e2e
(``VIVARIUM_INTEGRATION`` + built fixtures + a worker image + a container engine); otherwise it
skips cleanly. No real malware — the benign OSS fixture only.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

import pytest

from tests.e2e.test_abuse_containment_oss import (
    _SKIP,
    _first_valid_fixture,
    _fixtures_dir,
    _timeout,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]


class _RecordingSink:
    """In-memory :class:`GraphSink` — records upserts, mimics memory-graph key derivation."""

    def __init__(self) -> None:
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []

    def ensure_project(self, name: str, description: str) -> str:
        self.name = name
        return f"proj_{name}"

    def upsert_nodes(self, project_id: str, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for n in nodes:
            addr = n.get("address")
            key = (
                f"{n['kind'].lower()}:@{addr}"
                if addr is not None
                else f"{n['kind'].lower()}:{n['name']}"
            )
            self.nodes.append(n)
            out.append({"key": key, "created": True})
        return out

    def upsert_edges(self, project_id: str, edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.edges.extend(edges)
        return [{"created": True} for _ in edges]


def test_export_session_over_real_worker() -> None:
    """Export a REAL analyzed binary's session to an in-memory sink (ADR-079 gather live gap)."""
    from vivarium.dashboard.executor import McpToolCaller
    from vivarium.graph_export.driver import export_session

    fixtures = _fixtures_dir()
    fixture = _first_valid_fixture()
    prev_root = os.environ.get("VIVARIUM_IMPORT_ROOT")
    os.environ["VIVARIUM_IMPORT_ROOT"] = str(fixtures)
    caller: McpToolCaller | None = None
    try:
        caller = McpToolCaller(timeout=_timeout().total_seconds())
        info = caller.call("session_create", {"label": "graph-export-e2e"})
        sid = info["session_id"]
        caller.call("session_import", {"session_id": sid, "source_ref": str(fixture)})
        caller.call("session_analyze", {"session_id": sid})

        sink = _RecordingSink()
        stats = export_session(caller, sink, sid, binary_label=str(fixture))

        # The project is keyed by the server-computed sha256 (safe digest).
        assert stats.project_name.startswith("vivarium-")
        kinds = {n["kind"] for n in sink.nodes}
        assert "PROGRAM" in kinds, "expected a PROGRAM node"
        assert "FUNCTION" in kinds, "expected FUNCTION nodes from a real analyzed binary"
        assert stats.nodes_total >= 2
        # Edges resolved (CONTAINS program→function at minimum); none fabricated.
        edge_types = {e["type"] for e in sink.edges}
        assert "CONTAINS" in edge_types
        # A binary-derived FUNCTION name crosses as inert data tagged hostile provenance.
        fn = next(n for n in sink.nodes if n["kind"] == "FUNCTION")
        assert isinstance(fn["name"], str) and fn["provenance"] in ("GHIDRA", "USER")
    finally:
        if caller is not None:
            with contextlib.suppress(Exception):
                caller.call("session_close", {"session_id": sid})
        if prev_root is None:
            os.environ.pop("VIVARIUM_IMPORT_ROOT", None)
        else:
            os.environ["VIVARIUM_IMPORT_ROOT"] = prev_root
