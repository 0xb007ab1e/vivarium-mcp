"""Full e2e ground-truth sanity check on real OSS binaries (WS5; GATED).

The truest end-to-end path: drive the real MCP server over **stdio** (FastMCP, real
``RpcGhidraAdapter`` → real hardened Ghidra **worker container**) on stripped real-tool fixtures
(cJSON / zlib minigzip / lua), then compare Ghidra's RECOVERED structure to a
GROUND TRUTH extracted from the unstripped, ``-no-pie`` build (so truth addresses == Ghidra's).

Per tool the journey is: ``session_create`` → ``session_import`` (the stripped fixture) →
``session_analyze`` → ``list_functions`` (recovered entry addresses) → ``call_graph`` (recovered
direct edges) → ``analysis_order`` (leaf-first SCC components) → ``session_close``. The recovered
data feeds :func:`tests.e2e._groundtruth.compare`, which asserts (within tolerance) that Ghidra
recovered most of the known functions + edges and produced a leaf-first order consistent with the
true partial order — i.e. the substrate the (client-driven) semantic-naming walk depends on.

GATING (hermetic by default — this never runs in the unit/coverage job):
    * ``VIVARIUM_INTEGRATION`` truthy — opts into the real-worker suite (gated; PLAN §6).
    * ``VIVARIUM_FIXTURES`` — dir holding the fixtures-build artifact (``index.json`` +
      ``<tool>.stripped`` + ``<tool>.groundtruth.json``), produced by ``build_fixtures.py``.
    * ``VIVARIUM_WORKER_IMAGE`` — the pinned-by-digest worker image the adapter runs.
    * a container engine (``VIVARIUM_CONTAINER_ENGINE``, default ``podman``) on PATH.
Any missing prerequisite → the whole module skips cleanly (not error/fail), keeping the default
suite green while the gated fixtures + worker image do not yet exist.

DISPATCH-VALIDATED SURFACE (like ``tests/integration/test_worker_analysis.py``): the exact MCP
client result shape, the server's ``source_ref`` import resolution, and the adapter's worker-run
wiring are exercised for real only here, under the gated dispatch — the in-band unit suite proves
the pure scorer (``test_groundtruth_compare.py``) and the extractor methodology offline.

No real malware: all three inputs are benign, source-available OSS tools (master §5, PLAN §6).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.e2e._groundtruth import GroundTruth, Thresholds, compare

_ENV_INTEGRATION = "VIVARIUM_INTEGRATION"
_ENV_FIXTURES = "VIVARIUM_FIXTURES"
_ENV_WORKER_IMAGE = "VIVARIUM_WORKER_IMAGE"
_ENV_ENGINE = "VIVARIUM_CONTAINER_ENGINE"

# Per-tool tolerances. lua's large VM (computed-goto dispatch, many small helpers) and zlib's
# asm/intrinsic paths give Ghidra slightly more to miss/merge, so their bars are a touch looser;
# cJSON (small, self-contained) holds the default.
_THRESHOLDS: dict[str, Thresholds] = {
    "cjson": Thresholds(function_recall=0.90, edge_recall=0.85),
    "zlib": Thresholds(function_recall=0.85, edge_recall=0.75),
    "lua": Thresholds(function_recall=0.85, edge_recall=0.70),
}
_DEFAULT_THRESHOLDS = Thresholds(function_recall=0.85, edge_recall=0.75)


def _truthy(v: str | None) -> bool:
    """Return whether an env flag is set to a truthy token."""
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


def _skip_reason() -> str | None:
    """Return a human reason to skip the whole module, or None if all prerequisites are met."""
    if not _truthy(os.environ.get(_ENV_INTEGRATION)):
        return f"{_ENV_INTEGRATION} not set (gated real-worker e2e)"
    fixtures = os.environ.get(_ENV_FIXTURES, "").strip()
    if not fixtures or not (Path(fixtures) / "index.json").is_file():
        return f"{_ENV_FIXTURES} not set or missing index.json (run build_fixtures.py)"
    if not os.environ.get(_ENV_WORKER_IMAGE, "").strip():
        return f"{_ENV_WORKER_IMAGE} not set (pinned worker image required)"
    engine = os.environ.get(_ENV_ENGINE, "podman")
    if shutil.which(engine) is None:
        return f"container engine {engine!r} not found on PATH"
    return None


_SKIP = _skip_reason()
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]


def _fixture_tools() -> list[str]:
    """Tool names from the fixtures index (empty when fixtures are absent → no params, skipped)."""
    fixtures = os.environ.get(_ENV_FIXTURES, "").strip()
    if not fixtures:
        return []
    index = Path(fixtures) / "index.json"
    if not index.is_file():
        return []
    return [t["tool"] for t in json.loads(index.read_text()).get("tools", [])]


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured JSON output from an MCP ``CallToolResult`` (fail on error)."""
    if getattr(result, "isError", False):
        raise AssertionError(f"tool returned an error envelope: {getattr(result, 'content', None)}")
    sc = getattr(result, "structuredContent", None)
    if isinstance(sc, dict):
        return sc
    # Fallback: first text content block is the serialized model.
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parsed: dict[str, Any] = json.loads(text)
            return parsed
    raise AssertionError("no structured content in tool result")


def _hexes_to_ints(values: Iterable[Any]) -> set[int]:
    """Parse a list of hex address strings to ints."""
    return {int(v, 16) for v in values}


async def _drive_one(tool: str, fixtures_dir: Path) -> None:
    """Run the full stdio journey for one tool and assert the ground-truth comparison passes."""
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    stripped = fixtures_dir / f"{tool}.stripped"
    truth_doc = json.loads((fixtures_dir / f"{tool}.groundtruth.json").read_text())
    truth = GroundTruth.from_json(truth_doc)

    # Launch the real server (composition root) over stdio with the real adapter; the worker
    # image + engine are taken from the environment (the adapter spawns the worker container).
    params = StdioServerParameters(
        command="python",
        args=["-m", "vivarium"],
        env={**os.environ, "VIVARIUM_IMPORT_ROOT": str(fixtures_dir)},
    )
    timeout = timedelta(seconds=int(os.environ.get("VIVARIUM_E2E_TIMEOUT", "600")))

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        created = _structured(await session.call_tool("session_create", {}))
        sid = created["session_id"]
        try:
            await session.call_tool(
                "session_import",
                {"session_id": sid, "source_ref": str(stripped)},
                read_timeout_seconds=timeout,
            )
            await session.call_tool(
                "session_analyze", {"session_id": sid}, read_timeout_seconds=timeout
            )

            # Recovered functions (paginate until not truncated).
            recovered_addrs: set[int] = set()
            offset = 0
            while True:
                page = _structured(
                    await session.call_tool(
                        "list_functions", {"session_id": sid, "offset": offset, "limit": 1000}
                    )
                )
                fns = page.get("functions", [])
                recovered_addrs |= {int(f["address"], 16) for f in fns}
                if not page.get("truncated") or not fns:
                    break
                offset += len(fns)

            cg = _structured(
                await session.call_tool(
                    "call_graph", {"session_id": sid, "max_nodes": 50000, "max_edges": 200000}
                )
            )
            recovered_edges = {
                (int(e["from_address"], 16), int(e["to_address"], 16)) for e in cg.get("edges", [])
            }

            order = _structured(await session.call_tool("analysis_order", {"session_id": sid}))
            components = [_hexes_to_ints(c["members"]) for c in order.get("components", [])]
            analysis_order = [sorted(c) for c in components]

            result = compare(
                truth,
                recovered_function_addrs=recovered_addrs,
                recovered_edges=recovered_edges,
                analysis_order=analysis_order,
                thresholds=_THRESHOLDS.get(tool, _DEFAULT_THRESHOLDS),
            )
            assert result.passed, (
                f"[{tool}] ground-truth comparison failed: {result.summary()} | "
                f"missing_functions={result.missing_functions[:10]} "
                f"missing_edges={result.missing_edges[:10]} "
                f"leaf_first_violations={result.leaf_first_violations[:10]} | {result.notes}"
            )
        finally:
            closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
            # Containment invariant (ADR-002): the per-session store is wiped on close.
            assert closed.get("store_wiped") is True


@pytest.mark.parametrize("tool", _fixture_tools())
def test_groundtruth_recovery(tool: str) -> None:
    """Ghidra's recovery of a real stripped OSS tool matches the source-derived ground truth.

    Full stdio → real worker journey per tool; recovered functions/edges/leaf-first order are
    scored against the unstripped DWARF/disasm truth with per-tool tolerances.
    """
    fixtures_dir = Path(os.environ[_ENV_FIXTURES])
    asyncio.run(_drive_one(tool, fixtures_dir))
