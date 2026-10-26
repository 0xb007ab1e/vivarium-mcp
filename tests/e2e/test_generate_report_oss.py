"""Live ADR-078 documentation-generation pipeline e2e (GATED, real worker).

Proves the Tier-0 report + Tier-1 whole-program atlas end-to-end against a REAL imported + analyzed
binary (the benign OSS fixture), over the production MCP server (stdio) — not the hermetic
unit/abuse harness with fakes. It exercises the real plumbing: a seeded annotation flows through
``session_export_annotations`` → ``compose_findings``, and the real ``program_summary`` /
``call_graph`` / ``list_functions`` flow through ``compose_atlas`` → projection → render.

Gated like the other ``_oss`` real-worker e2e: needs ``VIVARIUM_INTEGRATION`` + built fixtures +
a worker image + a container engine; otherwise the module skips cleanly. Runs under
``.github/workflows/e2e-groundtruth.yml``.
"""

from __future__ import annotations

import asyncio

import pytest

from tests.e2e.test_abuse_composite_oss import _enable_structural, _open_imported, _unwrap
from tests.e2e.test_abuse_containment_oss import (
    _SKIP,
    _fixtures_dir,
    _server_params,
    _structured,
    _timeout,
)
from tests.e2e.test_abuse_structural_oss import _list_first_function_addr

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]

_EXPECTED_SOURCES = {
    "session_export_annotations",
    "program_summary",
    "call_graph",
    "list_functions",
    "xrefs_to",  # Tier-1 xref drill-down into the top-fan-in functions (ADR-078)
}


async def _drive_generate_report() -> None:
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "gen-report")  # create + import(OSS) + analyze
        await _enable_structural(session, sid)  # write consent (annotation write below)
        addr = await _list_first_function_addr(session, sid)

        # Seed a Tier-0 finding: an in-session annotation the report composes from.
        _structured(
            await session.call_tool(
                "set_comment",
                {
                    "session_id": sid,
                    "address": addr,
                    "comment_type": "EOL",
                    "text": "seed-finding",
                },
                read_timeout_seconds=_timeout(),
            )
        )

        out = _structured(
            await session.call_tool(
                "session_generate_report",
                {
                    "session_id": sid,
                    "atlas": True,
                    "include_html": True,
                    "title": "ADR-078 e2e report",
                },
                read_timeout_seconds=_timeout(),
            )
        )

        # Tier-0 findings: the seeded annotation appears as a composed record.
        assert out["findings"], "expected >=1 finding from the seeded annotation"
        assert "set_comment" in {f["kind"] for f in out["findings"]}

        # Provenance manifest: all four reused read-only sources, authoritative program hash.
        assert set(out["manifest"]["generated_from"]) == _EXPECTED_SOURCES
        assert out["manifest"]["program_sha256"]

        # Tier-1 atlas: a REAL whole-program call graph from the worker.
        atlas = out["atlas"]
        assert atlas is not None, "expected an atlas when atlas=True"
        assert atlas["summary"]["program_sha256"] == out["manifest"]["program_sha256"]
        assert atlas["summary"]["function_count"] >= 1
        assert atlas["nodes"], "expected call-graph nodes for a real analyzed binary"
        assert atlas["edges"], "cJSON has a rich internal call graph"
        edge = atlas["edges"][0]
        assert edge["from_address"] and edge["to_address"]
        # Node/function name leaves are Untrusted-wrapped + (C)-projected (inert).
        assert _unwrap(atlas["nodes"][0]["name"]) is not None

        # Tier-1 xref drill-down: the top-fan-in (most-referenced) functions have referrers in a
        # rich call graph, so the bounded xrefs_to pull populates server-safe scalar edges.
        assert atlas["xrefs"], "expected xref edges into the top-fan-in functions"
        xref = atlas["xrefs"][0]
        assert xref["from_address"] and xref["to_address"] and xref["ref_type"]

        # The self-contained HTML artifact (Untrusted-wrapped → unwrap .value).
        html = _unwrap(out["html"])
        assert isinstance(html, str)
        assert "<html" in html.lower()
        assert "<script" not in html.lower()  # scriptless (A)

        closed = _structured(await session.call_tool("session_close", {"session_id": sid}))
        assert closed.get("store_wiped") is True


def test_generate_report_atlas_over_real_worker() -> None:
    """ADR-078 Tier-0 + Tier-1 pipeline end-to-end on a real imported + analyzed binary."""
    asyncio.run(_drive_generate_report())
