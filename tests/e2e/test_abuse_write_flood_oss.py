"""Live TB7 write-flood DoS-bound abuse case (G4; threat-model §10 case 19; GATED).

Drives the **real MCP server over stdio** (FastMCP → real ``RpcGhidraAdapter`` → hardened Ghidra
**worker container**) like the other ``test_abuse_*_oss.py`` suites, through the consent-gated write
path. Case 19's control: *a burst of writes is bounded — each write is one bounded transaction (no
unbounded growth), and the burst neither hangs nor exhausts the session.*

What is asserted LIVE here (the stdio-client-triggerable part): a concurrent burst of annotation
writes (``set_comment``) at one consented session is fully handled as bounded transactions — every
call returns (none hangs/crashes the transport), the worker processes the burst (it is serialized +
bounded, not exhausted), and the session stays RESPONSIVE afterward (a read still succeeds).

The remaining case-19 sub-properties are NOT stdio-client-triggerable and are covered elsewhere:
  * **per-tool timeout / a hung write kills the worker** — the timeout MECHANISM is proven live by
    the analysis-timeout case in ``test_abuse_containment_oss.py``; a fast annotation write cannot
    be made to hang from a client.
  * **(HTTP) rate limit** — an HTTP-transport (TB6) control, in ``test_http_abuse.py``; stdio has
    no rate limiter.
  * **each write is one bounded transaction (rollback on failure)** — proven by the structural
    rollback suite (composite/structural/batch ``test_abuse_*_oss.py``).

GATING + NO REAL MALWARE: identical to ``test_abuse_containment_oss.py`` — the benign OSS
``.stripped`` fixture is a *valid* program; this exercises the write path on it (master §5).
"""

from __future__ import annotations

import asyncio

import pytest

from tests.e2e.test_abuse_composite_oss import _enable_structural, _open_imported
from tests.e2e.test_abuse_containment_oss import (
    _SKIP,
    _error_type,
    _fixtures_dir,
    _server_params,
    _structured,
    _timeout,
)
from tests.e2e.test_abuse_structural_oss import _list_first_function_addr

pytestmark = [
    pytest.mark.integration,
    pytest.mark.abuse,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]

#: A burst size comfortably beyond any natural single-request count (still bounded; no DoS intent —
#: the point is that the SERVER bounds it, serializing at the one-per-session worker).
_FLOOD_N = 64


async def _drive_write_flood() -> None:
    """Fire a concurrent burst of annotation writes; assert all bounded + the session survives."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "write-flood")
        await _enable_structural(session, sid)  # write consent (annotation writes need only this)
        addr = await _list_first_function_addr(session, sid)

        async def _one(i: int) -> object:
            return await session.call_tool(
                "set_comment",
                {"session_id": sid, "address": addr, "comment_type": "EOL", "text": f"flood-{i}"},
                read_timeout_seconds=_timeout(),
            )

        # The burst: if any write HUNG, gather would never return (the gated job's wall-clock would
        # trip) — returning N results at all is the first half of "bounded".
        results = await asyncio.gather(*(_one(i) for i in range(_FLOOD_N)))
        assert len(results) == _FLOOD_N

        # Each write is a bounded transaction: a structured success (applied) OR a bounded error
        # envelope — never an unbounded/garbage shape. The worker PROCESSED the burst (serialized +
        # bounded at the one-per-session worker), not exhausted: a healthy majority committed.
        applied = sum(1 for r in results if _error_type(r) is None)
        assert applied >= _FLOOD_N // 2, (
            f"the worker must bound a write burst, only {applied}/{_FLOOD_N} applied"
        )

        # The session stays RESPONSIVE after the flood (not hung/exhausted) — a read still succeeds.
        status = _structured(await session.call_tool("session_status", {"session_id": sid}))
        assert status["session_id"] == sid


def test_write_flood_is_bounded_by_caps() -> None:
    """Case 19: a write burst is bounded — handled as bounded txns; the session stays healthy."""
    asyncio.run(_drive_write_flood())
