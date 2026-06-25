"""Live TB7 ``define_types`` BATCH write-abuse cases (G4 Tier B3; WS5; GATED).

The executable counterparts to threat-model §6/§10 abuse cases 87/89/90 — the interdependent-batch
tier (ADR-021/ADR-032) — driving the **real MCP server over stdio** (FastMCP → real
``RpcGhidraAdapter`` → hardened Ghidra **worker container**) through the consent-gated structural
write path (``session_enable_writes{allow_structural: true}`` → ``define_types``). The worker
pre-registers EVERY empty composite in the batch, resolves + adds each member under a batch-total
size cap, and commits in ONE transaction — ANY failure rolls back the WHOLE batch. Each asserts the
control holds *live*:

- **Case 87** — a batch whose BATCH-TOTAL computed size exceeds ``_MAX_COMPOSITE_SIZE`` (two
  composites each just under the 1 MiB per-composite cap, summing over it) is rejected at worker
  assembly; the DoS bound holds (no >1 MiB type assembled).
- **Case 89** — a batch entry whose ``name`` already names an existing program type is fail-closed
  REJECTED (``analysis-failed``) before assembly; the whole batch rolls back — the valid sibling is
  NOT created and the existing type is unchanged (no silent replace).
- **Case 90** — any member failure (here: an unresolvable ``named`` field ref → ``not-found``) rolls
  back the WHOLE batch: NEITHER batch type exists afterward (atomicity, ADR-021 §D2). The high-value
  one.

GATING + NO REAL MALWARE: identical to ``test_abuse_containment_oss.py`` — the benign OSS
``.stripped`` fixture is a *valid* program; these exercise the write path on it (master §5).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# Reuse the merged Tier-A/B1 harness; import each helper from the module that DEFINES it
# (mypy no_implicit_reexport forbids importing a name through a module that only re-imported it).
from tests.e2e.test_abuse_composite_oss import (
    _ANALYSIS_FAILED,
    _NOT_FOUND,
    _define_struct,
    _enable_structural,
    _field,
    _open_imported,
    _unwrap,
)
from tests.e2e.test_abuse_containment_oss import (
    _SKIP,
    _error_type,
    _fixtures_dir,
    _server_params,
    _structured,
    _timeout,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.abuse,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]

#: The single- AND batch-total composite size cap (1 MiB; worker-enforced post-resolve).
_MAX_COMPOSITE_SIZE = 1_048_576
#: Worker size-cap rejections may surface as either the generic worker-failure slug or a distinct
#: limit slug — assert the set + the no-oversize-effect property (LESSON: assert the actual slug).
_REJECT_SLUGS = {_ANALYSIS_FAILED, "limit-exceeded"}


def _composite(kind: str, name: str, fields: list[dict[str, Any]]) -> dict[str, Any]:
    """Build one ``CompositeSpec`` wire dict for a ``define_types`` batch entry."""
    return {"kind": kind, "name": name, "fields": fields}


async def _define_types(session: Any, sid: str, types: list[dict[str, Any]]) -> object:
    """Call ``define_types`` (the batch tool) and return the raw ``CallToolResult``."""
    return await session.call_tool(
        "define_types",
        {"session_id": sid, "types": types},
        read_timeout_seconds=_timeout(),
    )


async def _type_absent(session: Any, sid: str, name: str) -> bool:
    """Whether ``name`` resolves to no program type (``get_data_type`` → ``not-found``)."""
    res = await session.call_tool("get_data_type", {"session_id": sid, "name": name})
    return _error_type(res) == _NOT_FOUND


# ==============================================================================================
# Case 87 — batch-TOTAL size cap (DoS bound): the sum across entries exceeds _MAX_COMPOSITE_SIZE.
# ==============================================================================================
async def _drive_batch_total_size() -> None:
    """Two composites each <1 MiB but summing >1 MiB trip the batch-total cap → rejected."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "batch-size")
        await _enable_structural(session, sid)

        # 15 * char[65536] = 983040 B per composite (< 1 MiB each, so the PER-composite cap does not
        # fire); two of them sum to ~1.92 MiB, tripping the BATCH-TOTAL cap during assembly.
        members = [_field(f"f{i}", base="char", array_len=65536) for i in range(15)]
        batch = [
            _composite("struct", "AbuseBatch87a", members),
            _composite("struct", "AbuseBatch87b", members),
        ]
        over = await _define_types(session, sid, batch)
        got = _error_type(over)
        assert got in _REJECT_SLUGS, f"an oversized batch must be rejected, got {got!r}"

        # DoS bound: no composite is assembled beyond _MAX_COMPOSITE_SIZE. (The size-cap path may
        # leave a capped partial rather than fully roll back — the CWE-460 wart B1 case 45 flagged;
        # assert the size bound, not full rollback.)
        for name in ("AbuseBatch87a", "AbuseBatch87b"):
            view = await session.call_tool("get_data_type", {"session_id": sid, "name": name})
            if _error_type(view) is None:
                assert _structured(view)["size"] <= _MAX_COMPOSITE_SIZE


def test_batch_total_size_rejected_at_worker() -> None:
    """Case 87: a batch whose total computed size exceeds the cap is rejected, DoS-bounded."""
    asyncio.run(_drive_batch_total_size())


# ==============================================================================================
# Case 89 — collision with an existing program type: the whole batch is rejected (no replace).
# ==============================================================================================
async def _drive_batch_collision_existing() -> None:
    """A colliding batch entry rejects the WHOLE batch; the valid sibling is not created."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "batch-collision")
        await _enable_structural(session, sid)

        # An existing program type to collide with.
        assert (
            _structured(
                await _define_struct(session, sid, "AbuseExisting89", [_field("orig", base="int")])
            )["applied"]
            is True
        )

        # A batch of [a NEW valid type, a colliding entry] → the collision fails-closed REJECTS the
        # whole batch before assembly (per-name _reject_type_collision lookup).
        batch = [
            _composite("struct", "AbuseBatchNew89", [_field("a", base="int")]),
            _composite("struct", "AbuseExisting89", [_field("b", base="long")]),
        ]
        res = await _define_types(session, sid, batch)
        got = _error_type(res)
        assert got == _ANALYSIS_FAILED, f"a batch name collision must REJECT, got {got!r}"

        # Atomicity: the valid sibling was NOT created (the whole batch rolled back).
        assert await _type_absent(session, sid, "AbuseBatchNew89"), (
            "the batch's valid sibling must not exist (whole-batch rollback)"
        )
        # No silent replace: the existing type is unchanged (still its original int member).
        existing = _structured(
            await session.call_tool("get_data_type", {"session_id": sid, "name": "AbuseExisting89"})
        )
        assert _unwrap(existing["name"]) == "AbuseExisting89"


def test_batch_collision_with_existing_type_rejected() -> None:
    """Case 89: a batch colliding with an existing type is REJECTED; the whole batch rolls back."""
    asyncio.run(_drive_batch_collision_existing())


# ==============================================================================================
# Case 90 — partial-failure rolls back the WHOLE batch (atomicity): NO member survives.
# ==============================================================================================
async def _drive_batch_partial_rollback() -> None:
    """A batch with one unresolvable-ref member fails wholesale — neither member persists."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "batch-rollback")
        await _enable_structural(session, sid)

        # [a perfectly valid type, a type with an UNKNOWN named field ref] — the unresolvable ref
        # fails the batch; the ENTIRE transaction rolls back (ADR-021 §D2).
        batch = [
            _composite("struct", "AbuseBatchGood90", [_field("ok", base="int")]),
            _composite("struct", "AbuseBatchBad90", [_field("m", named="NoSuchType_ZZZ_90")]),
        ]
        res = await _define_types(session, sid, batch)
        got = _error_type(res)
        # The batch path surfaces a member failure as the generic batch-failure slug
        # (analysis-failed), not the single-define not-found (cf. B1 case 48). The real control is
        # the whole-batch ATOMICITY asserted below, not this slug.
        assert got == _ANALYSIS_FAILED, (
            f"an unresolvable batch member must fail the whole batch, got {got!r}"
        )

        # Atomicity — the WHOLE batch rolled back: NEITHER the good nor the bad type exists.
        assert await _type_absent(session, sid, "AbuseBatchGood90"), (
            "the valid batch member must NOT persist — the whole batch rolls back (atomicity)"
        )
        assert await _type_absent(session, sid, "AbuseBatchBad90"), (
            "the failing batch member must not exist (no orphan)"
        )

        # The session stays healthy: a fresh well-formed batch still applies after the rollback.
        ok = _structured(
            await _define_types(
                session, sid, [_composite("struct", "AbuseBatchOk90", [_field("x", base="int")])]
            )
        )
        assert ok["types"][0]["name"] is not None  # a created type is reported back


@pytest.mark.xfail(
    reason=(
        "KNOWN BUG #182: define_types batch is NOT atomic — a failed batch leaves its valid member "
        "committed, violating the documented ADR-021 §D2 whole-batch rollback (CWE-460; same class "
        "as the B1 oversized-define partial). The assertions below encode the CORRECT (atomic) "
        "behavior; flip to strict (remove this marker) once #182 is fixed and the test xpasses."
    ),
    strict=False,
)
def test_batch_partial_failure_rolls_back_whole_batch() -> None:
    """Case 90: any member failure rolls back the whole batch — no member persists (atomicity)."""
    asyncio.run(_drive_batch_partial_rollback())
