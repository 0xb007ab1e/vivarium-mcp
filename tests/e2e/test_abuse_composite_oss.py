"""Live TB7 composite/``define_struct`` write-abuse cases (G4 Tier B1; WS5; GATED).

The executable counterparts to threat-model §6/§10 abuse cases 44/45/48/51 — the structural-write
tier — driving the **real MCP server over stdio** (FastMCP → real ``RpcGhidraAdapter`` → hardened
Ghidra **worker container**) exactly like ``test_abuse_containment_oss.py``, through the
consent-gated write path (``session_enable_writes{allow_structural: true}`` → ``define_struct`` /
``define_union`` — ADR-012/ADR-015). Each asserts the control holds *live*:

- **Case 44** — a ``define_struct`` whose ``name`` already names a type is REJECTED
  (``analysis-failed``) with NO silent replace; the original type is unchanged.
- **Case 45** — a composite whose total computed size exceeds ``_MAX_COMPOSITE_SIZE`` (256 fields
  of ``char[65536]`` = 16 MiB) is rejected ``limit-exceeded`` at worker assembly — no type created.
- **Case 48** — a member ``FieldSpec.type`` with a well-formed but UNKNOWN ``named`` ref surfaces
  ``not-found`` with no partial/orphan type (the struct is absent afterward; a valid define works).
- **Case 51** — ``allow_structural`` + a ``define_struct`` on session A does NOT enable writes on
  session B (B stays ``forbidden``) nor leak A's type into B's independent store.

Case 54 (commit-time rollback) is intentionally NOT live here — forcing the worker's
``addDataType``/commit to *raise* needs a fault-injection hook the client cannot drive; its rollback
invariant is proven at the unit level (``_in_transaction`` in ``test_structural_mutation``) and the
"no orphan after a failed define" guarantee is observed live as the **fail-before-mutate** rejection
of cases 45/48 (#182: both reject pre-txn — size and unknown-ref — so no partial type is ever
opened). See its kept skip-stub in ``tests/security/test_abuse_cases.py``.

GATING + NO REAL MALWARE: identical to ``test_abuse_containment_oss.py`` — the benign OSS
``.stripped`` fixture is a *valid* program; these exercise the write path on it (master §5).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# Reuse the merged Tier-A harness verbatim (skip-guard, real-server drive, and the FIXED envelope
# detector that reads the {type,title,detail} triple from a content text block — see that module).
from tests.e2e.test_abuse_containment_oss import (
    _SKIP,
    _create,
    _error_type,
    _first_valid_fixture,
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

#: Error-envelope ``type`` slugs (mirror ``core.errors.ErrorType``).
_NOT_FOUND = "not-found"
_ANALYSIS_FAILED = "analysis-failed"
_LIMIT_EXCEEDED = "limit-exceeded"  # size/DoS cap rejection (ADR-021 §Bounds)
_FORBIDDEN = "forbidden"  # consent gate denies an owned-but-unconsented write (ADR-036)


def _unwrap(field: Any) -> Any:
    """Unwrap a binary-derived field from its untrusted-data envelope (ADR-005).

    Program-sourced string fields (a type's ``name``/``definition``) arrive wrapped as
    ``{"value": ..., "origin": ..., "truncated": ..., "encoding": ...}``; pass other values through.
    """
    if isinstance(field, dict) and "value" in field:
        return field["value"]
    return field


def _field(
    name: str, *, base: str | None = None, named: str | None = None, array_len: int | None = None
) -> dict[str, Any]:
    """Build a ``FieldSpec`` wire dict (exactly one of ``base``/``named`` identifies the leaf)."""
    type_ref: dict[str, Any] = {}
    if base is not None:
        type_ref["base"] = base
    if named is not None:
        type_ref["named"] = named
    if array_len is not None:
        type_ref["array_len"] = array_len
    return {"name": name, "type": type_ref}


async def _open_imported(session: Any, label: str) -> str:
    """``session_create`` → ``session_import`` (the benign OSS fixture) → ``session_analyze``.

    Returns the ready session id. Writes still require a separate ``session_enable_writes``.
    """
    fixture = _first_valid_fixture()
    sid: str = _structured(await _create(session, label))["session_id"]
    _structured(
        await session.call_tool(
            "session_import",
            {"session_id": sid, "source_ref": str(fixture)},
            read_timeout_seconds=_timeout(),
        )
    )
    _structured(
        await session.call_tool(
            "session_analyze", {"session_id": sid}, read_timeout_seconds=_timeout()
        )
    )
    return sid


async def _enable_structural(session: Any, sid: str) -> None:
    """Grant write consent + the structural opt-in to ``sid`` and assert the grant took."""
    state = _structured(
        await session.call_tool(
            "session_enable_writes", {"session_id": sid, "allow_structural": True}
        )
    )
    assert state["writes_enabled"] is True and state["allow_structural"] is True


async def _define_struct(session: Any, sid: str, name: str, fields: list[dict[str, Any]]) -> object:
    """Call ``define_struct`` and return the raw ``CallToolResult`` for the caller to inspect."""
    return await session.call_tool(
        "define_struct",
        {"session_id": sid, "name": name, "fields": fields},
        read_timeout_seconds=_timeout(),
    )


# ==============================================================================================
# Case 44 — name-collision REJECT (no silent replace): the second define of an existing name fails.
# ==============================================================================================
async def _drive_name_collision() -> None:
    """A second ``define_struct`` of an existing name is rejected; the original is unchanged."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "collide")
        await _enable_structural(session, sid)

        name = "AbuseCollide44"
        first = _structured(await _define_struct(session, sid, name, [_field("a", base="int")]))
        assert first["applied"] is True

        # Re-defining the SAME name must fail-closed REJECT — no silent replace (ADR-015 §6).
        collide = await _define_struct(session, sid, name, [_field("b", base="long")])
        got = _error_type(collide)
        assert got == _ANALYSIS_FAILED, f"name collision must REJECT, got {got!r}"

        # The original type is intact (unchanged shape) — proof there was no silent replace.
        existing = _structured(
            await session.call_tool("get_data_type", {"session_id": sid, "name": name})
        )
        # The type name is binary-derived → wrapped in the untrusted-data envelope (ADR-005).
        assert _unwrap(existing["name"]) == name


def test_name_collision_rejected_no_silent_replace() -> None:
    """Case 44: a ``define_struct`` whose name already exists is REJECTED, original unchanged."""
    asyncio.run(_drive_name_collision())


# ==============================================================================================
# Case 45 — oversized total size rejected at worker assembly (DoS bound; CWE-400/190).
# ==============================================================================================
async def _drive_oversized_total_size() -> None:
    """256 fields of ``char[65536]`` (16 MiB) exceed the 1 MiB composite cap → rejected."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "huge")
        await _enable_structural(session, sid)

        # Field count is at the MAX_FIELDS bound (256); each member is a 64 KiB char array, so the
        # worker's running size sum (16 MiB) trips _MAX_COMPOSITE_SIZE (1 MiB) during assembly.
        fields = [_field(f"f{i}", base="char", array_len=65536) for i in range(256)]
        over = await _define_struct(session, sid, "AbuseHuge45", fields)
        got = _error_type(over)
        # The worker size-checks the resolved members BEFORE the txn (#182) and surfaces the
        # precise documented slug (limit-exceeded) — not the analysis-failed the in-txn masked.
        assert got == _LIMIT_EXCEEDED, (
            f"an oversized composite must be rejected {_LIMIT_EXCEEDED}, got {got!r}"
        )
        # All-or-nothing (#182 fixed): the rejected define leaves NO type — not even the size-capped
        # partial the worker assembled before the cap tripped (the explicit
        # _remove_registered_composites rollback in _gh_define_struct removes the pre-registered
        # struct). The DoS bound also held (never assembled beyond _MAX_COMPOSITE_SIZE).
        view = await session.call_tool("get_data_type", {"session_id": sid, "name": "AbuseHuge45"})
        assert _error_type(view) == _NOT_FOUND, (
            "the rejected oversized define must leave NO partial/orphan type (ADR-021 §D2 rollback)"
        )


def test_oversized_total_size_rejected_at_worker() -> None:
    """Case 45: a composite exceeding _MAX_COMPOSITE_SIZE is rejected ``limit-exceeded``."""
    asyncio.run(_drive_oversized_total_size())


# ==============================================================================================
# Case 48 — unresolvable field TypeRef fails closed with no write (atomicity; ADR-015 §4).
# ==============================================================================================
async def _drive_unresolvable_field_typeref() -> None:
    """A member typed by an UNKNOWN ``named`` ref → ``not-found``; no orphan; session healthy."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "unresolved")
        await _enable_structural(session, sid)

        name = "AbuseUnresolved48"
        bad = await _define_struct(session, sid, name, [_field("m", named="NoSuchType_ZZZ_48")])
        got = _error_type(bad)
        assert got == _NOT_FOUND, f"an unknown field typeref must fail {_NOT_FOUND}, got {got!r}"

        # No partial/orphan type: the struct was never finalized (rolled back).
        absent = await session.call_tool("get_data_type", {"session_id": sid, "name": name})
        assert _error_type(absent) == _NOT_FOUND, "the failed struct must not exist (no orphan)"

        # The session is healthy: a well-formed define still succeeds after the rollback.
        ok = _structured(
            await _define_struct(session, sid, "AbuseValid48", [_field("x", base="int")])
        )
        assert ok["applied"] is True


def test_unresolvable_field_typeref_fails_closed_with_no_write() -> None:
    """Case 48: an unknown member typeref → ``not-found``, no orphan, session still writable."""
    asyncio.run(_drive_unresolvable_field_typeref())


# ==============================================================================================
# Case 51 — cross-session structural isolation: A's consent + type never reach B (store-I; ADR-002).
# ==============================================================================================
async def _drive_cross_session_isolation() -> None:
    """Granting structural writes + a define on A leaves B read-only with an independent store."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid_a = await _open_imported(session, "iso-a")
        sid_b = await _open_imported(session, "iso-b")
        assert sid_a != sid_b

        # A opts into structural writes and defines a type.
        await _enable_structural(session, sid_a)
        a_name = "AbuseIsoA51"
        assert (
            _structured(await _define_struct(session, sid_a, a_name, [_field("x", base="int")]))[
                "applied"
            ]
            is True
        )

        # B never granted consent → its write is denied (A's grant did not leak). Fail-closed.
        denied = await _define_struct(session, sid_b, "AbuseIsoB51", [_field("y", base="int")])
        got = _error_type(denied)
        assert got == _FORBIDDEN, f"B has no write consent → must be {_FORBIDDEN}, got {got!r}"

        # A's type is NOT visible in B's independent DataTypeManager (store isolation).
        b_view = await session.call_tool("get_data_type", {"session_id": sid_b, "name": a_name})
        assert _error_type(b_view) == _NOT_FOUND, "A's type must not appear in B's store"
        # A still has its type (sanity: A's write was real and contained to A).
        a_view = _structured(
            await session.call_tool("get_data_type", {"session_id": sid_a, "name": a_name})
        )
        assert _unwrap(a_view["name"]) == a_name


def test_cross_session_composite_isolation() -> None:
    """Case 51: A's structural consent + type do not enable or leak into session B."""
    asyncio.run(_drive_cross_session_isolation())
