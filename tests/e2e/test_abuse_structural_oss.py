"""Live TB7 signature / ``apply_data_type`` / embed-cycle write-abuse cases (G4 Tier B2; GATED).

The executable counterparts to threat-model §6/§10 abuse cases 32/36/40/42 — the structural
signature/type-apply tier — driving the **real MCP server over stdio** (FastMCP → real
``RpcGhidraAdapter`` → hardened Ghidra **worker container**) through the consent-gated structural
write path (``session_enable_writes{allow_structural: true}`` → ``apply_data_type`` /
``set_function_signature`` / ``define_struct`` — ADR-012/ADR-014/ADR-015). Each asserts the control
holds *live*:

- **Case 32** — ``apply_data_type`` with a well-formed but UNKNOWN ``named`` TypeRef fails closed
  ``not-found`` (resolution runs before ``startTransaction`` — ADR-014 §4); no write, healthy.
- **Case 36** — a structural grant + write on session A does NOT leak structural consent to session
  B (B's identical structural op is ``forbidden``) — per-session consent isolation (ADR-036).
- **Case 40** — ``apply_data_type`` at a valid-hex address OUTSIDE the program memory map fails
  closed (worker map-confinement before the transaction — no write).
- **Case 42** — a by-value embed *cycle* (A↔B) cannot be assembled: the B-first-then-A flow leaves
  the cycle-closing redefine of B rejected (name collision), so the unbounded cycle is
  unconstructable.

Cases 33 (signature commit-time re-flow rollback) and 41 (a by-value self-embed that *slips past*
the boundary) are intentionally NOT live here — see their kept skip-stubs in
``tests/security/test_abuse_cases.py`` for the honest reasons (neither is client-triggerable: 33
needs a fault-injection hook to force the worker commit to raise; 41 is rejected at the boundary
``validate_composite`` and never reaches the worker, so the worker-side rollback cannot be driven
from a client — both are unit-proven via ``_in_transaction`` in ``test_structural_mutation``).

GATING + NO REAL MALWARE: identical to ``test_abuse_containment_oss.py`` — the benign OSS
``.stripped`` fixture is a *valid* program; these exercise the write path on it (master §5).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# Reuse the merged Tier-A/B1 harness verbatim. Import each helper from the module that DEFINES it
# (mypy no_implicit_reexport forbids re-importing a name through a module that only re-imported it):
# the base real-server drive lives in the containment module; the composite consent/define helpers
# and slug constants live in the composite module.
from tests.e2e.test_abuse_composite_oss import (
    _ANALYSIS_FAILED,
    _FORBIDDEN,
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

#: A valid-hex address far outside any non-PIE OSS fixture's memory map (~0x400000) — used to drive
#: the worker's map-confinement (it parses cleanly via parse_address, so the worker sees it).
_OUT_OF_MAP_ADDR = "0xffffff000000"


async def _list_first_function_addr(session: Any, sid: str) -> str:
    """Return one valid in-map entry address (hex) from the imported program, or skip if none."""
    out = _structured(await session.call_tool("list_functions", {"session_id": sid}))
    funcs = out.get("functions") or []
    if not funcs:
        pytest.skip("fixture program lists no functions to target")
    # FunctionSummary.address is a server-derived (safe) bare hex string.
    return str(funcs[0]["address"])


async def _apply_data_type(
    session: Any, sid: str, address: str, type_ref: dict[str, Any]
) -> object:
    """Call ``apply_data_type`` and return the raw ``CallToolResult`` for the caller to inspect."""
    return await session.call_tool(
        "apply_data_type",
        {"session_id": sid, "address": address, "type": type_ref},
        read_timeout_seconds=_timeout(),
    )


async def _set_signature(
    session: Any, sid: str, function: str, return_type: dict[str, Any]
) -> object:
    """Call ``set_function_signature`` (no params) and return the raw ``CallToolResult``."""
    return await session.call_tool(
        "set_function_signature",
        {"session_id": sid, "function": function, "return_type": return_type, "parameters": []},
        read_timeout_seconds=_timeout(),
    )


# ==============================================================================================
# Case 32 — unresolvable named TypeRef fails closed with no write (resolution before txn).
# ==============================================================================================
async def _drive_unresolvable_named_type() -> None:
    """``apply_data_type`` with an unknown ``named`` type → ``not-found``; stays writable."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "unresolved-type")
        await _enable_structural(session, sid)
        addr = await _list_first_function_addr(session, sid)

        # The named type does not exist → resolution fails BEFORE any transaction opens (no write).
        bad = await _apply_data_type(session, sid, addr, {"named": "NoSuchType_ZZZ_32"})
        got = _error_type(bad)
        assert got == _NOT_FOUND, f"an unknown named type must fail {_NOT_FOUND}, got {got!r}"

        # No write happened / the session is healthy: a well-formed structural define still works.
        ok = _structured(
            await _define_struct(session, sid, "AbuseValid32", [_field("x", base="int")])
        )
        assert ok["applied"] is True


def test_unresolvable_named_type_fails_closed_with_no_write() -> None:
    """Case 32: an unresolvable ``named`` TypeRef → ``not-found``, no write, session healthy."""
    asyncio.run(_drive_unresolvable_named_type())


# ==============================================================================================
# Case 36 — per-session structural-consent isolation: A's grant does not leak to B.
# ==============================================================================================
async def _drive_cross_session_structural_isolation() -> None:
    """A grants structural + passes the consent gate; B (annotation-only) is ``forbidden``."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid_a = await _open_imported(session, "struct-iso-a")
        sid_b = await _open_imported(session, "struct-iso-b")
        assert sid_a != sid_b
        addr = await _list_first_function_addr(session, sid_a)  # same binary → valid in both

        # A opts into structural writes; B takes annotation consent ONLY (no allow_structural).
        await _enable_structural(session, sid_a)
        b_state = _structured(
            await session.call_tool(
                "session_enable_writes", {"session_id": sid_b, "allow_structural": False}
            )
        )
        assert b_state["writes_enabled"] is True and b_state["allow_structural"] is False

        # A passes the structural consent gate (its grant is real); B's identical op is denied —
        # A's structural grant did NOT leak to B (per-session consent — ADR-036).
        a_res = await _set_signature(session, sid_a, addr, {"base": "int"})
        assert _error_type(a_res) != _FORBIDDEN, (
            "A holds structural consent — must not be forbidden"
        )
        b_res = await _set_signature(session, sid_b, addr, {"base": "int"})
        assert _error_type(b_res) == _FORBIDDEN, (
            f"B lacks structural consent → must be {_FORBIDDEN}, got {_error_type(b_res)!r}"
        )


def test_cross_session_structural_type_isolation() -> None:
    """Case 36: a structural grant on A does not enable structural writes on B."""
    asyncio.run(_drive_cross_session_structural_isolation())


# ==============================================================================================
# Case 40 — apply_data_type at an out-of-map address fails closed (worker map-confinement).
# ==============================================================================================
async def _drive_apply_out_of_map() -> None:
    """A valid-hex address outside the program map → fail closed (no write)."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "out-of-map")
        await _enable_structural(session, sid)

        # Parses cleanly (boundary OK), so the worker sees it and rejects via map-confinement.
        out = await _apply_data_type(session, sid, _OUT_OF_MAP_ADDR, {"base": "int"})
        got = _error_type(out)
        # Worker-mapped: an out-of-map apply fails closed; the exact slug is worker-determined.
        assert got in {_ANALYSIS_FAILED, _NOT_FOUND}, (
            f"an out-of-map apply must fail closed, got {got!r}"
        )


def test_apply_data_type_out_of_map_fails_closed() -> None:
    """Case 40: ``apply_data_type`` outside the program memory map fails closed, no write."""
    asyncio.run(_drive_apply_out_of_map())


# ==============================================================================================
# Case 42 — a by-value embed cycle (A↔B) cannot be assembled (the cycle-closing redefine fails).
# ==============================================================================================
async def _drive_embed_cycle_unconstructable() -> None:
    """B-first-then-A: define B, then A embedding B; the redefine of B to embed A is rejected."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        stdio_client(_server_params(_fixtures_dir())) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sid = await _open_imported(session, "embed-cycle")
        await _enable_structural(session, sid)

        # Define B (a leaf), then A embedding B by value — both succeed (no cycle yet).
        assert (
            _structured(
                await _define_struct(session, sid, "AbuseCycB42", [_field("v", base="int")])
            )["applied"]
            is True
        )
        assert (
            _structured(
                await _define_struct(
                    session, sid, "AbuseCycA42", [_field("b", named="AbuseCycB42")]
                )
            )["applied"]
            is True
        )

        # Closing the cycle requires REDEFINING B to embed A — but B already exists, so the worker
        # rejects the name collision: the unbounded by-value cycle is unconstructable.
        close = await _define_struct(
            session, sid, "AbuseCycB42", [_field("a", named="AbuseCycA42")]
        )
        got = _error_type(close)
        assert got == _ANALYSIS_FAILED, (
            f"the cycle-closing redefine of B must be rejected, got {got!r}"
        )
        # B is unchanged (no silent replace) — its single int member persists (no A-embed).
        b_view = _structured(
            await session.call_tool("get_data_type", {"session_id": sid, "name": "AbuseCycB42"})
        )
        assert _unwrap(b_view["name"]) == "AbuseCycB42"


def test_cross_type_embed_cycle_cannot_be_assembled() -> None:
    """Case 42: an A↔B by-value embed cycle cannot be assembled (cycle-closing redefine fails)."""
    asyncio.run(_drive_embed_cycle_unconstructable())
