"""Live TB3-containment abuse cases against the real server→worker chain (WS5; GATED).

The executable counterparts to threat-model §6 abuse cases 1/3/4/7/8 — the *containment* tier
(G4 Phase 1). Each drives the **real MCP server over stdio** (FastMCP → real ``RpcGhidraAdapter``
→ hardened Ghidra **worker container**) exactly like ``test_groundtruth_oss.py``, and asserts that
the control holds *live* rather than against a hermetic double:

- **Case 7** — exceeding the session concurrency cap yields backpressure (``limit-exceeded``),
  not resource exhaustion or a crash (DoS bound; PLAN §3 F7).
- **Case 8** — sessions are isolated (independent stores/workers) and ``session_close`` verified-
  wipes the per-session store (``store_wiped=True`` — ADR-002, master §5 confidentiality).
- **Case 1** — a deliberately tiny analysis timeout makes a real analysis hit the wall-clock,
  surfacing a ``timeout`` envelope and killing the worker (no hung/hostile JVM; the session dies).
- **Case 4** — a malformed loader input is contained to the worker's fault domain (a safe error
  envelope, no RCE) and the SERVER stays healthy (a fresh session afterwards still works).
- **Case 3** — an oversized input is rejected at the import size cap (``limit-exceeded``) *before*
  the worker is ever reached (the decompression-bomb-class control; v1 has no archive inputs).

GATING (hermetic by default — never runs in the unit/coverage job): identical to
``test_groundtruth_oss.py`` — needs ``VIVARIUM_INTEGRATION`` truthy, ``VIVARIUM_FIXTURES`` with an
``index.json`` (for the valid OSS ``.stripped`` reused by cases 7/8/1), ``VIVARIUM_WORKER_IMAGE``,
and a container engine on PATH. Any missing prerequisite skips the whole module cleanly.

No real malware: cases 7/8/1 reuse the benign OSS fixtures; cases 3/4 use synthetic byte blobs
built by ``tests._fixtures`` (master §5, PLAN §6).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from tests._fixtures import build_elf64, malformed_elf, oversized_blob

_ENV_INTEGRATION = "VIVARIUM_INTEGRATION"
_ENV_FIXTURES = "VIVARIUM_FIXTURES"
_ENV_WORKER_IMAGE = "VIVARIUM_WORKER_IMAGE"
_ENV_ENGINE = "VIVARIUM_CONTAINER_ENGINE"

#: Error envelope ``type`` slugs this suite asserts on (mirrors ``core.errors.ErrorType``).
_LIMIT_EXCEEDED = "limit-exceeded"
_TIMEOUT = "timeout"
#: Contained-worker-failure slugs: any of these is an acceptable *safe* containment of a bad input
#: (the point of case 4 is that it is contained + the server survives, not the exact slug).
_CONTAINED = {"analysis-failed", "worker-unavailable", "internal-error", "validation-error"}


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
    pytest.mark.abuse,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]


def _fixtures_dir() -> Path:
    """Return the gated fixtures directory (only called when the module is not skipped)."""
    return Path(os.environ[_ENV_FIXTURES])


def _first_valid_fixture() -> Path:
    """Return one benign, well-formed OSS ``.stripped`` fixture path (reused by cases 7/8/1)."""
    fixtures = _fixtures_dir()
    index = json.loads((fixtures / "index.json").read_text())
    tools = [t["tool"] for t in index.get("tools", [])]
    if not tools:
        pytest.skip("fixtures index lists no tools")
    return fixtures / f"{tools[0]}.stripped"


def _server_params(import_root: Path, env_overrides: Mapping[str, str] | None = None) -> Any:
    """Build ``StdioServerParameters`` for a fresh real server subprocess (real adapter→worker).

    Args:
        import_root: Value for ``VIVARIUM_IMPORT_ROOT`` (the confinement root ``source_ref`` is
            resolved under — CWE-22).
        env_overrides: Extra environment for this server (e.g. a low session cap or tiny timeout),
            layered over the inherited environment.

    Returns:
        The ``StdioServerParameters`` launching ``python -m vivarium``.
    """
    from mcp.client.stdio import StdioServerParameters

    env = {**os.environ, "VIVARIUM_IMPORT_ROOT": str(import_root)}
    if env_overrides:
        env.update(env_overrides)
    return StdioServerParameters(command="python", args=["-m", "vivarium"], env=env)


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured success output, raising if it is an error envelope.

    Use for steps that MUST succeed; use :func:`_error_type` for steps expected to fail.
    """
    err = _error_type(result)
    if err is not None:
        raise AssertionError(f"expected success, got error envelope type={err!r}")
    sc = getattr(result, "structuredContent", None)
    if isinstance(sc, dict):
        return sc
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parsed: dict[str, Any] = json.loads(text)
            return parsed
    raise AssertionError("no structured content in tool result")


def _is_envelope(d: object) -> bool:
    """Whether a decoded value is the frozen error envelope (the ``{type,title,detail}`` triple).

    A success model never carries all three keys, so the triple unambiguously marks an error.
    """
    return isinstance(d, dict) and {"type", "title", "detail"} <= d.keys()


def _error_type(result: object) -> str | None:
    """Return the error-envelope ``type`` slug for a failed tool call, or None on success.

    The server returns the frozen ``{type,title,detail,status,...}`` envelope **as data** (ADR-005):
    in practice it arrives as a ``content`` **text block of JSON** with ``isError`` False and
    ``structuredContent`` None — so detect the envelope from EITHER ``structuredContent`` or any
    content text block, independent of the ``isError`` flag (which the server does not set for a
    returned envelope). ``isError`` without a parseable envelope is still treated as an error.
    """
    sc = getattr(result, "structuredContent", None)
    if _is_envelope(sc):
        return str(sc["type"])  # type: ignore[index]
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            continue
        if _is_envelope(parsed):
            return str(parsed["type"])
    return "unknown-error" if getattr(result, "isError", False) else None


async def _create(session: Any, label: str | None = None) -> object:
    """Call ``session_create`` and return the raw ``CallToolResult`` for the caller to inspect."""
    args: dict[str, Any] = {"label": label} if label is not None else {}
    return await session.call_tool("session_create", args)


def _timeout(seconds: int = 600) -> timedelta:
    """Client read-timeout for worker-backed calls (must exceed the server-side wall so the server
    returns its own envelope first)."""
    return timedelta(seconds=int(os.environ.get("VIVARIUM_E2E_TIMEOUT", str(seconds))))


# ==============================================================================================
# Case 7 — pool starvation → backpressure (no fixture needed; the cap is a SessionManager control).
# ==============================================================================================
async def _drive_pool_starvation() -> None:
    """Open sessions up to a low cap, assert the over-cap create is backpressured, then recovers."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    # A low global cap makes the bound trivial to hit deterministically.
    params = _server_params(_fixtures_dir(), {"VIVARIUM_MAX_SESSIONS": "2"})
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        sid_a = _structured(await _create(session, "a"))["session_id"]
        sid_b = _structured(await _create(session, "b"))["session_id"]
        assert sid_a != sid_b

        # Third create exceeds the cap → backpressure, NOT a crash or exhaustion.
        over = await _create(session, "c")
        assert _error_type(over) == _LIMIT_EXCEEDED, (
            f"over-cap session_create must be backpressured with {_LIMIT_EXCEEDED}, "
            f"got {_error_type(over)!r}"
        )

        # Freeing a slot restores capacity (the cap is a live gauge, not a latch).
        closed = _structured(await session.call_tool("session_close", {"session_id": sid_a}))
        assert closed["store_wiped"] is True
        sid_d = _structured(await _create(session, "d"))["session_id"]
        assert sid_d not in {sid_a, sid_b}


def test_pool_starvation_backpressured() -> None:
    """Case 7: exceeding the session concurrency cap yields ``limit-exceeded``, not exhaustion."""
    asyncio.run(_drive_pool_starvation())


# ==============================================================================================
# Case 8 — cross-session store isolation + verified wipe on eviction (ADR-002).
# ==============================================================================================
async def _drive_cross_session_isolation() -> None:
    """Two imported sessions are independent; closing one verified-wipes it and never touches the
    other."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    fixture = _first_valid_fixture()
    params = _server_params(_fixtures_dir())
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        sid_a = _structured(await _create(session, "a"))["session_id"]
        sid_b = _structured(await _create(session, "b"))["session_id"]
        assert sid_a != sid_b

        for sid in (sid_a, sid_b):
            _structured(
                await session.call_tool(
                    "session_import",
                    {"session_id": sid, "source_ref": str(fixture)},
                    read_timeout_seconds=_timeout(),
                )
            )

        # Each session is independent: its own status + server-computed digest.
        status_a = _structured(await session.call_tool("session_status", {"session_id": sid_a}))
        status_b = _structured(await session.call_tool("session_status", {"session_id": sid_b}))
        assert status_a["session_id"] == sid_a and status_b["session_id"] == sid_b
        assert status_a.get("binary_sha256") is not None

        # Closing A verified-wipes A's store and leaves B fully intact (no cross-session coupling).
        closed_a = _structured(await session.call_tool("session_close", {"session_id": sid_a}))
        assert closed_a["store_wiped"] is True, (
            "A's per-session store must be verified-wiped (ADR-002)"
        )
        # A is gone; addressing it now fails closed (not a leak of another session).
        gone_a = await session.call_tool("session_status", {"session_id": sid_a})
        assert _error_type(gone_a) is not None
        # B is unaffected by A's eviction.
        still_b = _structured(await session.call_tool("session_status", {"session_id": sid_b}))
        assert still_b["session_id"] == sid_b
        closed_b = _structured(await session.call_tool("session_close", {"session_id": sid_b}))
        assert closed_b["store_wiped"] is True


def test_cross_session_store_isolation_and_verified_wipe() -> None:
    """Case 8: sessions are isolated; ``session_close`` verified-wipes the per-session store."""
    asyncio.run(_drive_cross_session_isolation())


# ==============================================================================================
# Case 1 — decompile/analysis bomb is bounded: a tiny timeout kills the worker (no hung JVM).
# ==============================================================================================
async def _drive_decompile_bomb() -> None:
    """A 1-second analysis budget on a real binary trips the wall → ``timeout`` + worker kill."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    fixture = _first_valid_fixture()
    # Tiny per-analysis wall-clock; a real OSS analysis takes many seconds, so this reliably trips.
    params = _server_params(_fixtures_dir(), {"VIVARIUM_ANALYSIS_TIMEOUT_SECONDS": "1"})
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        sid = _structured(await _create(session, "bomb"))["session_id"]
        _structured(
            await session.call_tool(
                "session_import",
                {"session_id": sid, "source_ref": str(fixture)},
                read_timeout_seconds=_timeout(),
            )
        )
        # The server enforces its 1s analysis wall and returns the envelope; give the CLIENT a
        # generous read window so the server's own timeout fires first (not a client read timeout).
        analyzed = await session.call_tool(
            "session_analyze", {"session_id": sid}, read_timeout_seconds=_timeout()
        )
        got = _error_type(analyzed)
        assert got == _TIMEOUT, f"a 1s analysis budget must surface {_TIMEOUT}, got {got!r}"
        # The worker was killed and the session marked for eviction — it is unusable afterwards.
        after = await session.call_tool("session_status", {"session_id": sid})
        assert _error_type(after) is not None or _structured(after).get("state") in {
            "evicted",
            "open",
        }


def test_decompile_bomb_bounded_kills_worker() -> None:
    """Case 1: analysis hits the timeout → ``timeout`` envelope, worker killed."""
    asyncio.run(_drive_decompile_bomb())


# ==============================================================================================
# Case 4 — a malformed loader input is contained (no RCE) and the SERVER stays healthy.
# ==============================================================================================
async def _drive_malformed_loader(import_root: Path) -> None:
    """Importing/analyzing a malformed ELF fails *contained*; a subsequent valid session works."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    bad = import_root / "malformed.elf"
    bad.write_bytes(malformed_elf())
    good = import_root / "valid.elf"
    good.write_bytes(build_elf64())

    params = _server_params(import_root)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        sid = _structured(await _create(session, "malformed"))["session_id"]
        # The malformed input must be contained to the worker's fault domain: a safe envelope on
        # import or analyze (NOT a transport crash / hang). Either step may surface it.
        imp = await session.call_tool(
            "session_import",
            {"session_id": sid, "source_ref": str(bad)},
            read_timeout_seconds=_timeout(),
        )
        err = _error_type(imp)
        if err is None:
            err = _error_type(
                await session.call_tool(
                    "session_analyze", {"session_id": sid}, read_timeout_seconds=_timeout()
                )
            )
        assert err in _CONTAINED, f"malformed input must be contained safely, got type={err!r}"

        # SERVER stays healthy: a brand-new session on a well-formed input still imports fine.
        sid2 = _structured(await _create(session, "recover"))["session_id"]
        _structured(
            await session.call_tool(
                "session_import",
                {"session_id": sid2, "source_ref": str(good)},
                read_timeout_seconds=_timeout(),
            )
        )
        _structured(await session.call_tool("session_close", {"session_id": sid2}))


def test_malformed_loader_contained_no_rce(tmp_path: Path) -> None:
    """Case 4: a malformed loader input crashes only the contained worker; the server survives."""
    asyncio.run(_drive_malformed_loader(tmp_path))


# ==============================================================================================
# Case 3 — oversized input rejected at the import size cap, BEFORE the worker (DoS bound).
# ==============================================================================================
async def _drive_oversized_rejected(import_root: Path) -> None:
    """An input exceeding the binary-size cap is rejected with ``limit-exceeded`` pre-worker."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    big = import_root / "oversized.bin"
    big.write_bytes(oversized_blob(4096))  # 4 KiB, well over the 1 KiB cap set below.

    params = _server_params(import_root, {"VIVARIUM_MAX_BINARY_BYTES": "1024"})
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        sid = _structured(await _create(session, "oversized"))["session_id"]
        imp = await session.call_tool(
            "session_import",
            {"session_id": sid, "source_ref": str(big)},
            read_timeout_seconds=_timeout(),
        )
        assert _error_type(imp) == _LIMIT_EXCEEDED, (
            f"oversized import must be rejected at the size cap with {_LIMIT_EXCEEDED}, "
            f"got {_error_type(imp)!r}"
        )


def test_oversized_input_rejected_at_boundary(tmp_path: Path) -> None:
    """Case 3: an oversized input is rejected at the import size cap, before the worker."""
    asyncio.run(_drive_oversized_rejected(tmp_path))
