"""E2E: stdio app-level abuse paths — BOLA-safety + boundary validation (WS5 → implemented).

Drives the real server application (``vivarium.server.app.build_app``) with the in-process
:class:`tests.conftest.FakeGhidraPort` and a REAL :class:`~vivarium.sessions.manager.SessionManager`
injected at the composition root, exercising the full server shell (tool registry, input
validation, session authorization, untrusted/error envelope mapping) end-to-end **without** a real
worker or gated image pull. Tools are invoked exactly as the MCP stdio transport delivers them —
``app.call_tool(name, flat_kwargs)`` — so the same registry + boundary code runs.

Scope (WS5 scaffold resolved): the **full read-only journey** over a real stdio transport
(create → import → analyze → read tools → close, with a real worker) is covered by
``tests/e2e/test_groundtruth_oss.py`` and ``tests/integration/test_decompile_stream_*.py`` (a real
MCP stdio client against the real server + worker). What those do NOT cover — and what lives here —
is the **abuse-path** server behavior with a fake adapter: BOLA-safety on an unknown ``session_id``
and input validation at the boundary BEFORE any port dispatch. Synthetic only — never real malware
(master §5).
"""

from __future__ import annotations

import json
from typing import Any, cast

import anyio

from tests.conftest import FakeGhidraPort
from vivarium.config import Config
from vivarium.ghidra.port import GhidraPort
from vivarium.security.limits import Limits
from vivarium.server.app import build_app
from vivarium.sessions.manager import SessionManager
from vivarium.tools.schemas import ReadBytesIn

# An unknown-but-well-formed session id (matches the schema's 1..64 char bound; never created).
_UNKNOWN_SID = "0" * 32
_OTHER_UNKNOWN_SID = "f" * 32


def _config() -> Config:
    """A minimal valid stdio Config (mirrors the composition root; no real worker is contacted)."""
    return Config(
        log_level="INFO",
        log_format="json",
        session_ttl_s=3600,
        session_idle_s=900,
        limits=Limits(),
        worker_image="x",
        worker_runtime="runsc",
        worker_uid=65532,
        worker_gid=65532,
        rpc_socket_dir="/run/x",
        import_root="/work/imports",
    )


def _build(port: GhidraPort) -> tuple[Any, SessionManager]:
    """Build the real app + a real SessionManager wired to ``port`` (composition root)."""
    config = _config()
    sm = SessionManager(
        port=port,
        ttl_s=config.session_ttl_s,
        idle_s=config.session_idle_s,
        max_sessions=config.limits.max_sessions,
        max_sessions_per_owner=config.limits.max_sessions_per_owner,
    )
    app = build_app(config, session_manager=sm, port=port)
    return app, sm


def _envelope(result: object) -> dict[str, Any]:
    """Parse the JSON envelope from a FastMCP call_tool result's first content block."""
    block = cast(Any, result)[0]
    return cast("dict[str, Any]", json.loads(block.text))


def test_unknown_session_id_is_bola_safe_over_stdio(fake_port: FakeGhidraPort) -> None:
    """A tool call with a foreign/unknown ``session_id`` returns SESSION_INVALID, with NO oracle.

    The error must be identical whether or not other sessions exist (no existence oracle) and must
    not leak internals (the rejected id / internal paths never appear in the safe detail).
    """
    app, _sm = _build(fake_port)

    # (1) No sessions exist at all → unknown id is SESSION_INVALID, leak-free.
    res = anyio.run(
        app.call_tool, "decompile_function", {"session_id": _UNKNOWN_SID, "function": "main"}
    )
    env = _envelope(res)
    assert env["type"] == "session-invalid"
    assert _UNKNOWN_SID not in json.dumps(env)  # the id is not echoed back (no leak)
    assert "/" not in env["detail"]  # no path/internal leakage in the safe detail

    # (2) Create a REAL session (no worker spawn — that is lazy on import), then query a DIFFERENT
    #     unknown id. The envelope must be IDENTICAL modulo correlation_id → no existence oracle.
    created = _envelope(anyio.run(app.call_tool, "session_create", {}))
    assert "session_id" in created
    res2 = anyio.run(
        app.call_tool, "decompile_function", {"session_id": _OTHER_UNKNOWN_SID, "function": "main"}
    )
    env2 = _envelope(res2)
    for field in ("type", "title", "detail", "status"):
        assert env2[field] == env[field], f"{field} differs → existence oracle"


def test_oversize_argument_rejected_at_boundary_over_stdio() -> None:
    """An over-cap tool argument is rejected with VALIDATION before the port is called (TB1)."""

    class _TrackingPort(FakeGhidraPort):
        """FakeGhidraPort that records whether read_bytes was dispatched (it must NOT be)."""

        read_bytes_called: bool = False

        def read_bytes(self, sid: str, a: ReadBytesIn) -> Any:
            type(self).read_bytes_called = True
            return super().read_bytes(sid, a)

    port = _TrackingPort()
    app, _sm = _build(port)

    # length is capped at 1 MiB by the input schema; 2 MiB must fail closed at the boundary.
    res = anyio.run(
        app.call_tool,
        "read_bytes",
        {"session_id": _UNKNOWN_SID, "address": "0x401000", "length": 2_000_000},
    )
    assert _envelope(res)["type"] == "validation-error"
    assert _TrackingPort.read_bytes_called is False  # rejected BEFORE any port dispatch
