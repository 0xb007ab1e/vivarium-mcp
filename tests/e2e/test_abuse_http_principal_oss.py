"""Live TB6 HTTP cross-principal isolation (G4 Tier D; threat-model §13 cases 61-63; GATED).

Drives the **real composed HTTP transport** end-to-end: the production server is launched as a
subprocess in ``transport=http`` mode (composition root → ``run_http`` → uvicorn) on a loopback
port with **two distinct bearer tokens → two principals** (``MultiTokenBearerAuthenticator``,
ADR-017), and two real MCP **Streamable-HTTP** clients (`mcp.client.streamable_http`) connect with
distinct ``Authorization: Bearer`` headers.

Case 61-63: principal **B**, presenting principal **A**'s ``session_id`` to a session-scoped tool,
gets **``session-invalid``** (404, no existence oracle — NOT ``forbidden``; ADR-036 forbids an
ownership/cross-caller denial from becoming the capability-denial slug), while **A**'s session is
left untouched. The manager-level owner check + the authenticator are proven hermetically; THIS
exercises the live wiring (per-request principal → ``ToolContext`` → ``SessionManager``).

No worker is needed: ``session_create`` opens a session with NO binary and NO worker (the owner is
recorded at creation), so this is a pure transport + auth + ownership test — fast and deterministic.
Loopback bearer needs no TLS (``HttpConfig``: ``tls_cert=None`` is the plaintext-loopback case).

GATING: skip unless ``VIVARIUM_INTEGRATION`` is truthy, ``VIVARIUM_WORKER_IMAGE`` is set (the server
config requires a worker image even though no worker is spawned here), a container engine is on
PATH, and the mcp Streamable-HTTP client is importable. NO REAL MALWARE / no binary touched.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import sys
import time
from typing import Any

import pytest

from tests.e2e.test_abuse_containment_oss import _error_type, _structured, _timeout

_ENV_INTEGRATION = "VIVARIUM_INTEGRATION"
_ENV_WORKER_IMAGE = "VIVARIUM_WORKER_IMAGE"
_ENV_ENGINE = "VIVARIUM_CONTAINER_ENGINE"

# Two principals with distinct bearer secrets (ADR-017). Tokens clear the 16-char floor; the
# principal ids are within the allowed charset. These are synthetic test fixtures, not real secrets.
_PRINCIPAL_A = "alice"
_PRINCIPAL_B = "bob"
_TOKEN_A = "alice-bearer-token-of-ample-length-aaaaaaaaaaaa"  # noqa: S105 - test fixture
_TOKEN_B = "bob-bearer-token-of-ample-length-bbbbbbbbbbbbbb"  # noqa: S105 - test fixture
_SESSION_INVALID = "session-invalid"
_MCP_PATH = "/mcp"

try:
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:  # pragma: no cover - the mcp http client extra is absent
    streamablehttp_client = None  # type: ignore[assignment]
#: The Streamable-HTTP client factory, or None if the mcp http extra is absent (skip-guarded).
_http_client: Any = streamablehttp_client


def _truthy(v: str | None) -> bool:
    """Return whether an env flag is set to a truthy token."""
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


def _skip_reason() -> str | None:
    """Return a human reason to skip, or None if the HTTP-transport prerequisites are met."""
    if not _truthy(os.environ.get(_ENV_INTEGRATION)):
        return f"{_ENV_INTEGRATION} not set (gated HTTP-transport e2e)"
    if _http_client is None:
        return "mcp Streamable-HTTP client (mcp.client.streamable_http) unavailable"
    if not os.environ.get(_ENV_WORKER_IMAGE, "").strip():
        return f"{_ENV_WORKER_IMAGE} not set (the server config requires a worker image)"
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


def _free_loopback_port() -> int:
    """Reserve an ephemeral loopback port (closed immediately; uvicorn rebinds it)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _server_env(port: int) -> dict[str, str]:
    """Production server env for an HTTP/bearer/loopback (no-TLS) run with two principals."""
    return {
        **os.environ,
        "VIVARIUM_TRANSPORT": "http",
        "VIVARIUM_HTTP_BIND": f"127.0.0.1:{port}",
        "VIVARIUM_HTTP_AUTH": "bearer",
        # `principal-id:token` pairs (comma-separated) → the MultiTokenBearerAuthenticator map.
        "VIVARIUM_HTTP_BEARER_TOKENS": f"{_PRINCIPAL_A}:{_TOKEN_A},{_PRINCIPAL_B}:{_TOKEN_B}",
        # A confinement root is required by config; no import happens, so any existing dir is fine.
        "VIVARIUM_IMPORT_ROOT": os.environ.get("VIVARIUM_FIXTURES", "/tmp"),  # noqa: S108
    }


def _wait_listening(port: int, proc: subprocess.Popen[bytes], timeout: float = 45.0) -> None:
    """Block until the server accepts a loopback TCP connection, or fail with its stderr."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:  # the server exited before binding — surface why
            err = (proc.stderr.read().decode("utf-8", "replace") if proc.stderr else "")[-2000:]
            pytest.fail(f"HTTP server exited early (code {proc.returncode}); stderr tail:\n{err}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.25)
    pytest.fail(f"HTTP server did not start listening on :{port} within {timeout}s")


async def _drive_cross_principal_isolation() -> None:
    """A creates a session; B (other token) cannot address it → session-invalid; A is untouched."""
    from mcp import ClientSession

    assert _http_client is not None  # narrowed by the skip-guard
    port = _free_loopback_port()
    proc = subprocess.Popen(  # fixed argv (no shell), our own server module
        [sys.executable, "-m", "vivarium"],
        env=_server_env(port),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    url = f"http://127.0.0.1:{port}{_MCP_PATH}"
    try:
        _wait_listening(port, proc)

        # Principal A opens a session and captures its id.
        async with (
            _http_client(url, headers={"Authorization": f"Bearer {_TOKEN_A}"}) as (a_r, a_w, _a),
            ClientSession(a_r, a_w) as a,
        ):
            await a.initialize()
            sid = _structured(
                await a.call_tool("session_create", {}, read_timeout_seconds=_timeout())
            )["session_id"]

            # Principal B (a DIFFERENT bearer → a different principal) presents A's session id.
            async with (
                _http_client(url, headers={"Authorization": f"Bearer {_TOKEN_B}"}) as (
                    b_r,
                    b_w,
                    _b,
                ),
                ClientSession(b_r, b_w) as b,
            ):
                await b.initialize()
                denied = await b.call_tool("session_status", {"session_id": sid})
                got = _error_type(denied)
                # Cross-principal access fails CLOSED with no existence oracle: the SAME slug as an
                # unknown/expired session (session-invalid, 404) — NOT `forbidden` (ADR-036).
                assert got == _SESSION_INVALID, (
                    f"cross-principal access must be {_SESSION_INVALID} (no oracle), got {got!r}"
                )

            # A's session is UNTOUCHED by B's denied attempt — A can still address it.
            still = _structured(await a.call_tool("session_status", {"session_id": sid}))
            assert still["session_id"] == sid
            _structured(await a.call_tool("session_close", {"session_id": sid}))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        if proc.stderr:
            proc.stderr.close()


def test_cross_principal_isolation_end_to_end_over_http() -> None:
    """Case 61-63: B cannot address A's session over HTTP (session-invalid); A is untouched."""
    asyncio.run(_drive_cross_principal_isolation())
