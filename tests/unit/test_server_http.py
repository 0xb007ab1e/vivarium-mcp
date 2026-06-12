"""Unit tests for the HTTP shell composition + transport selection (v1.1 — ADR-011 slice 3b).

`build_http_asgi_app` is pure composition, so it's driven end-to-end through the real middleware
stack with a fake inner ASGI app + a tiny in-memory harness (no live server). `run_http` itself
(uvicorn bind) is the I/O edge, validated by the gated HTTP integration/DAST (slice 5). Transport
selection in ``main`` is checked with injected factories + monkeypatched runners.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest

from ghidra_mcp import __main__ as entry
from ghidra_mcp.config import HttpConfig
from ghidra_mcp.ghidra.port import GhidraPort
from ghidra_mcp.server.app import build_http_asgi_app
from ghidra_mcp.server.auth import BearerAuthenticator, NullAuthenticator
from ghidra_mcp.sessions.manager import SessionManager

_TOKEN = "token-of-sufficient-length-xx"  # noqa: S105  # test fixture, not a real secret


def _http(**over: Any) -> HttpConfig:
    base: dict[str, Any] = {
        "bind": "127.0.0.1:8765",
        "is_network": False,
        "is_unix_socket": False,
        "tls_cert": None,
        "tls_key": None,
        "auth_mode": "none",
        "bearer_token": None,
        "cors_origins": (),
        "rate_per_second": 1000.0,
        "rate_burst": 1000,
        "max_body_bytes": 1_000_000,
    }
    base.update(over)
    return HttpConfig(**base)


class _Inner:
    """Fake inner MCP ASGI app: records invocation, emits a 200."""

    def __init__(self) -> None:
        self.called = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _drive(
    app: Any,
    *,
    method: str = "POST",
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] = ("1.2.3.4", 5),
) -> tuple[int | None, dict[bytes, bytes]]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": method,
        "path": "/mcp",
        "headers": headers or [],
        "client": client,
        "scheme": "http",
    }
    asyncio.run(app(scope, receive, send))
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    resp_headers = dict(start["headers"] if start else [])
    return (start["status"] if start else None), resp_headers


def test_stack_passes_authenticated_request_and_adds_security_headers() -> None:
    inner = _Inner()
    app = build_http_asgi_app(inner, _http(), authenticator=NullAuthenticator())
    status, headers = _drive(app)
    assert status == 200 and inner.called is True
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert b"strict-transport-security" not in headers  # plaintext loopback → no HSTS


def test_stack_rejects_missing_auth_401() -> None:
    inner = _Inner()
    app = build_http_asgi_app(
        inner, _http(auth_mode="bearer"), authenticator=BearerAuthenticator(expected_token=_TOKEN)
    )
    status, _ = _drive(app, headers=[])
    assert status == 401 and inner.called is False


def test_stack_rejects_oversize_413() -> None:
    inner = _Inner()
    app = build_http_asgi_app(inner, _http(max_body_bytes=10), authenticator=NullAuthenticator())
    status, _ = _drive(app, headers=[(b"content-length", b"11")])
    assert status == 413 and inner.called is False


def test_stack_rate_limits_429() -> None:
    inner = _Inner()
    app = build_http_asgi_app(
        inner,
        _http(rate_per_second=1, rate_burst=1),
        authenticator=NullAuthenticator(),
        clock=lambda: 0.0,
    )
    assert _drive(app)[0] == 200
    assert _drive(app)[0] == 429  # burst exhausted, clock frozen


def test_stack_hsts_present_when_network() -> None:
    inner = _Inner()
    app = build_http_asgi_app(
        inner,
        _http(is_network=True, tls_cert="/c.pem", tls_key="/k.pem"),
        authenticator=NullAuthenticator(),
    )
    _, headers = _drive(app)
    assert b"strict-transport-security" in headers


def test_stack_adds_cors_headers_when_origins_configured() -> None:
    inner = _Inner()
    app = build_http_asgi_app(
        inner, _http(cors_origins=("https://ui.example",)), authenticator=NullAuthenticator()
    )
    _, headers = _drive(app, headers=[(b"origin", b"https://ui.example")])
    assert headers.get(b"access-control-allow-origin") == b"https://ui.example"


# --- transport selection in main() -------------------------------------------------------------


def _min_http_env() -> dict[str, str]:
    return {
        "GHIDRA_MCP_WORKER_IMAGE": "ghcr.io/x/worker@sha256:" + "a" * 64,
        "GHIDRA_MCP_TRANSPORT": "http",  # loopback default → auth none, valid
    }


class _FakeSM:
    def shutdown(self) -> None: ...


def _patch_runners(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(entry, "build_app", lambda *a, **k: object())

    def _http_runner(app: Any, config: Any, *, session_manager: Any) -> int:
        calls.append("http")
        return 0

    def _stdio_runner(app: Any, *, session_manager: Any) -> int:
        calls.append("stdio")
        return 0

    monkeypatch.setattr(entry, "run_http", _http_runner)
    monkeypatch.setattr(entry, "run_stdio", _stdio_runner)
    return calls


def test_main_selects_http_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in _min_http_env().items():
        monkeypatch.setenv(k, v)
    calls = _patch_runners(monkeypatch)
    rc = entry.main(
        port_factory=lambda c: cast(GhidraPort, object()),
        session_manager_factory=lambda c, p: cast(SessionManager, _FakeSM()),
    )
    assert rc == 0 and calls == ["http"]


def test_main_defaults_to_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GHIDRA_MCP_WORKER_IMAGE", "ghcr.io/x/worker@sha256:" + "a" * 64)
    monkeypatch.delenv("GHIDRA_MCP_TRANSPORT", raising=False)
    calls = _patch_runners(monkeypatch)
    rc = entry.main(
        port_factory=lambda c: cast(GhidraPort, object()),
        session_manager_factory=lambda c, p: cast(SessionManager, _FakeSM()),
    )
    assert rc == 0 and calls == ["stdio"]
