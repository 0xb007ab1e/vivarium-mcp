"""Black-box HTTP abuse tests for the TB6 network edge (v1.1 — ADR-011 slice 5).

Unlike the slice-3 unit tests (a hand-rolled ASGI harness around a *fake* inner app), these drive
the **real composed stack** — ``build_http_asgi_app`` wrapping the genuine
``FastMCP.streamable_http_app()`` from ``build_app`` — through a real HTTP client
(`starlette.testclient.TestClient`, which parses actual HTTP and runs the app lifespan so the
inner MCP app is live). The Ghidra port is a fake: no JVM, no worker, no binary (ADR-001) — the
tool handlers are never reached because every abuse case is rejected at the middleware edge.

This is the DAST-lite the unit tests can't give: it exercises the security edge (401/413/429,
security headers, CORS preflight) as an external caller sees it. The gated real-worker e2e adds the
authenticated happy-path against a live socket; here we assert the *reject* behaviors hermetically.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from vivarium.config import Config, HttpConfig
from vivarium.ghidra.port import GhidraPort
from vivarium.security.limits import Limits
from vivarium.server.app import build_app, build_http_asgi_app
from vivarium.server.auth import BearerAuthenticator, NullAuthenticator
from vivarium.sessions.manager import SessionManager

# starlette is a transitive dep via the `mcp` SDK; skip cleanly if the optional client extra is
# unavailable in a given environment rather than erroring the whole suite.
TestClient = pytest.importorskip("starlette.testclient").TestClient

_TOKEN = "token-of-sufficient-length-xx"  # noqa: S105  # test fixture, not a real secret
_MCP_PATH = "/mcp"


def _config() -> Config:
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


def _composed(http: HttpConfig, *, authenticator: Any, clock: Any = None) -> Any:
    """Build the real FastMCP MCP app wrapped in the full TB6 middleware stack.

    The Ghidra port is a bare object (never invoked — abuse cases are rejected at the edge); a real
    :class:`SessionManager` holds it so construction matches production wiring.
    """
    port = cast(GhidraPort, object())
    sessions = SessionManager(port=port, ttl_s=3600, idle_s=900, max_sessions=4)
    inner = build_app(_config(), session_manager=sessions, port=port).streamable_http_app()
    kw: dict[str, Any] = {"authenticator": authenticator}
    if clock is not None:
        kw["clock"] = clock
    return build_http_asgi_app(inner, http, **kw)


# --- authentication edge (401) -----------------------------------------------------------------


def test_unauthenticated_request_is_rejected_401_before_the_mcp_app() -> None:
    app = _composed(
        _http(auth_mode="bearer"), authenticator=BearerAuthenticator(expected_token=_TOKEN)
    )
    with TestClient(app) as client:
        resp = client.post(_MCP_PATH, content=b"{}")
    assert resp.status_code == 401


def test_401_response_leaks_no_internals() -> None:
    app = _composed(
        _http(auth_mode="bearer"), authenticator=BearerAuthenticator(expected_token=_TOKEN)
    )
    with TestClient(app) as client:
        resp = client.post(_MCP_PATH, content=b"{}")
    body = resp.text.lower()
    # No stack frames / file paths / token echoes in the rejection body (master §5 / TB6-I).
    assert "traceback" not in body
    assert "/home/" not in body and ".py" not in body
    assert _TOKEN.lower() not in body


def test_wrong_bearer_token_is_rejected_401() -> None:
    app = _composed(
        _http(auth_mode="bearer"), authenticator=BearerAuthenticator(expected_token=_TOKEN)
    )
    with TestClient(app) as client:
        resp = client.post(_MCP_PATH, headers={"authorization": "Bearer not-the-real-token"})
    assert resp.status_code == 401


# --- request-size cap (413) --------------------------------------------------------------------


def test_oversized_body_is_rejected_413() -> None:
    app = _composed(_http(max_body_bytes=10), authenticator=NullAuthenticator())
    with TestClient(app) as client:
        # Content-Length (set by the client from the body) exceeds the cap → 413 at the edge.
        resp = client.post(_MCP_PATH, content=b"x" * 64)
    assert resp.status_code == 413


# --- rate limiting (429) -----------------------------------------------------------------------


def test_rate_limit_returns_429_when_burst_exhausted() -> None:
    # Frozen clock + burst of 1: the second request in the same instant has no token left. Bearer
    # mode with no credentials means neither request reaches the inner MCP app — the rate limiter
    # sits in front of auth, so the 429 proves the limiter fires independently of authentication.
    app = _composed(
        _http(auth_mode="bearer", rate_per_second=1, rate_burst=1),
        authenticator=BearerAuthenticator(expected_token=_TOKEN),
        clock=lambda: 0.0,
    )
    with TestClient(app) as client:
        first = client.post(_MCP_PATH, content=b"{}")
        second = client.post(_MCP_PATH, content=b"{}")
    assert first.status_code == 401  # token consumed, then auth rejects
    assert second.status_code == 429  # bucket empty (clock frozen)


# --- security headers --------------------------------------------------------------------------


def test_security_headers_present_on_every_response() -> None:
    app = _composed(
        _http(auth_mode="bearer"), authenticator=BearerAuthenticator(expected_token=_TOKEN)
    )
    with TestClient(app) as client:
        resp = client.post(_MCP_PATH, content=b"{}")  # 401, but headers still applied
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert "referrer-policy" in resp.headers
    # Plaintext loopback (no TLS, not network) → no HSTS.
    assert "strict-transport-security" not in resp.headers


def test_hsts_present_when_served_over_tls() -> None:
    app = _composed(
        _http(is_network=True, tls_cert="/c.pem", tls_key="/k.pem", auth_mode="bearer"),
        authenticator=BearerAuthenticator(expected_token=_TOKEN),
    )
    with TestClient(app) as client:
        resp = client.post(_MCP_PATH, content=b"{}")
    assert "strict-transport-security" in resp.headers


# --- CORS --------------------------------------------------------------------------------------


def test_cors_preflight_allows_configured_origin() -> None:
    app = _composed(
        _http(cors_origins=("https://ui.example",), auth_mode="bearer"),
        authenticator=BearerAuthenticator(expected_token=_TOKEN),
    )
    with TestClient(app) as client:
        # Preflight is exempt from auth and handled by the CORS layer itself (never the inner app).
        resp = client.options(
            _MCP_PATH,
            headers={
                "origin": "https://ui.example",
                "access-control-request-method": "POST",
            },
        )
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "https://ui.example"


def test_cors_rejects_unconfigured_origin() -> None:
    app = _composed(
        _http(cors_origins=("https://ui.example",), auth_mode="bearer"),
        authenticator=BearerAuthenticator(expected_token=_TOKEN),
    )
    with TestClient(app) as client:
        resp = client.options(
            _MCP_PATH,
            headers={
                "origin": "https://evil.example",
                "access-control-request-method": "POST",
            },
        )
    # The disallowed origin is never reflected back (no allow-origin for it).
    assert resp.headers.get("access-control-allow-origin") != "https://evil.example"
