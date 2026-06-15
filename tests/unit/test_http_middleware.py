"""Unit tests for the HTTP transport ASGI middleware (v1.1 — ADR-011 / TB6).

Hermetic: a tiny in-memory ASGI harness drives each middleware with a constructed scope — no live
server. Asserts the security behavior (413 / 429 / 401, default-deny, preflight exemption, principal
stashing) and that a rejected request never reaches the wrapped app.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ghidra_mcp.server import http_middleware as _mw
from ghidra_mcp.server.auth import (
    BearerAuthenticator,
    MtlsAuthenticator,
    NullAuthenticator,
    Principal,
)
from ghidra_mcp.server.http_middleware import (
    _SCOPE_PRINCIPAL_KEY,
    AuthenticationMiddleware,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
)

_TOKEN = "token-of-sufficient-length-xx"  # noqa: S105  # test fixture, not a real secret


class _App:
    """Terminal ASGI app that records invocation and emits a trivial 200."""

    def __init__(self) -> None:
        self.called = False
        self.seen_scope: dict[str, Any] | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True
        self.seen_scope = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(
    *,
    method: str = "POST",
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] | None = ("1.2.3.4", 5555),
    kind: str = "http",
    extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scope: dict[str, Any] = {
        "type": kind,
        "method": method,
        "headers": headers or [],
        "client": client,
    }
    if extensions is not None:
        scope["extensions"] = extensions
    return scope


def _drive(mw: Any, scope: dict[str, Any]) -> tuple[int | None, bytes]:
    """Run a middleware against ``scope`` (empty body) and return ``(status, body)``."""
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(mw(scope, receive, send))
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return (start["status"] if start else None), body


# --- RequestSizeLimitMiddleware ----------------------------------------------------------------


def test_size_limit_rejects_over_content_length() -> None:
    app = _App()
    mw = RequestSizeLimitMiddleware(app, max_body_bytes=100)
    status, _ = _drive(mw, _scope(headers=[(b"content-length", b"101")]))
    assert status == 413 and app.called is False


def test_size_limit_allows_within_limit() -> None:
    app = _App()
    mw = RequestSizeLimitMiddleware(app, max_body_bytes=100)
    status, _ = _drive(mw, _scope(headers=[(b"content-length", b"100")]))
    assert status == 200 and app.called is True


def test_size_limit_allows_missing_content_length() -> None:
    app = _App()
    mw = RequestSizeLimitMiddleware(app, max_body_bytes=100)
    status, _ = _drive(mw, _scope(headers=[]))
    assert status == 200 and app.called is True


# --- RateLimitMiddleware -----------------------------------------------------------------------


def test_rate_limit_allows_within_burst_then_429() -> None:
    app = _App()
    t = [1000.0]  # frozen clock
    mw = RateLimitMiddleware(app, rate_per_second=1, burst=2, clock=lambda: t[0])
    s = _scope()
    assert _drive(mw, s)[0] == 200  # token 1
    assert _drive(mw, s)[0] == 200  # token 2
    status, _ = _drive(mw, s)  # bucket empty
    assert status == 429


def test_rate_limit_refills_over_time() -> None:
    app = _App()
    t = [1000.0]
    mw = RateLimitMiddleware(app, rate_per_second=1, burst=1, clock=lambda: t[0])
    assert _drive(mw, _scope())[0] == 200
    assert _drive(mw, _scope())[0] == 429  # empty
    t[0] += 1.0  # one second → one token refilled
    assert _drive(mw, _scope())[0] == 200


def test_rate_limit_bucket_map_is_bounded_lru(monkeypatch: pytest.MonkeyPatch) -> None:
    """The per-client bucket map is a size-bounded LRU (CWE-400) — review Low-1."""
    monkeypatch.setattr(_mw, "_MAX_RATE_LIMIT_BUCKETS", 3)
    mw = RateLimitMiddleware(_App(), rate_per_second=1000, burst=1000, clock=lambda: 1000.0)
    for k in ("A", "B", "C", "D"):  # 4 distinct clients, cap 3
        mw._allow(k)
    assert len(mw._buckets) == 3  # bounded
    assert "A" not in mw._buckets  # least-recently-used evicted
    assert set(mw._buckets) == {"B", "C", "D"}


def test_rate_limit_lru_keeps_recently_seen_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-touching a client refreshes its recency so it survives eviction (LRU, not FIFO)."""
    monkeypatch.setattr(_mw, "_MAX_RATE_LIMIT_BUCKETS", 3)
    mw = RateLimitMiddleware(_App(), rate_per_second=1000, burst=1000, clock=lambda: 1000.0)
    for k in ("A", "B", "C", "A"):  # touch A again → B is now least-recently-used
        mw._allow(k)
    mw._allow("D")  # overflow → evicts B, not A
    assert "A" in mw._buckets and "B" not in mw._buckets
    assert set(mw._buckets) == {"A", "C", "D"}


def test_rate_limit_is_per_client() -> None:
    app = _App()
    t = [1000.0]
    mw = RateLimitMiddleware(app, rate_per_second=1, burst=1, clock=lambda: t[0])
    assert _drive(mw, _scope(client=("10.0.0.1", 1)))[0] == 200
    assert _drive(mw, _scope(client=("10.0.0.2", 1)))[0] == 200  # different client, own bucket
    assert _drive(mw, _scope(client=("10.0.0.1", 1)))[0] == 429  # first client exhausted


# --- AuthenticationMiddleware ------------------------------------------------------------------


def test_auth_rejects_missing_credentials_with_401() -> None:
    app = _App()
    mw = AuthenticationMiddleware(app, authenticator=BearerAuthenticator(expected_token=_TOKEN))
    status, _ = _drive(mw, _scope(headers=[]))
    assert status == 401 and app.called is False


def test_auth_accepts_valid_bearer_and_stashes_principal() -> None:
    app = _App()
    mw = AuthenticationMiddleware(app, authenticator=BearerAuthenticator(expected_token=_TOKEN))
    status, _ = _drive(mw, _scope(headers=[(b"authorization", f"Bearer {_TOKEN}".encode())]))
    assert status == 200 and app.called is True
    assert app.seen_scope is not None
    assert app.seen_scope["state"][_SCOPE_PRINCIPAL_KEY] == Principal(id="bearer")


def test_auth_exempts_cors_preflight() -> None:
    app = _App()
    mw = AuthenticationMiddleware(app, authenticator=BearerAuthenticator(expected_token=_TOKEN))
    status, _ = _drive(mw, _scope(method="OPTIONS", headers=[]))
    assert status == 200 and app.called is True  # preflight passes without auth


def test_non_http_scope_passes_through_all_middleware() -> None:
    """A non-HTTP scope (e.g. lifespan/websocket) is forwarded untouched by every middleware."""
    for mw_factory in (
        lambda app: RequestSizeLimitMiddleware(app, max_body_bytes=10),
        lambda app: RateLimitMiddleware(app, rate_per_second=1, burst=1, clock=lambda: 0.0),
        lambda app: AuthenticationMiddleware(app, authenticator=NullAuthenticator()),
    ):
        app = _App()
        status, _ = _drive(mw_factory(app), _scope(kind="lifespan"))
        assert status == 200 and app.called is True


def test_auth_null_authenticator_passes() -> None:
    app = _App()
    mw = AuthenticationMiddleware(app, authenticator=NullAuthenticator())
    status, _ = _drive(mw, _scope(headers=[]))
    assert status == 200 and app.called is True
    assert app.seen_scope["state"][_SCOPE_PRINCIPAL_KEY] == Principal(id="local")  # type: ignore[index]


# --- mTLS peer-cert extraction (ADR-019 increment A) -------------------------------------------
# The verified peer cert is read from the ASGI TLS extension (scope["extensions"]["tls"]["peercert"]
# — the parsed ssl.getpeercert() dict). These assert the middleware surfaces it into AuthContext and
# the wired MtlsAuthenticator maps it (or fails closed → 401 with no cert). SYNTHETIC certs only.


def _tls_scope(peercert: Any, *, present: bool = True) -> dict[str, Any]:
    """A scope with the ASGI TLS extension carrying ``peercert`` (or absent when present=False)."""
    if not present:
        return _scope(headers=[])
    return _scope(headers=[], extensions={"tls": {"peercert": peercert}})


def test_peer_certificate_extracted_from_tls_extension() -> None:
    """The helper returns the parsed cert dict from scope["extensions"]["tls"]["peercert"]."""
    cert = {"subject": ((("commonName", "alice"),),)}
    assert _mw._peer_certificate(_tls_scope(cert)) == cert


@pytest.mark.parametrize(
    "scope",
    [
        _scope(headers=[]),  # no extensions key at all
        _scope(headers=[], extensions={}),  # extensions present, no tls
        _scope(headers=[], extensions={"tls": {}}),  # tls present, no peercert
        {"type": "http", "extensions": "not-a-dict"},  # extensions wrong type
        {"type": "http", "extensions": {"tls": "not-a-dict"}},  # tls wrong type
    ],
)
def test_peer_certificate_absent_returns_none(scope: dict[str, Any]) -> None:
    assert _mw._peer_certificate(scope) is None


def test_auth_mtls_maps_verified_cert_to_principal() -> None:
    """The middleware threads the verified peer cert → MtlsAuthenticator → stashed Principal."""
    app = _App()
    mw = AuthenticationMiddleware(app, authenticator=MtlsAuthenticator())  # default cn
    cert = {"subject": ((("commonName", "carol"),),)}
    status, _ = _drive(mw, _tls_scope(cert))
    assert status == 200 and app.called is True
    assert app.seen_scope["state"][_SCOPE_PRINCIPAL_KEY] == Principal(id="carol")  # type: ignore[index]


def test_auth_mtls_no_client_cert_is_401() -> None:
    """No verified peer cert in the scope → the authenticator fails closed → generic 401."""
    app = _App()
    mw = AuthenticationMiddleware(app, authenticator=MtlsAuthenticator())
    status, _ = _drive(mw, _tls_scope(None, present=False))
    assert status == 401 and app.called is False


def test_auth_mtls_empty_cn_is_401() -> None:
    """A verified cert whose mapped field is empty → fail closed → 401 (no anonymous principal)."""
    app = _App()
    mw = AuthenticationMiddleware(app, authenticator=MtlsAuthenticator())
    status, _ = _drive(mw, _tls_scope({"subject": ((("commonName", ""),),)}))
    assert status == 401 and app.called is False
