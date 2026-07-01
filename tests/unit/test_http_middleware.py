"""Unit tests for the HTTP transport ASGI middleware (v1.1 — ADR-011 / TB6).

Hermetic: a tiny in-memory ASGI harness drives each middleware with a constructed scope — no live
server. Asserts the security behavior (413 / 429 / 401, default-deny, preflight exemption, principal
stashing) and that a rejected request never reaches the wrapped app.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from vivarium.server import http_middleware as _mw
from vivarium.server.auth import (
    BearerAuthenticator,
    MtlsAuthenticator,
    NullAuthenticator,
    Principal,
    ReverseProxyMtlsAuthenticator,
)
from vivarium.server.http_middleware import (
    _SCOPE_PRINCIPAL_KEY,
    AuthenticationMiddleware,
    CachedReadiness,
    HealthMiddleware,
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


# --- _header_map: lowercased name → first value (ADR-034) --------------------------------------
# The reverse-proxy authenticator reads request headers via AuthContext.headers; the middleware
# builds that map from the ASGI scope. ASGI header NAMES are already lowercase bytes; values are
# latin-1 decoded; the FIRST value wins on a duplicate (deterministic).


def test_header_map_lowercases_and_first_value_wins() -> None:
    scope = _scope(
        headers=[
            (b"authorization", b"Bearer abc"),
            (b"x-proxy-auth", b"secret-1"),
            (b"x-proxy-auth", b"secret-2"),  # duplicate — first wins
            (b"x-client-cert-subject", b"CN=alice"),
        ]
    )
    hm = _mw._header_map(scope)
    assert hm == {
        "authorization": "Bearer abc",
        "x-proxy-auth": "secret-1",  # first value, not "secret-2"
        "x-client-cert-subject": "CN=alice",
    }


def test_header_map_latin1_decoded_and_empty_scope() -> None:
    """Values are latin-1 decoded (the HTTP header charset); a header-less scope → empty map."""
    scope = _scope(headers=[(b"x-client-cert-subject", "CN=café".encode("latin-1"))])
    assert _mw._header_map(scope) == {"x-client-cert-subject": "CN=café"}
    assert _mw._header_map(_scope(headers=[])) == {}


# --- AuthenticationMiddleware end-to-end with the reverse-proxy authenticator (ADR-034) --------
_PROXY_SECRET = "proxy-shared-secret-of-len"  # noqa: S105  # test fixture, not a real secret


def _proxy_scope(*, secret: bytes | None, identity: bytes | None = b"CN=alice") -> dict[str, Any]:
    """A scope carrying the proxy secret + identity headers (omit either when its arg is None)."""
    headers: list[tuple[bytes, bytes]] = []
    if secret is not None:
        headers.append((b"x-proxy-auth", secret))
    if identity is not None:
        headers.append((b"x-client-cert-subject", identity))
    return _scope(headers=headers)


def test_auth_proxy_correct_secret_and_identity_authenticates() -> None:
    """Right secret + identity headers → authenticated; principal stashed on scope state."""
    app = _App()
    mw = AuthenticationMiddleware(
        app, authenticator=ReverseProxyMtlsAuthenticator(shared_secret=_PROXY_SECRET)
    )
    status, _ = _drive(mw, _proxy_scope(secret=_PROXY_SECRET.encode(), identity=b"CN=carol"))
    assert status == 200 and app.called is True
    assert app.seen_scope is not None
    assert app.seen_scope["state"][_SCOPE_PRINCIPAL_KEY] == Principal(id="CN=carol")


def test_auth_proxy_missing_secret_header_is_401() -> None:
    app = _App()
    mw = AuthenticationMiddleware(
        app, authenticator=ReverseProxyMtlsAuthenticator(shared_secret=_PROXY_SECRET)
    )
    status, _ = _drive(mw, _proxy_scope(secret=None))  # identity present, no secret
    assert status == 401 and app.called is False


def test_auth_proxy_wrong_secret_is_401() -> None:
    app = _App()
    mw = AuthenticationMiddleware(
        app, authenticator=ReverseProxyMtlsAuthenticator(shared_secret=_PROXY_SECRET)
    )
    status, _ = _drive(mw, _proxy_scope(secret=b"wrong-but-long-enough-secret"))
    assert status == 401 and app.called is False


# --- HealthMiddleware (N3b: unauthenticated, detail-free liveness/readiness) ---
def _probe_scope(method: str, path: str) -> dict[str, Any]:
    """A minimal HTTP scope for a health-probe request (carries the path)."""
    return {"type": "http", "method": method, "path": path, "headers": [], "client": ("1.2.3.4", 5)}


def test_health_liveness_is_always_200_and_bare() -> None:
    """GET /healthz short-circuits to a 200 with no body (no internals leaked) — app not called."""
    app = _App()
    mw = HealthMiddleware(app, is_ready=lambda: False)  # readiness is irrelevant to liveness
    status, body = _drive(mw, _probe_scope("GET", "/healthz"))
    assert status == 200 and body == b"" and app.called is False


def test_health_readiness_reflects_the_predicate() -> None:
    """GET /readyz is 200 when ready and 503 when not — both bare; app never called."""
    ready_app, not_ready_app = _App(), _App()
    ok, _ = _drive(
        HealthMiddleware(ready_app, is_ready=lambda: True), _probe_scope("GET", "/readyz")
    )
    busy, _ = _drive(
        HealthMiddleware(not_ready_app, is_ready=lambda: False), _probe_scope("GET", "/readyz")
    )
    assert ok == 200 and busy == 503
    assert ready_app.called is False and not_ready_app.called is False


def test_health_passes_through_non_probe_path() -> None:
    """A normal request path is delegated to the wrapped app unchanged."""
    app = _App()
    mw = HealthMiddleware(app, is_ready=lambda: True)
    _drive(mw, _probe_scope("POST", "/mcp"))
    assert app.called is True


def test_health_passes_through_get_on_non_probe_path() -> None:
    """A GET to a non-probe path falls past both probe checks and delegates to the app."""
    app = _App()
    mw = HealthMiddleware(app, is_ready=lambda: True)
    _drive(mw, _probe_scope("GET", "/mcp"))
    assert app.called is True


def test_health_passes_through_non_get_on_a_probe_path() -> None:
    """A POST to /healthz is NOT a probe (only GET/HEAD) → delegated, not short-circuited."""
    app = _App()
    mw = HealthMiddleware(app, is_ready=lambda: True)
    _drive(mw, _probe_scope("POST", "/healthz"))
    assert app.called is True


# --- CachedReadiness (gap P3: bound the pre-auth /readyz predicate to 1 call per TTL window) ---
class _FakeClock:
    """A manually-advanced monotonic clock (deterministic — no wall-clock/sleep in tests)."""

    def __init__(self, start: float = 0.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds


class _Counter:
    """A readiness predicate that counts calls and returns a settable value (fake for the cache)."""

    def __init__(self, value: bool = True) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> bool:
        self.calls += 1
        return self.value


def test_cached_readiness_memoizes_within_ttl() -> None:
    """Within the TTL the underlying predicate is called ONCE, however many probes arrive."""
    clock = _FakeClock()  # starts at 0.0, advances only when told
    pred = _Counter(value=True)
    cached = CachedReadiness(pred, ttl_s=1.0, clock=clock.now)
    assert cached() is True  # first call computes
    for _ in range(50):  # a flood within the window
        assert cached() is True
    assert pred.calls == 1  # only one underlying (session-lock-taking) call


def test_cached_readiness_recomputes_after_ttl() -> None:
    """Once the TTL elapses the value is recomputed (and reflects the new underlying answer)."""
    clock = _FakeClock()
    pred = _Counter(value=True)
    cached = CachedReadiness(pred, ttl_s=1.0, clock=clock.now)
    assert cached() is True and pred.calls == 1
    clock.advance(0.5)
    assert cached() is True and pred.calls == 1  # still fresh
    pred.value = False
    clock.advance(0.6)  # now 1.1 > ttl → recompute
    assert cached() is False and pred.calls == 2


def test_cached_readiness_boundary_is_exclusive() -> None:
    """At exactly ttl_s elapsed the entry is stale (``< ttl_s`` is the freshness test)."""
    clock = _FakeClock()
    pred = _Counter(value=True)
    cached = CachedReadiness(pred, ttl_s=1.0, clock=clock.now)
    cached()
    clock.advance(1.0)  # elapsed == ttl → NOT < ttl → recompute
    cached()
    assert pred.calls == 2
