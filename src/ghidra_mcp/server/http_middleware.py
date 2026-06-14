"""ASGI middleware for the HTTP transport (v1.1 — ADR-011 / threat-model TB6).

The security edge of the HTTP shell, applied around FastMCP's Streamable-HTTP app (`std-owasp-api`):

- :class:`RequestSizeLimitMiddleware` — reject oversized bodies (``413``) on the ``Content-Length``
  header before the handler reads them (DoS — API4); chunked/length-less bodies are bounded
  downstream by the per-tool argument caps (defense in depth).
- :class:`RateLimitMiddleware` — per-client token bucket (``429`` on exhaustion); the clock is
  injected so it is deterministic + unit-testable.
- :class:`AuthenticationMiddleware` — default-deny: runs the injected :class:`Authenticator`
  (`ghidra_mcp.server.auth`); a rejected request gets a generic ``401`` (no oracle), an accepted one
  has its :class:`~ghidra_mcp.server.auth.Principal` stashed on the ASGI scope for the per-request
  authZ check (slice 4). CORS preflight (``OPTIONS``) is exempt (it carries no credentials).

Pure ASGI (operate on ``scope``/``receive``/``send``) so they are framework-light and
100%-unit-testable with a tiny in-memory harness — no live server needed. Error responses reuse the
frozen :class:`~ghidra_mcp.core.errors.ErrorEnvelope` shape and leak nothing.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, cast

from starlette.types import ASGIApp, Receive, Scope, Send

from ghidra_mcp.server.auth import AuthContext, Authenticator

#: ASGI ``scope["state"]`` key under which :class:`AuthenticationMiddleware` stashes the
#: authenticated :class:`~ghidra_mcp.server.auth.Principal` for the per-request, server-side
#: ownership check (ADR-017). Public so the composition root's per-request principal resolver
#: (:func:`ghidra_mcp.server.app._http_principal_resolver`) reads the same key.
SCOPE_PRINCIPAL_KEY = "ghidra_mcp.principal"
_SCOPE_PRINCIPAL_KEY = SCOPE_PRINCIPAL_KEY  # backward-compatible private alias

# Cap on distinct per-client rate-limit buckets so the limiter (itself the TB6-D DoS control)
# cannot become an unbounded memory-growth vector under many-source traffic (CWE-400). The LRU
# evicts the least-recently-seen client; on a network bind this is far above any real client count
# (the default exposure is single-key loopback), and an evicted, long-idle bucket would have
# refilled anyway, so dropping it is safe.
_MAX_RATE_LIMIT_BUCKETS = 8192


def _header(scope: Scope, name: bytes) -> bytes | None:
    """Return the first value of a request header (lowercased name), or ``None``."""
    for key, value in scope.get("headers", []):
        if key == name:
            return cast("bytes", value)
    return None


async def _send_error(send: Send, status: int, title: str, detail: str) -> None:
    """Send a minimal JSON error response (no internals; generic, safe-to-surface)."""
    body = json.dumps(
        {"type": "about:blank", "title": title, "status": status, "detail": detail}
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class RequestSizeLimitMiddleware:
    """Reject bodies whose ``Content-Length`` exceeds ``max_body_bytes`` (``413``; API4).

    The Content-Length pre-check is the primary control (MCP Streamable-HTTP clients send a
    length). Chunked / length-less bodies are bounded downstream by the per-tool argument caps
    (`security.limits`) — defense in depth; a streaming byte-counter can harden this later.
    """

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        """Wrap ``app``, rejecting requests whose Content-Length exceeds ``max_body_bytes``."""
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Reject on an over-limit ``Content-Length`` before the body is read; else pass through."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _header(scope, b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_body_bytes:
            await _send_error(send, 413, "Payload too large", "Request body exceeds the limit.")
            return
        await self.app(scope, receive, send)


class RateLimitMiddleware:
    """Per-client token-bucket rate limiter; ``429`` when a client's bucket is empty (API4)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        rate_per_second: float,
        burst: int,
        clock: Callable[[], float],
    ) -> None:
        """Wrap ``app`` with a per-client token bucket (rate/burst; injected clock)."""
        self.app = app
        self.rate = float(rate_per_second)
        self.burst = float(burst)
        self._clock = clock
        # client-key -> (tokens, last_refill_ts); LRU-ordered + size-bounded (see _allow).
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def _allow(self, key: str) -> bool:
        """Token-bucket decision for ``key``: refill by elapsed time, spend a token if any.

        Maintains the bucket map as a bounded LRU: the touched key moves to the most-recent end,
        and once the map exceeds ``_MAX_RATE_LIMIT_BUCKETS`` the least-recently-seen client is
        evicted, so the map cannot grow without bound under many-source traffic (CWE-400).
        """
        now = self._clock()
        tokens, last = self._buckets.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= 1.0
        self._buckets[key] = (tokens - 1.0 if allowed else tokens, now)
        self._buckets.move_to_end(key)  # mark most-recently-used
        if len(self._buckets) > _MAX_RATE_LIMIT_BUCKETS:
            self._buckets.popitem(last=False)  # evict least-recently-used
        return allowed

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Allow or ``429`` based on the per-client bucket (client host, or ``"local"`` for UDS)."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        key = client[0] if client else "local"
        if not self._allow(key):
            await _send_error(send, 429, "Too many requests", "Rate limit exceeded; retry later.")
            return
        await self.app(scope, receive, send)


class AuthenticationMiddleware:
    """Default-deny auth: reject → generic ``401``; accept → stash the principal on scope."""

    def __init__(self, app: ASGIApp, *, authenticator: Authenticator) -> None:
        """Wrap ``app`` so every request is authenticated by ``authenticator`` (default-deny)."""
        self.app = app
        self.authenticator = authenticator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Authenticate every HTTP request except CORS preflight; ``401`` on reject (no oracle)."""
        if scope["type"] != "http" or scope.get("method") == "OPTIONS":
            await self.app(
                scope, receive, send
            )  # preflight carries no credentials — let CORS handle
            return
        authorization = _header(scope, b"authorization")
        principal = self.authenticator.authenticate(
            AuthContext(authorization=authorization.decode("latin-1") if authorization else None)
        )
        if principal is None:
            await _send_error(send, 401, "Unauthorized", "Authentication required.")
            return
        # Stash for the per-request authZ + session-ownership check (slice 4). scope state is a
        # per-request dict; create it if the server didn't.
        state: dict[str, Any] = scope.setdefault("state", {})
        state[_SCOPE_PRINCIPAL_KEY] = principal
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Add baseline security headers to every HTTP response (TB6-T; topic-web-frontend)."""

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        """Wrap ``app``; add HSTS only when served over TLS (``hsts=True``)."""
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Inject nosniff / Referrer-Policy / X-Frame-Options (+ HSTS) headers on the response."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def _send(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers += [
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                ]
                if self.hsts:
                    headers.append(
                        (b"strict-transport-security", b"max-age=63072000; includeSubDomains")
                    )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, _send)
