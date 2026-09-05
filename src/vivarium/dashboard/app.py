"""Read-only Starlette ASGI app for the Vivarium status dashboard (display-only MVP).

Serves a static, inline-free page + three read-only JSON/SSE endpoints over a pluggable
:class:`~vivarium.dashboard.providers.StatusProvider`. Security posture is part of the scaffold, not
a later retrofit:

- **Strict, inline-free CSP** — ``default-src 'none'`` with only ``'self'`` script/style/connect and
  ``img-src 'self' data:``; no ``unsafe-inline``/``unsafe-eval``. All JS/CSS are external files, so
  no nonce is needed and the browser refuses any injected inline script (XSS backstop for the
  UNTRUSTED content the panes render).
- **Hardening headers** — ``X-Content-Type-Options: nosniff``, ``Referrer-Policy: no-referrer``,
  ``X-Frame-Options: DENY`` + ``frame-ancestors 'none'`` (clickjacking), a tight
  ``Permissions-Policy``.
- **Read-only** — GET-only routes; the app holds no write path and cannot invoke a tool.
- **Optional bearer gate** — if ``VIVARIUM_DASHBOARD_TOKEN`` is set, every request must present it
  (constant-time compare); else the app relies on the tailnet bind (see ``__main__``) and warns.
"""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp

from vivarium.dashboard.catalog import catalog
from vivarium.dashboard.commands import INVALID_JSON, CommandExecutor, dispatch
from vivarium.dashboard.providers import DemoProvider, StatusProvider

_STATIC_DIR = Path(__file__).parent / "static"

#: Env var name for an optional shared bearer token gating the whole dashboard.
_TOKEN_ENV = "VIVARIUM_DASHBOARD_TOKEN"  # noqa: S105  # nosec B105 - env var name, not a secret

#: The strict, inline-free Content-Security-Policy. Everything is same-origin + external; no inline
#: script/style is permitted, so injected UNTRUSTED content can never execute even if a render sink
#: were mis-wired (defense in depth on top of the browser-side ``textContent``-only rendering).
_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cache-Control": "no-store",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach the strict CSP + hardening headers to every response."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Call the app, then stamp the security headers."""
        response = await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response


#: HTTP methods that only READ. Read-only viewing is gated by the tailnet bind (the original
#: posture); the token specifically protects the **command surface** (the sole non-safe route,
#: ``POST /api/command``). Gating only mutating methods lets a browser LOAD the UI + read-only APIs
#: over the tailnet (it cannot attach a bearer on navigation) while every command still needs auth.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """If a shared token is configured, require it on **mutating** requests (constant-time compare).

    Read-only GET/HEAD/OPTIONS (the UI + read-only APIs) pass — gated by the tailnet/loopback bind,
    the dashboard's primary access control. Non-safe methods (``POST /api/command`` — the
    command surface, the only write/compute path) require the bearer token. A production deployment
    reuses the server's per-principal authz (ADR-017/019) — a tracked follow-up.
    """

    def __init__(self, app: ASGIApp, token: str | None) -> None:
        """Store the optional expected token."""
        super().__init__(app)
        self._token = token

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Enforce the bearer token on mutating requests when configured; otherwise pass through."""
        if self._token is not None and request.method not in _SAFE_METHODS:
            presented = request.headers.get("authorization", "")
            expected = f"Bearer {self._token}"
            if not hmac.compare_digest(presented, expected):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def _sse_format(data: dict[str, object]) -> bytes:
    """Format one dict as a single SSE ``data:`` event (JSON payload, blank-line terminated)."""
    return f"data: {json.dumps(data)}\n\n".encode()


def build_app(  # noqa: C901 - composition root: one nested handler per route (wiring, not logic)
    provider: StatusProvider | None = None, executor: CommandExecutor | None = None
) -> Starlette:
    """Construct the dashboard ASGI app.

    Args:
        provider: The read-only data source. Defaults to the deterministic :class:`DemoProvider`.
        executor: OPTIONAL interactive command executor (Phase 2 — ADR-076 / TB9). Default ``None``
            keeps the app **read-only + fail-closed**: ``POST /api/command`` returns 503 (disabled)
            and no execution path exists. A live executor is wired only by the (gated) integration,
            and interactive requires auth (a token) — enforced fail-closed below.

    Returns:
        A configured :class:`starlette.applications.Starlette` app (hardened; GET-only unless an
        interactive executor is wired).
    """
    source: StatusProvider = provider if provider is not None else DemoProvider()
    token = os.environ.get(_TOKEN_ENV) or None

    async def health(_request: Request) -> JSONResponse:
        """Liveness — the dashboard process is up (does not assert upstream health in the MVP)."""
        return JSONResponse({"status": "ok"})

    async def sessions(_request: Request) -> JSONResponse:
        """List current analysis sessions (safe scalars)."""
        return JSONResponse({"sessions": [s.json() for s in source.list_sessions()]})

    async def build(_request: Request) -> JSONResponse:
        """The build/deliverable snapshot (catalog, gates, PRs, benchmark)."""
        return JSONResponse(source.build_snapshot().json())

    async def catalog_route(_request: Request) -> JSONResponse:
        """The static workflow + operation catalog (read-only, safe metadata)."""
        return JSONResponse(catalog())

    async def command_route(request: Request) -> JSONResponse:
        """Interactive command endpoint (Phase 2 — ADR-076 / TB9). Default OFF + fail closed.

        Thin: parse the body (or a sentinel) and defer the disabled/auth/gate/execute decision to
        :func:`commands.dispatch`. No executor wired ⇒ 503; no token ⇒ 403; gated op ⇒ 202
        (not executed — human write-consent only); read-only ⇒ executed via the injected executor.
        """
        try:
            body: object = await request.json()
        except Exception:  # any parse failure → the INVALID_JSON sentinel (handled after auth)
            body = INVALID_JSON
        status, payload = dispatch(catalog(), executor, token is not None, body)
        return JSONResponse(payload, status_code=status)

    async def session_events(request: Request) -> StreamingResponse:
        """Stream one session's live events as Server-Sent Events (progress/tool/output/verdict)."""
        session_id = request.path_params["session_id"]

        async def event_stream() -> AsyncIterator[bytes]:
            async for event in source.session_events(session_id):
                if await request.is_disconnected():
                    break
                yield _sse_format(event.json())

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    routes = [
        Route("/api/health", health, methods=["GET"]),
        Route("/api/sessions", sessions, methods=["GET"]),
        Route("/api/sessions/{session_id}/events", session_events, methods=["GET"]),
        Route("/api/build", build, methods=["GET"]),
        Route("/api/catalog", catalog_route, methods=["GET"]),
        Route("/api/command", command_route, methods=["POST"]),
        Mount("/", app=StaticFiles(directory=_STATIC_DIR, html=True), name="static"),
    ]

    middleware = [
        Middleware(SecurityHeadersMiddleware),
        Middleware(BearerAuthMiddleware, token=token),
    ]
    return Starlette(routes=routes, middleware=middleware)
