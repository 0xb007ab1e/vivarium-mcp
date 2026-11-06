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
- **Read-only by default** — GET routes are the UI + read-only APIs; the sole command surface
  (``POST /api/command``) is Phase-2 interactive (ADR-076 / TB9), default-OFF + fail-closed.

Interactive command backend (ADR-076 Phase 2 / threat-model TB9) — the §21 pre-exposure controls:

- **Per-principal auth (ADR-017/019 — reuse the server).** When interactive is enabled the command
  route authenticates each request with the server's :class:`MultiTokenBearerAuthenticator` built
  from a ``{token: principal-id}`` map — distinct tokens are distinct principals (BOLA-closed), and
  an interactive app built WITHOUT an authenticator **fails closed at startup** (ADR-076 D2). The
  read-only GET routes stay tailnet-gated (a browser cannot attach a bearer on navigation).
- **App-layer rate limiter (TB9 / API4).** ``POST /api/command`` is wrapped in the server's
  per-client token-bucket :class:`RateLimitMiddleware` (``429`` on exhaustion) — scoped to the
  command path only, so the UI's read-only GETs are never rate-limited. This is a hard prerequisite
  for ever enabling a compute executor.
- **Per-command audit (redacted).** Every command logs principal id, op, gating decision, and HTTP
  status to the ``vivarium.dashboard.audit`` logger — never the params' values or any
  binary-derived content (master §5 redaction).

The compute-capable ``WorkerExecutor`` and any production enablement remain **gated** (ADR-076).
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from vivarium.dashboard.catalog import catalog
from vivarium.dashboard.commands import INVALID_JSON, CommandExecutor, dispatch
from vivarium.dashboard.providers import DemoProvider, StatusProvider
from vivarium.server.auth import AuthContext, Authenticator, MultiTokenBearerAuthenticator
from vivarium.server.http_middleware import RateLimitMiddleware

_STATIC_DIR = Path(__file__).parent / "static"

#: Env var: a single shared bearer token (legacy / single-principal). Mapped to the ``dashboard``
#: principal for backward compatibility when ``_PRINCIPALS_ENV`` is unset.
_TOKEN_ENV = "VIVARIUM_DASHBOARD_TOKEN"  # noqa: S105  # nosec B105 - env var name, not a secret

#: Env var: a JSON object ``{"<token>": "<principal-id>"}`` mapping each bearer token to its
#: principal (ADR-017 per-principal auth). Takes precedence over ``_TOKEN_ENV`` when both are set.
_PRINCIPALS_ENV = "VIVARIUM_DASHBOARD_PRINCIPALS"  # nosec B105 - env var name

#: Env vars: the command-route token-bucket rate (requests/sec) + burst. Conservative defaults — a
#: human driving the UI issues a few commands at a time; a flood is a DoS signal (TB9 / API4).
_RATE_ENV = "VIVARIUM_DASHBOARD_COMMAND_RATE"
_BURST_ENV = "VIVARIUM_DASHBOARD_COMMAND_BURST"
_DEFAULT_RATE = 5.0
_DEFAULT_BURST = 10

#: The command surface path (the sole non-safe route; the only one authenticated + rate-limited).
_COMMAND_PATH = "/api/command"

#: Per-command audit logger. Emits principal/op/decision/status ONLY — never params or binary
#: content (master §5 redaction). Routed by the host logging config.
_audit = logging.getLogger("vivarium.dashboard.audit")

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


class _CommandScopedRateLimit:
    """Apply the token-bucket rate limiter ONLY to ``POST`` on the command path, else pass through.

    Reuses the server's :class:`RateLimitMiddleware` (per-client bucket, ``429``) as the limiter for
    the command surface, so the UI's read-only GET navigation (many asset loads) is never
    rate-limited. For a command request the call is routed through the limiter (which rate-checks,
    then invokes the base app); every other request goes straight to the base app.
    """

    def __init__(self, base: ASGIApp, limited: ASGIApp) -> None:
        """Store the unlimited base app and the same app wrapped by the limiter."""
        self._base = base
        self._limited = limited

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Route command POSTs through the limiter; everything else straight to the base app."""
        if (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == _COMMAND_PATH
        ):
            await self._limited(scope, receive, send)
        else:
            await self._base(scope, receive, send)


def _build_authenticator() -> Authenticator | None:
    """Build the command authenticator from config, or ``None`` when no credentials are configured.

    ``_PRINCIPALS_ENV`` (a JSON ``{token: principal}`` map) takes precedence; else a lone
    ``_TOKEN_ENV`` maps to the ``dashboard`` principal (backward compatibility). Returns ``None``
    when neither is set (interactive then fails closed at :func:`build_app`). A malformed map or a
    too-short token raises at construction — a misconfigured interactive dashboard refuses to start.

    Returns:
        A :class:`MultiTokenBearerAuthenticator`, or ``None`` when no token/map is set.
    """
    raw = os.environ.get(_PRINCIPALS_ENV)
    if raw:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
        ):
            raise ValueError(f"{_PRINCIPALS_ENV} must be a JSON object of {{token: principal-id}}")
        return MultiTokenBearerAuthenticator(tokens=dict(parsed))
    token = os.environ.get(_TOKEN_ENV)
    if token:
        return MultiTokenBearerAuthenticator(tokens={token: "dashboard"})
    return None


def _auth_context(request: Request) -> AuthContext:
    """Build a transport-agnostic :class:`AuthContext` from the request (bearer header only)."""
    return AuthContext(
        authorization=request.headers.get("authorization"),
        peer_certificate=None,
        headers={k.lower(): v for k, v in request.headers.items()},
    )


def _rate_config() -> tuple[float, int]:
    """Resolve the command-route rate/burst from config (clamped to sane positive values)."""
    try:
        rate = float(os.environ.get(_RATE_ENV, _DEFAULT_RATE))
    except ValueError:
        rate = _DEFAULT_RATE
    try:
        burst = int(os.environ.get(_BURST_ENV, _DEFAULT_BURST))
    except ValueError:
        burst = _DEFAULT_BURST
    return (max(rate, 0.1), max(burst, 1))


def _sse_format(data: dict[str, object]) -> bytes:
    """Format one dict as a single SSE ``data:`` event (JSON payload, blank-line terminated)."""
    return f"data: {json.dumps(data)}\n\n".encode()


def build_app(  # noqa: C901 - composition root: one nested handler per route (wiring, not logic)
    provider: StatusProvider | None = None, executor: CommandExecutor | None = None
) -> ASGIApp:
    """Construct the dashboard ASGI app.

    Args:
        provider: The read-only data source. Defaults to the deterministic :class:`DemoProvider`.
        executor: OPTIONAL interactive command executor (Phase 2 — ADR-076 / TB9). Default ``None``
            keeps the app **read-only + fail-closed**: ``POST /api/command`` returns 503 (disabled)
            and no execution path exists. When an executor IS wired (interactive enabled), a
            per-principal authenticator is REQUIRED — otherwise this raises at startup (ADR-076 D2).

    Returns:
        The hardened ASGI app. GET routes are the UI + read-only APIs; the command POST is
        authenticated + rate-limited + audited when interactive is enabled.

    Raises:
        ValueError: If ``executor`` is wired (interactive on) but no per-principal authenticator is
            configured (``VIVARIUM_DASHBOARD_PRINCIPALS`` / ``VIVARIUM_DASHBOARD_TOKEN``) — an
            interactive dashboard without auth fails closed at startup.
    """
    source: StatusProvider = provider if provider is not None else DemoProvider()
    # Auth only matters for the interactive command surface; a read-only dashboard (no executor)
    # returns 503 before auth, so it never builds/requires an authenticator.
    authenticator = _build_authenticator() if executor is not None else None
    if executor is not None and authenticator is None:
        raise ValueError(
            "interactive dashboard (executor wired) requires per-principal auth — set "
            f"{_PRINCIPALS_ENV} (a JSON {{token: principal}} map) or {_TOKEN_ENV}"
        )

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

        Order (ADR-076): disabled (503) → authenticate → parse → gate → (read-only) execute.
        Authentication binds the command to a :class:`Principal`; a gated op is never executed here
        (202). Every outcome is audit-logged (principal/op/decision/status — redacted).
        """
        if executor is None:
            # Disabled interactive leaks nothing and never consults auth/parse (fail-closed first).
            _audit.info("command", extra=_audit_fields("-", "-", "disabled", 503))
            return JSONResponse({"error": "interactive-disabled"}, status_code=503)
        principal = authenticator.authenticate(_auth_context(request)) if authenticator else None
        principal_id = principal.id if principal is not None else "-"
        try:
            body: object = await request.json()
        except Exception:  # any parse failure → the INVALID_JSON sentinel (handled after auth)
            body = INVALID_JSON
        status, payload = dispatch(catalog(), executor, principal is not None, body)
        op = body.get("op") if isinstance(body, dict) else "-"
        _audit.info(
            "command",
            extra=_audit_fields(
                principal_id, str(op) if op else "-", payload.get("decision"), status
            ),
        )
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
        Route(_COMMAND_PATH, command_route, methods=["POST"]),
        Mount("/", app=StaticFiles(directory=_STATIC_DIR, html=True), name="static"),
    ]

    base: ASGIApp = Starlette(routes=routes, middleware=[Middleware(SecurityHeadersMiddleware)])
    rate, burst = _rate_config()
    limited = RateLimitMiddleware(base, rate_per_second=rate, burst=burst, clock=time.monotonic)
    return _CommandScopedRateLimit(base=base, limited=limited)


def _audit_fields(principal_id: str, op: str, decision: object, status: int) -> dict[str, object]:
    """Build the redacted audit ``extra`` for one command (no params/binary content; master §5)."""
    return {
        "dashboard_principal": principal_id,
        "dashboard_op": op,
        "dashboard_decision": decision if isinstance(decision, str) else "-",
        "dashboard_status": status,
    }
