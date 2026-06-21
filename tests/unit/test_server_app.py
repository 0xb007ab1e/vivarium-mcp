"""Unit tests for the server shell: error boundary, app composition, and stdio runner (WS1).

The error boundary is the trust-boundary-4 chokepoint that turns every failure into a safe, frozen
:class:`ErrorEnvelope`. ``build_app`` is the composition root; ``run_stdio`` must always drain the
session manager on exit (graceful shutdown). ``main`` wires config→logging→collaborators→serve.

All collaborators are local fakes; no real worker / JVM / transport is exercised (ADR-001).
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from vivarium import __main__ as entry
from vivarium.config import Config
from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.ghidra.port import GhidraPort
from vivarium.security.limits import Limits
from vivarium.server import app as srv
from vivarium.sessions.manager import SessionManager
from vivarium.tools import schemas as s


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


# --- error boundary ------------------------------------------------------------------
def test_boundary_passes_success_through() -> None:
    def ok(**_kw: object) -> str:
        return "result"

    guarded = srv._with_error_boundary("t", ok)
    assert guarded(session_id="s") == "result"


def test_boundary_translates_ghidra_error_and_adds_correlation() -> None:
    env = ErrorEnvelope(type=ErrorType.SESSION_INVALID, title="x", detail="unknown", status=404)

    def boom(**_kw: object) -> object:
        raise GhidraMcpError(env)

    out = srv._with_error_boundary("t", boom)()
    assert isinstance(out, ErrorEnvelope)
    assert out.type is ErrorType.SESSION_INVALID
    assert out.correlation_id is not None  # boundary stamps one when absent


def test_boundary_preserves_existing_correlation_id() -> None:
    env = ErrorEnvelope(
        type=ErrorType.VALIDATION, title="x", detail="bad", status=400, correlation_id="c-fixed"
    )

    def boom(**_kw: object) -> object:
        raise GhidraMcpError(env)

    out = srv._with_error_boundary("t", boom)()
    assert isinstance(out, ErrorEnvelope)
    assert out.correlation_id == "c-fixed"


def test_boundary_maps_unexpected_exception_to_generic_internal() -> None:
    def boom(**_kw: object) -> object:
        raise RuntimeError("/secret/host/path leaked")

    out = srv._with_error_boundary("t", boom)()
    assert isinstance(out, ErrorEnvelope)
    assert out.type is ErrorType.INTERNAL
    assert "secret" not in out.detail  # never leak internals (master §5)
    assert out.correlation_id is not None


def test_boundary_maps_pydantic_validation_error() -> None:
    def boom(**_kw: object) -> object:
        s.ReadBytesIn()  # type: ignore[call-arg]  # intentionally missing required fields
        return None

    out = srv._with_error_boundary("read_bytes", boom)()
    assert isinstance(out, ErrorEnvelope)
    assert out.type is ErrorType.VALIDATION
    assert out.detail == "One or more arguments failed validation."


def test_boundary_preserves_handler_signature() -> None:
    import inspect

    def handler(**_kw: object) -> object:
        return None

    handler.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        [inspect.Parameter("session_id", inspect.Parameter.KEYWORD_ONLY, annotation=str)]
    )
    handler.__annotations__ = {"session_id": str}
    guarded = srv._with_error_boundary("t", handler)
    assert list(inspect.signature(guarded).parameters) == ["session_id"]


# --- build_app -----------------------------------------------------------------------
class _FakeSessions:
    def begin_call(self, session_id: str) -> None:
        """In-flight marker (ADR-025 / F4) — no-op for these app tests."""

    def end_call(self, session_id: str) -> None:
        """In-flight clear (ADR-025 / F4) — no-op for these app tests."""

    def authorize(self, sid: str, *, caller: str = "local") -> s.SessionInfo:
        return s.SessionInfo(session_id=sid, state="ready", created_at=0, expires_at=10)

    def create(self, *, owner: str = "local", label: str | None = None) -> s.SessionInfo:
        return s.SessionInfo(session_id="sid1", state="open", created_at=0, expires_at=10)

    def ensure_worker(self, sid: str, *, caller: str = "local") -> None:
        return None

    def evict(self, sid: str, *, reason: str, caller: str | None = None) -> bool:
        return True

    def shutdown(self) -> None:
        self.drained = True


class _FakePort:
    def read_bytes(self, sid: str, a: s.ReadBytesIn) -> s.ReadBytesOut:
        return s.ReadBytesOut(
            address="0x401000",
            data=Untrusted(value="deadbeef", origin=DataOrigin.BINARY, encoding="hex"),
            length=4,
        )

    def attach_stream_jobs(self, manager: object) -> None:
        """No-op streaming-job injection (ADR-040 composition-root wiring seam)."""
        return None

    def __getattr__(self, name: str) -> Any:
        def _unused(sid: str, a: object | None = None) -> object:
            raise AssertionError(f"unexpected port call {name}")

        return _unused


class _StubPort:
    """Minimal port stub for wiring-only tests (no tool is dispatched).

    Implements only the composition-root seam (:meth:`attach_stream_jobs`) that ``build_app`` calls
    while wiring streaming (ADR-040); any other attribute access would be a test bug.
    """

    def attach_stream_jobs(self, manager: object) -> None:
        """No-op streaming-job injection (ADR-040 composition-root wiring seam)."""
        return None


def _build_with_fakes() -> Any:
    """Build the app with cast fakes (``SessionManager`` is concrete, ``GhidraPort`` a Protocol)."""
    return srv.build_app(
        _config(),
        session_manager=cast(SessionManager, _FakeSessions()),
        port=cast(GhidraPort, _FakePort()),
    )


def _result_text(result: object) -> str:
    """Extract the text payload from a FastMCP ``call_tool`` result (first content block)."""
    block = cast(Any, result)[0]
    return cast(str, block.text)


def test_build_app_registers_full_catalog() -> None:
    import anyio

    app = _build_with_fakes()
    tools = anyio.run(app.list_tools)
    from vivarium.tools.registry import TIER1_TOOL_NAMES

    assert {t.name for t in tools} == set(TIER1_TOOL_NAMES)


def test_build_app_publishes_flat_input_schema() -> None:
    import anyio

    app = _build_with_fakes()
    tools = {t.name: t for t in anyio.run(app.list_tools)}
    props = tools["read_bytes"].inputSchema.get("properties") or {}
    assert {"session_id", "address", "length"} <= set(props)


def test_build_app_tool_call_returns_wrapped_output_and_errors() -> None:
    import json

    import anyio

    app = _build_with_fakes()
    ok = anyio.run(
        app.call_tool, "read_bytes", {"session_id": "sid1", "address": "0x401000", "length": 4}
    )
    doc = json.loads(_result_text(ok))
    assert doc["data"]["origin"] == "binary-derived"  # untrusted envelope preserved end-to-end

    # Semantic validation failure surfaces as the frozen error envelope (not a transport crash).
    bad = anyio.run(
        app.call_tool, "read_bytes", {"session_id": "sid1", "address": "NOTHEX", "length": 4}
    )
    assert json.loads(_result_text(bad))["type"] == "validation-error"


# --- run_stdio -----------------------------------------------------------------------
class _RunnableApp:
    def __init__(self, *, raise_on_run: BaseException | None = None) -> None:
        self.ran = False
        self._raise = raise_on_run

    def run(self, transport: str = "stdio", mount_path: str | None = None) -> None:
        self.ran = True
        if self._raise is not None:
            raise self._raise


def test_run_stdio_drains_sessions_on_clean_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(srv, "_install_shutdown_handlers", lambda: None)
    sm = _FakeSessions()
    app = _RunnableApp()
    code = srv.run_stdio(app, session_manager=sm)  # type: ignore[arg-type]
    assert code == 0
    assert app.ran is True
    assert getattr(sm, "drained", False) is True


def test_run_stdio_drains_on_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(srv, "_install_shutdown_handlers", lambda: None)
    sm = _FakeSessions()
    app = _RunnableApp(raise_on_run=KeyboardInterrupt())
    code = srv.run_stdio(app, session_manager=sm)  # type: ignore[arg-type]
    assert code == 0
    assert getattr(sm, "drained", False) is True


def test_run_stdio_drains_even_when_shutdown_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(srv, "_install_shutdown_handlers", lambda: None)

    class _BadSessions(_FakeSessions):
        def shutdown(self) -> None:
            raise RuntimeError("wipe failed")

    # The shutdown error is swallowed (best-effort) and must not mask the clean exit code.
    code = srv.run_stdio(_RunnableApp(), session_manager=_BadSessions())  # type: ignore[arg-type]
    assert code == 0


# --- main wiring ---------------------------------------------------------------------
def test_main_happy_path_wires_and_serves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(entry, "load_config", _config)
    monkeypatch.setattr(entry, "configure_logging", lambda **_k: None)

    built: dict[str, object] = {}

    def fake_build(config: Config, *, session_manager: object, port: object) -> object:
        built["ok"] = True
        return _RunnableApp()

    def fake_run(app: object, *, session_manager: object) -> int:
        return 0

    monkeypatch.setattr(entry, "build_app", fake_build)
    monkeypatch.setattr(entry, "run_stdio", fake_run)

    code = entry.main(
        port_factory=lambda cfg: cast(GhidraPort, object()),
        session_manager_factory=lambda cfg, port: cast(SessionManager, _FakeSessions()),
    )
    assert code == 0
    assert built["ok"] is True


def test_main_returns_nonzero_on_bad_config(monkeypatch: pytest.MonkeyPatch) -> None:
    def bad_load() -> Config:
        raise GhidraMcpError(
            ErrorEnvelope(type=ErrorType.VALIDATION, title="x", detail="bad", status=500)
        )

    monkeypatch.setattr(entry, "load_config", bad_load)
    assert entry.main() == 2


def test_main_returns_nonzero_on_bad_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(entry, "load_config", _config)

    def bad_logging(**_k: object) -> None:
        raise ValueError("bad level")

    monkeypatch.setattr(entry, "configure_logging", bad_logging)
    assert entry.main() == 2


def test_main_returns_nonzero_on_collaborator_construction_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(entry, "load_config", _config)
    monkeypatch.setattr(entry, "configure_logging", lambda **_k: None)

    def bad_port(cfg: Config) -> GhidraPort:
        raise GhidraMcpError(
            ErrorEnvelope(type=ErrorType.INTERNAL, title="x", detail="no worker", status=500)
        )

    assert entry.main(port_factory=bad_port) == 2


# ==============================================================================================
# ADR-017: HTTP per-request principal resolver — reads the authenticated principal stashed on the
# ASGI scope by the auth middleware (server-derived), and fails closed if it is missing.
# ==============================================================================================
import dataclasses  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from vivarium.server.auth import Principal  # noqa: E402
from vivarium.server.http_middleware import SCOPE_PRINCIPAL_KEY  # noqa: E402


class _FakeAppWithScope:
    """Stand-in exposing ``get_context().request_context.request.scope`` for the resolver."""

    def __init__(self, scope: dict[str, Any] | None) -> None:
        request = None if scope is None else SimpleNamespace(scope=scope)
        self._ctx = SimpleNamespace(request_context=SimpleNamespace(request=request))

    def get_context(self) -> Any:
        return self._ctx


def test_http_principal_resolver_returns_scope_principal() -> None:
    scope = {"state": {SCOPE_PRINCIPAL_KEY: Principal(id="alice")}}
    resolver = srv._http_principal_resolver(cast(Any, _FakeAppWithScope(scope)))
    assert resolver() == Principal(id="alice")


def test_http_principal_resolver_fails_closed_when_principal_missing() -> None:
    """No stashed principal (a path that bypassed auth) → fail closed, never default to local."""
    resolver = srv._http_principal_resolver(cast(Any, _FakeAppWithScope({"state": {}})))
    with pytest.raises(GhidraMcpError) as ei:
        resolver()
    assert ei.value.envelope.type is ErrorType.INTERNAL


def test_http_principal_resolver_fails_closed_when_no_request() -> None:
    resolver = srv._http_principal_resolver(cast(Any, _FakeAppWithScope(None)))
    with pytest.raises(GhidraMcpError):
        resolver()


def test_build_app_wires_resolver_for_http_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """``build_app`` attaches the per-request resolver only when transport == 'http'."""
    captured: dict[str, Any] = {}

    def _capture_register(registrar: Any, ctx: Any, *, wrap: Any = None) -> None:
        captured["ctx"] = ctx

    monkeypatch.setattr(srv, "register_tools", _capture_register)

    http_cfg = dataclasses.replace(_config(), transport="http")
    srv.build_app(
        http_cfg,
        session_manager=cast(SessionManager, _FakeSessions()),
        port=cast(GhidraPort, _StubPort()),
    )
    assert captured["ctx"].resolve_principal is not None  # HTTP → resolver wired

    captured.clear()
    srv.build_app(
        _config(),  # stdio (default)
        session_manager=cast(SessionManager, _FakeSessions()),
        port=cast(GhidraPort, _StubPort()),
    )
    assert captured["ctx"].resolve_principal is None  # stdio → static local principal
