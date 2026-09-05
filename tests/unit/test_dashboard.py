"""Unit tests for the read-only status dashboard (display-only MVP).

Covers the security posture (strict inline-free CSP + hardening headers, GET-only, optional bearer,
fail-closed tailnet/loopback bind) and the data contract (session summaries, build snapshot, SSE
events) — including the load-bearing rule that binary-derived content is delivered TAGGED untrusted.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from vivarium.dashboard.__main__ import _check_bind, _is_tailnet_or_loopback, _parse_bind
from vivarium.dashboard.app import build_app
from vivarium.dashboard.models import UiValue
from vivarium.dashboard.providers import DemoProvider


@pytest.fixture
def client() -> TestClient:
    """A TestClient over the app with the deterministic demo provider (no token)."""
    return TestClient(build_app(DemoProvider()))


# --- data contract --------------------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    """Liveness endpoint responds ok."""
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_sessions_are_safe_scalars(client: TestClient) -> None:
    """The session list returns safe scalars (ids/state/progress) — no untrusted wrapper needed."""
    r = client.get("/api/sessions")
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert len(sessions) == 2
    s = sessions[0]
    assert s["session_id"] and s["state"] and isinstance(s["progress_percent"], int)


def test_build_snapshot(client: TestClient) -> None:
    """The build snapshot carries the catalog/gates/benchmark numbers."""
    b = client.get("/api/build").json()
    assert b["tool_count"] == 78
    assert b["read_only_count"] == 62
    assert any(g["name"] == "live-regression" for g in b["gates"])
    assert b["benchmark"]["verdict_hits"] == 4


def test_sse_stream_tags_untrusted_output(client: TestClient) -> None:
    """The SSE stream delivers an OUTPUT event whose binary-derived content is tagged untrusted.

    The demo output deliberately contains injection-shaped characters; the API must carry it as
    inert DATA (``untrusted: true``), never as pre-rendered markup — the browser then renders it via
    ``textContent`` only.
    """
    import json

    with client.stream("GET", "/api/sessions/demo-analyzing/events") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        events = []
        for line in r.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[len("data: ") :]))
            if len(events) >= 7:  # 4 progress + tool + output + verdict
                break
    kinds = [e["kind"] for e in events]
    assert "progress" in kinds and "output" in kinds and "verdict" in kinds
    out = next(e for e in events if e["kind"] == "output")
    assert out["content"]["untrusted"] is True
    assert (
        "onerror=alert(1)" in out["content"]["value"]
    )  # carried inert as data, not executed markup


# --- security posture -----------------------------------------------------------------------------


def test_strict_csp_and_hardening_headers(client: TestClient) -> None:
    """A strict, inline-free CSP + hardening headers are present on every response."""
    h = client.get("/api/health").headers
    csp = h["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"


def test_read_only_no_post() -> None:
    """The app exposes no write verb — a POST to an API route is not allowed."""
    c = TestClient(build_app(DemoProvider()))
    assert c.post("/api/sessions").status_code in (405, 404)


def test_bearer_token_gate() -> None:
    """When a token is configured, requests without it are 401; with it, 200."""
    import os

    os.environ["VIVARIUM_DASHBOARD_TOKEN"] = "s3cret-demo"  # noqa: S105 - test fixture, not a secret
    try:
        c = TestClient(build_app(DemoProvider()))
        assert c.get("/api/health").status_code == 401
        assert (
            c.get("/api/health", headers={"authorization": "Bearer s3cret-demo"}).status_code == 200
        )
    finally:
        del os.environ["VIVARIUM_DASHBOARD_TOKEN"]


# --- fail-closed bind -----------------------------------------------------------------------------


def test_parse_bind_ipv4_and_ipv6() -> None:
    """host:port and [ipv6]:port both parse."""
    assert _parse_bind("127.0.0.1:8760") == ("127.0.0.1", 8760)
    assert _parse_bind("[::1]:8760") == ("::1", 8760)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "100.101.102.103"])
def test_bind_allows_loopback_and_tailnet(host: str) -> None:
    """Loopback + Tailscale CGNAT (100.64.0.0/10) addresses are allowed."""
    assert _is_tailnet_or_loopback(host) is True


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "::", "192.168.1.10", "10.0.0.5", "8.8.8.8", "localhost"],  # noqa: S104 - refuse-list literals, not a bind
)
def test_bind_refuses_public_and_lan_and_hostnames(host: str) -> None:
    """Public / LAN / wildcard / resolvable-hostname binds are refused (fail closed)."""
    assert _is_tailnet_or_loopback(host) is False


def test_check_bind_exits_on_public() -> None:
    """_check_bind raises SystemExit on a non-loopback/non-tailnet host."""
    with pytest.raises(SystemExit):
        _check_bind("0.0.0.0:8760")
    assert _check_bind("127.0.0.1:8760") == ("127.0.0.1", 8760)


def test_parse_bind_rejects_malformed() -> None:
    """A value without a port (no ``host:port`` shape) is rejected."""
    with pytest.raises(ValueError, match="invalid bind"):
        _parse_bind("noport")


def test_bind_non_ip_hostname_refused() -> None:
    """A non-IP hostname (not a bare literal) fails the IP parse and is refused (fail closed)."""
    assert _is_tailnet_or_loopback("host.example.invalid") is False


def test_bind_allows_non_literal_loopback() -> None:
    """A loopback IP outside the literal set (e.g. 127.0.0.2) is still allowed via is_loopback."""
    assert _is_tailnet_or_loopback("127.0.0.2") is True


# --- entrypoint (main) ----------------------------------------------------------------------------


def test_main_runs_on_valid_bind(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """main() validates the bind and hands the app to uvicorn; warns when no token is set."""
    import uvicorn

    from vivarium.dashboard.__main__ import main

    calls: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(app=app, **kw))
    monkeypatch.setenv("VIVARIUM_DASHBOARD_BIND", "127.0.0.1:8799")
    monkeypatch.delenv("VIVARIUM_DASHBOARD_TOKEN", raising=False)

    main()

    assert (calls["host"], calls["port"]) == ("127.0.0.1", 8799)
    assert "VIVARIUM_DASHBOARD_TOKEN not set" in capsys.readouterr().err


def test_main_no_warning_with_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With a token configured, main() runs without emitting the no-token warning."""
    import uvicorn

    from vivarium.dashboard.__main__ import main

    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    monkeypatch.setenv("VIVARIUM_DASHBOARD_BIND", "127.0.0.1:8799")
    monkeypatch.setenv("VIVARIUM_DASHBOARD_TOKEN", "t0ken")

    main()

    assert "VIVARIUM_DASHBOARD_TOKEN not set" not in capsys.readouterr().err


# --- model ----------------------------------------------------------------------------------------


def test_uivalue_json_shape() -> None:
    """UiValue serializes to the {value, untrusted} contract the browser keys off."""
    assert UiValue("x", untrusted=True).json() == {"value": "x", "untrusted": True}
