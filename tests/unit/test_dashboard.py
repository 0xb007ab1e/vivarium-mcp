"""Unit tests for the read-only status dashboard (display-only MVP).

Covers the security posture (strict inline-free CSP + hardening headers, GET-only, optional bearer,
fail-closed tailnet/loopback bind) and the data contract (session summaries, build snapshot, SSE
events) — including the load-bearing rule that binary-derived content is delivered TAGGED untrusted.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from vivarium.dashboard.__main__ import _check_bind, _is_tailnet_or_loopback, _parse_bind
from vivarium.dashboard.app import build_app
from vivarium.dashboard.models import (
    BuildSnapshot,
    GateStatus,
    SessionEvent,
    SessionSummary,
    UiValue,
    tag,
)
from vivarium.dashboard.providers import DemoProvider


@pytest.fixture
def client() -> TestClient:
    """A TestClient over the app with the deterministic demo provider (no token)."""
    return TestClient(build_app(DemoProvider()))


def _drain_sse(client: TestClient, session_id: str) -> list[dict[str, Any]]:
    """Read a session's SSE stream to the terminal verdict, returning the parsed events."""
    import json

    events: list[dict[str, Any]] = []
    with client.stream("GET", f"/api/sessions/{session_id}/events") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        for line in r.iter_lines():
            if line.startswith("data: "):
                event = json.loads(line[len("data: ") :])
                events.append(event)
                if event["kind"] == "verdict":
                    break
    return events


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
    events = _drain_sse(client, "demo-analyzing")
    kinds = [e["kind"] for e in events]
    assert "progress" in kinds and "output" in kinds and "verdict" in kinds
    out = next(e for e in events if e["kind"] == "output")
    assert out["content"]["untrusted"] is True
    assert (
        "onerror=alert(1)" in out["content"]["value"]
    )  # carried inert as data, not executed markup


def test_sse_stream_emits_analysis_panels(client: TestClient) -> None:
    """The stream carries the richer analysis panels (format, imports/exports, strings, callgraph).

    Every binary-derived leaf inside a panel's ``data`` MUST be a tagged untrusted value
    (``{"value","untrusted":true}``) — never a bare string — so the browser renders it inert.
    """
    events = {e["kind"]: e for e in _drain_sse(client, "demo-analyzing")}
    for kind in ("metadata", "imports", "exports", "strings", "callgraph"):
        assert kind in events, f"missing panel kind {kind}"

    # metadata: safe scalars are bare; binary-derived fields (program/compiler) are tagged
    fields = {f["k"]: f["v"] for f in events["metadata"]["data"]["fields"]}
    assert fields["format"] == "ELF"  # safe scalar, bare
    assert fields["program"] == {"value": "demo.elf", "untrusted": True}  # tagged

    # imports: each name is a tagged untrusted leaf; the injection-shaped one is carried inert
    imp = events["imports"]["data"]["items"]
    assert all(i["name"]["untrusted"] is True for i in imp)
    assert any("onerror=alert(1)" in i["name"]["value"] for i in imp)

    # strings + callgraph labels are tagged untrusted too
    assert all(s["value"]["untrusted"] is True for s in events["strings"]["data"]["items"])
    assert all(n["label"]["untrusted"] is True for n in events["callgraph"]["data"]["nodes"])


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


def test_tag_builds_untrusted_leaf() -> None:
    """tag() builds the tagged untrusted-leaf shape used inside SessionEvent.data."""
    assert tag("puts") == {"value": "puts", "untrusted": True}


def test_session_event_data_roundtrips() -> None:
    """A panel event's structured ``data`` (with tagged leaves) survives json() serialization."""
    ev = SessionEvent(
        kind="imports",
        session_id="s",
        label="imports",
        data={"total": 1, "items": [{"address": "0x1", "name": tag("system")}]},
    )
    j = ev.json()
    assert j["kind"] == "imports"
    assert j["data"]["items"][0]["name"] == {"value": "system", "untrusted": True}


# --- live file bridge -----------------------------------------------------------------------------


def test_file_state_roundtrip(tmp_path: Path) -> None:
    """DashboardState written rows read back identically through FileStatusProvider."""
    from vivarium.dashboard.state import DashboardState, FileStatusProvider

    state_file = tmp_path / "state.json"
    writer = DashboardState(state_file)
    writer.upsert_session(
        SessionSummary(
            session_id="live-1",
            state="analyzing",
            progress_percent=10,
            phase="importing",
            binary_sha256="ab" * 32,
            tool_count=1,
            last_tool="session_analyze",
            started_at="2026-09-05T00:00:00Z",
        )
    )
    writer.set_build(
        BuildSnapshot(
            tool_count=78,
            read_only_count=62,
            gates=[GateStatus("quality", "pass")],
            recent_prs=["#317 dashboard"],
            benchmark={"cases": 1},
        )
    )

    provider = FileStatusProvider(state_file)
    sessions = provider.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].session_id == "live-1" and sessions[0].progress_percent == 10
    snap = provider.build_snapshot()
    assert snap.tool_count == 78
    assert snap.gates[0].name == "quality"
    assert snap.recent_prs == ["#317 dashboard"]


def test_file_state_missing_is_empty(tmp_path: Path) -> None:
    """A missing/never-written state file reads as empty, never raising."""
    from vivarium.dashboard.state import FileStatusProvider

    provider = FileStatusProvider(tmp_path / "absent.json")
    assert provider.list_sessions() == []
    assert provider.build_snapshot().tool_count == 0


def test_file_state_corrupt_is_empty(tmp_path: Path) -> None:
    """A torn/invalid-JSON state file degrades to empty (fail-soft), never raising."""
    from vivarium.dashboard.state import FileStatusProvider

    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    provider = FileStatusProvider(bad)
    assert provider.list_sessions() == []


def test_file_state_non_dict_is_empty(tmp_path: Path) -> None:
    """A valid-JSON-but-non-object state file (e.g. a bare list) degrades to empty."""
    from vivarium.dashboard.state import FileStatusProvider

    f = tmp_path / "list.json"
    f.write_text("[]", encoding="utf-8")
    assert FileStatusProvider(f).list_sessions() == []


def test_file_state_tail_ends_on_idle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A stream with no terminal verdict ends after the bounded idle window (no infinite tail)."""
    from vivarium.dashboard import state as state_mod
    from vivarium.dashboard.state import DashboardState, FileStatusProvider

    monkeypatch.setattr(state_mod, "_TAIL_INTERVAL_S", 0.0)
    monkeypatch.setattr(state_mod, "_TAIL_MAX_IDLE", 2)
    state_file = tmp_path / "state.json"
    DashboardState(state_file).append_event(
        SessionEvent(kind="progress", session_id="s", percent=10)
    )
    provider = FileStatusProvider(state_file)

    async def _drain() -> list[SessionEvent]:
        return [e async for e in provider.session_events("s")]

    got = asyncio.run(_drain())
    assert [e.kind for e in got] == ["progress"]  # yielded, then stream closed on idle timeout


def test_dashboard_state_cleans_temp_on_write_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failed persist raises and leaves no orphan temp file (atomic-write cleanup)."""
    import json

    from vivarium.dashboard.state import DashboardState

    state_file = tmp_path / "state.json"
    writer = DashboardState(state_file)

    def _boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(json, "dump", _boom)
    with pytest.raises(RuntimeError, match="disk full"):
        writer.append_event(SessionEvent(kind="progress", session_id="s", percent=1))
    assert list(tmp_path.glob("*.tmp")) == []


def test_file_state_sse_tail_preserves_untrusted(tmp_path: Path) -> None:
    """The SSE tail replays events and preserves the untrusted tag on binary-derived content."""
    from vivarium.dashboard.state import DashboardState, FileStatusProvider

    state_file = tmp_path / "state.json"
    writer = DashboardState(state_file)
    writer.append_event(SessionEvent(kind="progress", session_id="live-1", percent=50, phase="x"))
    writer.append_event(
        SessionEvent(
            kind="output",
            session_id="live-1",
            label="decompile",
            content=UiValue("<img src=x onerror=alert(1)>", untrusted=True),
        )
    )
    writer.append_event(
        SessionEvent(kind="verdict", session_id="live-1", content=UiValue("benign"))
    )

    provider = FileStatusProvider(state_file)

    async def _drain() -> list[SessionEvent]:
        return [e async for e in provider.session_events("live-1")]

    got = asyncio.run(_drain())

    kinds = [e.kind for e in got]
    assert kinds == ["progress", "output", "verdict"]  # stops after the terminal verdict
    out = next(e for e in got if e.kind == "output")
    assert out.content is not None and out.content.untrusted is True
    assert "onerror=alert(1)" in out.content.value


def test_file_state_preserves_panel_data(tmp_path: Path) -> None:
    """The bridge round-trips a panel event's structured ``data`` (tagged leaves intact)."""
    from vivarium.dashboard.state import DashboardState, FileStatusProvider

    state_file = tmp_path / "state.json"
    DashboardState(state_file).append_event(
        SessionEvent(
            kind="callgraph",
            session_id="s",
            data={"nodes": [{"id": "0x1", "label": tag("main")}], "edges": []},
        )
    )
    DashboardState(state_file).append_event(SessionEvent(kind="verdict", session_id="s"))

    provider = FileStatusProvider(state_file)

    async def _drain() -> list[SessionEvent]:
        return [e async for e in provider.session_events("s")]

    got = asyncio.run(_drain())
    cg = next(e for e in got if e.kind == "callgraph")
    assert cg.data is not None
    assert cg.data["nodes"][0]["label"] == {"value": "main", "untrusted": True}


def test_select_provider_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """_select_provider returns a file provider iff VIVARIUM_DASHBOARD_STATE is set."""
    from vivarium.dashboard.__main__ import _select_provider

    monkeypatch.delenv("VIVARIUM_DASHBOARD_STATE", raising=False)
    assert _select_provider() is None
    monkeypatch.setenv("VIVARIUM_DASHBOARD_STATE", str(tmp_path / "s.json"))
    assert _select_provider() is not None
