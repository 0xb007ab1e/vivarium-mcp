"""Unit tests for startup config loading and redacting structured logging (WS1).

Config is hermetic: it reads an injected ``env`` mapping (never the real environment) and fails
closed on missing/invalid values. ``resolve_limits`` is a WS4 stub, so these tests inject a fake
via monkeypatch to exercise the full config path without depending on WS4.

Logging tests assert the redaction contract: binary-derived / sensitive-keyed fields are never
emitted, output goes to stderr, and the format is structured JSON.
"""

from __future__ import annotations

import json
import logging

import pytest

from ghidra_mcp import config as cfgmod
from ghidra_mcp import logging as glog
from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.security.limits import Limits


@pytest.fixture
def fake_resolve_limits(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, int] | None]:
    """Replace the WS4 ``resolve_limits`` stub with a recording fake returning default limits.

    Returns:
        A list capturing the ``overrides`` argument passed on each call (for assertions).
    """
    calls: list[dict[str, int] | None] = []

    def _fake(overrides: dict[str, int] | None = None) -> Limits:
        calls.append(overrides)
        return Limits()

    monkeypatch.setattr(cfgmod, "resolve_limits", _fake)
    return calls


_MINIMAL_ENV = {"GHIDRA_MCP_WORKER_IMAGE": "ghcr.io/x/worker@sha256:" + "a" * 64}


def test_load_config_minimal_uses_secure_defaults(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    cfg = cfgmod.load_config(dict(_MINIMAL_ENV))
    assert cfg.log_level == "INFO"
    assert cfg.log_format == "json"
    assert cfg.session_ttl_s == 3600
    assert cfg.session_idle_s == 900
    assert cfg.worker_runtime == "runsc"
    assert cfg.worker_uid == 65532
    assert cfg.worker_gid == 65532
    assert cfg.rpc_socket_dir == "/run/ghidra-mcp"
    assert isinstance(cfg.limits, Limits)
    # No overrides set → resolve_limits called with None.
    assert fake_resolve_limits == [None]


def test_load_config_worker_uid_gid_overridable(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """A host-run server can align the worker uid/gid to its own (ADR-009 socket-dir mapping)."""
    env = dict(_MINIMAL_ENV)
    env["GHIDRA_MCP_WORKER_UID"] = "1000"
    env["GHIDRA_MCP_WORKER_GID"] = "1000"
    cfg = cfgmod.load_config(env)
    assert cfg.worker_uid == 1000
    assert cfg.worker_gid == 1000


def test_load_config_collects_only_set_limit_overrides(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    env = dict(_MINIMAL_ENV)
    env["GHIDRA_MCP_MAX_SESSIONS"] = "2"
    env["GHIDRA_MCP_TOOL_TIMEOUT_SECONDS"] = "30"
    cfgmod.load_config(env)
    assert fake_resolve_limits == [{"max_sessions": 2, "tool_timeout_s": 30}]


def test_load_config_worker_resources_default(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """With no worker-resource env set, the resolved defaults are used (ADR-023 / F1)."""
    cfg = cfgmod.load_config(dict(_MINIMAL_ENV))
    assert cfg.worker_resources.mem_mib == 4096
    assert cfg.worker_resources.cpus == 2
    assert cfg.worker_resources.pids == 512
    assert cfg.worker_resources.tmpfs_scratch_mib == 2048
    assert cfg.worker_resources.tmpfs_project_mib == 4096


def test_load_config_worker_resources_overrides_collected_and_clamped(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """Explicitly-set worker-resource env vars are collected, validated, and clamped (ADR-023)."""
    env = dict(_MINIMAL_ENV)
    env["GHIDRA_MCP_WORKER_MEM_MIB"] = "8192"  # tuned up, below ceiling → honored
    env["GHIDRA_MCP_WORKER_CPUS"] = "99"  # above the cpu ceiling (16) → clamped DOWN
    cfg = cfgmod.load_config(env)
    assert cfg.worker_resources.mem_mib == 8192
    assert cfg.worker_resources.cpus == 16  # clamped to HARD_MAX_WORKER_CPUS


def test_load_config_worker_resources_reject_invalid(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """A non-integer worker-resource env value fails closed as VALIDATION (refuse to boot)."""
    env = dict(_MINIMAL_ENV)
    env["GHIDRA_MCP_WORKER_MEM_MIB"] = "lots"
    with pytest.raises(GhidraMcpError) as exc:
        cfgmod.load_config(env)
    assert exc.value.envelope.type is ErrorType.VALIDATION


def test_load_config_missing_required_worker_image_fails_closed(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        cfgmod.load_config({})
    assert exc.value.envelope.type is ErrorType.VALIDATION
    # Required-field check happens before limits resolution.
    assert fake_resolve_limits == []


@pytest.mark.parametrize(
    "env",
    [
        {**_MINIMAL_ENV, "GHIDRA_MCP_LOG_LEVEL": "NOPE"},
        {**_MINIMAL_ENV, "GHIDRA_MCP_LOG_FORMAT": "xml"},
        {**_MINIMAL_ENV, "GHIDRA_MCP_SESSION_TTL_SECONDS": "0"},
        {**_MINIMAL_ENV, "GHIDRA_MCP_SESSION_TTL_SECONDS": "-5"},
        {**_MINIMAL_ENV, "GHIDRA_MCP_MAX_SESSIONS": "abc"},
        {**_MINIMAL_ENV, "GHIDRA_MCP_MAX_SESSIONS": "0x10"},
        {
            **_MINIMAL_ENV,
            "GHIDRA_MCP_SESSION_IDLE_SECONDS": "9999",
            "GHIDRA_MCP_SESSION_TTL_SECONDS": "10",
        },
        {**_MINIMAL_ENV, "GHIDRA_MCP_WORKER_IMAGE": "img\x00bad"},
        {"GHIDRA_MCP_WORKER_IMAGE": "a" * 600},  # too long
    ],
)
def test_load_config_rejects_invalid_values(
    env: dict[str, str], fake_resolve_limits: list[dict[str, int] | None]
) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        cfgmod.load_config(env)
    assert exc.value.envelope.type is ErrorType.VALIDATION


def test_load_config_blank_values_treated_as_unset(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    env = dict(_MINIMAL_ENV)
    env["GHIDRA_MCP_SESSION_TTL_SECONDS"] = "   "  # whitespace → use default
    cfg = cfgmod.load_config(env)
    assert cfg.session_ttl_s == 3600


# --- session-liveness invariant: idle >= analysis_timeout (ADR-025 / F4) ----------------------
# The fake resolve_limits returns default Limits (analysis_timeout_s == 600). The startup invariant
# must reject a deployment whose idle window is shorter than the analysis timeout (a long analyze
# could otherwise idle-evict its own session mid-call), and accept idle >= analysis_timeout.
def test_load_config_rejects_idle_below_analysis_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """idle < analysis_timeout is a fatal misconfiguration (fail-closed VALIDATION)."""
    # Force a known analysis_timeout via the limits fake (700) and set idle below it (650 < 700),
    # keeping ttl >= idle so only the new invariant trips.
    monkeypatch.setattr(
        cfgmod, "resolve_limits", lambda overrides=None: Limits(analysis_timeout_s=700)
    )
    env = dict(_MINIMAL_ENV)
    env["GHIDRA_MCP_SESSION_IDLE_SECONDS"] = "650"
    env["GHIDRA_MCP_SESSION_TTL_SECONDS"] = "3600"
    with pytest.raises(GhidraMcpError) as exc:
        cfgmod.load_config(env)
    assert exc.value.envelope.type is ErrorType.VALIDATION


def test_load_config_accepts_idle_equal_to_analysis_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """idle == analysis_timeout is the boundary and is accepted (>=)."""
    monkeypatch.setattr(
        cfgmod, "resolve_limits", lambda overrides=None: Limits(analysis_timeout_s=700)
    )
    env = dict(_MINIMAL_ENV)
    env["GHIDRA_MCP_SESSION_IDLE_SECONDS"] = "700"
    env["GHIDRA_MCP_SESSION_TTL_SECONDS"] = "3600"
    cfg = cfgmod.load_config(env)
    assert cfg.session_idle_s == 700
    assert cfg.limits.analysis_timeout_s == 700


def test_load_config_defaults_satisfy_liveness_invariant(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """The shipped defaults (idle 900 >= analysis 600) boot cleanly — no value changes (ADR-025)."""
    cfg = cfgmod.load_config(dict(_MINIMAL_ENV))
    assert cfg.session_idle_s == 900
    assert cfg.limits.analysis_timeout_s == 600
    assert cfg.session_idle_s >= cfg.limits.analysis_timeout_s


# --- logging -------------------------------------------------------------------------
def _make_record(**extra: object) -> logging.LogRecord:
    rec = logging.LogRecord("ghidra_mcp.test", logging.INFO, "p.py", 10, "an.event", None, None)
    for key, value in extra.items():
        setattr(rec, key, value)
    return rec


def test_json_formatter_emits_structured_schema() -> None:
    out = glog._RedactingJsonFormatter().format(_make_record(session="opaque", size=42))
    doc = json.loads(out)
    assert doc["level"] == "INFO"
    assert doc["logger"] == "ghidra_mcp.test"
    assert doc["event"] == "an.event"
    assert doc["session"] == "opaque"
    assert doc["size"] == 42


@pytest.mark.parametrize(
    "key",
    ["c_code", "decompiled", "strings", "raw_bytes", "value", "comment_text", "secret", "token"],
)
def test_json_formatter_redacts_sensitive_keys(key: str) -> None:
    out = glog._RedactingJsonFormatter().format(_make_record(**{key: "HOSTILE PAYLOAD"}))
    doc = json.loads(out)
    assert doc[key] == "[REDACTED]"
    assert "HOSTILE PAYLOAD" not in out


def test_text_formatter_redacts_and_renders() -> None:
    line = glog._RedactingTextFormatter().format(_make_record(session="s1", c_code="evil"))
    assert "session=s1" in line
    assert "c_code=[REDACTED]" in line
    assert "evil" not in line


def test_text_formatter_without_extra_fields() -> None:
    line = glog._RedactingTextFormatter().format(_make_record())
    assert "an.event" in line
    assert "|" not in line  # no extra section when there are no structured fields


def test_configure_logging_installs_single_stderr_handler() -> None:
    glog.configure_logging(level="DEBUG", fmt="json")
    root = logging.getLogger()
    assert len(root.handlers) == 1
    handler = root.handlers[0]
    assert isinstance(handler, logging.StreamHandler)
    assert isinstance(handler.formatter, glog._RedactingJsonFormatter)
    # Idempotent: a second call replaces, does not duplicate.
    glog.configure_logging(level="INFO", fmt="text")
    assert len(logging.getLogger().handlers) == 1
    assert isinstance(logging.getLogger().handlers[0].formatter, glog._RedactingTextFormatter)


def test_configure_logging_rejects_bad_level() -> None:
    with pytest.raises(ValueError, match="log level"):
        glog.configure_logging(level="BOGUS")


def test_get_logger_returns_named_logger() -> None:
    assert glog.get_logger("ghidra_mcp.x").name == "ghidra_mcp.x"
