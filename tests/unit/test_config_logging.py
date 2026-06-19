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

from vivarium import config as cfgmod
from vivarium import logging as glog
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.security.limits import Limits


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


_MINIMAL_ENV = {"VIVARIUM_WORKER_IMAGE": "ghcr.io/x/worker@sha256:" + "a" * 64}


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
    assert cfg.rpc_socket_dir == "/run/vivarium"
    assert isinstance(cfg.limits, Limits)
    # No overrides set → resolve_limits called with None.
    assert fake_resolve_limits == [None]


def test_load_config_worker_uid_gid_overridable(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """A host-run server can align the worker uid/gid to its own (ADR-009 socket-dir mapping)."""
    env = dict(_MINIMAL_ENV)
    env["VIVARIUM_WORKER_UID"] = "1000"
    env["VIVARIUM_WORKER_GID"] = "1000"
    cfg = cfgmod.load_config(env)
    assert cfg.worker_uid == 1000
    assert cfg.worker_gid == 1000


def test_load_config_collects_only_set_limit_overrides(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    env = dict(_MINIMAL_ENV)
    env["VIVARIUM_MAX_SESSIONS"] = "2"
    env["VIVARIUM_TOOL_TIMEOUT_SECONDS"] = "30"
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
    env["VIVARIUM_WORKER_MEM_MIB"] = "8192"  # tuned up, below ceiling → honored
    env["VIVARIUM_WORKER_CPUS"] = "99"  # above the cpu ceiling (16) → clamped DOWN
    cfg = cfgmod.load_config(env)
    assert cfg.worker_resources.mem_mib == 8192
    assert cfg.worker_resources.cpus == 16  # clamped to HARD_MAX_WORKER_CPUS


def test_load_config_worker_resources_reject_invalid(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """A non-integer worker-resource env value fails closed as VALIDATION (refuse to boot)."""
    env = dict(_MINIMAL_ENV)
    env["VIVARIUM_WORKER_MEM_MIB"] = "lots"
    with pytest.raises(GhidraMcpError) as exc:
        cfgmod.load_config(env)
    assert exc.value.envelope.type is ErrorType.VALIDATION


def test_load_config_preflight_mode_defaults_to_warn(
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """Unset VIVARIUM_WORKER_PREFLIGHT → secure default ``warn`` (v1.3 behaviour — ADR-029)."""
    cfg = cfgmod.load_config(dict(_MINIMAL_ENV))
    assert cfg.worker_preflight_mode == "warn"


@pytest.mark.parametrize("mode", ["warn", "reject", "off"])
def test_load_config_preflight_mode_parses_each_valid_value(
    mode: str,
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """Each allow-listed pre-flight mode parses to itself (ADR-029 C)."""
    env = dict(_MINIMAL_ENV)
    env["VIVARIUM_WORKER_PREFLIGHT"] = mode
    cfg = cfgmod.load_config(env)
    assert cfg.worker_preflight_mode == mode


@pytest.mark.parametrize("bad", ["WARN", "drop", "true", "1", "rejectt", "warn off"])
def test_load_config_preflight_mode_rejects_invalid_fails_closed(
    bad: str,
    fake_resolve_limits: list[dict[str, int] | None],
) -> None:
    """An invalid pre-flight mode → VALIDATION error; refuse to boot (fail closed, ADR-029 C)."""
    env = dict(_MINIMAL_ENV)
    env["VIVARIUM_WORKER_PREFLIGHT"] = bad
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
        {**_MINIMAL_ENV, "VIVARIUM_LOG_LEVEL": "NOPE"},
        {**_MINIMAL_ENV, "VIVARIUM_LOG_FORMAT": "xml"},
        {**_MINIMAL_ENV, "VIVARIUM_SESSION_TTL_SECONDS": "0"},
        {**_MINIMAL_ENV, "VIVARIUM_SESSION_TTL_SECONDS": "-5"},
        {**_MINIMAL_ENV, "VIVARIUM_MAX_SESSIONS": "abc"},
        {**_MINIMAL_ENV, "VIVARIUM_MAX_SESSIONS": "0x10"},
        {
            **_MINIMAL_ENV,
            "VIVARIUM_SESSION_IDLE_SECONDS": "9999",
            "VIVARIUM_SESSION_TTL_SECONDS": "10",
        },
        {**_MINIMAL_ENV, "VIVARIUM_WORKER_IMAGE": "img\x00bad"},
        {"VIVARIUM_WORKER_IMAGE": "a" * 600},  # too long
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
    env["VIVARIUM_SESSION_TTL_SECONDS"] = "   "  # whitespace → use default
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
    env["VIVARIUM_SESSION_IDLE_SECONDS"] = "650"
    env["VIVARIUM_SESSION_TTL_SECONDS"] = "3600"
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
    env["VIVARIUM_SESSION_IDLE_SECONDS"] = "700"
    env["VIVARIUM_SESSION_TTL_SECONDS"] = "3600"
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
    rec = logging.LogRecord("vivarium.test", logging.INFO, "p.py", 10, "an.event", None, None)
    for key, value in extra.items():
        setattr(rec, key, value)
    return rec


def test_json_formatter_emits_structured_schema() -> None:
    out = glog._RedactingJsonFormatter().format(_make_record(session="opaque", size=42))
    doc = json.loads(out)
    assert doc["level"] == "INFO"
    assert doc["logger"] == "vivarium.test"
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
    assert glog.get_logger("vivarium.x").name == "vivarium.x"


# --- ADR-024 PR-1: traceback rendering + reserved-key guard ----------------------------------
def _record_with_exc(exc: BaseException) -> logging.LogRecord:
    """Build a log record carrying ``exc`` as ``exc_info`` (as ``_log.exception`` would)."""
    try:
        raise exc
    except BaseException:  # test helper deliberately captures any exception
        import sys

        return logging.LogRecord(
            "vivarium.test", logging.ERROR, "p.py", 10, "an.event", None, sys.exc_info()
        )


def test_json_formatter_renders_traceback_into_exc() -> None:
    """A record with ``exc_info`` renders frames into ``payload['exc']`` (diagnosable)."""
    out = glog._RedactingJsonFormatter().format(_record_with_exc(RuntimeError("boom")))
    doc = json.loads(out)
    assert "exc" in doc
    assert "Traceback" in doc["exc"]
    assert "RuntimeError" in doc["exc"]
    assert "boom" in doc["exc"]  # a normal exception keeps its message line


def test_json_formatter_without_exc_info_omits_exc() -> None:
    """A record with no exception has no ``exc`` field."""
    doc = json.loads(glog._RedactingJsonFormatter().format(_make_record(size=1)))
    assert "exc" not in doc


def test_json_formatter_strips_validation_error_message_line() -> None:
    """A ValidationError-class message line is stripped (it can echo a binary-derived value)."""
    from pydantic import BaseModel, ValidationError

    class _M(BaseModel):
        n: int

    try:
        _M(n="HOSTILE_SENTINEL_VALUE")  # type: ignore[arg-type]
    except ValidationError as ve:
        rec = _record_with_exc(ve)
    out = glog._RedactingJsonFormatter().format(rec)
    doc = json.loads(out)
    assert "exc" in doc
    assert "Traceback" in doc["exc"]  # frames retained for diagnosis
    assert "HOSTILE_SENTINEL_VALUE" not in out  # value-echoing message line dropped


def test_json_formatter_strips_chained_validation_error_message() -> None:
    """A ValidationError WRAPPED in another exception is still scrubbed (chain-walked)."""
    from pydantic import BaseModel, ValidationError

    class _M(BaseModel):
        n: int

    try:
        try:
            _M(n="HOSTILE_SENTINEL_VALUE")  # type: ignore[arg-type]
        except ValidationError as ve:
            raise RuntimeError("wrapped worker fault") from ve
    except RuntimeError as exc:
        rec = _record_with_exc(exc)
    out = glog._RedactingJsonFormatter().format(rec)
    doc = json.loads(out)
    assert "Traceback" in doc["exc"]  # frames retained for diagnosis
    assert "HOSTILE_SENTINEL_VALUE" not in out  # inner ValidationError value still scrubbed


def test_chain_has_value_echoing_detects_wrapped_and_cycles() -> None:
    """The chain walker finds a wrapped value-echoer and is cycle-safe."""
    assert glog._chain_has_value_echoing(None) is False
    assert glog._chain_has_value_echoing(RuntimeError("plain")) is False
    # a self-referential context must not loop forever
    a = RuntimeError("a")
    a.__context__ = a
    assert glog._chain_has_value_echoing(a) is False


def test_text_formatter_renders_traceback() -> None:
    line = glog._RedactingTextFormatter().format(_record_with_exc(RuntimeError("kaboom")))
    assert "Traceback" in line
    assert "kaboom" in line


def test_reserved_key_guard_renames_colliding_extra() -> None:
    """A caller ``extra`` colliding with a reserved LogRecord name is renamed, not crashed."""
    guarded = glog._guard_extra({"msg": "x", "args": "y", "name": "z", "method": "ok"})
    assert guarded is not None
    assert "msg" not in guarded
    assert guarded["x_msg"] == "x"
    assert guarded["x_args"] == "y"
    assert guarded["x_name"] == "z"
    assert guarded["method"] == "ok"  # non-reserved key untouched


def test_reserved_key_guard_handles_empty_and_none() -> None:
    assert glog._guard_extra(None) is None
    assert glog._guard_extra({}) == {}


def test_redacting_logger_does_not_crash_on_reserved_extra() -> None:
    """End-to-end: a reserved ``extra`` key does NOT raise KeyError (the makeRecord guard)."""
    glog.configure_logging(level="DEBUG", fmt="json")
    log = glog.get_logger("vivarium.reserved_test")
    handler = logging.getLogger().handlers[0]
    captured: list[str] = []
    orig_emit = handler.emit

    def _capture(record: logging.LogRecord) -> None:
        captured.append(handler.format(record))

    handler.emit = _capture  # type: ignore[method-assign]
    try:
        # Without the guard this raises: KeyError: Attempt to overwrite 'msg' in LogRecord.
        log.warning("worker.event", extra={"msg": "shadow", "session": "opaque"})
    finally:
        handler.emit = orig_emit  # type: ignore[method-assign]
    assert captured, "log call must succeed and produce output"
    doc = json.loads(captured[0])
    assert doc["x_msg"] == "shadow"  # renamed safely
    assert doc["session"] == "opaque"


def test_redacting_logger_reserved_guard_still_redacts_sensitive() -> None:
    """The reserved-key guard preserves the key so sensitive-substring redaction still fires."""
    guarded = glog._guard_extra({"args": "SENSITIVE"})  # 'args' is reserved → renamed x_args
    assert guarded == {"x_args": "SENSITIVE"}
    # A sensitive non-reserved key is redacted at format time (existing behavior, unchanged).
    out = glog._RedactingJsonFormatter().format(_make_record(decompiled="HOSTILE"))
    assert json.loads(out)["decompiled"] == "[REDACTED]"
