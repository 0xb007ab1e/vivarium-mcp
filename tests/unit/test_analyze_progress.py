"""Unit tests for the ADR-030 Phase 1 ``$/progress`` increment (framing + adapter read-loop).

These cover trust boundary 2 (server ↔ worker) for the **additive, opt-in** worker→server
``$/progress`` notification without a real Ghidra worker. Behavior under test (all hermetic — a
``socket.socketpair`` plays the worker, monotonic time is injected where the deadline matters):

- **Framing classifier + parser** (``is_progress_notification`` / ``parse_progress``): a valid frame
  is accepted; every malformed/abuse shape is REJECTED fail-closed; a progress frame and a response
  are never confused for one another (the no-top-level-``id`` invariant).
- **Pure adapter helpers** (``_analyze_params`` / ``_progress_log_payload`` /
  ``_should_relay_progress``) and the pure ``_monitor_percent`` JVM-edge helper.
- **The read-loop** (``_call(expect_progress=True)`` / ``_read_response_with_progress``): N progress
  frames precede the response and are all relayed (redacted) before the response returns; a
  non-opted-in call uses the unchanged single-frame path; the one-shot deadline is **NOT extended**
  by progress frames; the flood bound and coalescing behave per the documented policy.
- **Schema:** ``SessionAnalyzeIn.progress`` defaults ``False``, accepts ``True``, rejects extras.

No real worker, no Ghidra, no network, no wall-clock dependence on the deadline path.
"""

from __future__ import annotations

import contextlib
import json
import logging
import socket
import struct
import threading
from typing import Any

import pytest
from pydantic import ValidationError
from worker import dispatch as wd

from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra import rpc_client as rc
from vivarium.ghidra import rpc_framing as f
from vivarium.ghidra._jvm_bridge import _monitor_percent
from vivarium.ghidra.rpc_client import (
    RpcGhidraAdapter,
    _analyze_params,
    _progress_log_payload,
    _should_relay_progress,
)
from vivarium.tools import schemas as s

_CAP = 4 * 1024 * 1024
_RID = "req-abc"


# --- framing: is_progress_notification ---------------------------------------------------------
def test_is_progress_notification_true_for_well_formed() -> None:
    """A frame with the ``$/progress`` method and NO top-level id is a progress notification."""
    frame = {
        "jsonrpc": "2.0",
        "method": "$/progress",
        "params": {"id": _RID, "percent": 5, "phase": "analyzing"},
    }
    assert f.is_progress_notification(frame) is True


def test_is_progress_notification_false_when_top_level_id_present() -> None:
    """A ``$/progress`` method that ALSO carries a top-level id is NOT progress (fail closed).

    The no-id invariant is what guarantees a notification can never be mistaken for the request's
    correlated response — even if a hostile worker stamps ``method`` onto a response-shaped frame.
    """
    frame = {"jsonrpc": "2.0", "id": _RID, "method": "$/progress", "params": {"id": _RID}}
    assert f.is_progress_notification(frame) is False


def test_is_progress_notification_false_for_response_frame() -> None:
    """A normal response (result, has id, no method) is never classified as progress."""
    assert f.is_progress_notification({"jsonrpc": "2.0", "id": _RID, "result": {}}) is False


def test_is_progress_notification_false_for_wrong_method() -> None:
    """A notification with some other method name is not a ``$/progress`` frame."""
    assert f.is_progress_notification({"jsonrpc": "2.0", "method": "$/other"}) is False


def test_is_progress_notification_false_for_missing_method() -> None:
    """A frame with no method at all is not progress."""
    assert f.is_progress_notification({"jsonrpc": "2.0", "params": {}}) is False


# --- framing: parse_progress (happy path) ------------------------------------------------------
def test_parse_progress_accepts_valid_frame() -> None:
    """A well-formed frame parses to a safe RpcProgress (percent + closed-vocab phase)."""
    frame = f.build_progress(_RID, 42, "analyzing")
    prog = f.parse_progress(frame, expected_id=_RID)
    assert isinstance(prog, f.RpcProgress)
    assert prog.request_id == _RID
    assert prog.percent == 42
    assert prog.phase == "analyzing"


def test_parse_progress_accepts_null_percent() -> None:
    """An indeterminate monitor reports ``percent: null`` → ``None`` (honest 'no estimate')."""
    frame = f.build_progress(_RID, None, "importing")
    prog = f.parse_progress(frame, expected_id=_RID)
    assert prog.percent is None
    assert prog.phase == "importing"


@pytest.mark.parametrize("percent", [0, 100])
def test_parse_progress_accepts_boundary_percents(percent: int) -> None:
    """The percent bounds 0 and 100 are both accepted (inclusive range)."""
    prog = f.parse_progress(f.build_progress(_RID, percent, "finalizing"), expected_id=_RID)
    assert prog.percent == percent


@pytest.mark.parametrize("phase", sorted(f.PROGRESS_PHASES))
def test_parse_progress_accepts_every_closed_phase(phase: str) -> None:
    """Every phase in the closed vocabulary is accepted."""
    prog = f.parse_progress(f.build_progress(_RID, 1, phase), expected_id=_RID)
    assert prog.phase == phase


# --- framing: parse_progress fail-closed rejections (abuse paths) ------------------------------
def test_parse_progress_rejects_wrong_jsonrpc_version() -> None:
    """A non-2.0 jsonrpc version is rejected."""
    frame = {
        "jsonrpc": "1.0",
        "method": "$/progress",
        "params": {"id": _RID, "percent": 1, "phase": "analyzing"},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


def test_parse_progress_rejects_missing_method() -> None:
    """A frame without the ``$/progress`` method is rejected by the parser."""
    frame = {"jsonrpc": "2.0", "params": {"id": _RID, "percent": 1, "phase": "analyzing"}}
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


def test_parse_progress_rejects_frame_with_top_level_id() -> None:
    """A ``$/progress`` frame that also carries a top-level id is rejected by the parser too."""
    frame = {
        "jsonrpc": "2.0",
        "id": _RID,
        "method": "$/progress",
        "params": {"id": _RID, "percent": 1, "phase": "analyzing"},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


def test_parse_progress_rejects_non_object_params() -> None:
    """A ``params`` that is not a JSON object is rejected."""
    frame = {"jsonrpc": "2.0", "method": "$/progress", "params": [1, 2, 3]}
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


def test_parse_progress_rejects_wrong_expected_id() -> None:
    """A frame correlated to a different request id is rejected (no desync correlation)."""
    frame = f.build_progress("some-other-id", 1, "analyzing")
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


@pytest.mark.parametrize("bad", [-1, 101, 1000])
def test_parse_progress_rejects_out_of_range_percent(bad: int) -> None:
    """An out-of-range percent fails closed (the worker is potentially hostile)."""
    frame = {
        "jsonrpc": "2.0",
        "method": "$/progress",
        "params": {"id": _RID, "percent": bad, "phase": "analyzing"},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


@pytest.mark.parametrize("bad", ["50", 1.5, True, False])
def test_parse_progress_rejects_non_int_percent(bad: object) -> None:
    """A non-int (or bool — an int subclass) percent is rejected (defensive type narrowing)."""
    frame = {
        "jsonrpc": "2.0",
        "method": "$/progress",
        "params": {"id": _RID, "percent": bad, "phase": "analyzing"},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


def test_parse_progress_rejects_unknown_phase() -> None:
    """A phase outside the closed vocabulary is rejected (no free-form TaskMonitor text)."""
    frame = {
        "jsonrpc": "2.0",
        "method": "$/progress",
        "params": {"id": _RID, "percent": 1, "phase": "decompiling‮evil"},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


def test_parse_progress_rejects_non_string_phase() -> None:
    """A non-string phase is rejected."""
    frame = {
        "jsonrpc": "2.0",
        "method": "$/progress",
        "params": {"id": _RID, "percent": 1, "phase": 7},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


def test_parse_progress_rejects_missing_params_id() -> None:
    """A params object lacking the correlating id is rejected (id default None != expected)."""
    frame = {
        "jsonrpc": "2.0",
        "method": "$/progress",
        "params": {"percent": 1, "phase": "analyzing"},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_progress(frame, expected_id=_RID)


# --- a progress frame is never a response, and vice-versa --------------------------------------
def test_progress_frame_is_not_parsed_as_a_response() -> None:
    """parse_response REJECTS a progress notification (no result/error member)."""
    frame = f.build_progress(_RID, 10, "analyzing")
    assert f.is_progress_notification(frame) is True
    with pytest.raises(f.RpcProtocolError):
        f.parse_response(frame, expected_id=_RID)


def test_response_frame_is_not_classified_as_progress() -> None:
    """A success response is not a progress notification and parses as a response."""
    resp = {"jsonrpc": "2.0", "id": _RID, "result": {"state": "ready"}}
    assert f.is_progress_notification(resp) is False
    assert f.parse_response(resp, expected_id=_RID) == {"state": "ready"}


# --- framing: build_progress (worker side; validates its own output) ---------------------------
def test_build_progress_shape_has_no_top_level_id() -> None:
    """The emitted notification carries no top-level id and the safe payload only."""
    frame = f.build_progress(_RID, 33, "analyzing")
    assert frame == {
        "jsonrpc": "2.0",
        "method": "$/progress",
        "params": {"id": _RID, "percent": 33, "phase": "analyzing"},
    }
    assert "id" not in frame


def test_build_progress_rejects_unknown_phase() -> None:
    """build_progress fails loudly on an out-of-vocabulary phase (coding-mistake guard)."""
    with pytest.raises(ValueError, match="phase"):
        f.build_progress(_RID, 1, "not-a-phase")


@pytest.mark.parametrize("bad", [-1, 101])
def test_build_progress_rejects_out_of_range_percent(bad: int) -> None:
    """build_progress fails loudly on an out-of-range percent."""
    with pytest.raises(ValueError, match="percent"):
        f.build_progress(_RID, bad, "analyzing")


# --- rpc_client pure helper: _analyze_params ---------------------------------------------------
def test_analyze_params_default_no_progress_is_byte_for_byte_today() -> None:
    """Default profile + ``progress=False`` → ``{"timeout_seconds": ...}`` ONLY (both keys gone)."""
    assert _analyze_params(123, "default") == {"timeout_seconds": 123}
    assert _analyze_params(123, "default", progress=False) == {"timeout_seconds": 123}
    params = _analyze_params(None, "default")
    assert params == {"timeout_seconds": None}
    assert "profile" not in params and "progress" not in params


def test_analyze_params_progress_true_adds_only_progress_key() -> None:
    """``progress=True`` (default profile) adds the explicit ``progress`` key, no ``profile``."""
    assert _analyze_params(60, "default", progress=True) == {
        "timeout_seconds": 60,
        "progress": True,
    }


@pytest.mark.parametrize("profile", ["light", "deep"])
def test_analyze_params_profile_and_progress_combine(profile: str) -> None:
    """A non-default profile and the progress opt-in coexist as two additive keys."""
    assert _analyze_params(None, profile, progress=True) == {
        "timeout_seconds": None,
        "profile": profile,
        "progress": True,
    }


@pytest.mark.parametrize("profile", ["light", "deep"])
def test_analyze_params_profile_without_progress_omits_progress(profile: str) -> None:
    """A non-default profile with ``progress=False`` omits the ``progress`` key."""
    params = _analyze_params(5, profile)
    assert params == {"timeout_seconds": 5, "profile": profile}
    assert "progress" not in params


# --- rpc_client pure helper: _progress_log_payload ---------------------------------------------
def test_progress_log_payload_carries_percent_and_phase_only() -> None:
    """The log payload is EXACTLY {percent, phase} — no other key, no free-form text field."""
    payload = _progress_log_payload(f.RpcProgress(request_id=_RID, percent=77, phase="finalizing"))
    assert payload == {"percent": 77, "phase": "finalizing"}
    assert set(payload) == {"percent", "phase"}


def test_progress_log_payload_passes_null_percent_through() -> None:
    """A null percent rides through to the log payload unchanged."""
    payload = _progress_log_payload(f.RpcProgress(request_id=_RID, percent=None, phase="importing"))
    assert payload == {"percent": None, "phase": "importing"}


def test_progress_log_payload_has_no_freeform_text_field() -> None:
    """There is structurally no field that could hold binary-derived TaskMonitor text (master §5).

    RpcProgress only models ``request_id``/``percent``/``phase``; the payload derived from it can
    never carry a free-form message — the redaction is the type, not a scrub pass.
    """
    payload = _progress_log_payload(f.RpcProgress(request_id=_RID, percent=1, phase="analyzing"))
    forbidden = {"message", "msg", "text", "detail", "note", "name"}
    assert forbidden.isdisjoint(payload.keys())


# --- rpc_client pure helper: _should_relay_progress (coalescing) -------------------------------
def test_should_relay_first_frame_always() -> None:
    """The first frame (no prior relayed time) is always relayed."""
    assert _should_relay_progress(None, now=100.0, min_interval_s=0.5) is True


def test_should_relay_at_or_after_interval() -> None:
    """A frame at exactly / beyond the interval since the last relayed one is relayed."""
    assert _should_relay_progress(100.0, now=100.5, min_interval_s=0.5) is True
    assert _should_relay_progress(100.0, now=101.0, min_interval_s=0.5) is True


def test_should_relay_suppresses_sooner_than_interval() -> None:
    """A frame arriving sooner than the interval is coalesced (not relayed)."""
    assert _should_relay_progress(100.0, now=100.1, min_interval_s=0.5) is False


# --- _jvm_bridge pure helper: _monitor_percent -------------------------------------------------
def test_monitor_percent_basic_ratio() -> None:
    """A determinate (value, maximum) maps to the rounded percent."""
    assert _monitor_percent(50, 100) == 50
    assert _monitor_percent(1, 4) == 25


def test_monitor_percent_value_zero() -> None:
    """A zero value over a positive maximum is 0 percent."""
    assert _monitor_percent(0, 100) == 0


def test_monitor_percent_indeterminate_maximum_is_none() -> None:
    """A non-positive maximum (indeterminate monitor) reports None, not a fake 0."""
    assert _monitor_percent(5, 0) is None
    assert _monitor_percent(5, -10) is None


def test_monitor_percent_clamps_above_100() -> None:
    """A transient value > maximum (Ghidra does this) clamps to 100 (never out-of-range)."""
    assert _monitor_percent(150, 100) == 100


def test_monitor_percent_clamps_below_0() -> None:
    """A negative value clamps to 0."""
    assert _monitor_percent(-5, 100) == 0


def test_monitor_percent_rounds_to_nearest() -> None:
    """The mapping rounds to the nearest integer percent."""
    assert _monitor_percent(1, 3) == 33  # 33.33 → 33
    assert _monitor_percent(2, 3) == 67  # 66.67 → 67


# --- read-loop: a fake-socket harness ----------------------------------------------------------
class _FakeWorker:
    """A fake worker process handle that records kills (mirrors test_rpc_adapter harness)."""

    def __init__(self) -> None:
        """Initialize a live, un-killed fake worker."""
        self.killed = 0

    def kill(self) -> None:
        """Record a kill."""
        self.killed += 1

    def is_alive(self) -> bool:
        """Whether the fake worker is alive (always True until killed)."""
        return self.killed == 0

    def exit_diagnosis(self) -> str:
        """Return a generic crash diagnosis (no OOM)."""
        return "other"


class _ConnectedAdapter(RpcGhidraAdapter):
    """Adapter whose ``_ensure_connected`` returns a pre-wired socketpair end."""

    def __init__(self, *, server_sock: socket.socket, **kw: object) -> None:
        """Initialize with the server-side end of a connected socket pair.

        Args:
            server_sock: The socket the adapter uses as if connected to the worker.
            **kw: Forwarded to :class:`RpcGhidraAdapter`.
        """
        super().__init__(**kw)  # type: ignore[arg-type]
        self._wired = server_sock

    def _ensure_connected(self, sess: object, *, deadline: float = 0.0) -> socket.socket:
        """Return the pre-wired socket instead of dialing a real UDS.

        Args:
            sess: The per-session state (unused).

        Returns:
            The pre-wired socket.
        """
        sess.sock = self._wired  # type: ignore[attr-defined]
        return self._wired


def _make_adapter(
    server_sock: socket.socket,
    worker: _FakeWorker,
    *,
    analysis_timeout_s: float = 2.0,
) -> _ConnectedAdapter:
    """Build an adapter wired to ``server_sock`` with a live session ``"s"``.

    Args:
        server_sock: The adapter's end of the connected pair.
        worker: The fake worker handle to register.
        analysis_timeout_s: The per-analysis deadline (kept short for hermetic tests).

    Returns:
        A ready adapter with a live session ``"s"``.
    """
    adapter = _ConnectedAdapter(
        server_sock=server_sock,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=2.0,
        analysis_timeout_s=analysis_timeout_s,
        max_response_bytes=_CAP,
    )
    adapter.start_worker("s")
    return adapter


def _send_frame(sock: socket.socket, obj: dict[str, Any]) -> None:
    """Frame and send one JSON-RPC object on ``sock``."""
    sock.sendall(f.encode_frame(obj, max_frame_bytes=_CAP))


_ANALYZE_RESULT = {
    "session_id": "s",
    "state": "ready",
    "created_at": 1,
    "expires_at": 2,
    "binary_sha256": None,
}


# --- read-loop: progress frames relayed, then final response returned --------------------------
def test_read_loop_relays_progress_then_returns_response(caplog: pytest.LogCaptureFixture) -> None:
    """K $/progress notifications precede the response → relayed (redacted), response returned."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        # Three progress frames (real time spaces them under the coalescer in practice — but the
        # relay assertion below tolerates coalescing), then the response.
        for pct, phase in ((10, "importing"), (50, "analyzing"), (90, "finalizing")):
            _send_frame(wrk, f.build_progress(rid, pct, phase))
        _send_frame(wrk, {"jsonrpc": "2.0", "id": rid, "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    with caplog.at_level(logging.INFO):
        info = adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", progress=True))
    t.join(timeout=3)

    assert info.state == "ready"
    assert worker.killed == 0  # a clean progress+response stream never kills
    relayed = [r for r in caplog.records if r.message == "analyze.progress"]
    # At least the first frame is relayed (later ones may coalesce under the 0.5s interval).
    assert relayed, "expected at least one relayed progress frame"
    # Each relay carries ONLY the safe percent + closed-vocab phase (master §5 redaction).
    for rec in relayed:
        assert rec.phase in f.PROGRESS_PHASES  # type: ignore[attr-defined]
        pct = rec.percent  # type: ignore[attr-defined]
        assert isinstance(pct, int) and 0 <= pct <= 100
        # No binary-derived free-form text field ever appears on a relayed record.
        assert not hasattr(rec, "message_text") and not hasattr(rec, "detail")
    wrk.close()


def test_read_loop_response_with_no_progress_frames() -> None:
    """An opted-in call whose worker emits no progress frames still returns the response cleanly."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        _send_frame(wrk, {"jsonrpc": "2.0", "id": req["id"], "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    info = adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", progress=True))
    t.join(timeout=3)
    assert info.state == "ready"
    assert worker.killed == 0
    wrk.close()


def test_non_opted_in_call_uses_single_frame_path_unchanged() -> None:
    """A non-opted-in analyze takes the unchanged single-read path (no progress key, no loop)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    seen: dict[str, Any] = {}

    def _serve() -> None:
        req = _read_request(wrk)
        seen.update(req["params"])
        _send_frame(wrk, {"jsonrpc": "2.0", "id": req["id"], "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    info = adapter.analyze("s", s.SessionAnalyzeIn(session_id="s"))  # progress defaults False
    t.join(timeout=3)
    assert info.state == "ready"
    assert "progress" not in seen  # the opt-in key never crosses the wire on the default path
    assert seen == {"timeout_seconds": None}
    wrk.close()


def test_opted_in_call_sends_progress_param() -> None:
    """An opted-in analyze threads ``progress: True`` into the RPC params (additive)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    seen: dict[str, Any] = {}

    def _serve() -> None:
        req = _read_request(wrk)
        seen.update(req["params"])
        _send_frame(wrk, {"jsonrpc": "2.0", "id": req["id"], "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", progress=True))
    t.join(timeout=3)
    assert seen.get("progress") is True
    wrk.close()


# --- read-loop: deadline NOT extended by progress frames ---------------------------------------
def test_deadline_not_extended_by_progress_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    """Progress frames never push the one-shot deadline: a never-arriving response still times out.

    The worker streams a couple of progress frames then goes silent (no response). With a monotonic
    clock injected so time advances past ``total_timeout_s`` regardless of how many progress frames
    arrived, the loop must raise TimeoutError → the adapter SIGKILLs the worker and returns TIMEOUT.
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker, analysis_timeout_s=5.0)

    # Inject a monotonic clock: first call (deadline base) = 0; then the remaining-time check
    # returns a time already past the 5s budget, so the loop fails the remaining guard. The progress
    # frames arrive BEFORE that, proving they did not reset/extend the deadline.
    clock = iter([0.0, 100.0, 100.0, 100.0, 100.0])
    monkeypatch.setattr("vivarium.ghidra.rpc_client.time.monotonic", lambda: next(clock))

    def _serve() -> None:
        # Emit two progress frames, then never send a response (simulate a chatty hang). The
        # adapter SIGKILLs + closes its socket end on the deadline, so a late send here may
        # BrokenPipe — the simulated worker losing its socket; swallow it (not the tested path).
        with contextlib.suppress(OSError):
            req = _read_request(wrk)
            _send_frame(wrk, f.build_progress(req["id"], 10, "analyzing"))
            _send_frame(wrk, f.build_progress(req["id"], 20, "analyzing"))
        # Leave the socket otherwise silent; the deadline must fire regardless.

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", progress=True))
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.TIMEOUT
    assert worker.killed == 1  # SIGKILL on the un-extended deadline
    wrk.close()


# --- read-loop: flood bound --------------------------------------------------------------------
def test_progress_flood_over_cap_is_protocol_violation_and_kills(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """More than _MAX_PROGRESS_FRAMES progress frames is a protocol violation → kill + unavailable.

    Per the impl's documented policy: exceeding the hard frame count raises RpcProtocolError, which
    the universal kill handler maps to worker-unavailable + SIGKILL. The cap is shrunk via
    monkeypatch so the test stays fast and hermetic (behavior under test is the bound, not the
    literal number).
    """
    monkeypatch.setattr("vivarium.ghidra.rpc_client._MAX_PROGRESS_FRAMES", 3)
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        # Send 4 progress frames (cap is 3) → the 4th trips the flood bound before any response.
        for _ in range(4):
            _send_frame(wrk, f.build_progress(req["id"], 1, "analyzing"))

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", progress=True))
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1
    wrk.close()


def test_sub_interval_frames_are_coalesced_not_all_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Frames arriving sooner than the relay interval are coalesced (only some logged) — under cap.

    A monotonic clock pins every relay check to the same instant (well within the 0.5s interval), so
    only the FIRST frame is relayed and the rest are coalesced; none trip the (un-shrunk) flood cap,
    so mere chattiness is NOT fatal. This proves coalescing drops from the log while the count still
    advances toward the cap.
    """
    assert rc._MIN_PROGRESS_INTERVAL_S == 0.5  # documented default relay interval
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        for _ in range(5):
            _send_frame(wrk, f.build_progress(req["id"], 5, "analyzing"))
        _send_frame(wrk, {"jsonrpc": "2.0", "id": req["id"], "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    with caplog.at_level(logging.INFO):
        info = adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", progress=True))
    t.join(timeout=3)
    assert info.state == "ready"
    relayed = [r for r in caplog.records if r.message == "analyze.progress"]
    # All five back-to-back within ~one real instant → a subset relayed (at least the first).
    assert 1 <= len(relayed) <= 5
    assert worker.killed == 0  # mere chattiness under the cap is not fatal
    wrk.close()


# --- read-loop: a malformed progress frame fails closed (kill + evict) -------------------------
def test_malformed_progress_frame_in_loop_kills_worker() -> None:
    """A $/progress frame with an out-of-range percent → RpcProtocolError → kill + unavailable."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _serve() -> None:
        req = _read_request(wrk)
        # A frame classified as progress (method + no id) but with an out-of-range percent.
        bad = {
            "jsonrpc": "2.0",
            "method": "$/progress",
            "params": {"id": req["id"], "percent": 999, "phase": "analyzing"},
        }
        _send_frame(wrk, bad)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", progress=True))
    t.join(timeout=3)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1
    wrk.close()


def _read_request(wrk: socket.socket) -> dict[str, Any]:
    """Read exactly one framed JSON-RPC request from the worker end of the pair."""
    prefix = _recv_exact(wrk, f.LENGTH_PREFIX_BYTES)
    (n,) = struct.unpack(">I", prefix)
    body = _recv_exact(wrk, n) if n else b""
    obj: dict[str, Any] = f.decode_body(body)
    return obj


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly ``n`` bytes (test-side helper)."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("socket closed mid-frame in test harness")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --- schema: SessionAnalyzeIn.progress ---------------------------------------------------------
def test_schema_progress_defaults_false() -> None:
    """The additive ``progress`` field defaults to False (byte-for-byte today's behaviour)."""
    args = s.SessionAnalyzeIn(session_id="s")
    assert args.progress is False


def test_schema_progress_accepts_true() -> None:
    """The ``progress`` field accepts an explicit True opt-in."""
    args = s.SessionAnalyzeIn(session_id="s", progress=True)
    assert args.progress is True


def test_schema_rejects_unknown_extra_field() -> None:
    """An unknown field is rejected (frozen/extra=forbid — mass-assignment guard)."""
    with pytest.raises(ValidationError):
        s.SessionAnalyzeIn(session_id="s", progress=True, bogus=1)  # type: ignore[call-arg]


def test_schema_progress_rejects_non_bool_value() -> None:
    """A non-bool ``progress`` value is rejected by validation.

    NB: pydantic's lax mode coerces the JSON-bool token set (``"true"``/``"1"``/``"yes"``) — that is
    its documented behaviour, not an ADR-030 concern. Here we assert a clearly non-bool value (an
    arbitrary string and an out-of-set int) is rejected, so the field is not free-form.
    """
    with pytest.raises(ValidationError):
        s.SessionAnalyzeIn(session_id="s", progress="maybe")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        s.SessionAnalyzeIn(session_id="s", progress=2)  # type: ignore[arg-type]


# --- worker-side: opt-in routing + the socket-bound emitter (ADR-030 Phase 1 / D9) -----------


class _RecordingBackend:
    """Backend fake recording whether ``analyze`` received an ``emit_progress`` (opt-in routing)."""

    def __init__(self) -> None:
        self.analyze_emit: list[bool] = []

    def analyze(self, params: dict[str, Any], *, emit_progress: Any = None) -> dict[str, Any]:
        self.analyze_emit.append(emit_progress is not None)
        return {"state": "ready"}

    def __getattr__(self, name: str) -> Any:
        def _handler(params: dict[str, Any]) -> dict[str, Any]:
            return {"method": name}

        return _handler


class _RecordingConn:
    """A ``_Conn`` fake recording every frame sent (the worker's session socket)."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, _n: int) -> bytes:  # part of the _Conn protocol; unused by the emitter
        return b""

    def fileno(self) -> int:  # part of the _Conn protocol; unused by the progress emitter
        return -1


class _RaisingConn:
    """A ``_Conn`` fake whose ``sendall`` always raises ``OSError`` (transient socket error)."""

    def sendall(self, data: bytes) -> None:
        raise OSError("broken pipe")

    def recv(self, _n: int) -> bytes:  # part of the _Conn protocol; unused by the emitter
        return b""

    def fileno(self) -> int:  # part of the _Conn protocol; unused by the progress emitter
        return -1


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"progress": True}, True),
        ({"progress": False}, False),
        ({}, False),
        ({"progress": "true"}, False),  # only a literal True opts in (a string never does)
        ({"progress": 1}, False),
        ({"progress": None}, False),
    ],
)
def test_progress_opted_in_truth_table(params: dict[str, Any], expected: bool) -> None:
    assert wd._progress_opted_in(params) is expected


def test_dispatch_threads_emitter_only_for_opted_in_analyze() -> None:
    be = _RecordingBackend()

    def _emitter(percent: int | None, phase: str) -> None:
        return None

    wd.dispatch(be, "analyze", {"progress": True}, emit_progress=_emitter)
    wd.dispatch(be, "analyze", {"progress": False}, emit_progress=_emitter)  # opted out
    wd.dispatch(be, "analyze", {}, emit_progress=_emitter)  # omitted
    wd.dispatch(be, "analyze", {"progress": True}, emit_progress=None)  # no emitter built
    assert be.analyze_emit == [True, False, False, False]


def test_dispatch_non_analyze_never_uses_emitter() -> None:
    be = _RecordingBackend()
    called: list[tuple[int | None, str]] = []
    out = wd.dispatch(
        be, "list_functions", {"progress": True}, emit_progress=lambda p, ph: called.append((p, ph))
    )
    assert out == {"method": "list_functions"}
    assert called == []  # a non-analyze method ignores the emitter entirely


def test_make_progress_emitter_sends_a_valid_progress_frame() -> None:
    conn = _RecordingConn()
    emit = wd._make_progress_emitter(conn, "req-1", max_frame_bytes=4 * 1024 * 1024)
    emit(42, "analyzing")
    assert len(conn.sent) == 1
    obj = json.loads(conn.sent[0][4:])  # strip the 4-byte length prefix
    assert f.is_progress_notification(obj)
    assert obj["params"] == {"id": "req-1", "percent": 42, "phase": "analyzing"}


def test_make_progress_emitter_coalesces_sub_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"t": 100.0}
    monkeypatch.setattr("worker.dispatch.time.monotonic", lambda: clock["t"])
    conn = _RecordingConn()
    emit = wd._make_progress_emitter(conn, "r", max_frame_bytes=4 * 1024 * 1024)
    emit(1, "analyzing")  # t=100.0 → emitted
    clock["t"] = 100.0 + (wd._WORKER_MIN_PROGRESS_INTERVAL_S / 2)
    emit(2, "analyzing")  # too soon → coalesced (dropped)
    clock["t"] = 100.0 + wd._WORKER_MIN_PROGRESS_INTERVAL_S + 0.01
    emit(3, "analyzing")  # past the interval → emitted
    assert len(conn.sent) == 2


def test_make_progress_emitter_swallows_bad_phase() -> None:
    conn = _RecordingConn()
    emit = wd._make_progress_emitter(conn, "r", max_frame_bytes=4 * 1024 * 1024)
    emit(50, "not-a-real-phase")  # build_progress raises ValueError → swallowed, nothing sent
    assert conn.sent == []


def test_make_progress_emitter_swallows_send_error() -> None:
    emit = wd._make_progress_emitter(_RaisingConn(), "r", max_frame_bytes=4 * 1024 * 1024)
    emit(50, "analyzing")  # sendall raises OSError → swallowed (heartbeat must not crash analysis)


# =====================================================================================
# ADR-030 Phase 2 — adapter relays to an on_progress callback (in addition to the log) and
# forces worker emission when a callback is wired. The MCP-client wiring lives in the registry/
# server tests; here we prove the ADAPTER half: the callback fires per relayed frame, errors are
# swallowed, and a callback alone turns worker emission on.
# =====================================================================================
def test_analyze_invokes_on_progress_per_relayed_frame() -> None:
    """A wired on_progress callback receives (percent, phase) for each relayed frame."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    seen: list[tuple[int | None, str]] = []

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        _send_frame(wrk, f.build_progress(rid, 25, "analyzing"))
        _send_frame(wrk, {"jsonrpc": "2.0", "id": rid, "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    info = adapter.analyze(
        "s",
        s.SessionAnalyzeIn(session_id="s"),
        on_progress=lambda pct, phase: seen.append((pct, phase)),
    )
    t.join(timeout=3)
    assert info.state == "ready"
    assert worker.killed == 0
    assert (25, "analyzing") in seen
    wrk.close()


def test_on_progress_forces_worker_emission_without_the_progress_flag() -> None:
    """on_progress alone (args.progress=False) still sends ``progress: true`` to the worker."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    captured: dict[str, Any] = {}

    def _serve() -> None:
        req = _read_request(wrk)
        captured.update(req)
        _send_frame(wrk, {"jsonrpc": "2.0", "id": req["id"], "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    adapter.analyze("s", s.SessionAnalyzeIn(session_id="s"), on_progress=lambda _p, _ph: None)
    t.join(timeout=3)
    assert captured["params"].get("progress") is True
    wrk.close()


def test_analyze_relay_callback_error_never_aborts_analysis(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A raising on_progress is swallowed: the analysis completes and the worker is not killed."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _boom(_pct: int | None, _phase: str) -> None:
        raise RuntimeError("client gone")

    def _serve() -> None:
        req = _read_request(wrk)
        rid = req["id"]
        _send_frame(wrk, f.build_progress(rid, 10, "analyzing"))
        _send_frame(wrk, {"jsonrpc": "2.0", "id": rid, "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    with caplog.at_level(logging.WARNING):
        info = adapter.analyze("s", s.SessionAnalyzeIn(session_id="s"), on_progress=_boom)
    t.join(timeout=3)
    assert info.state == "ready"
    assert worker.killed == 0
    assert any(r.message == "analyze.progress_relay_failed" for r in caplog.records)
    wrk.close()


def test_analyze_without_callback_or_flag_omits_progress_and_does_not_relay() -> None:
    """No on_progress and no args.progress → unchanged single-frame path; ``progress`` omitted."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    captured: dict[str, Any] = {}

    def _serve() -> None:
        req = _read_request(wrk)
        captured.update(req)
        _send_frame(wrk, {"jsonrpc": "2.0", "id": req["id"], "result": dict(_ANALYZE_RESULT)})

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    adapter.analyze("s", s.SessionAnalyzeIn(session_id="s"))
    t.join(timeout=3)
    assert "progress" not in captured["params"]
    wrk.close()
