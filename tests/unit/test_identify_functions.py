"""Behavior tests for the Function ID library-match tool ``identify_functions`` (ADR-042 Phase 1).

The worker exposes one new READ-ONLY extraction primitive (``identify_functions`` — it runs the
Ghidra FID service; ADR-001). The candidate filtering/bounding + the untrusted-data wrap are
server-side and JVM-free. These tests fake the worker RPC (``RpcGhidraAdapter._tool_call``) and the
session manager, exercising the adapter (wrapping, ``limit``/``truncated`` bound, ``min_score``
forwarding) and the registry handler (BOLA authorize before delegation) with no JVM/Ghidra.

The worker-only ``_gh_identify_functions`` JVM binding is a coverage-omitted edge validated only by
the real-worker integration suite (see ``tests/integration/test_identify_functions_fid.py``, which
is skipped pending a benign static-MSVC PE fixture — our current fixtures are all ELF, which the
MSVC FID DBs do not match).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from vivarium.config import Config
from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.ghidra import rpc_client as rc
from vivarium.ghidra.port import GhidraPort
from vivarium.security.limits import Limits
from vivarium.sessions.manager import SessionManager
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

_SID = "sid1"

#: A faked worker response: a callable taking the request params and returning a plain result dict.
_Responder = Callable[[dict[str, Any]], dict[str, Any]]


class _DeadWorker:
    """An inert worker handle (the faked ``_tool_call`` never dials a real socket)."""

    def kill(self) -> None:
        """No-op kill."""

    def is_alive(self) -> bool:
        """Report not alive."""
        return False

    def exit_diagnosis(self) -> str:
        """Report an unknown exit (inert worker; never queried in these tests)."""
        return "unknown"


class _FakeAdapter(rc.RpcGhidraAdapter):
    """Adapter whose ``_tool_call`` returns canned per-method responses (no worker)."""

    responses: dict[str, _Responder]
    calls: list[tuple[str, dict[str, Any]]]

    def _tool_call(self, sid: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, params))
        return self.responses[method](params)


def _make(responses: dict[str, _Responder]) -> _FakeAdapter:
    """Build a fake adapter wired with the given per-method responders."""
    adapter = _FakeAdapter(
        launcher=lambda _sid, _path: _DeadWorker(),
        socket_dir="/run/x",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=1 << 20,
    )
    adapter.responses = responses
    adapter.calls = []
    return adapter


def _match(address: str, name: str, library: str, score: float) -> dict[str, Any]:
    """Build one plain worker FID match row."""
    return {"address": address, "matched_name": name, "library": library, "score": score}


# --- adapter: wrapping + multiplicity ----------------------------------------------------------
def test_identify_functions_wraps_name_and_library() -> None:
    """Each match's ``matched_name`` + ``library`` are wrapped BINARY-origin; address/score safe."""
    adapter = _make(
        {
            "identify_functions": lambda _p: {
                "matches": [
                    _match("0x401000", "strlen", "libc 2.31 release", 22.5),
                    _match("0x401000", "strnlen", "libc 2.31 release", 18.0),
                ],
                "truncated": False,
            }
        }
    )
    out = adapter.identify_functions(_SID, s.IdentifyFunctionsIn(session_id=_SID))
    # One row per surviving candidate — multiplicity is honest (two candidates at one address).
    assert out.total == 2
    assert [m.address for m in out.matches] == ["0x401000", "0x401000"]
    assert isinstance(out.matches[0].matched_name, Untrusted)
    assert out.matches[0].matched_name.origin is DataOrigin.BINARY
    assert isinstance(out.matches[0].library, Untrusted)
    assert out.matches[0].library.origin is DataOrigin.BINARY
    assert out.matches[0].score == 22.5
    assert out.truncated is False


def test_identify_functions_omits_min_score_when_none() -> None:
    """``min_score`` absent ⇒ the RPC omits the key (the worker uses the FID default threshold)."""
    adapter = _make({"identify_functions": lambda _p: {"matches": [], "truncated": False}})
    adapter.identify_functions(_SID, s.IdentifyFunctionsIn(session_id=_SID))
    assert adapter.calls[0][0] == "identify_functions"
    assert "min_score" not in adapter.calls[0][1]


def test_identify_functions_forwards_min_score() -> None:
    """A supplied ``min_score`` is forwarded to the worker RPC params."""
    adapter = _make({"identify_functions": lambda _p: {"matches": [], "truncated": False}})
    adapter.identify_functions(_SID, s.IdentifyFunctionsIn(session_id=_SID, min_score=12.5))
    assert adapter.calls[0][1]["min_score"] == 12.5


# --- adapter: bound + truncated honesty --------------------------------------------------------
def test_identify_functions_bounds_to_limit_and_sets_truncated() -> None:
    """More surviving matches than ``limit`` ⇒ the list is clipped and ``truncated`` is set."""
    rows = [_match(f"0x40{i:04x}", f"fn{i}", "libc 2.31 release", 20.0) for i in range(5)]
    adapter = _make({"identify_functions": lambda _p: {"matches": rows, "truncated": False}})
    out = adapter.identify_functions(_SID, s.IdentifyFunctionsIn(session_id=_SID, limit=3))
    assert out.total == 3  # == len(matches), the contract
    assert len(out.matches) == 3
    assert out.truncated is True


def test_identify_functions_propagates_worker_truncation() -> None:
    """A worker-side clip (its own cap) is OR-ed into the result's ``truncated`` flag."""
    adapter = _make(
        {
            "identify_functions": lambda _p: {
                "matches": [_match("0x401000", "main", "libc 2.31 release", 30.0)],
                "truncated": True,
            }
        }
    )
    out = adapter.identify_functions(_SID, s.IdentifyFunctionsIn(session_id=_SID, limit=100))
    assert out.total == 1
    assert out.truncated is True  # carried from the worker even though limit was not hit


def test_identify_functions_malformed_worker_result_maps_to_worker_unavailable() -> None:
    """A structurally-malformed worker row fails closed to ``WORKER_UNAVAILABLE`` (never raw)."""
    adapter = _make(
        {"identify_functions": lambda _p: {"matches": [{"address": "0x401000"}]}}  # missing fields
    )
    with pytest.raises(GhidraMcpError) as ei:
        adapter.identify_functions(_SID, s.IdentifyFunctionsIn(session_id=_SID))
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


# --- registry handler: BOLA authorize before delegation ----------------------------------------
class _FakeSessions:
    """Minimal session manager: authorizes only ``_SID`` and records the call ordering."""

    def __init__(self) -> None:
        """Initialize with an empty authorize log."""
        self.authorized: list[str] = []

    def begin_call(self, session_id: str) -> None:
        """No-op in-flight begin mark (test stub)."""

    def end_call(self, session_id: str) -> None:
        """No-op in-flight end mark (test stub)."""

    def authorize(self, session_id: str, *, caller: str = "local") -> s.SessionInfo:
        """Authorize ``_SID`` only; otherwise raise the BOLA-safe ``session-invalid`` error."""
        if session_id != _SID:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.SESSION_INVALID, title="x", detail="unknown", status=404
                )
            )
        self.authorized.append(session_id)
        return s.SessionInfo(session_id=session_id, state="ready", created_at=0, expires_at=10)


class _FakePort:
    """Records the call and returns a minimal valid (and Untrusted-wrapped) FID result."""

    def __init__(self) -> None:
        """Initialize with an empty call log."""
        self.calls: list[str] = []

    def identify_functions(self, sid: str, a: s.IdentifyFunctionsIn) -> s.IdentifyFunctionsOut:
        """Record the call and return a single Untrusted-wrapped FID match."""
        self.calls.append(sid)
        return s.IdentifyFunctionsOut(
            matches=[
                s.IdentifiedFunction(
                    address="0x401000",
                    matched_name=Untrusted(value="strlen", origin=DataOrigin.BINARY),
                    library=Untrusted(value="libc 2.31 release", origin=DataOrigin.BINARY),
                    score=22.5,
                )
            ],
            total=1,
        )


def _config() -> Config:
    """A minimal valid stdio config for building a tool context."""
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


def _ctx(port: _FakePort, sessions: _FakeSessions) -> reg.ToolContext:
    return reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, sessions),
        port=cast(GhidraPort, port),
    )


def test_handler_authorizes_then_delegates() -> None:
    """The handler authorizes the session (BOLA) before delegating, and returns the schema."""
    sessions = _FakeSessions()
    port = _FakePort()
    out = reg._handle_identify_functions(
        _ctx(port, sessions), s.IdentifyFunctionsIn(session_id=_SID)
    )
    assert sessions.authorized == [_SID]  # authorized before the port call
    assert port.calls == [_SID]
    assert isinstance(out, s.IdentifyFunctionsOut)
    assert out.matches[0].matched_name.value == "strlen"
    assert isinstance(out.matches[0].matched_name, Untrusted)


def test_handler_rejects_foreign_session_before_port_call() -> None:
    """An unknown/foreign session id fails closed (SESSION_INVALID) with no port call (BOLA)."""
    sessions = _FakeSessions()
    port = _FakePort()
    with pytest.raises(GhidraMcpError) as ei:
        reg._handle_identify_functions(
            _ctx(port, sessions), s.IdentifyFunctionsIn(session_id="other")
        )
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID
    assert port.calls == []  # never reached the port


# --- registry wiring ---------------------------------------------------------------------------
def test_identify_functions_is_a_read_tool() -> None:
    """``identify_functions`` is in the catalog and requires ``read`` (not a mutator)."""
    assert "identify_functions" in reg.TIER1_TOOL_NAMES
    assert "identify_functions" not in reg.WRITE_TOOLS
    assert reg.required_capability("identify_functions") == "read"
