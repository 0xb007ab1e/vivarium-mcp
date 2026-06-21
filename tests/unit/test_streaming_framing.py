"""Unit tests for the ADR-040 Phase 2 ``$/chunk`` framing codec (classifier + parser + builder).

Hermetic, JVM-free: these cover the pure :mod:`vivarium.ghidra.rpc_framing` helpers for the
partial-result notification — exactly as ``test_analyze_progress`` covers ``$/progress``. The worker
is potentially hostile (TB2/TB3), so every malformed/abuse shape is REJECTED fail-closed, a chunk
frame and a response are never confused for one another (the no-top-level-``id`` invariant), and the
builder validates its own output (loud on a coding mistake).
"""

from __future__ import annotations

from typing import Any

import pytest

from vivarium.ghidra import rpc_framing as f

_RID = "req-stream-1"


def _payload() -> dict[str, Any]:
    """A representative plain (un-enveloped) per-function chunk payload."""
    return {
        "address": "0x00401000",
        "name": "FUN_00401000",
        "c_code": "int f(void){return 0;}",
        "signature": "int f(void)",
    }


# --- is_chunk_notification ---------------------------------------------------------------------
def test_is_chunk_notification_true_for_well_formed() -> None:
    frame = f.build_chunk(_RID, 0, "function", _payload())
    assert f.is_chunk_notification(frame) is True


def test_is_chunk_notification_false_when_top_level_id_present() -> None:
    """A ``$/chunk`` method that ALSO carries a top-level id is NOT a chunk (fail closed).

    The no-id invariant guarantees a chunk can never be mistaken for the streaming call's correlated
    response — even if a hostile worker stamps ``method`` onto a response-shaped frame.
    """
    frame = {"jsonrpc": "2.0", "id": _RID, "method": "$/chunk", "params": {"id": _RID}}
    assert f.is_chunk_notification(frame) is False


def test_is_chunk_notification_false_for_response_frame() -> None:
    assert f.is_chunk_notification({"jsonrpc": "2.0", "id": _RID, "result": {}}) is False


def test_is_chunk_notification_false_for_progress_frame() -> None:
    """A $/progress frame is not classified as a $/chunk (distinct closed methods)."""
    prog = f.build_progress(_RID, 5, "analyzing")
    assert f.is_chunk_notification(prog) is False


def test_is_chunk_notification_false_for_missing_method() -> None:
    assert f.is_chunk_notification({"jsonrpc": "2.0", "params": {}}) is False


# --- parse_chunk (happy path) ------------------------------------------------------------------
def test_parse_chunk_accepts_valid_frame() -> None:
    chunk = f.parse_chunk(f.build_chunk(_RID, 7, "function", _payload()), expected_id=_RID)
    assert isinstance(chunk, f.RpcChunk)
    assert chunk.request_id == _RID
    assert chunk.seq == 7
    assert chunk.kind == "function"
    assert chunk.payload == _payload()


def test_parse_chunk_accepts_seq_zero() -> None:
    chunk = f.parse_chunk(f.build_chunk(_RID, 0, "function", {}), expected_id=_RID)
    assert chunk.seq == 0
    assert chunk.payload == {}


@pytest.mark.parametrize("kind", sorted(f.CHUNK_KINDS))
def test_parse_chunk_accepts_every_closed_kind(kind: str) -> None:
    chunk = f.parse_chunk(f.build_chunk(_RID, 1, kind, {}), expected_id=_RID)
    assert chunk.kind == kind


# --- parse_chunk fail-closed rejections (abuse paths) ------------------------------------------
def test_parse_chunk_rejects_wrong_jsonrpc_version() -> None:
    frame = {
        "jsonrpc": "1.0",
        "method": "$/chunk",
        "params": {"id": _RID, "seq": 0, "kind": "function", "payload": {}},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_missing_method() -> None:
    frame = {"jsonrpc": "2.0", "params": {"id": _RID, "seq": 0, "kind": "function", "payload": {}}}
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_frame_with_top_level_id() -> None:
    frame = {
        "jsonrpc": "2.0",
        "id": _RID,
        "method": "$/chunk",
        "params": {"id": _RID, "seq": 0, "kind": "function", "payload": {}},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_non_object_params() -> None:
    frame = {"jsonrpc": "2.0", "method": "$/chunk", "params": [1, 2, 3]}
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_missing_params_id() -> None:
    """A frame correlating to no/another request id is rejected (no desync correlation)."""
    frame = {
        "jsonrpc": "2.0",
        "method": "$/chunk",
        "params": {"seq": 0, "kind": "function", "payload": {}},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_wrong_expected_id() -> None:
    frame = f.build_chunk("some-other-id", 0, "function", {})
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


@pytest.mark.parametrize("bad", [-1, -5])
def test_parse_chunk_rejects_negative_seq(bad: int) -> None:
    frame = {
        "jsonrpc": "2.0",
        "method": "$/chunk",
        "params": {"id": _RID, "seq": bad, "kind": "function", "payload": {}},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


@pytest.mark.parametrize("bad", ["0", 1.5, True, False, None])
def test_parse_chunk_rejects_non_int_seq(bad: object) -> None:
    """A non-int (or bool — an int subclass) seq is rejected (defensive type narrowing)."""
    frame = {
        "jsonrpc": "2.0",
        "method": "$/chunk",
        "params": {"id": _RID, "seq": bad, "kind": "function", "payload": {}},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_out_of_vocab_kind() -> None:
    frame = {
        "jsonrpc": "2.0",
        "method": "$/chunk",
        "params": {"id": _RID, "seq": 0, "kind": "string", "payload": {}},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_non_string_kind() -> None:
    frame = {
        "jsonrpc": "2.0",
        "method": "$/chunk",
        "params": {"id": _RID, "seq": 0, "kind": 7, "payload": {}},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_non_object_payload() -> None:
    frame = {
        "jsonrpc": "2.0",
        "method": "$/chunk",
        "params": {"id": _RID, "seq": 0, "kind": "function", "payload": "x"},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


def test_parse_chunk_rejects_missing_payload() -> None:
    frame = {
        "jsonrpc": "2.0",
        "method": "$/chunk",
        "params": {"id": _RID, "seq": 0, "kind": "function"},
    }
    with pytest.raises(f.RpcProtocolError):
        f.parse_chunk(frame, expected_id=_RID)


# --- a chunk frame is never a response, and vice-versa -----------------------------------------
def test_chunk_frame_is_not_parsed_as_a_response() -> None:
    """parse_response REJECTS a chunk notification (no result/error member)."""
    frame = f.build_chunk(_RID, 0, "function", _payload())
    assert f.is_chunk_notification(frame) is True
    with pytest.raises(f.RpcProtocolError):
        f.parse_response(frame, expected_id=_RID)


def test_response_frame_is_not_classified_as_chunk() -> None:
    resp = {"jsonrpc": "2.0", "id": _RID, "result": {"total": 0, "done": True}}
    assert f.is_chunk_notification(resp) is False
    assert f.parse_response(resp, expected_id=_RID) == {"total": 0, "done": True}


# --- build_chunk (worker side; validates its own output) ---------------------------------------
def test_build_chunk_shape_has_no_top_level_id() -> None:
    frame = f.build_chunk(_RID, 3, "function", _payload())
    assert frame == {
        "jsonrpc": "2.0",
        "method": "$/chunk",
        "params": {"id": _RID, "seq": 3, "kind": "function", "payload": _payload()},
    }
    assert "id" not in frame


def test_build_chunk_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="kind"):
        f.build_chunk(_RID, 0, "not-a-kind", {})


def test_build_chunk_rejects_negative_seq() -> None:
    with pytest.raises(ValueError, match="seq"):
        f.build_chunk(_RID, -1, "function", {})


def test_build_chunk_then_parse_round_trips() -> None:
    """A built chunk parses back to the same fields (codec symmetry)."""
    built = f.build_chunk(_RID, 11, "function", _payload())
    parsed = f.parse_chunk(built, expected_id=_RID)
    assert (parsed.seq, parsed.kind, parsed.payload) == (11, "function", _payload())


# --- oversized chunk frame: the shared §3 cap rejects it on encode -----------------------------
def test_oversized_chunk_frame_rejected_by_size_cap() -> None:
    """A chunk body over the configured cap is a framing violation on encode (CWE-400 bound)."""
    huge = {"address": "0x0", "name": "n", "c_code": "A" * 4096, "signature": "s"}
    frame = f.build_chunk(_RID, 0, "function", huge)
    with pytest.raises(f.FramingError):
        f.encode_frame(frame, max_frame_bytes=64)  # far below the body size


# --- $/cancel notification (ADR-041; server → worker) ------------------------------------------
def test_build_cancel_shape_has_no_top_level_id() -> None:
    """A built $/cancel is a notification (no top-level id), with params.id = the target id."""
    frame = f.build_cancel(_RID)
    assert frame == {"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": _RID}}
    assert "id" not in frame


def test_is_cancel_notification_true_for_well_formed() -> None:
    assert f.is_cancel_notification(f.build_cancel(_RID)) is True


def test_is_cancel_notification_false_when_top_level_id_present() -> None:
    """A $/cancel method that ALSO carries a top-level id is NOT a cancel (fail closed)."""
    frame = {"jsonrpc": "2.0", "id": _RID, "method": "$/cancel", "params": {"id": _RID}}
    assert f.is_cancel_notification(frame) is False


def test_is_cancel_notification_false_for_response_frame() -> None:
    assert f.is_cancel_notification({"jsonrpc": "2.0", "id": _RID, "result": {}}) is False


def test_is_cancel_notification_false_for_chunk_frame() -> None:
    """A $/chunk frame is not classified as a $/cancel (distinct closed methods)."""
    assert f.is_cancel_notification(f.build_chunk(_RID, 0, "function", {})) is False


def test_is_cancel_notification_false_for_missing_method() -> None:
    assert f.is_cancel_notification({"jsonrpc": "2.0", "params": {"id": _RID}}) is False


def test_parse_cancel_accepts_valid_frame() -> None:
    cancel = f.parse_cancel(f.build_cancel(_RID), expected_id=_RID)
    assert isinstance(cancel, f.RpcCancel)
    assert cancel.request_id == _RID


def test_parse_cancel_returns_id_even_when_unmatched() -> None:
    """A $/cancel for ANOTHER id parses fine (the caller decides no-op vs. cancel — ADR-041 D6)."""
    cancel = f.parse_cancel(f.build_cancel("other-id"), expected_id=_RID)
    assert cancel.request_id == "other-id"


def test_parse_cancel_rejects_wrong_jsonrpc_version() -> None:
    frame = {"jsonrpc": "1.0", "method": "$/cancel", "params": {"id": _RID}}
    with pytest.raises(f.RpcProtocolError):
        f.parse_cancel(frame, expected_id=_RID)


def test_parse_cancel_rejects_frame_with_top_level_id() -> None:
    frame = {"jsonrpc": "2.0", "id": _RID, "method": "$/cancel", "params": {"id": _RID}}
    with pytest.raises(f.RpcProtocolError):
        f.parse_cancel(frame, expected_id=_RID)


def test_parse_cancel_rejects_missing_method() -> None:
    with pytest.raises(f.RpcProtocolError):
        f.parse_cancel({"jsonrpc": "2.0", "params": {"id": _RID}}, expected_id=_RID)


def test_parse_cancel_rejects_non_object_params() -> None:
    frame = {"jsonrpc": "2.0", "method": "$/cancel", "params": [1, 2, 3]}
    with pytest.raises(f.RpcProtocolError):
        f.parse_cancel(frame, expected_id=_RID)


def test_parse_cancel_rejects_missing_params_id() -> None:
    frame = {"jsonrpc": "2.0", "method": "$/cancel", "params": {}}
    with pytest.raises(f.RpcProtocolError):
        f.parse_cancel(frame, expected_id=_RID)


@pytest.mark.parametrize("bad", [7, 1.5, True, None, ["x"]])
def test_parse_cancel_rejects_non_string_params_id(bad: object) -> None:
    frame = {"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": bad}}
    with pytest.raises(f.RpcProtocolError):
        f.parse_cancel(frame, expected_id=_RID)


def test_cancel_frame_is_not_parsed_as_a_response() -> None:
    """parse_response REJECTS a cancel notification (no result/error member)."""
    frame = f.build_cancel(_RID)
    assert f.is_cancel_notification(frame) is True
    with pytest.raises(f.RpcProtocolError):
        f.parse_response(frame, expected_id=_RID)


def test_build_cancel_then_parse_round_trips() -> None:
    parsed = f.parse_cancel(f.build_cancel("abc-123"), expected_id="abc-123")
    assert parsed.request_id == "abc-123"
