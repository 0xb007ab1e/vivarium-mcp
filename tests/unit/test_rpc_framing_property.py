"""Property/fuzz tests for the JVM-free RPC framing codec (G11; TB2).

Complements the example-based tests in ``test_rpc_adapter.py`` / ``test_streaming_framing.py`` with
generated-input PROPERTIES over the pure codec in :mod:`vivarium.ghidra.rpc_framing`: the
server↔worker wire boundary, where the worker is treated as a potentially hostile fault domain. The
load-bearing invariants:

- **Round-trip:** a well-formed JSON-object message survives ``encode_frame`` →
  ``decode_length_prefix`` + ``decode_body`` unchanged.
- **Total decode (no crash on hostile bytes):** ``decode_body`` over ARBITRARY bytes either returns
  a ``dict`` or raises ``RpcProtocolError`` — never another exception, never a non-dict.
- **Bounded length prefix:** ``decode_length_prefix`` over arbitrary bytes either returns an int in
  ``[0, cap]`` or raises ``FramingError`` — never a value above the cap, never another exception.
- **Oversize is rejected:** ``encode_frame`` of a body over the cap raises ``FramingError``.
- **Total response parse:** ``parse_response`` over an arbitrary decoded object raises only the
  documented ``RpcProtocolError`` / ``RpcCallError`` (no ``KeyError``/``TypeError``).
- **Total notification decode (gap round-4 Q5):** ``parse_progress`` / ``parse_chunk`` /
  ``parse_cancel`` over an arbitrary (or plausibly-shaped-but-fuzzed) object either raise
  ``RpcProtocolError`` or return a value whose fields meet the documented bounds (percent in
  ``0..100`` or ``None``; seq a non-negative int; kind/phase in the closed vocabulary; cancel id a
  str) — never another exception. ``_parse_error`` is TOTAL (never raises) and bounds its outputs
  (message ≤ 512 chars, detail ≤ ``_MAX_DETAIL_CHARS`` or ``None``, code an int). These decode
  frames from a potentially hostile worker (TB2/TB3) — the canonical "fuzz your decoders" boundary.

Hermetic + deterministic (``derandomize``); no worker, no I/O. Runs in the unit ``quality`` job.
"""

from __future__ import annotations

from typing import Any

import pytest

hypothesis = pytest.importorskip("hypothesis")  # skip cleanly if the property-test extra is absent
from hypothesis import example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from vivarium.ghidra.rpc_framing import (  # noqa: E402
    _MAX_DETAIL_CHARS,
    CANCEL_METHOD,
    CHUNK_KINDS,
    CHUNK_METHOD,
    LENGTH_PREFIX_BYTES,
    PROGRESS_METHOD,
    PROGRESS_PHASES,
    FramingError,
    RpcCallError,
    RpcProtocolError,
    _parse_error,
    decode_body,
    decode_length_prefix,
    encode_frame,
    parse_cancel,
    parse_chunk,
    parse_progress,
    parse_response,
)

#: Deterministic + CI-safe: a bounded example count, no per-example deadline (shared runners make
#: wall-clock deadlines flaky), and a fixed input sequence (``derandomize``) for reproducibility.
_PROFILE = settings(max_examples=200, deadline=None, derandomize=True)

#: The default frame cap (mirrors the worker/security default); ample for the bounded messages here.
_MAX_FRAME = 4 * 1024 * 1024

#: UTF-8-encodable text only — exclude surrogate code points so a well-formed message round-trips
#: (``encode_frame`` does ``.encode("utf-8")``; lone surrogates would not encode).
_utf8_text: st.SearchStrategy[str] = st.text(st.characters(codec="utf-8"), max_size=64)

#: Arbitrary JSON values (bounded depth/breadth for speed), with NaN/Inf excluded so equality after
#: a JSON round-trip is well-defined.
_json_values: st.SearchStrategy[Any] = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**63), max_value=2**63)
    | st.floats(allow_nan=False, allow_infinity=False)
    | _utf8_text,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(_utf8_text, children, max_size=4)
    ),
    max_leaves=20,
)

#: A top-level JSON-RPC message is a JSON object (string keys → arbitrary JSON values).
_json_objects: st.SearchStrategy[dict[str, Any]] = st.dictionaries(
    _utf8_text, _json_values, max_size=6
)


@_PROFILE
@given(message=_json_objects)
def test_round_trip_recovers_the_message(message: dict[str, Any]) -> None:
    """encode_frame → (length prefix + body) → decode_length_prefix/decode_body recovers it."""
    frame = encode_frame(message, max_frame_bytes=_MAX_FRAME)
    prefix, body = frame[:LENGTH_PREFIX_BYTES], frame[LENGTH_PREFIX_BYTES:]
    declared = decode_length_prefix(prefix, max_frame_bytes=_MAX_FRAME)
    assert declared == len(body)  # the prefix declares exactly the body length
    assert decode_body(body) == message


@_PROFILE
@given(body=st.binary(max_size=512))
def test_decode_body_is_total_over_arbitrary_bytes(body: bytes) -> None:
    """decode_body returns a dict or raises RpcProtocolError — never any other exception/shape."""
    try:
        result = decode_body(body)
    except RpcProtocolError:
        return  # documented rejection — fine
    assert isinstance(result, dict)  # the only success shape


@_PROFILE
@given(prefix=st.binary(max_size=8), cap=st.integers(min_value=0, max_value=2**32 - 1))
def test_decode_length_prefix_is_bounded(prefix: bytes, cap: int) -> None:
    """decode_length_prefix returns an int in [0, cap] or raises FramingError — never above cap."""
    try:
        n = decode_length_prefix(prefix, max_frame_bytes=cap)
    except FramingError:
        return  # short prefix or over-cap declared length — documented rejection
    assert isinstance(n, int)
    assert 0 <= n <= cap  # the cap check happens BEFORE any allocation (TB2-D)


@_PROFILE
@given(cap=st.integers(min_value=0, max_value=256), filler=_utf8_text)
def test_encode_frame_rejects_an_oversized_body(cap: int, filler: str) -> None:
    """A message whose encoded body exceeds the cap raises FramingError (never frames it)."""
    # A value far larger than any cap in [0, 256] guarantees the body exceeds the cap.
    message = {"k": filler + "A" * 1024}
    with pytest.raises(FramingError):
        encode_frame(message, max_frame_bytes=cap)


@_PROFILE
@given(obj=_json_objects)
@example(obj={})  # empty: missing jsonrpc → RpcProtocolError
@example(obj={"jsonrpc": "2.0", "id": "X", "result": {}})  # well-formed success
@example(
    obj={"jsonrpc": "2.0", "id": "X", "error": {"code": -1, "message": "x"}}
)  # error → RpcCallError
def test_parse_response_raises_only_documented_errors(obj: dict[str, Any]) -> None:
    """parse_response over an arbitrary object raises only RpcProtocolError / RpcCallError."""
    try:
        result = parse_response(obj, expected_id="X")
    except (RpcProtocolError, RpcCallError):
        return  # the only documented failure modes
    assert isinstance(result, dict)  # success → the result object


# --- notification decoders: parse_progress / parse_chunk / parse_cancel / _parse_error (Q5) ------
# These decode $/progress, $/chunk, $/cancel notifications + the JSON-RPC error member from a
# potentially HOSTILE worker (TB2/TB3). Below: strategies mixing valid + junk field values so both
# the accept path (bounds asserted on the return) and near-miss reject paths are generated.
_EID = "req-correlated-id"

_id_vals = st.just(_EID) | _utf8_text | st.none()
_percent_vals = (
    st.none() | st.integers(min_value=0, max_value=100) | st.integers() | st.booleans() | _utf8_text
)
_phase_vals = st.sampled_from(sorted(PROGRESS_PHASES)) | _utf8_text
_seq_vals = st.integers(min_value=0, max_value=2**40) | st.integers() | st.booleans() | _utf8_text
_kind_vals = st.sampled_from(sorted(CHUNK_KINDS)) | _utf8_text
_payload_vals = _json_objects | st.none() | _utf8_text | st.integers()

_progress_frames = st.fixed_dictionaries(
    {
        "jsonrpc": st.just("2.0") | _utf8_text,
        "method": st.just(PROGRESS_METHOD) | _utf8_text,
        "params": st.fixed_dictionaries(
            {"id": _id_vals, "percent": _percent_vals, "phase": _phase_vals}
        )
        | _json_objects
        | st.none(),
    }
)
_chunk_frames = st.fixed_dictionaries(
    {
        "jsonrpc": st.just("2.0") | _utf8_text,
        "method": st.just(CHUNK_METHOD) | _utf8_text,
        "params": st.fixed_dictionaries(
            {"id": _id_vals, "seq": _seq_vals, "kind": _kind_vals, "payload": _payload_vals}
        )
        | _json_objects
        | st.none(),
    }
)
_cancel_frames = st.fixed_dictionaries(
    {
        "jsonrpc": st.just("2.0") | _utf8_text,
        "method": st.just(CANCEL_METHOD) | _utf8_text,
        "params": st.fixed_dictionaries({"id": _id_vals}) | _json_objects | st.none(),
    }
)


@_PROFILE
@given(obj=_progress_frames | _json_objects)
def test_parse_progress_is_total_and_bounded(obj: dict[str, Any]) -> None:
    """parse_progress raises RpcProtocolError or returns percent None-or-0..100 + phase in vocab."""
    try:
        p = parse_progress(obj, expected_id=_EID)
    except RpcProtocolError:
        return  # the only documented failure mode
    assert p.request_id == _EID
    assert p.percent is None or (isinstance(p.percent, int) and 0 <= p.percent <= 100)
    assert p.phase in PROGRESS_PHASES


@_PROFILE
@given(obj=_chunk_frames | _json_objects)
def test_parse_chunk_is_total_and_bounded(obj: dict[str, Any]) -> None:
    """parse_chunk raises RpcProtocolError or returns seq≥0 (int) + kind∈vocab + a dict payload."""
    try:
        c = parse_chunk(obj, expected_id=_EID)
    except RpcProtocolError:
        return
    assert c.request_id == _EID
    assert isinstance(c.seq, int) and not isinstance(c.seq, bool) and c.seq >= 0
    assert c.kind in CHUNK_KINDS
    assert isinstance(c.payload, dict)


@_PROFILE
@given(obj=_cancel_frames | _json_objects)
def test_parse_cancel_is_total_and_shape_valid(obj: dict[str, Any]) -> None:
    """parse_cancel raises RpcProtocolError or returns a str request_id (no id-mismatch raise)."""
    try:
        c = parse_cancel(obj, expected_id=_EID)
    except RpcProtocolError:
        return
    assert isinstance(c.request_id, str)


@_PROFILE
@given(err=_json_values)
@example(err={"code": 5, "message": "m" * 600, "data": {"type": "x", "detail": "d" * 400}})
@example(err="not-a-dict")  # non-object error member → safe defaults
@example(err={"data": {"type": 123, "detail": 456}})  # non-str slug/detail → ignored
def test_parse_error_is_total_and_bounded(err: Any) -> None:
    """_parse_error NEVER raises; bounds output (code int, message <=512, detail <=cap or None)."""
    e = _parse_error(err)  # total by contract — no exception permitted
    assert isinstance(e.code, int)
    assert isinstance(e.message, str) and len(e.message) <= 512
    assert e.type_slug is None or isinstance(e.type_slug, str)
    assert e.detail is None or (isinstance(e.detail, str) and len(e.detail) <= _MAX_DETAIL_CHARS)
