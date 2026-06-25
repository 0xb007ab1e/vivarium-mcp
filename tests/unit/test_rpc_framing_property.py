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

Hermetic + deterministic (``derandomize``); no worker, no I/O. Runs in the unit ``quality`` job.
"""

from __future__ import annotations

from typing import Any

import pytest

hypothesis = pytest.importorskip("hypothesis")  # skip cleanly if the property-test extra is absent
from hypothesis import example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from vivarium.ghidra.rpc_framing import (  # noqa: E402
    LENGTH_PREFIX_BYTES,
    FramingError,
    RpcCallError,
    RpcProtocolError,
    decode_body,
    decode_length_prefix,
    encode_frame,
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
