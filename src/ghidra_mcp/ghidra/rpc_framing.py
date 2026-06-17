"""JVM-free length-prefixed JSON-RPC 2.0 framing codec (shared by adapter + worker).

This module implements the wire protocol from ``docs/contracts/rpc-protocol.md`` §3-4 as pure,
side-effect-free helpers: a 4-byte big-endian length prefix followed by exactly ``N`` bytes of
UTF-8 JSON, with a hard frame cap. It contains NO socket I/O and NO JVM/PyGhidra symbols, so it is
safe to import from both the server-side adapter (:mod:`ghidra_mcp.ghidra.rpc_client`) and the
worker entrypoint (``worker/``), and is unit-testable without a real worker or Ghidra.

Security (rpc-protocol.md §3, TB2): a declared frame length above the configured cap is a protocol
error — the caller MUST close the socket and kill the worker (the codec only flags it; it never
allocates the oversized buffer). Frames are fully parsed and shape-checked before dispatch (no
partial-frame execution).
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any

#: Size of the big-endian unsigned length prefix, in bytes (rpc-protocol.md §3).
LENGTH_PREFIX_BYTES = 4

#: Structural maximum a 4-byte unsigned prefix can express (4 GiB - 1). We never accept a frame
#: approaching this; the configured ``max_frame_bytes`` is the real cap.
_STRUCT_MAX = 0xFFFFFFFF

_LENGTH_STRUCT = struct.Struct(">I")  # 4-byte big-endian unsigned


class FramingError(Exception):
    """A wire-protocol framing violation (oversized/short/garbled frame).

    Raised by the pure codec; the I/O layer translates it into "close socket + kill worker"
    (rpc-protocol.md §3/§6). Carries a safe message only — never host detail.
    """


class RpcProtocolError(Exception):
    """A JSON-RPC envelope that is structurally invalid (not a framing error).

    Distinct from :class:`FramingError`: the bytes framed correctly but the decoded JSON is not a
    well-formed JSON-RPC 2.0 message. Also resolves to kill+evict on the wire.
    """


#: Hard cap on the optional worker-supplied ``data.detail`` we will retain for server logs
#: (ADR-024). The worker already scrubs it (class name + fixed template); this is a defensive
#: outbound bound so a buggy/hostile worker cannot bloat a log line.
_MAX_DETAIL_CHARS = 256

#: JSON-RPC method name for the additive worker→server progress NOTIFICATION (ADR-030 Phase 1,
#: rpc-protocol.md §4). A notification carries NO top-level ``id`` (per JSON-RPC 2.0), so it can
#: never be mistaken for the request's correlated response.
PROGRESS_METHOD = "$/progress"

#: CLOSED phase vocabulary for a progress frame (ADR-030 Phase 1). The worker maps Ghidra's
#: free-form ``TaskMonitor`` state onto exactly one of these — its raw message (which embeds
#: attacker-controlled symbol/function names) NEVER crosses the boundary (master §5 redaction).
#: ``analyzing`` is the safe catch-all when a cleaner phase mapping is unavailable.
PROGRESS_PHASES: frozenset[str] = frozenset({"importing", "analyzing", "finalizing"})


@dataclass(frozen=True, slots=True)
class RpcError:
    """A decoded JSON-RPC error object (``error`` member of a response).

    Attributes:
        code: Numeric JSON-RPC error code.
        message: Safe, human-readable message (no internals — rpc-protocol.md §5).
        type_slug: The ``data.type`` slug used to map to a public error type, or ``None``.
        detail: Optional **redacted, log-only** diagnostic from ``data.detail`` (ADR-024) — the
            worker exception's class name + a fixed template, NEVER the raw message. Used ONLY for
            a redacted server-side log; it never reaches the client-facing error envelope.
    """

    code: int
    message: str
    type_slug: str | None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class RpcProgress:
    """A decoded ``$/progress`` notification (ADR-030 Phase 1; rpc-protocol.md §4).

    A notification, NOT a response: it carries no top-level ``id`` and is one of N frames the worker
    may send (in order) BEFORE the final response for an opted-in ``analyze`` call. Its content is
    deliberately minimal and SAFE — a percent and a closed-vocabulary phase only; NO binary-derived
    ``TaskMonitor`` text ever reaches this type (master §5 redaction).

    Attributes:
        request_id: The id of the ``analyze`` request this progress pertains to (a ``params`` field,
            not the JSON-RPC top-level ``id`` — notifications have none). Used to confirm the frame
            correlates to the in-flight call.
        percent: Completion estimate ``0..100``, or ``None`` when the worker has no estimate.
        phase: A value from :data:`PROGRESS_PHASES` (closed vocabulary) — safe to log.
    """

    request_id: str
    percent: int | None
    phase: str


class RpcCallError(Exception):
    """The worker returned a JSON-RPC error response (a method-level failure).

    Carries the parsed :class:`RpcError`; the adapter maps ``type_slug`` to a public error type.
    """

    def __init__(self, error: RpcError) -> None:
        """Initialize with the parsed worker error.

        Args:
            error: The decoded JSON-RPC error.
        """
        super().__init__(error.message)
        self.error = error


def encode_frame(message: dict[str, Any], *, max_frame_bytes: int) -> bytes:
    """Serialize a JSON-RPC message to a length-prefixed UTF-8 JSON frame.

    Args:
        message: The JSON-RPC message object (request or response).
        max_frame_bytes: Hard cap on the JSON body length; encoding a larger body is a protocol
            violation (we never put a frame on the wire we would reject on read).

    Returns:
        The complete frame: 4-byte big-endian length prefix followed by the JSON body.

    Raises:
        FramingError: If the encoded body exceeds ``max_frame_bytes`` or the structural maximum.
    """
    body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    n = len(body)
    if n > max_frame_bytes or n > _STRUCT_MAX:
        raise FramingError("outbound frame exceeds maximum size")
    return _LENGTH_STRUCT.pack(n) + body


def decode_length_prefix(prefix: bytes, *, max_frame_bytes: int) -> int:
    """Decode and bounds-check a 4-byte big-endian length prefix.

    The cap check happens BEFORE any body buffer is allocated, so a malicious worker declaring a
    huge frame cannot force a large allocation (rpc-protocol.md §3, TB2-D).

    Args:
        prefix: Exactly ``LENGTH_PREFIX_BYTES`` bytes.
        max_frame_bytes: Hard cap; a declared length above this is a protocol error.

    Returns:
        The declared body length ``N`` (already validated ``0 <= N <= max_frame_bytes``).

    Raises:
        FramingError: If ``prefix`` is the wrong length or the declared length exceeds the cap.
    """
    if len(prefix) != LENGTH_PREFIX_BYTES:
        raise FramingError("short length prefix")
    (n,) = _LENGTH_STRUCT.unpack(prefix)
    if n > max_frame_bytes:
        raise FramingError("declared frame length exceeds maximum")
    return int(n)  # struct.unpack returns Any; narrow to the declared int return


def decode_body(body: bytes) -> dict[str, Any]:
    """Parse a frame body (already length-validated) into a JSON object.

    Args:
        body: The UTF-8 JSON body bytes.

    Returns:
        The decoded JSON object.

    Raises:
        RpcProtocolError: If the body is not valid UTF-8 JSON or not a JSON object.
    """
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:  # safe: no detail leaked outward
        raise RpcProtocolError("malformed JSON frame") from exc
    if not isinstance(obj, dict):
        raise RpcProtocolError("frame is not a JSON object")
    return obj


def build_request(request_id: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Construct a JSON-RPC 2.0 request object (server → worker).

    Args:
        request_id: Correlation id (a UUID string) tying request to response and to logs.
        method: The RPC method name (one of the worker-facing methods).
        params: The method parameters (mirrors the tool schema minus ``session_id``).

    Returns:
        A JSON-RPC 2.0 request dict.
    """
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def parse_response(obj: dict[str, Any], *, expected_id: str) -> dict[str, Any]:
    """Validate a JSON-RPC 2.0 response and return its ``result`` member.

    Enforces protocol version, id correlation, and exactly-one-of result/error (rpc-protocol.md
    §4). Unknown top-level members are tolerated for forward-compat but the core fields are strict.

    Args:
        obj: The decoded response object.
        expected_id: The id of the request this response must correlate to.

    Returns:
        The ``result`` object on success.

    Raises:
        RpcProtocolError: If the envelope is malformed or the id does not correlate.
        RpcCallError: If the response carries a JSON-RPC ``error`` member.
    """
    if obj.get("jsonrpc") != "2.0":
        raise RpcProtocolError("missing or wrong jsonrpc version")
    if obj.get("id") != expected_id:
        raise RpcProtocolError("response id does not correlate to request")
    has_result = "result" in obj
    has_error = "error" in obj
    if has_result == has_error:  # neither, or both — both are protocol violations
        raise RpcProtocolError("response must contain exactly one of result/error")
    if has_error:
        raise RpcCallError(_parse_error(obj["error"]))
    result = obj["result"]
    if not isinstance(result, dict):
        raise RpcProtocolError("result is not a JSON object")
    return result


def is_progress_notification(obj: dict[str, Any]) -> bool:
    """Classify a decoded frame as a ``$/progress`` notification (ADR-030 Phase 1).

    A frame is a progress notification iff it declares ``method == "$/progress"`` AND carries NO
    top-level ``id`` (per JSON-RPC 2.0 a notification has no id). The id check is what guarantees a
    notification can never be mistaken for the request's correlated response, even if a
    buggy/hostile worker also set a ``method`` on a response-shaped frame (fail closed: a frame
    with both a ``$/progress`` method AND an id is NOT treated as progress — it falls through to
    response parsing, which then rejects it on the exactly-one-of-result/error rule).

    Args:
        obj: The decoded frame object.

    Returns:
        ``True`` only for a well-formed progress notification (method matches, no top-level id).
    """
    return obj.get("method") == PROGRESS_METHOD and "id" not in obj


def parse_progress(obj: dict[str, Any], *, expected_id: str) -> RpcProgress:
    """Validate a ``$/progress`` notification and return its safe payload (ADR-030 Phase 1).

    Strict, fail-closed validation (the worker is potentially hostile — TB2/TB3): the method must be
    ``$/progress`` with no top-level id; ``params`` must be an object whose ``id`` correlates to the
    in-flight request, whose ``percent`` is an int in ``0..100`` or ``null``, and whose ``phase`` is
    in the CLOSED :data:`PROGRESS_PHASES` vocabulary. Anything else raises — NO binary-derived text
    is ever read from the frame (master §5).

    Args:
        obj: The decoded notification object (already classified by :func:`is_progress_notification`
            in the loop, but re-checked here so the parser is safe to call standalone).
        expected_id: The id of the ``analyze`` request the progress must correlate to.

    Returns:
        The validated, safe :class:`RpcProgress`.

    Raises:
        RpcProtocolError: If the notification is malformed, mis-correlated, or carries an
            out-of-range percent / out-of-vocabulary phase.
    """
    if obj.get("jsonrpc") != "2.0":
        raise RpcProtocolError("progress: missing or wrong jsonrpc version")
    if obj.get("method") != PROGRESS_METHOD or "id" in obj:
        raise RpcProtocolError("progress: not a $/progress notification")
    params = obj.get("params")
    if not isinstance(params, dict):
        raise RpcProtocolError("progress: params is not a JSON object")
    if params.get("id") != expected_id:
        raise RpcProtocolError("progress: id does not correlate to request")
    percent = _parse_percent(params.get("percent"))
    phase = params.get("phase")
    if not isinstance(phase, str) or phase not in PROGRESS_PHASES:
        raise RpcProtocolError("progress: phase not in the closed vocabulary")
    return RpcProgress(request_id=expected_id, percent=percent, phase=phase)


def _parse_percent(raw: Any) -> int | None:
    """Validate a progress ``percent``: an int in ``0..100`` or ``None`` (fail closed otherwise).

    A ``bool`` is rejected even though it is an ``int`` subclass in Python — a hostile worker MUST
    send a real integer, not ``true``/``false`` (defensive type-narrowing).

    Args:
        raw: The raw ``params.percent`` value.

    Returns:
        The validated percent, or ``None`` when the worker reported no estimate.

    Raises:
        RpcProtocolError: If ``raw`` is neither ``None`` nor an int in ``[0, 100]``.
    """
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise RpcProtocolError("progress: percent is not an integer or null")
    if raw < 0 or raw > 100:
        raise RpcProtocolError("progress: percent out of range 0..100")
    return raw


def build_progress(request_id: str, percent: int | None, phase: str) -> dict[str, Any]:
    """Construct a ``$/progress`` JSON-RPC notification (worker → server; ADR-030 Phase 1).

    Used by the worker side. The result carries NO top-level ``id`` (notification), and its content
    is the safe percent + closed-vocabulary phase ONLY — callers MUST NOT pass any binary-derived
    ``TaskMonitor`` message (master §5). The ``phase`` is asserted in-vocabulary so a coding mistake
    fails loudly here rather than emitting an unparseable frame.

    Args:
        request_id: The ``analyze`` request id this progress pertains to (placed in ``params.id``).
        percent: Completion estimate ``0..100`` or ``None``.
        phase: A value from :data:`PROGRESS_PHASES`.

    Returns:
        A JSON-RPC 2.0 notification dict ready to encode + frame.

    Raises:
        ValueError: If ``phase`` is not in :data:`PROGRESS_PHASES` or ``percent`` is out of range.
    """
    if phase not in PROGRESS_PHASES:
        raise ValueError("progress phase not in the closed vocabulary")
    if percent is not None and (percent < 0 or percent > 100):
        raise ValueError("progress percent out of range 0..100")
    return {
        "jsonrpc": "2.0",
        "method": PROGRESS_METHOD,
        "params": {"id": request_id, "percent": percent, "phase": phase},
    }


def _parse_error(err: Any) -> RpcError:
    """Parse a JSON-RPC ``error`` member into a safe :class:`RpcError`.

    Args:
        err: The raw ``error`` member.

    Returns:
        A structured, safe :class:`RpcError` (defaults applied for missing fields).
    """
    if not isinstance(err, dict):
        return RpcError(code=-32603, message="worker error", type_slug="internal-error")
    raw_code = err.get("code")
    code = raw_code if isinstance(raw_code, int) else -32603
    raw_msg = err.get("message")
    message = raw_msg if isinstance(raw_msg, str) else "worker error"
    type_slug: str | None = None
    detail: str | None = None
    data = err.get("data")
    if isinstance(data, dict):
        slug = data.get("type")
        if isinstance(slug, str):
            type_slug = slug
        # Optional redacted, log-only diagnostic (ADR-024). Capped defensively; only a str is
        # accepted (a hostile worker sending a non-string is simply ignored — fail closed).
        raw_detail = data.get("detail")
        if isinstance(raw_detail, str):
            detail = raw_detail[:_MAX_DETAIL_CHARS]
    return RpcError(code=code, message=message[:512], type_slug=type_slug, detail=detail)
