"""Structured logging with mandatory redaction (WS1).

Logs are an event stream of structured JSON to **stderr** (12-Factor; stdout is reserved for the
MCP stdio transport — writing logs to stdout would corrupt the protocol stream). REDACTION IS
MANDATORY (master §5, topic-logging-observability): the logger NEVER emits binary content,
decompiled text, strings, symbol values, or session secrets. It emits opaque session ids, tool
names, sizes, durations, outcomes, and a correlation id only.

The redaction is enforced structurally: handlers pass only safe, allow-listed key/value ``extra``
fields, and a formatter additionally scrubs any field whose key matches a sensitive-name pattern
even if one is accidentally attached. This is defense-in-depth — the primary control is that
handlers never pass untrusted content into a log call.

It also carries the security audit trail: session create/evict (with reason), worker kills,
limit-exceeded events, and validation rejections — all redacted.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping
from typing import Any

# Reserved attributes set by the stdlib ``LogRecord``; everything else on a record's ``__dict__``
# is a caller-supplied ``extra`` field that we treat as a structured log key.
_RESERVED_RECORD_ATTRS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
    }
)

# Substrings that mark a log *field key* as potentially sensitive. If a caller ever attaches such a
# field, its value is replaced with a redaction marker rather than emitted (belt-and-braces; the
# real control is not passing untrusted content at all).
_SENSITIVE_KEY_SUBSTRINGS = (
    "content",
    "code",
    "decompil",
    "disassembl",
    "string",
    "bytes",
    "data",
    "value",
    "text",
    "secret",
    "token",
    "password",
    "payload",
    "comment",
    "operand",
)

_REDACTED = "[REDACTED]"

#: LogRecord attribute names that, if passed as a caller ``extra`` key, crash stdlib
#: ``Logger.makeRecord`` with ``KeyError: Attempt to overwrite '<k>' in LogRecord`` BEFORE any
#: formatter runs. ``message`` and ``asctime`` are reserved by ``makeRecord`` itself; the rest are
#: the attributes already present on a fresh record. We rename a colliding key (safe prefix) at the
#: log boundary so a stray ``extra={"msg": ...}`` is diagnosable, not fatal (ADR-024 PR-1).
_RESERVED_EXTRA_KEYS = _RESERVED_RECORD_ATTRS | {"message", "asctime"}

#: Prefix applied to a caller ``extra`` key that collides with a reserved LogRecord attribute.
_COLLISION_PREFIX = "x_"

#: Exception *type names* whose final ``formatException`` message line may echo a value (a pydantic
#: ``ValidationError`` renders the offending input, which can be binary-derived). For these we keep
#: the traceback frames but DROP the trailing message line(s) to avoid a redaction leak (ADR-024).
_VALUE_ECHOING_EXC_NAMES = frozenset({"ValidationError"})


def _guard_extra(extra: Mapping[str, object] | None) -> Mapping[str, object] | None:
    """Rename caller ``extra`` keys that collide with reserved LogRecord attributes.

    The collision otherwise raises ``KeyError`` inside stdlib ``makeRecord`` *before* the formatter
    can run (so the redacting formatter never gets a chance). Renaming with a safe prefix keeps the
    field diagnosable while letting the log call succeed. Key-based sensitive-value redaction still
    applies later in the formatter (the prefixed key preserves any sensitive substring).

    Args:
        extra: The caller-supplied structured fields, or ``None``.

    Returns:
        A new mapping with colliding keys renamed (or the original ``None``/empty input).
    """
    if not extra:
        return extra
    guarded: dict[str, object] = {}
    for key, value in extra.items():
        safe_key = f"{_COLLISION_PREFIX}{key}" if key in _RESERVED_EXTRA_KEYS else key
        guarded[safe_key] = value
    return guarded


def _format_exc(formatter: logging.Formatter, record: logging.LogRecord) -> str | None:
    """Render ``record.exc_info`` to a safe traceback string (frames only — never locals).

    Uses the stdlib ``formatException`` (frame summaries: file/line/function/source — NO local
    variable values), so an exception attached via ``_log.exception()`` is diagnosable. For
    value-echoing exception classes (e.g. pydantic ``ValidationError``, whose message AND whose
    failing call's source line can render the offending — possibly binary-derived — input), the
    rendering is reduced to **frame location lines only** (``File "...", line N, in func``): the
    indented source-code lines and the trailing exception-message line(s) are dropped, so no
    value can leak from a retained source line (ADR-024 / master §5).

    Args:
        formatter: The formatter whose ``formatException`` is used.
        record: The record whose ``exc_info`` to render.

    Returns:
        The safe traceback string, or ``None`` if the record carries no exception.
    """
    if not record.exc_info:
        return None
    text = formatter.formatException(record.exc_info)
    # Scrub if ANY exception in the chain is value-echoing — a ValidationError wrapped inside
    # another type (``raise Other(...) from ve``) still renders its value-bearing message line via
    # ``formatException``, so keying only on the outermost type would leak it (ADR-024 / master §5).
    if _chain_has_value_echoing(record.exc_info[1]):
        # Conservative scrub: keep ONLY the "Traceback" header and the frame *location* lines
        # ("File ..., line N, in func"). Drop indented source-code lines (which can echo the
        # value) and the trailing exception-message line(s) across the whole chain.
        kept = [
            line
            for line in text.splitlines()
            if line.startswith("Traceback") or line.lstrip().startswith("File ")
        ]
        text = "\n".join(kept)
    return text


def _chain_has_value_echoing(exc: BaseException | None) -> bool:
    """Return whether any exception in ``exc``'s cause/context chain may echo an input value.

    Walks ``__cause__``/``__context__`` (cycle-guarded) so a value-echoing exception (e.g. pydantic
    ``ValidationError``) is detected even when wrapped/chained inside another exception type — the
    trigger for the frames-only scrub in :func:`_format_exc`.

    Args:
        exc: The exception instance to inspect (``record.exc_info[1]``), or ``None``.

    Returns:
        ``True`` if any exception in the chain's class name is in ``_VALUE_ECHOING_EXC_NAMES``.
    """
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if type(exc).__name__ in _VALUE_ECHOING_EXC_NAMES:
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def _is_sensitive_key(key: str) -> bool:
    """Return whether a structured-log field key looks sensitive and must be redacted.

    Args:
        key: The ``extra`` field name attached to a log record.

    Returns:
        ``True`` if the key contains a known sensitive substring (case-insensitive).
    """
    lowered = key.lower()
    return any(token in lowered for token in _SENSITIVE_KEY_SUBSTRINGS)


def _safe_extra(record: logging.LogRecord) -> dict[str, Any]:
    """Extract caller-supplied structured fields from a record, redacting sensitive keys.

    Args:
        record: The log record being formatted.

    Returns:
        A mapping of safe structured fields; any sensitive-keyed value is replaced with the
        redaction marker.
    """
    fields: dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if key in _RESERVED_RECORD_ATTRS or key.startswith("_"):
            continue
        fields[key] = _REDACTED if _is_sensitive_key(key) else value
    return fields


class _RedactingJsonFormatter(logging.Formatter):
    """Format log records as a single line of structured JSON with redaction applied.

    Emits a stable schema: UTC-ish timestamp, level, logger, event message, plus any safe ``extra``
    structured fields. Never serializes binary-derived content (redacted by key).
    """

    def format(self, record: logging.LogRecord) -> str:
        """Render ``record`` as a compact JSON object.

        Args:
            record: The log record to format.

        Returns:
            A JSON string (single line; ASCII-escaped so embedded bytes can't break shippers).
        """
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update(_safe_extra(record))
        exc = _format_exc(self, record)
        if exc is not None:
            payload["exc"] = exc
        return json.dumps(payload, default=str, ensure_ascii=True)


class _RedactingTextFormatter(logging.Formatter):
    """Human-readable formatter for local dev, applying the same key-based redaction."""

    def format(self, record: logging.LogRecord) -> str:
        """Render ``record`` as a single readable line with safe structured fields appended.

        Args:
            record: The log record to format.

        Returns:
            A formatted, redacted log line.
        """
        base = (
            f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<7} "
            f"{record.name}: {record.getMessage()}"
        )
        extra = _safe_extra(record)
        if extra:
            joined = " ".join(f"{k}={v}" for k, v in extra.items())
            base = f"{base} | {joined}"
        exc = _format_exc(self, record)
        if exc is not None:
            base = f"{base}\n{exc}"
        return base


class _RedactingLogger(logging.Logger):
    """A :class:`logging.Logger` that guards reserved ``extra`` keys at the log boundary.

    The reserved-key crash (``KeyError: Attempt to overwrite 'msg' in LogRecord``) happens inside
    stdlib :meth:`logging.Logger.makeRecord` — BEFORE any formatter runs — so guarding only in the
    formatter is too late. Renaming colliding keys here (the boundary) means a stray
    ``extra={"msg": ...}`` is safely renamed instead of crashing the log call (ADR-024 PR-1).
    """

    def makeRecord(  # noqa: N802  (overriding the stdlib camelCase method)
        self,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: object,
        args: Any,
        exc_info: Any,
        func: str | None = None,
        extra: Mapping[str, object] | None = None,
        sinfo: str | None = None,
    ) -> logging.LogRecord:
        """Create a record after renaming reserved-name ``extra`` keys (collision-safe).

        Args:
            name: Logger name.
            level: Numeric level.
            fn: Source filename.
            lno: Source line number.
            msg: The log message.
            args: Message args.
            exc_info: Exception info tuple, if any.
            func: Calling function name.
            extra: Caller-supplied structured fields (guarded here).
            sinfo: Stack info string, if any.

        Returns:
            The constructed :class:`logging.LogRecord`.
        """
        return super().makeRecord(
            name, level, fn, lno, msg, args, exc_info, func, _guard_extra(extra), sinfo
        )


def configure_logging(*, level: str = "INFO", fmt: str = "json") -> None:
    """Configure process-wide structured logging to stderr with mandatory redaction.

    Idempotent: replaces any handlers previously installed on the root logger so repeated calls (or
    re-configuration after a config reload) do not duplicate output.

    Args:
        level: Log level name (``DEBUG``..``ERROR``).
        fmt: ``"json"`` (production) or ``"text"`` (local dev).

    Raises:
        ValueError: If ``level`` is not a recognized level name.
    """
    numeric_level = logging.getLevelNamesMapping().get(level.upper())
    if numeric_level is None:
        raise ValueError(f"unsupported log level: {level!r}")

    # Guard the reserved-key crash at the boundary for every logger created from here on (ADR-024).
    logging.setLoggerClass(_RedactingLogger)

    # stdout is the MCP transport — logs go to stderr only.
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(_RedactingJsonFormatter() if fmt == "json" else _RedactingTextFormatter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric_level)


def get_logger(name: str) -> logging.Logger:
    """Return a module logger bound to the redacting configuration.

    Ensures the reserved-key-guarding logger class is registered so a logger fetched before
    :func:`configure_logging` (e.g. at module import) is still collision-safe (ADR-024).

    Args:
        name: Logger name (typically ``__name__``).

    Returns:
        A configured :class:`logging.Logger` (a :class:`_RedactingLogger`).
    """
    if logging.getLoggerClass() is not _RedactingLogger:
        logging.setLoggerClass(_RedactingLogger)
    return logging.getLogger(name)
