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
            return f"{base} | {joined}"
        return base


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

    Args:
        name: Logger name (typically ``__name__``).

    Returns:
        A configured :class:`logging.Logger`.
    """
    return logging.getLogger(name)
