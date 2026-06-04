"""Structured logging with mandatory redaction (stub, WS1).

Logs are an event stream of structured JSON to stderr (12-Factor; stdout is reserved for the MCP
stdio transport). REDACTION IS MANDATORY (master §5, topic-logging-observability): the logger
NEVER emits binary content, decompiled text, strings, symbol values, or session secrets. It logs
opaque session ids, tool names, sizes, durations, outcomes, and a correlation id only.

It also carries the security audit trail: session create/evict (with reason), worker kills,
limit-exceeded events, and validation rejections — all redacted.
"""

from __future__ import annotations

import logging


def configure_logging(*, level: str = "INFO", fmt: str = "json") -> None:
    """Configure process-wide structured logging to stderr with redaction.

    Args:
        level: Log level name (``DEBUG``..``ERROR``).
        fmt: ``"json"`` (production) or ``"text"`` (local dev).

    Note:
        STUB (WS1). Must install a redacting formatter/filter so no untrusted/binary-derived field
        can be logged even if accidentally passed; route to stderr only.
    """
    raise NotImplementedError("WS1: implement redacting structured logging to stderr")


def get_logger(name: str) -> logging.Logger:
    """Return a module logger bound to the redacting configuration.

    Args:
        name: Logger name (typically ``__name__``).

    Returns:
        A configured :class:`logging.Logger`.
    """
    return logging.getLogger(name)
