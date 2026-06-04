"""Boundary validation for tool arguments (trust boundary 1) — critical path (100% target).

Pure, I/O-free validation helpers used by the tool schemas in :mod:`ghidra_mcp.tools.schemas`.
These complement pydantic field constraints with the domain rules that pydantic can't express
declaratively: address syntax, name/identifier allow-listing, and confinement of any path-like or
range-like argument (CWE-20 input validation, CWE-22 path traversal, CWE-190 overflow on ranges).

Everything here is allow-list (positive) validation and fails closed on anything unexpected
(std-owasp-proactive #5). No value from the client is trusted.

WS0 ships interface stubs with frozen signatures; WS1 implements the logic and WS5 drives them to
100% coverage including negative/abuse inputs.
"""

from __future__ import annotations

# Frozen domain bounds (also surfaced via env config in security/limits.py at runtime).
# Declared here so validation has stable, testable constants independent of I/O.
MAX_NAME_LEN = 1024
"""Maximum accepted length for a function/symbol/data-type name argument."""

MAX_QUERY_LEN = 4096
"""Maximum accepted length for a search query (bytes pattern / string query)."""

MAX_READ_BYTES = 1_048_576
"""Maximum number of bytes a single bounded read may request (1 MiB)."""

MAX_RESULT_COUNT = 10_000
"""Maximum number of items any list/search tool may return in one call."""


def parse_address(value: str) -> int:
    """Validate and parse a Ghidra address argument into an integer offset.

    Accepts a hex address (e.g. ``"0x401000"`` or ``"00401000"``); rejects anything else. This is
    the canonical place address syntax is enforced (no trust in client formatting).

    Args:
        value: The raw address string from the client.

    Returns:
        The address as a non-negative integer.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope if ``value`` is not a valid address.

    Note:
        STUB (WS1).
    """
    raise NotImplementedError("WS1: implement strict address parsing/validation")


def validate_name(value: str) -> str:
    """Validate a symbol/function/data-type name argument.

    Enforces length (``MAX_NAME_LEN``) and rejects control characters. Names are matched against
    Ghidra objects, never interpolated into a shell/query/script (read-only v1) — but they are
    still validated defensively.

    Args:
        value: The raw name string from the client.

    Returns:
        The validated name (unchanged on success).

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on length/charset violation.

    Note:
        STUB (WS1).
    """
    raise NotImplementedError("WS1: implement name validation")


def validate_byte_range(offset: int, length: int) -> tuple[int, int]:
    """Validate a bounded (offset, length) byte range for ``read_bytes``.

    Guards against negative values, overflow on ``offset + length`` (CWE-190), and ``length``
    exceeding ``MAX_READ_BYTES``. Confinement to the program's actual memory map is enforced
    downstream by the worker/adapter (the core cannot know the map).

    Args:
        offset: Start offset (non-negative).
        length: Number of bytes (1..``MAX_READ_BYTES``).

    Returns:
        The validated ``(offset, length)`` tuple.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` or ``LIMIT_EXCEEDED`` envelope.

    Note:
        STUB (WS1).
    """
    raise NotImplementedError("WS1: implement bounded byte-range validation")
