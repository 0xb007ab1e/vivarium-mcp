"""Boundary validation for tool arguments (trust boundary 1) — critical path (100% target).

Pure, I/O-free validation helpers used by the tool handlers and schemas. These complement pydantic
field constraints with the domain rules that pydantic cannot express declaratively: address
syntax, name/identifier allow-listing, and confinement of any range-like argument (CWE-20 input
validation, CWE-22 path traversal, CWE-190 overflow on ranges).

Everything here is allow-list (positive) validation and fails closed on anything unexpected
(std-owasp-proactive #5). No value from the client is trusted, and no value is ever interpolated
into a shell/query/script (read-only v1) — but every value is validated defensively regardless.

The module performs **no I/O** (functional core — topic-architecture-patterns): on any violation
it raises a typed :class:`~ghidra_mcp.core.errors.GhidraMcpError` carrying a safe, redacted error
envelope. The imperative shell translates that envelope to the client.
"""

from __future__ import annotations

from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError

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

# Absolute ceiling for any address we accept (64-bit address space). Guards CWE-190 on offsets and
# keeps parsed addresses representable. Inclusive upper bound.
_MAX_ADDRESS = (1 << 64) - 1

# Maximum hex digits we will parse for an address (16 hex digits = 64 bits, plus an optional
# ``0x`` prefix). A short, fixed cap prevents pathological huge-string inputs reaching ``int``.
_MAX_ADDRESS_HEX_DIGITS = 16

# Hex digit alphabet (case-insensitive) used for fast, allow-list character checks.
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# Unicode line/paragraph separators (U+2028 / U+2029) that must never appear in a name (log/render
# corruption, injection smuggling — topic-i18n, std-cwe). Spelled as escapes (not literal glyphs) so
# the source stays unambiguous; C0/C1 controls and DEL are handled by the code-point range below.
_UNICODE_SEPARATORS = frozenset("\u2028\u2029")


def _validation_error(detail: str) -> GhidraMcpError:
    """Build a fail-closed ``VALIDATION`` error with a safe, generic detail.

    The ``detail`` MUST be a safe summary — it names the offending *field/condition*, never echoes
    the rejected value (which is untrusted and could carry an injection payload — std-owasp-llm
    LLM01) and never includes internals (topic-error-handling, master §5).

    Args:
        detail: A short, safe, value-free description of why validation failed.

    Returns:
        A :class:`GhidraMcpError` wrapping a ``validation-error`` envelope (HTTP 400, terminal).
    """
    return GhidraMcpError(
        ErrorEnvelope(
            type=ErrorType.VALIDATION,
            title="Invalid arguments",
            detail=detail,
            status=400,
            retryable=False,
        )
    )


def _limit_error(detail: str) -> GhidraMcpError:
    """Build a fail-closed ``LIMIT_EXCEEDED`` error with a safe detail.

    Args:
        detail: A short, safe description of the bound that was exceeded (no values echoed).

    Returns:
        A :class:`GhidraMcpError` wrapping a ``limit-exceeded`` envelope (HTTP 413, terminal).
    """
    return GhidraMcpError(
        ErrorEnvelope(
            type=ErrorType.LIMIT_EXCEEDED,
            title="Limit exceeded",
            detail=detail,
            status=413,
            retryable=False,
        )
    )


def parse_address(value: str) -> int:
    """Validate and parse a Ghidra address argument into an integer offset.

    Accepts a hexadecimal address with an optional ``0x``/``0X`` prefix (e.g. ``"0x401000"`` or
    ``"00401000"``) and rejects anything else. This is the canonical place address syntax is
    enforced; no trust is placed in client formatting. Parsing is allow-list (only hex digits after
    an optional prefix) and bounded to 64 bits to guard CWE-190.

    Args:
        value: The raw address string from the client.

    Returns:
        The address as a non-negative integer in ``[0, 2**64 - 1]``.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope if ``value`` is not a syntactically valid,
            in-range hexadecimal address.
    """
    if not isinstance(value, str):  # defensive: schema types it str, but never trust the caller.
        raise _validation_error("address must be a string")

    text = value.strip()
    if not text:
        raise _validation_error("address must not be empty")

    # Strip an optional single 0x/0X prefix.
    digits = text[2:] if text[:2] in ("0x", "0X") else text

    if not digits:
        raise _validation_error("address has no hexadecimal digits")

    if len(digits) > _MAX_ADDRESS_HEX_DIGITS:
        raise _validation_error("address has too many hexadecimal digits")

    # Allow-list: every character must be a hex digit. Rejects whitespace, signs, '+', '_',
    # underscores, and any non-hex byte (no reliance on int()'s lenient grammar).
    if any(ch not in _HEX_DIGITS for ch in digits):
        raise _validation_error("address contains non-hexadecimal characters")

    address = int(digits, 16)
    # Defensive, fail-closed ceiling. With the 16-hex-digit cap above, ``int(digits, 16)`` cannot
    # exceed ``_MAX_ADDRESS`` (0xffff_ffff_ffff_ffff), so this branch is provably unreachable via
    # the validated path; it stays as an explicit bound and is excluded from coverage as dead-by-
    # construction (topic-defensive-programming; the live guard is the digit cap, tested above).
    if address > _MAX_ADDRESS:  # pragma: no cover
        raise _validation_error("address is out of range")
    return address


def validate_name(value: str) -> str:
    """Validate a symbol/function/data-type name argument.

    Enforces a non-empty length within ``MAX_NAME_LEN`` and rejects ASCII control characters
    (C0/C1 plus DEL) and Unicode line/paragraph separators, which can smuggle injection payloads or
    corrupt logs/rendering (std-cwe, topic-i18n). Names are matched against Ghidra objects, never
    interpolated into a shell/query/script in read-only v1, but are validated defensively all the
    same.

    Args:
        value: The raw name string from the client.

    Returns:
        The validated name, unchanged on success.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on a length or character-set violation.
    """
    if not isinstance(value, str):
        raise _validation_error("name must be a string")

    if not value:
        raise _validation_error("name must not be empty")

    if len(value) > MAX_NAME_LEN:
        raise _validation_error("name exceeds maximum length")

    for ch in value:
        code = ord(ch)
        is_control = code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F
        if is_control or ch in _UNICODE_SEPARATORS:
            raise _validation_error("name contains disallowed control characters")

    return value


def validate_byte_range(offset: int, length: int) -> tuple[int, int]:
    """Validate a bounded ``(offset, length)`` byte range for ``read_bytes``.

    Guards against negative values, non-integer inputs, ``length`` exceeding ``MAX_READ_BYTES``,
    and integer overflow on ``offset + length`` past the 64-bit address ceiling (CWE-190).
    Confinement to the program's actual memory map is enforced downstream by the worker/adapter
    (the pure core cannot know the map).

    Args:
        offset: Start offset (non-negative).
        length: Number of bytes to read (``1..MAX_READ_BYTES``).

    Returns:
        The validated ``(offset, length)`` tuple, unchanged on success.

    Raises:
        GhidraMcpError: ``VALIDATION`` envelope for non-integer/negative/zero/overflowing values;
            ``LIMIT_EXCEEDED`` envelope when ``length`` exceeds ``MAX_READ_BYTES``.
    """
    # ``bool`` is an ``int`` subclass; reject it explicitly so True/False can't pose as 1/0.
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise _validation_error("offset must be an integer")
    if isinstance(length, bool) or not isinstance(length, int):
        raise _validation_error("length must be an integer")

    if offset < 0:
        raise _validation_error("offset must be non-negative")
    if offset > _MAX_ADDRESS:
        raise _validation_error("offset is out of range")

    if length < 1:
        raise _validation_error("length must be at least 1 byte")
    if length > MAX_READ_BYTES:
        raise _limit_error("requested byte length exceeds the maximum")

    # Overflow guard: the inclusive end address must remain within the 64-bit space.
    if offset + length - 1 > _MAX_ADDRESS:
        raise _validation_error("byte range overflows the address space")

    return offset, length


def validate_query(value: str) -> str:
    """Validate a free-text search query (``search_strings``) defensively.

    Enforces a non-empty length within ``MAX_QUERY_LEN`` and rejects control characters. The query
    is matched as a literal case-insensitive substring server-side — never compiled as a regex or
    interpolated into a script (read-only v1) — but is validated as untrusted input regardless.

    Args:
        value: The raw query string from the client.

    Returns:
        The validated query, unchanged on success.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on a length or character-set violation.
    """
    if not isinstance(value, str):
        raise _validation_error("query must be a string")
    if not value:
        raise _validation_error("query must not be empty")
    if len(value) > MAX_QUERY_LEN:
        raise _validation_error("query exceeds maximum length")
    for ch in value:
        code = ord(ch)
        is_control = code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F
        if is_control or ch in _UNICODE_SEPARATORS:
            raise _validation_error("query contains disallowed control characters")
    return value


def validate_byte_pattern(pattern_hex: str) -> str:
    """Validate a ``search_bytes`` pattern: hex byte pairs with optional ``"??"`` wildcards.

    Allow-list only: ignoring single-space separators, the pattern must be a sequence of *whole
    bytes*, each either two hex digits or ``"??"`` (a wildcard byte). Rejects empty, odd-length,
    non-hex, and over-length input (CWE-20). The pattern is never interpolated into a query/script;
    the worker performs the actual scan.

    Args:
        pattern_hex: The raw pattern string from the client.

    Returns:
        The validated pattern, unchanged on success.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on any malformed pattern.
    """
    if not isinstance(pattern_hex, str):
        raise _validation_error("byte pattern must be a string")
    if len(pattern_hex) > MAX_QUERY_LEN:
        raise _validation_error("byte pattern exceeds maximum length")

    compact = pattern_hex.replace(" ", "")
    if not compact or len(compact) % 2 != 0:
        raise _validation_error("byte pattern must be whole bytes (pairs of hex digits)")

    for i in range(0, len(compact), 2):
        pair = compact[i : i + 2]
        if pair == "??":
            continue
        if pair[0] not in _HEX_DIGITS or pair[1] not in _HEX_DIGITS:
            raise _validation_error("byte pattern contains a non-hex, non-wildcard byte")
    return pattern_hex
