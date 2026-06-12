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

from typing import TYPE_CHECKING

from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError

if TYPE_CHECKING:  # avoid an import cycle at runtime (schemas imports nothing from this module).
    from ghidra_mcp.tools.schemas import (
        DefineStructIn,
        DefineUnionIn,
        FieldSpec,
        SetFunctionSignatureIn,
        TypeRef,
    )

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

# Maximum accepted/written comment text length (ADR-012 \u00a76; mirrors schemas._MAX_COMMENT). The
# comment is persisted into the program DB and re-served by ``get_comments``, so its size is bounded
# on the way IN as well as out (DoS / unbounded-growth \u2014 CWE-400).
MAX_COMMENT_LEN = 4096

# Allow-listed character set for a WRITE-target identifier (function/symbol ``new_name``) \u2014 a
# conservative C-identifier-like charset (ADR-012 \u00a77). A name the client supplies is
# attacker-INFLUENCED (an injection-steered LLM may propose it) and is PERSISTED into the program DB
# then re-served by the read tools, so it must not smuggle markup, path separators, whitespace,
# zero-width/RTL formatting, or control characters (stored-injection / data-poisoning defense). The
# leading character may not be a digit; subsequent characters add ``$`` and ``.`` (legitimate in
# mangled/namespaced symbol names) \u2014 but NOT ``/``, spaces, or any byte outside this set.
_WRITE_NAME_LEAD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")
_WRITE_NAME_REST = _WRITE_NAME_LEAD | frozenset("0123456789$.")

# --- structured type-model bounds + vocab (ADR-014 §2.5; mirror schemas._MAX_*). The signature/
# type input is STRUCTURED (resolved TypeRefs, never free-form C), so these validators are
# allow-list type-REFERENCE resolution (CWE-20), not parsing — CParser/DataTypeParser are never
# instantiated on a client value. ---
MAX_PARAMS = 64
"""Maximum parameters accepted in a structured signature (construction/re-flow DoS guard)."""

MAX_POINTER_DEPTH = 8
"""Maximum pointer-modifier depth on a :class:`TypeRef` (sane ``****…`` cap)."""

MAX_ARRAY_LEN = 65_536
"""Maximum fixed array length on a :class:`TypeRef` (element count; footprint worker-confined)."""

# --- composite-type bounds (ADR-015 §2.5; mirror schemas._MAX_FIELDS / _MAX_COMPOSITE_SIZE). A new
# composite is assembled field-by-field from resolved TypeRefs (NEVER free-form C), so these
# validators are allow-list resolution + bounds (CWE-20/CWE-400), not parsing. ---
MAX_FIELDS = 256
"""Maximum members accepted in a new composite (construction/cycle-summation DoS guard)."""

MAX_COMPOSITE_SIZE = 1_048_576
"""Maximum total computed size of an assembled composite (1 MiB; worker enforces post-resolve)."""

# Closed base-type vocabulary (ADR-014 §2.5). Mirrors schemas.BaseType; mapped to Ghidra built-ins
# in the worker. A ``base`` outside this set fails closed — never extensible by the client.
BASE_TYPE_VOCAB = frozenset(
    {
        "void",
        "bool",
        "char",
        "uchar",
        "wchar_t",
        "int8",
        "uint8",
        "int16",
        "uint16",
        "int32",
        "uint32",
        "int64",
        "uint64",
        "int",
        "uint",
        "long",
        "ulong",
        "float",
        "double",
    }
)

# Conservative static fallback calling-convention allow-list (ADR-014 §2.5 / KEY DECISION (c)). The
# program-derived set (``getCompilerSpec().getCallingConventions()``) is the precise source at the
# worker; this is the closed superset the SERVER boundary membership-checks against (a value outside
# it is rejected before the RPC). Never a free-form convention string.
CALLING_CONVENTIONS = frozenset(
    {
        "default",
        "__cdecl",
        "__stdcall",
        "__fastcall",
        "__thiscall",
        "__vectorcall",
    }
)


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


def validate_write_name(name: str) -> str:
    """Validate a WRITE-target name (``rename_function`` / ``rename_symbol`` ``new_name``).

    This is the strictest name validation in the system, applied only to values the client asks the
    server to PERSIST into the program DB (ADR-012 §7); it is attacker-INFLUENCED (an indirect
    prompt injection — std-owasp-llm LLM01 — can steer the client into proposing it) and, once
    written, is re-served by the read tools; so beyond the baseline :func:`validate_name` checks it
    is restricted to a conservative identifier allow-list — a leading letter/underscore followed by
    letters, digits, underscores, ``$`` and ``.`` — rejecting markup, path separators, whitespace,
    and any control/bidi/zero-width/separator character (stored-injection / data-poisoning defense,
    CWE-20). The value is never interpolated into a script (no ``runScript`` exists, PLAN §2); the
    worker passes it to a typed Java setter.

    Args:
        name: The raw new-name string from the client.

    Returns:
        The validated name, unchanged on success.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on a length, baseline-charset, or
            identifier-allow-list violation. The detail names the condition, never the value.
    """
    # Baseline first: type, non-empty, length, and the control/separator rejection shared with the
    # read path. Layering keeps the allow-list below the single new concern (defense in depth).
    validate_name(name)

    if name[0] not in _WRITE_NAME_LEAD:
        raise _validation_error("name must begin with a letter or underscore")

    for ch in name[1:]:
        if ch not in _WRITE_NAME_REST:
            raise _validation_error("name contains characters outside the identifier allow-list")

    return name


def validate_target_ref(value: str) -> str:
    """Validate a structural-write TARGET REFERENCE — the local/parameter selector (ADR-013 §6).

    The ``variable``/``parameter`` argument identifies *which* existing local/param to rename (a
    decompiler-assigned name like ``local_28`` / ``param_1``). It is a **selector, not a value we
    persist**, so it is NOT held to the strict write-name identifier allow-list (that charset would
    wrongly reject legitimate decompiler names). It is still attacker-influenceable, so it gets the
    baseline :func:`validate_name` treatment (bounded length, reject control/separator/zero-width
    chars); the worker's ``not-found`` is the authoritative confinement if it does not resolve to a
    ``HighSymbol``.

    Args:
        value: The raw target-reference string from the client.

    Returns:
        The validated reference, unchanged on success.

    Raises:
        GhidraMcpError: ``VALIDATION`` on a length or control/separator-char violation.
    """
    return validate_name(value)


def validate_comment_text(text: str) -> str:
    """Validate and normalize WRITE-target comment text (``set_comment``).

    The way-IN mirror of the untrusted-data envelope's normalization (ADR-005): the comment is
    attacker-INFLUENCED input that is PERSISTED into the program DB and later re-served by
    ``get_comments``, so it is bounded in length and its dangerous characters are neutralized on the
    way in (so the *stored* value is conservative) — the read path still re-wraps + re-normalizes on
    the way out, giving the two-sided defense in depth ADR-012 §7 specifies.

    Normalization reuses the single envelope chokepoint (:func:`ghidra_mcp.core.envelope.wrap`):
    control (C0/C1/DEL, except tab/newline/CR), bidirectional/override, and zero-width/invisible
    characters are replaced with inert ``<U+XXXX>`` tokens — never silently dropped. Newlines and
    tabs are preserved (legitimate in multi-line comments). Length is bounded BEFORE normalization
    (so an oversized payload is rejected, not expanded then accepted).

    Args:
        text: The raw comment text from the client (a non-empty string; ``None``-clears are handled
            by the handler before calling this — only a present value is validated/normalized).

    Returns:
        The normalized comment text, safe to persist.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope when ``text`` is not a string or is empty;
            with a ``LIMIT_EXCEEDED`` envelope when it exceeds ``MAX_COMMENT_LEN``.
    """
    if not isinstance(text, str):
        raise _validation_error("comment text must be a string")
    if not text:
        raise _validation_error("comment text must not be empty")
    if len(text) > MAX_COMMENT_LEN:
        raise _limit_error("comment text exceeds the maximum length")

    # Reuse the single normalization chokepoint (ADR-005). Import locally to keep this pure module
    # free of an envelope dependency at import time and to avoid any import cycle; ``wrap``'s
    # normalization is itself pure/I/O-free.
    from ghidra_mcp.core.envelope import wrap

    return wrap(text).value


def validate_calling_convention(name: str | None) -> str | None:
    """Validate a structured-signature calling-convention name (ADR-014 §2.5 / §3).

    ``None`` is allowed (leave the convention unchanged); otherwise the value must be a member of
    the closed :data:`CALLING_CONVENTIONS` allow-list — never a free-form convention string. The
    worker membership-checks again against the program-derived set; this is the boundary's closed
    superset (fail closed on a non-member — CWE-20).

    Args:
        name: The client-supplied convention name, or ``None`` to leave it unchanged.

    Returns:
        The validated convention (``None`` unchanged), unchanged on success.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope when ``name`` is not a string/``None`` or is
            outside the allow-list. The detail names the condition, never the value.
    """
    if name is None:
        return None
    if not isinstance(name, str):
        raise _validation_error("calling convention must be a string")
    if name not in CALLING_CONVENTIONS:
        raise _validation_error("calling convention is not in the allow-list")
    return name


def validate_type_ref(ref: TypeRef) -> None:
    """Validate a :class:`TypeRef`'s shape and bounds (ADR-014 §3) — allow-list, never parsed.

    Validates the pure part — the EXISTENCE of a ``named`` type is a worker concern (resolved
    against the program's ``DataTypeManager`` → ``not-found``). Enforced here: exactly one of
    ``base``/``named`` is set; ``base`` ∈ :data:`BASE_TYPE_VOCAB`; ``named`` passes the strict
    write-name identifier allow-list (it is attacker-influenceable and used as a DB lookup key — the
    conservative choice, ADR-014 §3, which a legitimate recovered type name satisfies);
    ``0 ≤ pointer_levels ≤ MAX_POINTER_DEPTH``; ``array_len`` is ``None`` or
    ``1..=MAX_ARRAY_LEN``. NO type string is parsed — this is a typed reference, not a C declaration
    (the barrier that REPLACES the C parser — CParser/DataTypeParser are never instantiated).

    Args:
        ref: The :class:`TypeRef` to validate (pydantic has already applied coarse field bounds and
            the exactly-one-leaf model validator; this re-asserts defensively + applies the
            allow-lists pydantic cannot express).

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on any shape/vocab/bounds/charset violation.
    """
    base = ref.base
    named = ref.named
    # Exactly one leaf (defense in depth — the model validator enforces it too; never trust caller).
    if (base is None) == (named is None):
        raise _validation_error("type reference must set exactly one of base/named")
    if base is not None and base not in BASE_TYPE_VOCAB:
        raise _validation_error("type reference base is not in the allow-list")
    if named is not None:
        # A ``named`` reference is attacker-influenceable and used as a DB lookup key → strict
        # identifier allow-list (rejects markup / C-declaration syntax / path / control chars). A
        # value carrying a struct body or ``int*`` is NOT a valid identifier and is never parsed.
        validate_write_name(named)
    if not isinstance(ref.pointer_levels, int) or isinstance(ref.pointer_levels, bool):
        raise _validation_error("pointer depth must be an integer")
    if ref.pointer_levels < 0 or ref.pointer_levels > MAX_POINTER_DEPTH:
        raise _validation_error("pointer depth is out of range")
    if ref.array_len is not None:
        if not isinstance(ref.array_len, int) or isinstance(ref.array_len, bool):
            raise _validation_error("array length must be an integer")
        if ref.array_len < 1 or ref.array_len > MAX_ARRAY_LEN:
            raise _validation_error("array length is out of range")


def validate_signature(sig: SetFunctionSignatureIn) -> None:
    """Validate a ``set_function_signature`` payload end-to-end (ADR-014 §3) — allow-list only.

    Enforces: ``function`` via :func:`validate_name` (read-path baseline selector); the parameter
    list bounded by :data:`MAX_PARAMS`; each ``ParamSpec.name`` via :func:`validate_write_name` (it
    is PERSISTED into the program DB and re-served — identical stored-injection profile as a
    local/param rename); each ``ParamSpec.type`` and ``return_type`` via :func:`validate_type_ref`;
    ``calling_convention`` via :func:`validate_calling_convention`. Parameter names need not be
    unique server-side (Ghidra disambiguates); an empty/duplicate-heavy list is bounded by
    ``MAX_PARAMS``. NO value is parsed by a C-type parser.

    Args:
        sig: The :class:`SetFunctionSignatureIn` payload to validate.

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on any name/cc/shape/bounds violation.
    """
    validate_name(sig.function)
    if len(sig.parameters) > MAX_PARAMS:
        raise _limit_error("parameter count exceeds the maximum")
    validate_type_ref(sig.return_type)
    for param in sig.parameters:
        validate_write_name(param.name)  # persisted → strict allow-list (stored-injection defense)
        validate_type_ref(param.type)
    validate_calling_convention(sig.calling_convention)


def validate_field_spec(field: FieldSpec) -> None:
    """Validate one composite member (ADR-015 §4) — allow-list, never parsed.

    A member ``name`` is PERSISTED into the program DB and re-served by the read tools, so it is
    held to the strict :func:`validate_write_name` identifier allow-list (stored-injection defense —
    identical profile to a Phase-B ``ParamSpec.name``). Its ``type`` is the EXISTING Phase-B
    :class:`TypeRef`, validated by :func:`validate_type_ref` (resolved, never parsed). ``offset`` is
    ``None`` (append sequentially) or a bounded non-negative int ``< MAX_COMPOSITE_SIZE``. NO type
    string is parsed (CParser/DataTypeParser are never instantiated on a client value).

    Args:
        field: The :class:`FieldSpec` to validate (pydantic has applied coarse field bounds; this
            re-asserts defensively + applies the allow-lists pydantic cannot express).

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on any name/type/offset shape/bounds
            violation. The detail names the condition, never the (untrusted) value.
    """
    validate_write_name(field.name)  # persisted → strict allow-list (stored-injection defense)
    validate_type_ref(field.type)
    if field.offset is not None:
        if not isinstance(field.offset, int) or isinstance(field.offset, bool):
            raise _validation_error("field offset must be an integer")
        if field.offset < 0 or field.offset >= MAX_COMPOSITE_SIZE:
            raise _validation_error("field offset is out of range")


def validate_composite(payload: DefineStructIn | DefineUnionIn, *, kind: str) -> None:
    """Validate a ``define_struct`` / ``define_union`` payload end-to-end (ADR-015 §4) — allow-list.

    Enforces, fail-closed and value-free: ``name`` via :func:`validate_write_name` (persisted type
    name); ``1 <= len(fields) <= MAX_FIELDS`` (non-empty, bounded — CWE-400); **no duplicate member
    name** within the composite (two ``x`` members are rejected); each member via
    :func:`validate_field_spec`; the **by-value self-embed boundary check** (the recursion crux,
    ADR-015 §3.2 — reject any ``field.type.named == payload.name`` with ``pointer_levels == 0``, an
    embedded self incl. an array-of-self); for ``kind == "union"`` every member ``offset`` MUST be
    ``None`` (a struct-only field — total schema per variant). The **total computed size** cap
    (``MAX_COMPOSITE_SIZE``) is enforced at the worker after resolution (it needs each resolved
    ``DataType.getLength()`` — a worker concern, like the Phase-B ``not-found``). NO value is parsed
    by a C-type parser — the structured model assembles typed Java objects (ADR-015 §2).

    Args:
        payload: The :class:`DefineStructIn` or :class:`DefineUnionIn` to validate.
        kind: ``"struct"`` or ``"union"`` — selects the variant rules (``offset`` is union-illegal).

    Raises:
        GhidraMcpError: With a ``VALIDATION`` envelope on any name/duplicate/self-embed/variant
            violation; with a ``LIMIT_EXCEEDED`` envelope when the field count exceeds the max.
    """
    validate_write_name(payload.name)  # persisted type name → strict allow-list
    fields = payload.fields
    if len(fields) < 1:
        raise _validation_error("a composite must have at least one member")
    if len(fields) > MAX_FIELDS:
        raise _limit_error("member count exceeds the maximum")

    seen: set[str] = set()
    for field in fields:
        validate_field_spec(field)
        if field.name in seen:
            raise _validation_error("composite members must have unique names")
        seen.add(field.name)
        # The recursion crux (ADR-015 §3.2): a by-value embed of self (named == this composite's
        # name, no pointer) would resolve against the pre-registered empty type into an
        # infinite-size type — reject it actively at the boundary (defense in depth; the schema
        # model validator enforces it too — never trust the caller). An ARRAY-of-self
        # (pointer_levels == 0, array_len set) is equally a by-value embed and is rejected (ADR-015
        # §3.2 "incl. array-of-self"); only a pointer-to-self (pointer_levels >= 1) is fixed-size.
        if field.type.named == payload.name and field.type.pointer_levels == 0:
            raise _validation_error("a composite member may not embed the composite by value")
        # A union overlays all members at offset 0 — an offset is a struct-only field (foot-gun).
        if kind == "union" and field.offset is not None:
            raise _validation_error("a union member may not carry an offset")
