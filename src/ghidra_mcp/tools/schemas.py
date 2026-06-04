"""Frozen pydantic input/output schemas for the Tier-1 read-only tool catalog — FROZEN (WS0).

This module is THE contract WS1 implements and WS5 tests. Every tool listed in
``docs/contracts/tool-catalog.md`` has an ``*In`` (arguments) and ``*Out`` (result) model here.

Design rules baked into these schemas:

- **Bounded by default.** Every list/search/read tool carries explicit ``limit``/``length`` caps
  with pydantic ``le=`` bounds, and pagination via ``offset``. No unbounded result sets
  (DoS control — PLAN §3 F7, std-owasp-api API4 analog).
- **Untrusted output is wrapped.** All binary-derived fields are typed ``Untrusted[...]``
  (ADR-005). Server-controlled scalars (counts, addresses we computed, sizes) are bare.
- **No extra fields.** ``extra="forbid"`` on inputs rejects unexpected args (mass-assignment /
  typo defense); models are ``frozen`` for immutability.
- **Session-scoped.** Every tool except ``session_create`` takes a ``session_id``; the session
  manager authorizes it server-side (BOLA defense — the client never names another binary's data).

NOTE: address/name/range fields use ``str``/``int`` with coarse pydantic bounds here; the
*semantic* validation (hex syntax, charset, overflow, map-confinement) is applied by
:mod:`ghidra_mcp.core.validation` inside each tool. Bounds are intentionally conservative; exact
numeric values are mirrored from :mod:`ghidra_mcp.core.validation` / ``security.limits``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ghidra_mcp.core.envelope import Untrusted

# --- shared bounds (mirror core.validation; kept literal so schemas are self-contained) ---
_MAX_NAME = 1024
_MAX_QUERY = 4096
_MAX_LIMIT = 10_000
_MAX_READ = 1_048_576  # 1 MiB
_DEFAULT_LIMIT = 100


class _In(BaseModel):
    """Base for tool *input* models: immutable, reject unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class _Out(BaseModel):
    """Base for tool *output* models: immutable."""

    model_config = ConfigDict(frozen=True)


class _SessionScopedIn(_In):
    """Base for any tool input bound to an existing session.

    Attributes:
        session_id: Opaque session identifier returned by ``session_create``. Authorized
            server-side; an unknown/foreign id yields a ``SESSION_INVALID`` error (BOLA-safe).
    """

    session_id: str = Field(min_length=1, max_length=64)


class _Page(_SessionScopedIn):
    """Base for paginated, bounded list tools.

    Attributes:
        offset: Zero-based start index into the result set.
        limit: Maximum items to return (capped at ``_MAX_LIMIT``).
    """

    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT)


# =====================================================================================
# Session lifecycle
# =====================================================================================
class SessionCreateIn(_In):
    """Arguments for ``session_create`` — open a session (does NOT import a binary yet).

    Attributes:
        label: Optional client-supplied label for audit/correlation (not trusted; not a path).
    """

    label: str | None = Field(default=None, max_length=128)


class SessionInfo(_Out):
    """A session's server-side state summary (no binary-derived content).

    Attributes:
        session_id: Opaque id.
        state: Lifecycle state (e.g. ``"open"``, ``"importing"``, ``"analyzing"``, ``"ready"``,
            ``"evicted"``).
        created_at: Unix epoch seconds (server clock) when the session opened.
        expires_at: Unix epoch seconds at which TTL eviction occurs.
        binary_sha256: Hex SHA-256 of the imported binary, or ``None`` before import. This is a
            server-computed digest of input — safe (not binary-derived content).
    """

    session_id: str
    state: str
    created_at: int
    expires_at: int
    binary_sha256: str | None = None


class SessionImportIn(_SessionScopedIn):
    """Arguments for ``session_import`` — load a binary into the session.

    The binary is provided out-of-band by reference (the server reads it under its own confinement
    and enforces the size cap BEFORE handing it to the worker). The client never streams arbitrary
    bytes that bypass the cap.

    Attributes:
        source_ref: Server-resolved reference to the input (e.g. a pre-registered upload id or an
            allow-listed mount path). Resolution + path confinement happen server-side (CWE-22).
        expected_sha256: Optional client-asserted digest; the server verifies the actual bytes
            match (integrity / wrong-file guard).
    """

    source_ref: str = Field(min_length=1, max_length=512)
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


class SessionAnalyzeIn(_SessionScopedIn):
    """Arguments for ``session_analyze`` — run Ghidra auto-analysis on the imported binary.

    Bounded by the per-analysis wall-clock timeout (kills the worker on expiry — PLAN §3 F7).

    Attributes:
        timeout_seconds: Optional override, clamped server-side to the configured maximum.
    """

    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)


class SessionCloseIn(_SessionScopedIn):
    """Arguments for ``session_close`` — evict the session now (kill worker, wipe store)."""


class SessionCloseOut(_Out):
    """Result of ``session_close``.

    Attributes:
        session_id: The closed session's id.
        store_wiped: Whether the per-session project store was verified-wiped (ADR-002). MUST be
            ``True`` on success; ``False`` indicates a cleanup failure to alert on.
    """

    session_id: str
    store_wiped: bool


# =====================================================================================
# Code: decompile / disassemble / functions
# =====================================================================================
class DecompileFunctionIn(_SessionScopedIn):
    """Arguments for ``decompile_function``.

    Attributes:
        function: Function entry address (hex) OR name. Validated by ``core.validation``.
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)


class DecompiledFunction(_Out):
    """Decompiler output for one function (binary-derived → untrusted).

    Attributes:
        address: Server-normalized entry address (hex string) — safe.
        name: Function name as Ghidra knows it — untrusted (attacker-influenced symbol).
        c_code: The decompiled pseudo-C — untrusted (prime injection vector).
        signature: Recovered signature — untrusted.
    """

    address: str
    name: Untrusted[str]
    c_code: Untrusted[str]
    signature: Untrusted[str]


class DisassembleIn(_SessionScopedIn):
    """Arguments for ``disassemble`` a bounded range or a function.

    Attributes:
        start: Start address (hex).
        max_instructions: Cap on instructions returned (bounded).
        function: Optional function name/address to disassemble instead of a raw range.
    """

    start: str | None = Field(default=None, max_length=_MAX_NAME)
    function: str | None = Field(default=None, max_length=_MAX_NAME)
    max_instructions: int = Field(default=256, ge=1, le=_MAX_LIMIT)


class Instruction(_Out):
    """One disassembled instruction.

    Attributes:
        address: Instruction address (hex) — server-normalized, safe.
        mnemonic: Instruction mnemonic — untrusted.
        operands: Operand text — untrusted.
        bytes_hex: Raw instruction bytes (hex) — untrusted.
    """

    address: str
    mnemonic: Untrusted[str]
    operands: Untrusted[str]
    bytes_hex: Untrusted[str]


class DisassembleOut(_Out):
    """Result of ``disassemble``.

    Attributes:
        instructions: Bounded list of instructions.
        truncated: Whether the cap clipped the result.
    """

    instructions: list[Instruction]
    truncated: bool = False


class ListFunctionsIn(_Page):
    """Arguments for ``list_functions`` — paginated, bounded.

    Attributes:
        name_contains: Optional case-insensitive substring filter (validated; not a regex).
    """

    name_contains: str | None = Field(default=None, max_length=_MAX_NAME)


class FunctionSummary(_Out):
    """Summary record for one function.

    Attributes:
        address: Entry address (hex) — safe.
        name: Function name — untrusted.
        size: Byte size — safe (server-computed integer).
    """

    address: str
    name: Untrusted[str]
    size: int


class FunctionListOut(_Out):
    """Result of ``list_functions``.

    Attributes:
        functions: Bounded list of function summaries.
        total: Total matching functions (for pagination) — safe count.
        truncated: Whether the page was capped.
    """

    functions: list[FunctionSummary]
    total: int
    truncated: bool = False


class GetFunctionIn(DecompileFunctionIn):
    """Arguments for ``get_function`` — detailed metadata for one function (no decompilation)."""


class FunctionDetail(_Out):
    """Detailed metadata for one function.

    Attributes:
        address: Entry address (hex) — safe.
        name: Function name — untrusted.
        signature: Recovered signature — untrusted.
        size: Byte size — safe.
        is_thunk: Whether Ghidra flags it a thunk — safe boolean.
        calling_convention: Recovered convention — untrusted (string from analysis).
    """

    address: str
    name: Untrusted[str]
    signature: Untrusted[str]
    size: int
    is_thunk: bool
    calling_convention: Untrusted[str] | None = None


# =====================================================================================
# Cross-references
# =====================================================================================
class XrefsIn(_Page):
    """Arguments for ``xrefs_to`` / ``xrefs_from`` — references for an address/function.

    Attributes:
        target: Address (hex) or function name to find references for.
    """

    target: str = Field(min_length=1, max_length=_MAX_NAME)


class Xref(_Out):
    """A single cross-reference.

    Attributes:
        from_address: Source address (hex) — safe.
        to_address: Destination address (hex) — safe.
        ref_type: Reference kind (e.g. ``"CALL"``, ``"READ"``, ``"DATA"``) — safe enum-like string.
    """

    from_address: str
    to_address: str
    ref_type: str


class XrefsOut(_Out):
    """Result of ``xrefs_to`` / ``xrefs_from``.

    Attributes:
        xrefs: Bounded list of references.
        total: Total references (for pagination) — safe.
        truncated: Whether the page was capped.
    """

    xrefs: list[Xref]
    total: int
    truncated: bool = False


# =====================================================================================
# Strings / symbols / data
# =====================================================================================
class ListStringsIn(_Page):
    """Arguments for ``list_strings`` — paginated, bounded.

    Attributes:
        min_length: Minimum string length to include (bounded).
    """

    min_length: int = Field(default=4, ge=1, le=4096)


class DefinedString(_Out):
    """One defined string in the program (binary-derived → untrusted).

    Attributes:
        address: Address (hex) — safe.
        value: The string content — UNTRUSTED (top injection vector).
        length: Length in bytes — safe.
    """

    address: str
    value: Untrusted[str]
    length: int


class StringListOut(_Out):
    """Result of ``list_strings``.

    Attributes:
        strings: Bounded list of defined strings.
        total: Total matching strings — safe.
        truncated: Whether the page was capped.
    """

    strings: list[DefinedString]
    total: int
    truncated: bool = False


class ListSymbolsIn(_Page):
    """Arguments for ``list_symbols`` — paginated, bounded.

    Attributes:
        name_contains: Optional substring filter (validated; not a regex).
    """

    name_contains: str | None = Field(default=None, max_length=_MAX_NAME)


class Symbol(_Out):
    """One symbol/label.

    Attributes:
        address: Address (hex) — safe.
        name: Symbol name — UNTRUSTED.
        kind: Symbol kind (e.g. ``"FUNCTION"``, ``"LABEL"``, ``"IMPORT"``) — safe.
        namespace: Containing namespace — untrusted.
    """

    address: str
    name: Untrusted[str]
    kind: str
    namespace: Untrusted[str] | None = None


class SymbolListOut(_Out):
    """Result of ``list_symbols``.

    Attributes:
        symbols: Bounded list of symbols.
        total: Total matching symbols — safe.
        truncated: Whether the page was capped.
    """

    symbols: list[Symbol]
    total: int
    truncated: bool = False


class GetSymbolIn(_SessionScopedIn):
    """Arguments for ``get_symbol`` — resolve one symbol by name or address.

    Attributes:
        identifier: Symbol name or address (hex).
    """

    identifier: str = Field(min_length=1, max_length=_MAX_NAME)


class ListDataIn(_Page):
    """Arguments for ``list_data`` — paginated, bounded defined-data listing."""


class DefinedData(_Out):
    """One defined data item.

    Attributes:
        address: Address (hex) — safe.
        data_type: Type name — untrusted.
        value_repr: Rendered value representation — UNTRUSTED.
        length: Size in bytes — safe.
    """

    address: str
    data_type: Untrusted[str]
    value_repr: Untrusted[str]
    length: int


class DataListOut(_Out):
    """Result of ``list_data``.

    Attributes:
        data: Bounded list of defined data items.
        total: Total items — safe.
        truncated: Whether the page was capped.
    """

    data: list[DefinedData]
    total: int
    truncated: bool = False


class GetDataTypeIn(_SessionScopedIn):
    """Arguments for ``get_data_type`` — resolve one data type by name.

    Attributes:
        name: Data-type name (validated).
    """

    name: str = Field(min_length=1, max_length=_MAX_NAME)


class DataType(_Out):
    """A data-type definition.

    Attributes:
        name: Type name — untrusted.
        kind: Category (e.g. ``"struct"``, ``"enum"``, ``"typedef"``, ``"pointer"``) — safe.
        size: Size in bytes — safe.
        definition: Rendered definition (e.g. struct layout) — UNTRUSTED.
    """

    name: Untrusted[str]
    kind: str
    size: int
    definition: Untrusted[str]


# =====================================================================================
# Comments
# =====================================================================================
class GetCommentsIn(_Page):
    """Arguments for ``get_comments`` — READ-ONLY comment retrieval (no write in v1).

    Attributes:
        address: Optional address (hex) to scope comments to; omit for all (paginated).
    """

    address: str | None = Field(default=None, max_length=_MAX_NAME)


class Comment(_Out):
    """One comment attached to the program (binary-derived → untrusted).

    Attributes:
        address: Address (hex) — safe.
        comment_type: Kind (e.g. ``"EOL"``, ``"PRE"``, ``"PLATE"``) — safe.
        text: Comment text — UNTRUSTED (injection vector, esp. in malware with planted comments).
    """

    address: str
    comment_type: str
    text: Untrusted[str]


class CommentListOut(_Out):
    """Result of ``get_comments``.

    Attributes:
        comments: Bounded list of comments.
        total: Total comments — safe.
        truncated: Whether the page was capped.
    """

    comments: list[Comment]
    total: int
    truncated: bool = False


# =====================================================================================
# Memory / bytes / search
# =====================================================================================
class MemoryMapIn(_SessionScopedIn):
    """Arguments for ``memory_map`` — list memory blocks/segments."""


class MemoryBlock(_Out):
    """One memory block/segment.

    Attributes:
        name: Block name — untrusted (from binary section headers).
        start: Start address (hex) — safe.
        end: End address (hex) — safe.
        size: Size in bytes — safe.
        permissions: e.g. ``"rwx"`` — safe (derived flags).
        initialized: Whether the block is initialized — safe.
    """

    name: Untrusted[str]
    start: str
    end: str
    size: int
    permissions: str
    initialized: bool


class MemoryMapOut(_Out):
    """Result of ``memory_map``.

    Attributes:
        blocks: List of memory blocks (bounded by the program; typically small).
    """

    blocks: list[MemoryBlock]


class ReadBytesIn(_SessionScopedIn):
    """Arguments for ``read_bytes`` — BOUNDED raw byte read.

    Attributes:
        address: Start address (hex).
        length: Number of bytes (1..``_MAX_READ`` = 1 MiB). Confined to the memory map server-side.
    """

    address: str = Field(min_length=1, max_length=_MAX_NAME)
    length: int = Field(ge=1, le=_MAX_READ)


class ReadBytesOut(_Out):
    """Result of ``read_bytes``.

    Attributes:
        address: Start address (hex) — safe.
        data: The bytes, hex-encoded — UNTRUSTED (envelope ``encoding="hex"``).
        length: Number of bytes actually returned — safe.
        truncated: Whether fewer bytes were returned than requested (end of block).
    """

    address: str
    data: Untrusted[str]
    length: int
    truncated: bool = False


class SearchBytesIn(_Page):
    """Arguments for ``search_bytes`` — BOUNDED byte-pattern search.

    Attributes:
        pattern_hex: Hex byte pattern, optionally with ``"??"`` wildcards (validated; bounded).
    """

    pattern_hex: str = Field(min_length=2, max_length=_MAX_QUERY)


class ByteMatch(_Out):
    """One byte-search hit.

    Attributes:
        address: Match address (hex) — safe.
        context_hex: Surrounding bytes (hex, bounded) — UNTRUSTED.
    """

    address: str
    context_hex: Untrusted[str]


class SearchBytesOut(_Out):
    """Result of ``search_bytes``.

    Attributes:
        matches: Bounded list of matches.
        total: Total matches found (may exceed returned count) — safe.
        truncated: Whether results were capped.
    """

    matches: list[ByteMatch]
    total: int
    truncated: bool = False


class SearchStringsIn(_Page):
    """Arguments for ``search_strings`` — BOUNDED defined-string search.

    Attributes:
        query: Case-insensitive substring to match (validated; not a regex; bounded).
    """

    query: str = Field(min_length=1, max_length=_MAX_QUERY)


class SearchStringsOut(StringListOut):
    """Result of ``search_strings`` — same shape as ``list_strings`` (bounded string list)."""


# =====================================================================================
# Program metadata
# =====================================================================================
class ProgramMetadataIn(_SessionScopedIn):
    """Arguments for ``program_metadata`` — high-level program facts."""


class ProgramMetadata(_Out):
    """High-level metadata about the analyzed program.

    Server-computed/structural fields are safe; format-reported strings are untrusted.

    Attributes:
        sha256: Server-computed digest of the input — safe.
        size_bytes: Input size — safe.
        format: Detected executable format (e.g. ``"ELF"``, ``"PE"``) — safe (Ghidra-classified).
        architecture: Language/processor id — safe.
        endianness: ``"little"`` / ``"big"`` — safe.
        compiler: Detected compiler spec — untrusted (format-reported).
        entry_point: Entry address (hex) — safe.
        function_count: Number of functions discovered — safe.
        analysis_complete: Whether auto-analysis finished — safe.
    """

    sha256: str
    size_bytes: int
    format: str
    architecture: str
    endianness: str
    compiler: Untrusted[str] | None
    entry_point: str | None
    function_count: int
    analysis_complete: bool
