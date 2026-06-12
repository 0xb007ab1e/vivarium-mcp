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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ghidra_mcp.core.envelope import Untrusted

# --- shared bounds (mirror core.validation; kept literal so schemas are self-contained) ---
_MAX_NAME = 1024
_MAX_QUERY = 4096
_MAX_LIMIT = 10_000
_MAX_READ = 1_048_576  # 1 MiB
_DEFAULT_LIMIT = 100
_MAX_COMMENT = 4096  # max accepted/written comment text length (ADR-012 §6; bounded write payload)

# --- structured type-model bounds (ADR-014 §2.5; construction-time DoS guard — CWE-400) ---
_MAX_PARAMS = 64  # a function with >64 params is pathological; bounds construction + re-flow cost
_MAX_POINTER_DEPTH = 8  # sane ``****…`` cap on a TypeRef's pointer modifiers
_MAX_ARRAY_LEN = 65_536  # bounds an array element-count; the worker confines its byte footprint too


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
        writes_enabled: Whether this session holds write consent (annotation mutation permitted —
            ADR-012 §3). Default-deny: ``False`` until ``session_enable_writes`` is called. Server-
            authoritative, safe.
        allow_structural: Whether the (deferred) structural write set is additionally permitted on
            this session — server-authoritative, safe. Defaults to ``False``.
    """

    session_id: str
    state: str
    created_at: int
    expires_at: int
    binary_sha256: str | None = None
    writes_enabled: bool = False
    allow_structural: bool = False


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
# Call graph / semantic-naming support (v1.1 — ADR-007)
# =====================================================================================
# Bounds for graph-shaped tools (DoS — a hostile binary can present a huge/deep/cyclic call graph;
# threat-model TB4 / std-owasp-llm LLM04). These cap node/edge fan-out and traversal depth BEFORE
# the worker is asked, mirrored in core.validation / security.limits.
_MAX_GRAPH_NODES = 50_000
_MAX_GRAPH_EDGES = 200_000
_MAX_GRAPH_DEPTH = 256
_DEFAULT_GRAPH_DEPTH = 8


class CallGraphIn(_SessionScopedIn):
    """Arguments for ``call_graph`` — extract the (bounded) function call adjacency.

    The worker returns RESOLVED call edges (caller -> callees) plus the ids of functions with
    UNRESOLVED outgoing edges (indirect/virtual/computed calls). Output is bounded by node/edge
    caps; ``truncated`` flags a clipped view (ADR-005 honesty).

    Attributes:
        root: Optional function (entry address hex or name) to scope the graph to its reachable
            sub-graph; omit for the whole program (still node/edge-capped).
        max_depth: Maximum call depth to traverse from ``root`` (ignored when ``root`` is omitted),
            bounded to guard a pathologically deep graph (DoS).
        max_nodes: Hard cap on returned nodes (the worker stops and sets ``truncated``).
        max_edges: Hard cap on returned edges.
    """

    root: str | None = Field(default=None, max_length=_MAX_NAME)
    max_depth: int = Field(default=_DEFAULT_GRAPH_DEPTH, ge=1, le=_MAX_GRAPH_DEPTH)
    max_nodes: int = Field(default=10_000, ge=1, le=_MAX_GRAPH_NODES)
    max_edges: int = Field(default=40_000, ge=1, le=_MAX_GRAPH_EDGES)


class CallEdge(_Out):
    """One resolved call edge (caller -> callee). Addresses are server-safe (normalized).

    Attributes:
        from_address: Caller function entry address (hex) — safe.
        to_address: Callee function entry address (hex) — safe.
    """

    from_address: str
    to_address: str


class CallGraphNode(_Out):
    """One function node in the call graph.

    Attributes:
        address: Function entry address (hex) — safe.
        name: Function name as Ghidra knows it — untrusted (attacker-influenced symbol).
        is_external: Whether the function is an imported/external/thunk function whose name is
            KNOWN (not to be re-inferred) — safe boolean.
        has_unresolved_calls: Whether this node has at least one unresolved (indirect/virtual)
            outgoing call edge not represented in ``edges`` — safe boolean (honesty flag).
    """

    address: str
    name: Untrusted[str]
    is_external: bool
    has_unresolved_calls: bool


class CallGraphOut(_Out):
    """Result of ``call_graph`` — a bounded adjacency view of the program's calls.

    Attributes:
        nodes: Bounded list of function nodes.
        edges: Bounded list of resolved call edges.
        unresolved_callers: Entry addresses (hex) of nodes with unresolved outgoing calls — safe;
            surfaced, never silently dropped (ADR-005, threat-model TB4).
        truncated: Whether a node/edge cap clipped the graph.
    """

    nodes: list[CallGraphNode]
    edges: list[CallEdge]
    unresolved_callers: list[str]
    truncated: bool = False


class CalleesIn(_Page):
    """Arguments for ``callees`` — the functions a given function directly calls (one hop).

    Attributes:
        function: The function (entry address hex or name) to list direct callees of.
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)


class CallersIn(_Page):
    """Arguments for ``callers`` — the functions that directly call a given function (one hop).

    Attributes:
        function: The function (entry address hex or name) to list direct callers of.
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)


class CallNeighborsOut(_Out):
    """Result of ``callees`` / ``callers`` — a bounded list of one-hop neighbor functions.

    Attributes:
        neighbors: Bounded list of neighbor function nodes.
        total: Total neighbors (for pagination) — safe count.
        unresolved: Whether the target has unresolved (indirect/virtual) edges in this direction
            not represented in ``neighbors`` — safe honesty flag (only meaningful for ``callees``).
        truncated: Whether the page was capped.
    """

    neighbors: list[CallGraphNode]
    total: int
    unresolved: bool = False
    truncated: bool = False


class AnalysisOrderIn(CallGraphIn):
    """Arguments for ``analysis_order`` — leaf-first ordering over the (bounded) call graph.

    Same bounds/scoping as ``call_graph``; the server extracts the adjacency (worker) and computes
    the pure leaf-first reverse-topological order over SCCs (server-side core — ADR-007/ADR-001).
    """


class OrderedComponent(_Out):
    """One strongly-connected component in leaf-first analysis order.

    Attributes:
        members: Function entry addresses (hex) in this component — safe. More than one member is a
            mutual-recursion cycle; a single member may still be self-recursive.
        is_recursive: Whether the component represents recursion (a cycle or a self-loop) — safe.
    """

    members: list[str]
    is_recursive: bool


class AnalysisOrderOut(_Out):
    """Result of ``analysis_order`` — the leaf-first plan a client walks to name callees first.

    Attributes:
        components: Strongly-connected components in leaf-first reverse-topological order (sinks
            first, entry roots last) — names assigned to earlier components carry forward.
        unresolved_callers: Entry addresses (hex) with unresolved outgoing calls — safe honesty
            flag (their inferred purpose rests on incomplete call info).
        self_recursive: Entry addresses (hex) with a direct self-loop — safe.
        truncated: Whether the underlying graph was node/edge-capped before ordering.
    """

    components: list[OrderedComponent]
    unresolved_callers: list[str]
    self_recursive: list[str]
    truncated: bool = False


class FunctionContextIn(_SessionScopedIn):
    """Arguments for ``function_context`` — the bundle a client needs to name/synthesize one func.

    Aggregates (server-side) the per-function facts the client LLM uses to infer a semantic name
    and draft recompilable C: decompiled pseudo-C, signature, direct callees/callers, referenced
    strings, and the names already assigned to its callees (passed back by the client as it walks
    leaf-first). Every binary-derived field is untrusted-wrapped; assigned names the client sends
    in are echoed back only as context and are NOT trusted as instructions.

    Attributes:
        function: The function (entry address hex or name) to build context for.
        include_decompilation: Whether to include the decompiled pseudo-C (default True).
        max_callees: Cap on direct callees included.
        max_callers: Cap on direct callers included.
        max_strings: Cap on referenced strings included.
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)
    include_decompilation: bool = Field(default=True)
    max_callees: int = Field(default=64, ge=0, le=1024)
    max_callers: int = Field(default=64, ge=0, le=1024)
    max_strings: int = Field(default=64, ge=0, le=1024)


class FunctionContext(_Out):
    """The per-function context bundle for client-side naming + C synthesis (ADR-007).

    Server-assembled from several read-only tools; the server performs NO naming or C synthesis
    (no server-side LLM — locked decision #1). All binary-derived fields are untrusted-wrapped
    (ADR-005); the client treats them as inert data.

    Attributes:
        address: Function entry address (hex) — safe.
        name: Current Ghidra name — untrusted.
        signature: Recovered signature — untrusted.
        is_external: Whether this is an imported/external/thunk function with a KNOWN name (the
            client should NOT re-infer a name for it) — safe.
        decompilation: The decompiled pseudo-C, or ``None`` when not requested — untrusted
            (GHIDRA origin; prime injection vector — ADR-005).
        callees: Direct callee function nodes (bounded) — for naming bottom-up context.
        callers: Direct caller function nodes (bounded) — for usage context.
        referenced_strings: String literals referenced by this function (bounded) — untrusted
            (BINARY origin), strong semantic signal for naming.
        has_unresolved_calls: Whether the function makes unresolved (indirect/virtual) calls — safe
            honesty flag (the context is incomplete).
        truncated: Whether any bundled list was capped.
    """

    address: str
    name: Untrusted[str]
    signature: Untrusted[str]
    is_external: bool
    decompilation: Untrusted[str] | None = None
    callees: list[CallGraphNode] = Field(default_factory=list)
    callers: list[CallGraphNode] = Field(default_factory=list)
    referenced_strings: list[Untrusted[str]] = Field(default_factory=list)
    has_unresolved_calls: bool = False
    truncated: bool = False


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


# =====================================================================================
# Tier-2 reporting / metrics (v1.1 — ADR-008). READ-ONLY, output-only, bounded; binary-derived
# fields are Untrusted-wrapped. Derivation is pure-core; only raw extraction touches the worker.
# =====================================================================================
class CyclomaticComplexityIn(_SessionScopedIn):
    """Arguments for ``cyclomatic_complexity`` — McCabe complexity of one function.

    Attributes:
        function: The function (entry address hex or name) to measure.
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)


class CyclomaticComplexity(_Out):
    """McCabe cyclomatic complexity for one function (computed in the pure core).

    Attributes:
        address: Function entry address (hex) — safe.
        name: Function name — untrusted.
        complexity: McCabe ``E - N + 2`` (``>= 1``) — safe (server-computed).
        block_count: Basic-block count (CFG nodes) — safe.
        edge_count: Control-flow edge count — safe.
        incomplete: Whether the CFG had unresolved flow (complexity is then a lower bound) — safe.
    """

    address: str
    name: Untrusted[str]
    complexity: int
    block_count: int
    edge_count: int
    incomplete: bool = False


class ListImportsIn(_Page):
    """Arguments for ``list_imports`` — paginated imported symbols/functions."""


class ImportedSymbol(_Out):
    """One imported symbol/function.

    Attributes:
        name: Imported symbol name — untrusted.
        library: Source library/module — untrusted (``None`` if unknown).
        address: Address of the import thunk/pointer (hex) — safe (``None`` if none).
    """

    name: Untrusted[str]
    library: Untrusted[str] | None = None
    address: str | None = None


class ImportListOut(_Out):
    """Result of ``list_imports``.

    Attributes:
        imports: Bounded page of imported symbols.
        total: Total imports (for pagination) — safe.
        truncated: Whether the page was capped.
    """

    imports: list[ImportedSymbol]
    total: int
    truncated: bool = False


class ListExportsIn(_Page):
    """Arguments for ``list_exports`` — paginated exported symbols/entry points."""


class ExportedSymbol(_Out):
    """One exported symbol/entry point.

    Attributes:
        name: Exported symbol name — untrusted.
        address: Export address (hex) — safe.
    """

    name: Untrusted[str]
    address: str


class ExportListOut(_Out):
    """Result of ``list_exports``.

    Attributes:
        exports: Bounded page of exported symbols.
        total: Total exports (for pagination) — safe.
        truncated: Whether the page was capped.
    """

    exports: list[ExportedSymbol]
    total: int
    truncated: bool = False


class CoverageIn(_SessionScopedIn):
    """Arguments for ``coverage`` — defined-code/data byte coverage of the program."""


class CoverageOut(_Out):
    """Code/data coverage of the analyzed program (worker byte counts → pure ratios).

    Measures what Ghidra **defined**, not ground truth (ADR-008 caveat). All fields server-computed.

    Attributes:
        total_bytes: Total addressable bytes in the program's memory.
        defined_code_bytes: Bytes covered by defined instructions.
        defined_data_bytes: Bytes covered by defined data.
        undefined_bytes: Bytes neither defined code nor data.
        code_ratio: ``defined_code_bytes / total_bytes`` (0.0 if total is 0).
        data_ratio: ``defined_data_bytes / total_bytes`` (0.0 if total is 0).
        function_count: Number of functions discovered.
    """

    total_bytes: int
    defined_code_bytes: int
    defined_data_bytes: int
    undefined_bytes: int
    code_ratio: float
    data_ratio: float
    function_count: int


class IocScanIn(_Page):
    """Arguments for ``ioc_scan`` — heuristic IOC scan over defined strings (paginated).

    Attributes:
        categories: Restrict to these IOC categories (e.g. ``["ipv4", "url"]``); omit to scan all.
        min_length: Skip strings shorter than this (noise filter).
    """

    categories: list[str] | None = Field(default=None, max_length=32)
    min_length: int = Field(default=4, ge=1, le=4096)


class IocMatch(_Out):
    """One IOC match — HEURISTIC (a lead, not a verdict; ADR-008).

    Attributes:
        category: IOC category (closed vocabulary, e.g. ``"ipv4"``, ``"url"``) — safe.
        value: The matched substring — UNTRUSTED (attacker-controlled; prime injection vector).
        source_address: Address of the source string (hex) — safe (``None`` if unknown).
    """

    category: str
    value: Untrusted[str]
    source_address: str | None = None


class IocScanOut(_Out):
    """Result of ``ioc_scan``.

    Attributes:
        matches: Bounded page of IOC matches.
        total: Total matches found in the scanned set — safe.
        truncated: Whether the scanned string set or the page was capped.
    """

    matches: list[IocMatch]
    total: int
    truncated: bool = False


class CryptoConstantScanIn(_Page):
    """Arguments for ``crypto_constant_scan`` — heuristic search for known crypto constants."""


class CryptoConstantFinding(_Out):
    """One crypto-constant match — HEURISTIC (a lead, not proof; ADR-008).

    Attributes:
        algorithm: Algorithm label (closed vocabulary, e.g. ``"AES"``, ``"SHA-256"``) — safe.
        kind: Constant kind (``"sbox"`` / ``"iv"`` / ``"magic"`` / ``"table"``) — safe.
        address: Address where the constant was found (hex) — safe.
    """

    algorithm: str
    kind: str
    address: str


class CryptoConstantScanOut(_Out):
    """Result of ``crypto_constant_scan``.

    Attributes:
        findings: Bounded list of crypto-constant matches.
        total: Total matches — safe.
        truncated: Whether the signature set or matches were capped.
    """

    findings: list[CryptoConstantFinding]
    total: int
    truncated: bool = False


class CallGraphMetricsIn(CallGraphIn):
    """Arguments for ``call_graph_metrics`` — structural metrics over the (bounded) call graph.

    Same scoping/bounds as ``call_graph`` (``root``/``max_depth``/``max_nodes``/``max_edges``).

    Attributes:
        top_n: How many hotspots to return in ``top_fan_in`` / ``top_fan_out``.
    """

    top_n: int = Field(default=10, ge=0, le=1024)


class FanRanking(_Out):
    """One function ranked by fan-in or fan-out degree.

    Attributes:
        address: Function entry address (hex) — safe.
        name: Function name — untrusted.
        count: Degree (distinct callers for fan-in, distinct callees for fan-out) — safe.
    """

    address: str
    name: Untrusted[str]
    count: int


class CallGraphMetricsOut(_Out):
    """Result of ``call_graph_metrics`` — structural metrics over the call graph (pure core).

    Attributes:
        function_count: Distinct function nodes — safe.
        edge_count: Distinct resolved call edges — safe.
        leaf_count: Functions that call nothing further (fan-out 0) — safe.
        root_count: Functions nothing calls (fan-in 0) — safe.
        recursive_component_count: Recursion cycles (multi-member or self-loop) — safe.
        self_recursive_count: Directly self-recursive functions — safe.
        unresolved_caller_count: Functions with unresolved outgoing calls — safe.
        top_fan_in: Most-called functions, ranked (names untrusted).
        top_fan_out: Functions calling the most others, ranked (names untrusted).
        truncated: Whether the underlying graph was node/edge-capped.
    """

    function_count: int
    edge_count: int
    leaf_count: int
    root_count: int
    recursive_component_count: int
    self_recursive_count: int
    unresolved_caller_count: int
    top_fan_in: list[FanRanking]
    top_fan_out: list[FanRanking]
    truncated: bool = False


class ProgramSummaryIn(_SessionScopedIn):
    """Arguments for ``program_summary`` — one-shot aggregate triage report.

    Attributes:
        max_complex_functions: Cap on the top-by-complexity functions included.
        max_iocs: Cap on IOC matches scanned/summarized.
        include_call_graph: Include call-graph metrics (costlier — whole-program graph).
    """

    max_complex_functions: int = Field(default=10, ge=0, le=1024)
    max_iocs: int = Field(default=256, ge=0, le=_MAX_LIMIT)
    include_call_graph: bool = Field(default=True)


class IocCategoryCount(_Out):
    """IOC match count for one category (safe — count + closed-vocabulary label).

    Attributes:
        category: IOC category — safe.
        count: Number of matches in that category — safe.
    """

    category: str
    count: int


class ProgramSummary(_Out):
    """One-shot aggregate triage report — server-side aggregation, no naming/synthesis (ADR-008).

    Attributes:
        metadata: High-level program metadata.
        function_count: Total functions — safe.
        import_count: Total imports — safe.
        export_count: Total exports — safe.
        string_count: Total defined strings — safe.
        coverage: Code/data coverage (``None`` if unavailable).
        call_graph_metrics: Structural call-graph metrics (``None`` if not requested).
        top_complex_functions: Highest-complexity functions (bounded).
        ioc_counts: IOC match counts per category over the bounded scan — safe.
        crypto_algorithms: Distinct crypto algorithms detected (closed-vocabulary labels) — safe.
        truncated: Whether any bounded sub-result was capped.
    """

    metadata: ProgramMetadata
    function_count: int
    import_count: int
    export_count: int
    string_count: int
    coverage: CoverageOut | None = None
    call_graph_metrics: CallGraphMetricsOut | None = None
    top_complex_functions: list[CyclomaticComplexity] = Field(default_factory=list)
    ioc_counts: list[IocCategoryCount] = Field(default_factory=list)
    crypto_algorithms: list[str] = Field(default_factory=list)
    truncated: bool = False


# =====================================================================================
# Mutation (write) tools — first gated increment (ADR-012; TB7). ANNOTATION-ONLY.
#
# Asymmetry vs. read tools (ADR-012 §6): the ``new_name``/``text`` the client supplies is
# attacker-INFLUENCED (an injection-steered client may propose a malicious value), so it is
# validated server-side as untrusted input (``validate_write_name``/``validate_comment_text``)
# BEFORE the worker writes it — and the value we *set* is therefore bare/SAFE in the result. The
# prior Ghidra name we *echo* (``old_name``) is binary-derived → ``Untrusted[...]`` (ADR-005).
# ``applied``/``address``/``kind``/``comment_type`` are server- or closed-vocabulary — bare.
# Every write is default-denied unless the session holds write consent (``session_enable_writes``).
# =====================================================================================
class RenameFunctionIn(_SessionScopedIn):
    """Arguments for ``rename_function`` — set a function's name (write; gated by session consent).

    Attributes:
        function: The existing function to rename, by entry address (hex) or current name.
            Resolved by the worker; validated as a name argument server-side.
        new_name: The new name to set. Attacker-influenced input — validated against the
            conservative write-name allow-list (``validate_write_name``) before the worker writes
            it (stored-injection / data-poisoning defense — ADR-012 §7).
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)


class RenameResult(_Out):
    """Result of a rename write (ADR-012 §6).

    Attributes:
        address: Server-normalized entry/symbol address (hex) — safe.
        old_name: The PRIOR Ghidra name before the write — binary-derived → untrusted (ADR-005).
        new_name: The name we set — SAFE (server-validated before the write).
        applied: Whether the write committed — server/worker-controlled, safe.
    """

    address: str
    old_name: Untrusted[str]
    new_name: str
    applied: bool


class RenameSymbolIn(_SessionScopedIn):
    """Arguments for ``rename_symbol`` — set a data/label/global symbol's name (write).

    Attributes:
        identifier: The existing symbol to rename, by address (hex) or current name. Resolved by
            the worker; validated as a name argument server-side.
        new_name: The new name to set — validated against the write-name allow-list before write.
    """

    identifier: str = Field(min_length=1, max_length=_MAX_NAME)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)


class RenameSymbolResult(RenameResult):
    """Result of ``rename_symbol`` (adds the resolved symbol kind).

    Attributes:
        kind: Symbol kind (e.g. ``"FUNCTION"``, ``"LABEL"``) — closed-vocabulary, safe.
    """

    kind: str


class SetCommentIn(_SessionScopedIn):
    """Arguments for ``set_comment`` — set or clear one comment at an address (write).

    Attributes:
        address: The address (hex) the comment attaches to — validated via ``parse_address``.
        comment_type: Which comment slot to write — a closed allow-list (no free-form type).
        text: The comment text to set; ``None`` CLEARS the comment. Attacker-influenced input —
            bounded by ``_MAX_COMMENT`` and normalized/annotated on the way in
            (``validate_comment_text``) so the stored value is conservative (ADR-012 §7).
    """

    address: str = Field(min_length=1, max_length=_MAX_NAME)
    comment_type: Literal["EOL", "PRE", "POST", "PLATE", "REPEATABLE"]
    text: str | None = Field(default=None, max_length=_MAX_COMMENT)


class SetCommentResult(_Out):
    """Result of ``set_comment`` (ADR-012 §6).

    Attributes:
        address: Server-normalized address (hex) — safe.
        comment_type: The comment slot written — closed-vocabulary, safe.
        applied: Whether the write committed — safe.
    """

    address: str
    comment_type: str
    applied: bool


# --- server-side write-lifecycle (no worker RPC), mirroring SessionCloseIn/Out (ADR-012 §3) ---
class SessionEnableWritesIn(_SessionScopedIn):
    """Grant this session WRITE CONSENT — the human-in-the-loop gate for mutation (LLM08).

    Default-deny: a session is read-only until this is called. The grant is auditable, revocable
    (``session_disable_writes`` / implicit on evict), per-session, and non-transferable.

    Attributes:
        allow_structural: Forward hook to additionally opt into the (deferred) structural write set
            (locals/signatures/types). Defaults to ``False``; the annotation set does not require
            it. Defined now so the consent shape is forward-compatible (ADR-012 §3).
    """

    allow_structural: bool = Field(default=False)


class SessionWriteStateOut(_Out):
    """Reports a session's write-consent state (ADR-012 §6).

    Attributes:
        session_id: The session's opaque id — safe.
        writes_enabled: Whether annotation writes are permitted on this session — safe.
        allow_structural: Whether the (deferred) structural write set is additionally permitted —
            safe.
    """

    session_id: str
    writes_enabled: bool
    allow_structural: bool


class SessionDisableWritesIn(_SessionScopedIn):
    """Revoke write consent for this session (return it to read-only)."""


class SessionUndoIn(_SessionScopedIn):
    """Undo the last committed mutation transaction in this session (optional convenience)."""


class SessionUndoOut(_Out):
    """Result of ``session_undo`` (ADR-012 §4).

    Attributes:
        session_id: The session's opaque id — safe.
        undone: Whether a transaction was undone (``False`` if there was nothing to undo) — safe.
    """

    session_id: str
    undone: bool


# --- structural writes (v1.1 — ADR-013 Phase A; GATED by allow_structural; name-only) ---
class RenameLocalVariableIn(_SessionScopedIn):
    """Arguments for ``rename_local_variable`` — set a function-local's name (structural write).

    Gated by ``session_enable_writes{allow_structural: true}`` + ``require_write_consent(
    structural=True)``. **Name-only** (the worker passes a null data type — no type change in this
    increment, ADR-013 §1).

    Attributes:
        function: The owning function, by entry address (hex) or current name (resolved by worker).
        variable: The target local's stable identifier (the decompiler-assigned name, e.g.
            ``local_28``, as surfaced by ``function_context``) — a selector, not a persisted value.
        new_name: The new name to set — validated against the write-name allow-list before write.
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)
    variable: str = Field(min_length=1, max_length=_MAX_NAME)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)


class RenameParameterIn(_SessionScopedIn):
    """Arguments for ``rename_parameter`` — set a function parameter's name (structural write).

    Attributes:
        function: The owning function (address hex or current name).
        parameter: The target parameter's stable identifier (name as surfaced by
            ``function_context``) — a selector, not a persisted value.
        new_name: The new name to set — validated against the write-name allow-list before write.
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)
    parameter: str = Field(min_length=1, max_length=_MAX_NAME)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)


class StructuralRenameResult(_Out):
    """Result of a structural local/parameter rename (ADR-013 §6).

    Attributes:
        address: The owning function's entry address (hex) — server-normalized, safe.
        function: The function's current name — binary-derived → untrusted (ADR-005).
        old_name: The PRIOR decompiler name of the local/param — binary-derived → untrusted.
        new_name: The name we set — SAFE (server-validated before the write).
        applied: Whether the write committed — server/worker-controlled, safe.
    """

    address: str
    function: Untrusted[str]
    old_name: Untrusted[str]
    new_name: str
    applied: bool


# --- structural type-aware writes (v1.1 — ADR-014 Phase B; GATED by allow_structural) ----------
#
# The signature/type input is STRUCTURED, never free-form C (ADR-014 §2): a `TypeRef` names a base
# type (closed vocabulary) or an existing `named` type (looked up — never parsed) plus bounded
# pointer/array modifiers; a `ParamSpec` is a bounded (name, type) pair; the calling convention is a
# closed allow-list. The worker assembles every Ghidra type object from already-resolved `DataType`
# handles — `CParser`/`DataTypeParser` are NEVER instantiated on a client value. An unresolvable /
# out-of-vocab / out-of-bounds `TypeRef` fails closed (VALIDATION at the boundary; not-found at the
# worker for an unknown `named`). Asymmetry (ADR-005/ADR-012 §6): values WE set / closed-vocab are
# SAFE; echoed binary-derived fields (`function`/`old_signature`/`new_signature`/`type_name`) are
# `Untrusted` — note `new_signature` is untrusted because Ghidra RE-RENDERS our applied prototype.

# Closed base-type vocabulary mapped to Ghidra built-ins in the worker (NOT client-extensible —
# ADR-014 §2.5). Admits no free text; a value outside this Literal is rejected by pydantic.
BaseType = Literal[
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
]


class TypeRef(_In):
    """A structured reference to a data type — resolved against the program's DataTypeManager.

    Exactly one of ``base``/``named`` identifies the leaf type; the modifiers are bounded. NO C
    string is parsed — the worker assembles a ``DataType`` from already-resolved handles (ADR-014
    §2.1). A ``named`` reference must already EXIST in the program (validated at the worker; an
    unknown name → ``not-found``); ``base`` is mapped to a Ghidra built-in.

    Attributes:
        base: One of the closed :data:`BaseType` vocabulary, or ``None``. Mutually exclusive with
            ``named`` (exactly one must be set — model-validated).
        named: The name of a type already present in the program's ``DataTypeManager`` — looked up,
            never parsed. Mutually exclusive with ``base``.
        pointer_levels: Number of ``*`` modifiers to wrap the leaf in (``0..=_MAX_POINTER_DEPTH``).
        array_len: Fixed array length (``1..=_MAX_ARRAY_LEN``), or ``None`` for a non-array.
    """

    base: BaseType | None = None
    named: str | None = Field(default=None, min_length=1, max_length=_MAX_NAME)
    pointer_levels: int = Field(default=0, ge=0, le=_MAX_POINTER_DEPTH)
    array_len: int | None = Field(default=None, ge=1, le=_MAX_ARRAY_LEN)

    @model_validator(mode="after")
    def _exactly_one_leaf(self) -> TypeRef:
        """Enforce that exactly one of ``base``/``named`` identifies the leaf type (ADR-014 §2.1).

        Returns:
            ``self`` when the shape is valid.

        Raises:
            ValueError: When neither or both of ``base``/``named`` are set (the server boundary maps
                a pydantic ``ValidationError`` to a ``VALIDATION`` envelope — fail closed).
        """
        if (self.base is None) == (self.named is None):
            raise ValueError("exactly one of `base` or `named` must be set")
        return self


class ParamSpec(_In):
    """One parameter of a structured signature (ADR-014 §2.2).

    Attributes:
        name: The parameter name — PERSISTED into the program DB, so it is held to the strict
            write-name identifier allow-list (``validate_write_name``) server-side before the write.
        type: The parameter's type as a resolved :class:`TypeRef`.
    """

    name: str = Field(min_length=1, max_length=_MAX_NAME)
    type: TypeRef


class SetFunctionSignatureIn(_SessionScopedIn):
    """Arguments for ``set_function_signature`` — a structured signature (NO C string — ADR-014 §2).

    Gated by ``session_enable_writes{allow_structural: true}`` + ``require_write_consent(
    structural=True)``. The worker resolves ``return_type`` and each parameter ``type`` against the
    program's ``DataTypeManager`` BEFORE the transaction (resolution is read-only — ADR-014 §4); an
    unresolvable type is a clean ``not-found`` with no transaction opened.

    Attributes:
        function: The existing function to retype, by entry address (hex) or current name.
        return_type: The function's return type as a resolved :class:`TypeRef`.
        parameters: The ordered parameter list — bounded to ``_MAX_PARAMS`` (DoS guard, CWE-400).
        calling_convention: A closed-allow-list convention name (program-derived + static fallback),
            or ``None`` to leave the convention unchanged. Never a free-form string.
    """

    function: str = Field(min_length=1, max_length=_MAX_NAME)
    return_type: TypeRef
    parameters: list[ParamSpec] = Field(default_factory=list, max_length=_MAX_PARAMS)
    calling_convention: str | None = Field(default=None, max_length=_MAX_NAME)


class SetFunctionSignatureResult(_Out):
    """Result of ``set_function_signature`` (ADR-014 §5).

    Attributes:
        address: The function's entry address (hex) — server-normalized, safe.
        function: The function's current name — binary-derived → untrusted (ADR-005).
        old_signature: The PRIOR prototype string — binary-derived → untrusted.
        new_signature: The re-rendered applied prototype — binary-derived → untrusted (Ghidra
            RE-RENDERS our input, which can normalize/expand it).
        applied: Whether the write committed — server/worker-controlled, safe.
    """

    address: str
    function: Untrusted[str]
    old_signature: Untrusted[str]
    new_signature: Untrusted[str]
    applied: bool


class ApplyDataTypeIn(_SessionScopedIn):
    """Arguments for ``apply_data_type`` — lay a RESOLVABLE type at an address (ADR-014 §2.4).

    Gated by ``session_enable_writes{allow_structural: true}`` + ``require_write_consent(
    structural=True)``. The worker resolves ``type`` (read-only) and confines ``address`` to the
    program memory map BEFORE the transaction; an unresolvable type → ``not-found``, an out-of-map
    address or an over-running footprint → fail closed (no write).

    Attributes:
        address: The address (hex) to apply the type at — validated via ``parse_address`` + worker
            map-confinement.
        type: The type to apply as a resolved :class:`TypeRef` (existing/base/derived) — never
            parsed.
        clear_existing: Whether to clear conflicting defined data first (default ``False``).
    """

    address: str = Field(min_length=1, max_length=_MAX_NAME)
    type: TypeRef
    clear_existing: bool = Field(default=False)


class ApplyDataTypeResult(_Out):
    """Result of ``apply_data_type`` (ADR-014 §5).

    Attributes:
        address: Server-normalized address (hex) — safe.
        type_name: The resolved type's name — binary-derived → untrusted (ADR-005).
        size: The applied size in bytes — worker-computed scalar, safe.
        applied: Whether the write committed — safe.
    """

    address: str
    type_name: Untrusted[str]
    size: int
    applied: bool
