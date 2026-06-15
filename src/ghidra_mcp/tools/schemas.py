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


# --- composite-type creation (v1.1 — ADR-015 Phase C; GATED by allow_structural) ---------------
#
# Reuses the merged Phase-B TypeRef (above) — a FieldSpec.type is a flat TypeRef (NO nested define —
# ADR-015 §1). NO free-form C: the worker assembles StructureDataType/UnionDataType from already-
# resolved DataType handles via the existing _gh_resolve_type_ref. The asymmetry (ADR-005/ADR-012
# §6) is unusual for a write: EVERY result field is SAFE — name/kind/size/field_count/applied are
# all server- or worker-controlled (the name is the one WE set + validated; size a worker scalar);
# there is NO echoed binary-derived field (we do not return a Ghidra-rendered declaration). A future
# field echoing Ghidra's rendered layout MUST be Untrusted[...] (ADR-015 §7).
_MAX_FIELDS = 256  # a composite with >256 members is pathological (CWE-400)
_MAX_COMPOSITE_SIZE = 1_048_576  # 1 MiB cap on the assembled composite's total computed size


class FieldSpec(_In):
    """One member of a new composite type (ADR-015 §2.1).

    ``name`` is PERSISTED into the program DB and re-served by the read tools, so it is held to the
    strict ``validate_write_name`` identifier allow-list server-side (stored-injection defense —
    identical profile to a Phase-B ``ParamSpec.name``). ``type`` is the EXISTING Phase-B
    :class:`TypeRef` (resolved by ``_gh_resolve_type_ref``, never parsed). ``offset`` is struct-only
    (a union overlays all members at offset 0 — the union schema model-validates it is ``None``).

    Attributes:
        name: The member name — validated as a persisted write-name server-side.
        type: The member's type as a resolved :class:`TypeRef`.
        offset: Struct only — an explicit byte offset (``0..=_MAX_COMPOSITE_SIZE - 1``), or ``None``
            to append the member sequentially. Meaningless (and rejected) for a union.
    """

    name: str = Field(min_length=1, max_length=_MAX_NAME)
    type: TypeRef
    offset: int | None = Field(default=None, ge=0, lt=_MAX_COMPOSITE_SIZE)


def _reject_self_embed(name: str, fields: list[FieldSpec]) -> None:
    """Reject a by-value embed of the composite's own ``name`` (the recursion crux — ADR-015 §3.2).

    Because the empty composite is pre-registered in the ``DataTypeManager`` at the start of the
    transaction (so a self-``named`` *pointer* resolves and true self-referential types work), a
    by-value self-embed (``named == name`` with NO pointer and NO array) would also resolve into an
    infinite-size type — so it must be ACTIVELY rejected at the boundary, not left to fail
    ``not-found`` (ADR-015 §3). A pointer-to-self (``pointer_levels >= 1``) is fixed-size and
    ALLOWED; an array-of-self is a by-value embed and is rejected.

    Args:
        name: The composite's own type name.
        fields: The member list to scan.

    Raises:
        ValueError: When a member embeds the composite by value (the server boundary maps the
            pydantic ``ValidationError`` to a ``VALIDATION`` envelope — fail closed). The pure
            :func:`ghidra_mcp.core.validation.validate_composite` re-asserts this defensively too.
    """
    for field in fields:
        if field.type.named == name and field.type.pointer_levels == 0:
            raise ValueError("a composite member may not embed the composite by value")


class DefineStructIn(_SessionScopedIn):
    """Arguments for ``define_struct`` — create a NEW struct from a field list (ADR-015 §2.2).

    Gated by ``session_enable_writes{allow_structural: true}`` + ``require_write_consent(
    structural=True)``. The empty struct is pre-registered in the ``DataTypeManager`` at the start
    of the one transaction, fields are resolved + added (size-checked), then the type is finalized —
    ANY failure rolls back and removes the pre-registered type (no partial/orphan — ADR-015 §3). A
    name collision is a fail-closed REJECT (no silent replace — §6). NO free-form C is parsed.

    Attributes:
        name: The new type's name — validated as a persisted write-name; collision-checked at the
            worker before assembly (fail-closed REJECT).
        fields: The ordered member list — non-empty, bounded by ``_MAX_FIELDS`` (DoS — CWE-400); no
            duplicate member names; no by-value self-embed.
        packed: ``True`` packs the struct (no alignment padding); ``False`` uses default alignment.
    """

    name: str = Field(min_length=1, max_length=_MAX_NAME)
    fields: list[FieldSpec] = Field(min_length=1, max_length=_MAX_FIELDS)
    packed: bool = Field(default=False)

    @model_validator(mode="after")
    def _no_self_embed(self) -> DefineStructIn:
        """Reject a by-value embed of this struct's own name (ADR-015 §3.2).

        Returns:
            ``self`` when no member embeds the struct by value.

        Raises:
            ValueError: When a member embeds the struct by value (mapped to ``VALIDATION``).
        """
        _reject_self_embed(self.name, self.fields)
        return self


class DefineStructResult(_Out):
    """Result of ``define_struct`` (ADR-015 §7) — all fields server/worker-controlled, SAFE.

    Attributes:
        name: The struct's name — the one WE set + server-validated — SAFE.
        kind: Always ``"struct"`` — SAFE.
        size: The assembled total size in bytes — worker-computed scalar, SAFE.
        field_count: Number of members added — SAFE.
        applied: Whether the type was created — server/worker-controlled, SAFE.
    """

    name: str
    kind: str
    size: int
    field_count: int
    applied: bool


class DefineUnionIn(_SessionScopedIn):
    """Arguments for ``define_union`` — create a NEW union from a field list (ADR-015 §2.2).

    Same gate + recursion model + name-collision REJECT as :class:`DefineStructIn`. A union overlays
    all members at offset 0, so ``offset``/``packed`` are N/A — each member's ``offset`` MUST be
    ``None`` (model-validated). NO free-form C is parsed.

    Attributes:
        name: The new type's name — validated as a persisted write-name; collision-checked.
        fields: The member list — non-empty, bounded by ``_MAX_FIELDS``; no duplicate names; no
            by-value self-embed; each member's ``offset`` MUST be ``None``.
    """

    name: str = Field(min_length=1, max_length=_MAX_NAME)
    fields: list[FieldSpec] = Field(min_length=1, max_length=_MAX_FIELDS)

    @model_validator(mode="after")
    def _no_self_embed_no_offset(self) -> DefineUnionIn:
        """Reject a by-value self-embed and any per-member ``offset`` (ADR-015 §3.2/§2.2).

        Returns:
            ``self`` when the union shape is valid.

        Raises:
            ValueError: When a member embeds the union by value or carries a non-``None`` ``offset``
                (a struct-only field — mapped to ``VALIDATION`` at the server boundary).
        """
        _reject_self_embed(self.name, self.fields)
        for field in self.fields:
            if field.offset is not None:
                raise ValueError("a union member may not carry an offset")
        return self


class DefineUnionResult(_Out):
    """Result of ``define_union`` (ADR-015 §7) — all fields SAFE (no binary-derived echo).

    Attributes:
        name: The union's name — the one WE set + server-validated — SAFE.
        kind: Always ``"union"`` — SAFE.
        size: The assembled size in bytes (max member size) — worker scalar, SAFE.
        field_count: Number of members added — SAFE.
        applied: Whether the type was created — SAFE.
    """

    name: str
    kind: str
    size: int
    field_count: int
    applied: bool


# --- multi-type composite batch (v1.2 — ADR-021; GATED by allow_structural) ---------------------
#
# Generalizes the ADR-015 single-composite model to a BATCH of interdependent NEW composites created
# in ONE transaction: a field of one batch member may reference ANOTHER batch member (existing/base/
# self too). The worker pre-registers ALL empty composites in the batch before resolving any field,
# so an in-batch ``named`` ref (pointer OR by-value) resolves. The load-bearing NEW control is the
# pure BY-VALUE CYCLE DETECTOR (core.validation.validate_types_batch): because every batch type is
# pre-registered, a by-value cycle (A embeds B embeds A, or self) WOULD otherwise resolve into an
# infinite-size type — it must be rejected at the boundary. Pointer members create NO edge (fixed
# size), so mutually-recursive POINTER structs are allowed. NO free-form C (ADR-014). Every result
# field is SAFE — server/worker scalars, no binary-derived echo (ADR-015 §7).
_MAX_TYPES_PER_BATCH = 64  # a batch of >64 interdependent types is pathological (CWE-400)


class CompositeSpec(_In):
    """One composite entry in a :class:`DefineTypesIn` batch (ADR-021 §D1).

    A kind-discriminated struct/union entry. A ``struct`` honors per-member ``offset`` and
    ``packed`` (sequential/explicit-offset layout); a ``union`` overlays all members at offset 0 and
    so ignores ``packed`` and REQUIRES every member ``offset`` to be ``None`` (model-validated).
    Reuses the ADR-015 recursion model: a by-value self-embed (``named == name`` with
    ``pointer_levels == 0``, incl. an array-of-self) is rejected at construction; a pointer-to-self
    is fixed-size and allowed. A field's ``type.named`` may reference an existing program type, a
    base type, **self**, OR another composite defined in the SAME batch — the batch-level
    :func:`validate_types_batch` runs the by-value cycle detector over those in-batch edges.

    Attributes:
        kind: ``"struct"`` or ``"union"`` — selects the per-entry assembly path (a meaningful
            discriminator for a list input — ADR-021 §D1; it does NOT reopen ADR-015's single-tool
            split).
        name: The new type's name — validated as a persisted write-name; collision-checked at the
            worker before assembly (fail-closed REJECT).
        fields: The ordered member list — non-empty, bounded by ``_MAX_FIELDS``; no duplicate member
            names; no by-value self-embed (validated end-to-end at the boundary).
        packed: Struct only — ``True`` packs (no alignment padding). Ignored for a union.
    """

    kind: Literal["struct", "union"]
    name: str = Field(min_length=1, max_length=_MAX_NAME)
    fields: list[FieldSpec] = Field(min_length=1, max_length=_MAX_FIELDS)
    packed: bool = Field(default=False)

    @model_validator(mode="after")
    def _no_self_embed_and_union_shape(self) -> CompositeSpec:
        """Reject a by-value self-embed and (for a union) any per-member ``offset`` (ADR-015 §3.2).

        Returns:
            ``self`` when the entry shape is valid for its ``kind``.

        Raises:
            ValueError: When a member embeds the composite by value, or a union member carries a
                non-``None`` ``offset`` (a struct-only field — mapped to ``VALIDATION`` at the
                server boundary).
        """
        _reject_self_embed(self.name, self.fields)
        if self.kind == "union":
            for field in self.fields:
                if field.offset is not None:
                    raise ValueError("a union member may not carry an offset")
        return self


class DefineTypesIn(_SessionScopedIn):
    """Arguments for ``define_types`` — create a BATCH of interdependent composites (ADR-021 §D1).

    Gated by ``session_enable_writes{allow_structural: true}`` + ``require_write_consent(
    structural=True)``. The worker pre-registers EVERY empty composite in the batch (so any in-batch
    ``named`` ref resolves), resolves + adds each type's members, enforces a batch-total size cap,
    and commits — all inside ONE transaction; ANY failure rolls back the WHOLE batch (no partial
    type, no orphan). A name collision (with an existing program type OR a duplicate name within the
    batch) is a fail-closed REJECT. The boundary runs the by-value cycle detector
    (:func:`validate_types_batch`) before the worker. NO free-form C is parsed.

    Attributes:
        types: The batch of composites — non-empty, bounded by ``_MAX_TYPES_PER_BATCH`` (DoS —
            CWE-400). Mixed struct + union is allowed; a member's ``type.named`` may reference
            another batch member (a by-value cycle is rejected; a pointer cycle is allowed).
    """

    types: list[CompositeSpec] = Field(min_length=1, max_length=_MAX_TYPES_PER_BATCH)


class DefinedType(_Out):
    """One created composite's summary in a :class:`DefineTypesResult` (ADR-021 §D1) — all SAFE.

    Attributes:
        name: The type's name — the one WE set + server-validated — SAFE.
        kind: ``"struct"`` or ``"union"`` — SAFE.
        size: The assembled total size in bytes — worker-computed scalar, SAFE.
        field_count: Number of members added — SAFE.
    """

    name: str
    kind: str
    size: int
    field_count: int


class DefineTypesResult(_Out):
    """Result of ``define_types`` (ADR-021 §D1) — all fields server/worker-controlled, SAFE.

    There is NO binary-derived echo (a future field echoing Ghidra's rendered layout MUST be
    ``Untrusted`` — ADR-015 §7). The batch is one transaction, so ``applied`` reflects the whole
    batch (it is ``True`` only when every type was created and the transaction committed).

    Attributes:
        types: Per-type summaries in declaration order — every field SAFE.
        applied: Whether the batch committed — server/worker-controlled, SAFE.
    """

    types: list[DefinedType]
    applied: bool


# =====================================================================================
# Cross-session annotation persistence (v1.2 — ADR-018; TB8). EXPORT + IMPORT round-trip.
#
# A versioned, binary-hash-bound, structured (INERT) document of a session's USER_DEFINED
# annotations. Export reads it out (read-only, owner-scoped, untrusted-wrapped strings). Import
# REPLAYS each entry through the EXISTING gated write handlers/validators (ADR-018 D3) — it adds NO
# new write primitive. The document is FULLY UNTRUSTED (it may be tampered offline): import schema-
# validates it, verifies the binary-hash binding, gates on write consent (+ allow_structural for
# structural entries), re-validates EVERY entry via the live validators, and replays each in its own
# Ghidra transaction. The server persists nothing (stateless — ADR-002 preserved).
# =====================================================================================
#: Supported annotation-document schema version. An unknown version fails closed (forward-compat is
#: opt-in, never silent) — :func:`ghidra_mcp.core.validation.validate_annotation_document`.
ANNOTATION_SCHEMA_VERSION = 1

#: Hard cap on entries in one imported/exported document (DoS — CWE-400; mirrored in
#: ``core.validation``). A document over this is ``limit-exceeded`` (never a silent truncation).
_MAX_ENTRIES = 50_000


class AnnotationBinaryRef(_In):
    """Applicability binding for an annotation document — identifies the source program (ADR-018).

    The ``sha256`` is the load-bearing field: import verifies it equals the target session's program
    hash, so a document minted for a different/forged binary is rejected (TB8-S). ``name``/``size``
    are advisory provenance only (never trusted for application). It is an ``_In``
    (``extra=forbid``, frozen) — it is part of the fully-untrusted imported document.

    Attributes:
        sha256: Hex SHA-256 of the program the annotations were exported from — the binding key.
        name: Optional advisory original name/label (untrusted; not used for application).
        size: Optional advisory original byte size (untrusted; not used for application).
    """

    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    name: str | None = Field(default=None, max_length=_MAX_NAME)
    size: int | None = Field(default=None, ge=0)


# --- typed, discriminated Entry variants (one per existing write tool; ADR-018 D3) -------------
# Each variant carries the SAME payload fields as the write tool it replays (selector/target +
# value) PLUS a closed ``kind`` discriminator. On EXPORT the binary-derived value fields (a prior
# name we read out, a comment text, a recovered signature) are untrusted-wrapped (ADR-005). On
# IMPORT each variant is re-validated through the matching live validator and replayed via the
# existing handler — the document supplies only PROPOSED writes, never trusted claims.
class _Entry(_In):
    """Base for an annotation entry: immutable, reject unknown fields (fully-untrusted document)."""


class RenameFunctionEntry(_Entry):
    """A ``rename_function`` replay entry (mirrors :class:`RenameFunctionIn`).

    Attributes:
        kind: Discriminator — always ``"rename_function"``.
        function: The target function selector (entry address hex or current name).
        new_name: The name to set — re-validated via ``validate_write_name`` on import.
    """

    kind: Literal["rename_function"]
    function: str = Field(min_length=1, max_length=_MAX_NAME)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)


class RenameSymbolEntry(_Entry):
    """A ``rename_symbol`` replay entry (mirrors :class:`RenameSymbolIn`).

    Attributes:
        kind: Discriminator — always ``"rename_symbol"``.
        identifier: The target symbol selector (address hex or current name).
        new_name: The name to set — re-validated via ``validate_write_name`` on import.
    """

    kind: Literal["rename_symbol"]
    identifier: str = Field(min_length=1, max_length=_MAX_NAME)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)


class RenameLocalVariableEntry(_Entry):
    """A ``rename_local_variable`` replay entry (mirrors :class:`RenameLocalVariableIn`).

    Attributes:
        kind: Discriminator — always ``"rename_local_variable"``.
        function: The owning function selector.
        variable: The local's stable selector (decompiler-assigned name).
        new_name: The name to set — re-validated via ``validate_write_name`` on import.
    """

    kind: Literal["rename_local_variable"]
    function: str = Field(min_length=1, max_length=_MAX_NAME)
    variable: str = Field(min_length=1, max_length=_MAX_NAME)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)


class RenameParameterEntry(_Entry):
    """A ``rename_parameter`` replay entry (mirrors :class:`RenameParameterIn`).

    Attributes:
        kind: Discriminator — always ``"rename_parameter"``.
        function: The owning function selector.
        parameter: The parameter's stable selector.
        new_name: The name to set — re-validated via ``validate_write_name`` on import.
    """

    kind: Literal["rename_parameter"]
    function: str = Field(min_length=1, max_length=_MAX_NAME)
    parameter: str = Field(min_length=1, max_length=_MAX_NAME)
    new_name: str = Field(min_length=1, max_length=_MAX_NAME)


class SetCommentEntry(_Entry):
    """A ``set_comment`` replay entry (mirrors :class:`SetCommentIn`).

    Attributes:
        kind: Discriminator — always ``"set_comment"``.
        address: The address (hex) the comment attaches to.
        comment_type: The closed comment slot.
        text: The comment text to set; ``None`` clears it. Re-normalized via
            ``validate_comment_text`` on import.
    """

    kind: Literal["set_comment"]
    address: str = Field(min_length=1, max_length=_MAX_NAME)
    comment_type: Literal["EOL", "PRE", "POST", "PLATE", "REPEATABLE"]
    text: str | None = Field(default=None, max_length=_MAX_COMMENT)


class SetFunctionSignatureEntry(_Entry):
    """A ``set_function_signature`` replay entry (mirrors :class:`SetFunctionSignatureIn`).

    Structural entry (requires ``allow_structural`` on import). Re-validated via
    ``validate_signature`` (bounded params + resolved TypeRefs + closed-vocab cc).

    Attributes:
        kind: Discriminator — always ``"set_function_signature"``.
        function: The target function selector.
        return_type: The return type as a resolved :class:`TypeRef`.
        parameters: The ordered parameter list — bounded by ``_MAX_PARAMS``.
        calling_convention: A closed-allow-list convention, or ``None`` to leave unchanged.
    """

    kind: Literal["set_function_signature"]
    function: str = Field(min_length=1, max_length=_MAX_NAME)
    return_type: TypeRef
    parameters: list[ParamSpec] = Field(default_factory=list, max_length=_MAX_PARAMS)
    calling_convention: str | None = Field(default=None, max_length=_MAX_NAME)


class ApplyDataTypeEntry(_Entry):
    """An ``apply_data_type`` replay entry (mirrors :class:`ApplyDataTypeIn`).

    Structural entry. Re-validated via ``parse_address`` + ``validate_type_ref`` on import.

    Attributes:
        kind: Discriminator — always ``"apply_data_type"``.
        address: The address (hex) to apply the type at.
        type: The type to apply as a resolved :class:`TypeRef`.
        clear_existing: Whether to clear conflicting defined data first.
    """

    kind: Literal["apply_data_type"]
    address: str = Field(min_length=1, max_length=_MAX_NAME)
    type: TypeRef
    clear_existing: bool = Field(default=False)


class DefineStructEntry(_Entry):
    """A ``define_struct`` replay entry (mirrors :class:`DefineStructIn`).

    Structural entry. Re-validated via ``validate_composite(kind="struct")`` on import (bounded
    fields, resolved TypeRefs, no duplicate/by-value self-embed).

    Attributes:
        kind: Discriminator — always ``"define_struct"``.
        name: The new struct's name.
        fields: The ordered member list — non-empty, bounded by ``_MAX_FIELDS``.
        packed: Whether to pack the struct.
    """

    kind: Literal["define_struct"]
    name: str = Field(min_length=1, max_length=_MAX_NAME)
    fields: list[FieldSpec] = Field(min_length=1, max_length=_MAX_FIELDS)
    packed: bool = Field(default=False)

    @model_validator(mode="after")
    def _no_self_embed(self) -> DefineStructEntry:
        """Reject a by-value embed of this struct's own name (ADR-015 §3.2; ADR-018 re-validate).

        Returns:
            ``self`` when no member embeds the struct by value.

        Raises:
            ValueError: When a member embeds the struct by value (mapped to ``VALIDATION``).
        """
        _reject_self_embed(self.name, self.fields)
        return self


class DefineUnionEntry(_Entry):
    """A ``define_union`` replay entry (mirrors :class:`DefineUnionIn`).

    Structural entry. Re-validated via ``validate_composite(kind="union")`` on import.

    Attributes:
        kind: Discriminator — always ``"define_union"``.
        name: The new union's name.
        fields: The member list — non-empty, bounded by ``_MAX_FIELDS``; each ``offset`` MUST be
            ``None`` (union members overlay at offset 0).
    """

    kind: Literal["define_union"]
    name: str = Field(min_length=1, max_length=_MAX_NAME)
    fields: list[FieldSpec] = Field(min_length=1, max_length=_MAX_FIELDS)

    @model_validator(mode="after")
    def _no_self_embed_no_offset(self) -> DefineUnionEntry:
        """Reject a by-value self-embed and any per-member ``offset`` (ADR-015 §3.2/§2.2).

        Returns:
            ``self`` when the union shape is valid.

        Raises:
            ValueError: When a member embeds the union by value or carries a non-``None`` ``offset``
                (mapped to ``VALIDATION`` at the server boundary).
        """
        _reject_self_embed(self.name, self.fields)
        for field in self.fields:
            if field.offset is not None:
                raise ValueError("a union member may not carry an offset")
        return self


#: The discriminated union of replay entries — pydantic selects the variant by the ``kind`` literal.
#: An unknown/missing ``kind`` fails closed at construction (ADR-018 fail-closed). The order matches
#: the document's dependency-safe emission order (types first, then refs, then renames, comments).
Entry = (
    DefineStructEntry
    | DefineUnionEntry
    | SetFunctionSignatureEntry
    | ApplyDataTypeEntry
    | RenameFunctionEntry
    | RenameSymbolEntry
    | RenameLocalVariableEntry
    | RenameParameterEntry
    | SetCommentEntry
)

#: The set of structural ``kind`` values — these entries additionally require ``allow_structural``
#: consent on import (LLM08 — the human-in-the-loop gate is not bypassed by importing). Kept as data
#: so the import handler and tests share one source of truth. Must list EVERY kind whose live
#: handler calls ``require_write_consent(structural=True)``: the Phase-A name-only renames
#: (``rename_local_variable``/``rename_parameter`` — ADR-013) as well as the Phase-B/C type-aware
#: writes (``set_function_signature``/``apply_data_type``/``define_struct``/``define_union``).
#: Omitting the Phase-A renames would diverge the up-front import gate from the per-entry handlers
#: (which still deny) — keep this in lockstep with the handlers so the gate is single-sourced.
STRUCTURAL_ENTRY_KINDS: frozenset[str] = frozenset(
    {
        "rename_local_variable",
        "rename_parameter",
        "set_function_signature",
        "apply_data_type",
        "define_struct",
        "define_union",
    }
)


class AnnotationDocument(_In):
    """A versioned, binary-hash-bound, structured document of a session's USER_DEFINED annotations.

    The round-trip artifact (ADR-018 D3): produced by ``session_export_annotations`` and consumed by
    ``session_import_annotations``. It is INERT structured data (never Ghidra-native), and on import
    it is treated as **fully untrusted** — schema-validated, hash-bound, consent-gated, and each
    entry re-validated + replayed via the existing gated write path. ``entries`` is bounded
    (``_MAX_ENTRIES``) and emitted dependency-ordered (composites/types before the refs that use
    them).

    Attributes:
        schema_version: Document format version — must equal :data:`ANNOTATION_SCHEMA_VERSION`
            (an unknown version fails closed on import).
        binary: The applicability binding (the source program's hash + advisory provenance).
        entries: The ordered, bounded list of typed replay entries.
    """

    schema_version: int = Field(ge=1)
    binary: AnnotationBinaryRef
    entries: list[Entry] = Field(default_factory=list, max_length=_MAX_ENTRIES)


# --- EXPORTED document view (ADR-005): the read-OUT document wraps binary-derived strings -------
# The IMPORT document (above) carries BARE strings (it is the untrusted input the validators
# re-check). The EXPORT view mirrors it field-for-field but wraps the binary-derived value fields
# (current names/comments/recovered signatures the worker read out of the hostile program) in the
# untrusted envelope — they are GHIDRA/BINARY-origin content (ADR-005, std-owasp-llm LLM01). The
# client extracts ``.value`` from each wrapper to rebuild a bare import document for round-trip.
class _ExportEntry(_Out):
    """Base for an exported-annotation entry (immutable output model)."""


# --- exported-view type models (ADR-005 / CWE-200): the read-OUT counterparts of the bare import
# specs, with the hostile-origin name LEAF Untrusted-wrapped --------------------------------------
# The bare ``TypeRef``/``ParamSpec``/``FieldSpec`` are IMPORT inputs (untrusted text the validators
# re-check), so their ``named``/``name`` are bare ``str``. On EXPORT, though, those same name leaves
# carry the program's CURRENT USER_DEFINED names read straight out of the HOSTILE binary — a
# struct/union/parameter name an injection-steered prior write or a planted symbol may control.
# Like every sibling export field (``new_name``, ``text``, ``type_name``, ``get_data_type.name``)
# they are binary-derived and MUST be ``Untrusted``-wrapped on the way out (ADR-005,
# std-owasp-llm LLM01). The wrapping happens at the ``rpc_client`` chokepoint; these models are the
# typed output view the four composite/signature exported entries embed (vs. the bare import specs).
class ExportedTypeRef(_Out):
    """The exported (read-out) view of a :class:`TypeRef` — ``named`` leaf Untrusted-wrapped.

    Mirrors :class:`TypeRef` field-for-field, but the ``named`` reference is binary-derived on
    export (a type name the worker read out of the hostile program) and so is ``Untrusted``-wrapped
    (ADR-005). ``base`` is a closed-vocabulary built-in (safe), and the modifiers are server-safe
    scalars. The client extracts ``named.value`` to rebuild a bare :class:`TypeRef` for round-trip.

    Attributes:
        base: One of the closed :data:`BaseType` vocabulary, or ``None`` — safe.
        named: The read-out name of an existing program type, or ``None`` — binary-derived →
            untrusted.
        pointer_levels: Number of ``*`` modifiers — server-safe scalar.
        array_len: Fixed array length, or ``None`` — server-safe scalar.
    """

    base: BaseType | None = None
    named: Untrusted[str] | None = None
    pointer_levels: int = 0
    array_len: int | None = None


class ExportedParamSpec(_Out):
    """The exported view of a :class:`ParamSpec` — ``name`` leaf Untrusted-wrapped.

    Attributes:
        name: The parameter's current name read out — binary-derived → untrusted.
        type: The parameter's type as an :class:`ExportedTypeRef`.
    """

    name: Untrusted[str]
    type: ExportedTypeRef


class ExportedFieldSpec(_Out):
    """The exported view of a :class:`FieldSpec` — ``name`` leaf Untrusted-wrapped.

    Attributes:
        name: The member's current name read out — binary-derived → untrusted.
        type: The member's type as an :class:`ExportedTypeRef`.
        offset: Struct-only explicit byte offset, or ``None`` — server-safe scalar.
    """

    name: Untrusted[str]
    type: ExportedTypeRef
    offset: int | None = None


class ExportedRenameFunctionEntry(_ExportEntry):
    """Exported ``rename_function`` entry — ``new_name`` is the read-out (binary-derived) name.

    Attributes:
        kind: Discriminator — always ``"rename_function"``.
        function: The function selector (address hex — server-safe).
        new_name: The current USER_DEFINED name read out — binary-derived → untrusted.
    """

    kind: Literal["rename_function"]
    function: str
    new_name: Untrusted[str]


class ExportedRenameSymbolEntry(_ExportEntry):
    """Exported ``rename_symbol`` entry.

    Attributes:
        kind: Discriminator — always ``"rename_symbol"``.
        identifier: The symbol selector (address hex — server-safe).
        new_name: The current USER_DEFINED name read out — binary-derived → untrusted.
    """

    kind: Literal["rename_symbol"]
    identifier: str
    new_name: Untrusted[str]


class ExportedRenameLocalVariableEntry(_ExportEntry):
    """Exported ``rename_local_variable`` entry.

    Attributes:
        kind: Discriminator — always ``"rename_local_variable"``.
        function: The owning function selector (address hex — server-safe).
        variable: The local selector — binary-derived → untrusted (decompiler-assigned name).
        new_name: The current USER_DEFINED name read out — binary-derived → untrusted.
    """

    kind: Literal["rename_local_variable"]
    function: str
    variable: Untrusted[str]
    new_name: Untrusted[str]


class ExportedRenameParameterEntry(_ExportEntry):
    """Exported ``rename_parameter`` entry.

    Attributes:
        kind: Discriminator — always ``"rename_parameter"``.
        function: The owning function selector (address hex — server-safe).
        parameter: The parameter selector — binary-derived → untrusted.
        new_name: The current USER_DEFINED name read out — binary-derived → untrusted.
    """

    kind: Literal["rename_parameter"]
    function: str
    parameter: Untrusted[str]
    new_name: Untrusted[str]


class ExportedSetCommentEntry(_ExportEntry):
    """Exported ``set_comment`` entry.

    Attributes:
        kind: Discriminator — always ``"set_comment"``.
        address: The comment address (hex — server-safe).
        comment_type: The closed comment slot — safe.
        text: The current comment text read out — binary-derived → untrusted.
    """

    kind: Literal["set_comment"]
    address: str
    comment_type: str
    text: Untrusted[str]


class ExportedSetFunctionSignatureEntry(_ExportEntry):
    """Exported ``set_function_signature`` entry — the structured prototype (resolved TypeRefs).

    Attributes:
        kind: Discriminator — always ``"set_function_signature"``.
        function: The function selector (address hex — server-safe).
        return_type: The return type as a :class:`TypeRef` (type names are an allow-listed
            structured reference — safe to round-trip bare).
        parameters: The ordered parameter list.
        calling_convention: The closed-vocab convention, or ``None`` — safe.
    """

    kind: Literal["set_function_signature"]
    function: str
    return_type: ExportedTypeRef
    parameters: list[ExportedParamSpec] = Field(default_factory=list)
    calling_convention: str | None = None


class ExportedApplyDataTypeEntry(_ExportEntry):
    """Exported ``apply_data_type`` entry.

    Attributes:
        kind: Discriminator — always ``"apply_data_type"``.
        address: The address (hex — server-safe).
        type: The applied type as an :class:`ExportedTypeRef` — its ``named`` leaf is the read-out,
            binary-derived type name (untrusted-wrapped — ADR-005).
        clear_existing: Whether conflicting data is cleared first — safe.
    """

    kind: Literal["apply_data_type"]
    address: str
    type: ExportedTypeRef
    clear_existing: bool = False


class ExportedDefineStructEntry(_ExportEntry):
    """Exported ``define_struct`` entry (the user-defined composite name + fields are structured).

    Attributes:
        kind: Discriminator — always ``"define_struct"``.
        name: The composite's name read out of the hostile program — binary-derived → untrusted
            (a USER_DEFINED identifier a prior injection-steered write may control; ADR-005).
        fields: The member list (each member name is binary-derived → untrusted).
        packed: Whether the struct is packed — safe.
    """

    kind: Literal["define_struct"]
    name: Untrusted[str]
    fields: list[ExportedFieldSpec]
    packed: bool = False


class ExportedDefineUnionEntry(_ExportEntry):
    """Exported ``define_union`` entry.

    Attributes:
        kind: Discriminator — always ``"define_union"``.
        name: The composite's name read out — binary-derived → untrusted (ADR-005).
        fields: The member list (each member name is binary-derived → untrusted).
    """

    kind: Literal["define_union"]
    name: Untrusted[str]
    fields: list[ExportedFieldSpec]


#: The discriminated union of EXPORTED entries (output view). Same dependency order as ``Entry``.
ExportedEntry = (
    ExportedDefineStructEntry
    | ExportedDefineUnionEntry
    | ExportedSetFunctionSignatureEntry
    | ExportedApplyDataTypeEntry
    | ExportedRenameFunctionEntry
    | ExportedRenameSymbolEntry
    | ExportedRenameLocalVariableEntry
    | ExportedRenameParameterEntry
    | ExportedSetCommentEntry
)


class ExportedBinaryRef(_Out):
    """The applicability binding on an exported document (server-authoritative — safe scalars).

    Attributes:
        sha256: The session's program hash — a server-computed digest of input, safe.
        name: Optional advisory original name — binary-derived → untrusted (``None`` if unknown).
        size: Optional advisory original byte size — server scalar, safe.
    """

    sha256: str
    name: Untrusted[str] | None = None
    size: int | None = None


class ExportedAnnotationDocument(_Out):
    """The exported (read-out) annotation document — binary-derived strings untrusted-wrapped.

    The output counterpart of :class:`AnnotationDocument`: same versioned, hash-bound, dependency-
    ordered shape, but the binary-derived value fields are ``Untrusted``-wrapped (ADR-005). The
    client persists this inert artifact and extracts ``.value`` from each wrapper to rebuild a bare
    import document for round-trip. The server persists nothing (D2).

    Attributes:
        schema_version: Document format version (always :data:`ANNOTATION_SCHEMA_VERSION`) — safe.
        binary: The applicability binding (server-authoritative hash + advisory provenance).
        entries: The ordered exported entries.
    """

    schema_version: int
    binary: ExportedBinaryRef
    entries: list[ExportedEntry]


class SessionExportAnnotationsIn(_SessionScopedIn):
    """Arguments for ``session_export_annotations`` — read out the session's annotation document.

    Read-only + owner-scoped (ADR-018): no write consent; only the caller's own session. Bounded:
    over ``_MAX_ENTRIES`` USER_DEFINED annotations → ``limit-exceeded`` (no silent truncation).
    """


class SessionExportAnnotationsOut(_Out):
    """Result of ``session_export_annotations`` (ADR-018) — the document for the client to persist.

    The binary-derived strings inside ``document`` (entry value fields the worker read out) are
    untrusted-wrapped at the ADR-005 chokepoint as the document is assembled; ``document`` itself is
    the inert, client-owned artifact (the server persists nothing — D2).

    Attributes:
        document: The versioned, hash-bound exported annotation document (untrusted-wrapped).
    """

    document: ExportedAnnotationDocument


class SessionImportAnnotationsIn(_SessionScopedIn):
    """Arguments for ``session_import_annotations`` — replay a document into a same-binary session.

    The new trust boundary, TB8 (ADR-018): ``document`` is FULLY UNTRUSTED (it may have been
    tampered offline). The handler schema-validates it, verifies ``document.binary.sha256`` against
    the session's program hash, gates on write consent (+ ``allow_structural`` for structural
    entries), and re-validates + replays each entry via the existing gated write path.

    Attributes:
        document: The client-supplied annotation document to replay (untrusted).
    """

    document: AnnotationDocument


class ImportedEntryOutcome(_Out):
    """The per-entry outcome of an import replay — applied or rejected, never echoing the value.

    Attributes:
        index: Zero-based position of the entry in the document — safe.
        kind: The entry's ``kind`` discriminator (closed vocabulary) — safe.
        applied: Whether the entry's write committed — safe.
        reason: A short, safe, value-free reason when ``applied`` is ``False`` (e.g.
            ``"validation"``, ``"not-found"``, ``"analysis-failed"``) — never the rejected value
            (it could carry an injection payload — std-owasp-llm LLM01). ``None`` on success.
    """

    index: int
    kind: str
    applied: bool
    reason: str | None = None


class SessionImportAnnotationsOut(_Out):
    """Result of ``session_import_annotations`` (ADR-018) — a per-entry outcome report.

    Best-effort per entry (partial application is acceptable — it matches the per-write transaction
    model); the report tells the client exactly what applied. Counts + per-entry outcomes only —
    never the imported values (master §5 redaction).

    Attributes:
        session_id: The target session's opaque id — safe.
        total: Number of entries in the document — safe.
        applied: Number of entries whose write committed — safe.
        rejected: Number of entries rejected (``total - applied``) — safe.
        outcomes: The ordered per-entry outcome list (applied/rejected + safe reason).
    """

    session_id: str
    total: int
    applied: int
    rejected: int
    outcomes: list[ImportedEntryOutcome]
