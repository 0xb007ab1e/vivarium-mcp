"""Tier-1 tool registry — the explicit allow-list of exposed tools (WS1).

There is no dynamic tool discovery: the catalog is a fixed, reviewed allow-list (PLAN §2). This
module binds each of the 22 catalog tools to a handler and registers them with the FastMCP server.

Each handler is a thin **imperative shell** step (topic-architecture-patterns) that:

1. Receives an already-pydantic-validated ``*In`` model (FastMCP validates against the frozen
   schema: ``extra="forbid"`` rejects unknown fields; ``frozen`` makes them immutable).
2. Applies the *semantic* boundary validation pydantic can't express — address syntax, name
   charset, byte-range overflow — via :mod:`ghidra_mcp.core.validation` (trust boundary 1).
3. Authorizes the session server-side via the injected :class:`SessionManager` (BOLA defense —
   the client never names another binary's data); ``session_create`` is the sole exception.
4. Enforces pre-worker caps where applicable (``check_binary_size`` before import).
5. Delegates the Ghidra-touching work to the injected :class:`GhidraPort` (the adapter owns the
   process/container boundary, per-call timeout, worker-kill, and the untrusted-data wrapping of
   binary-derived fields — ADR-001/005, ``docs/contracts/rpc-protocol.md`` §4).
6. Lets any :class:`GhidraMcpError` propagate to the server shell, which renders the frozen error
   envelope; the shell maps anything else to a generic ``internal-error`` (fail closed).

No handler runs Ghidra in-process (ADR-001) and no handler logs binary-derived content
(topic-logging-observability).
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from ghidra_mcp.config import Config
from ghidra_mcp.core import validation as v
from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from ghidra_mcp.ghidra.port import GhidraPort
from ghidra_mcp.logging import get_logger
from ghidra_mcp.sessions.manager import SessionManager
from ghidra_mcp.tools import schemas as s

_log = get_logger(__name__)

# The canonical, frozen list of Tier-1 tool names (matches docs/contracts/tool-catalog.md).
# Kept as data so the catalog can be asserted in tests and registered uniformly.
TIER1_TOOL_NAMES: tuple[str, ...] = (
    # session lifecycle
    "session_create",
    "session_import",
    "session_analyze",
    "session_status",
    "session_close",
    # code
    "decompile_function",
    "disassemble",
    "list_functions",
    "get_function",
    # xrefs
    "xrefs_to",
    "xrefs_from",
    # strings / symbols / data / types
    "list_strings",
    "list_symbols",
    "get_symbol",
    "list_data",
    "get_data_type",
    # comments (read-only)
    "get_comments",
    # memory / bytes / search
    "memory_map",
    "read_bytes",
    "search_bytes",
    "search_strings",
    # metadata
    "program_metadata",
)


class _ToolRegistrar(Protocol):
    """Minimal structural view of the FastMCP registration surface the registry depends on.

    Depending on this narrow Protocol (rather than the concrete ``FastMCP`` type) keeps the
    registry decoupled from the SDK and trivially fakeable in unit tests (dependency inversion —
    topic-dependency-injection).
    """

    def add_tool(
        self,
        fn: Callable[..., Any],
        name: str | None = ...,
        title: str | None = ...,
        description: str | None = ...,
    ) -> None:
        """Register a single tool handler under ``name``."""
        ...


@dataclass(frozen=True, slots=True)
class ToolContext:
    """Injected collaborators shared by every tool handler (composition-root wiring).

    Attributes:
        config: Validated server configuration (limits, session policy).
        sessions: The session manager that authorizes session-scoped calls (BOLA chokepoint).
        port: The Ghidra adapter the handlers delegate analysis to (ADR-001 boundary).
    """

    config: Config
    sessions: SessionManager
    port: GhidraPort


# =====================================================================================
# Session lifecycle handlers (server-side; not worker RPC)
# =====================================================================================
def _handle_session_create(ctx: ToolContext, args: s.SessionCreateIn) -> s.SessionInfo:
    """Open a new session (no binary, no worker yet).

    Args:
        ctx: Injected collaborators.
        args: Validated ``session_create`` arguments.

    Returns:
        The new session's :class:`~ghidra_mcp.tools.schemas.SessionInfo`.
    """
    info = ctx.sessions.create(label=args.label)
    _log.info("tool.session_create", extra={"tool": "session_create", "session": info.session_id})
    return info


def _handle_session_import(ctx: ToolContext, args: s.SessionImportIn) -> s.SessionInfo:
    """Import a (size-checked) binary into the session's worker.

    The size cap is enforced BEFORE any byte reaches Ghidra (DoS — PLAN §3 F7). The actual byte
    resolution + path confinement of ``source_ref`` is the adapter's responsibility (CWE-22),
    behind the port; the server only asserts the session is live first.

    Args:
        ctx: Injected collaborators.
        args: Validated ``session_import`` arguments.

    Returns:
        Updated :class:`SessionInfo` after import.
    """
    ctx.sessions.authorize(args.session_id)
    return ctx.port.import_binary(args.session_id, args)


def _handle_session_analyze(ctx: ToolContext, args: s.SessionAnalyzeIn) -> s.SessionInfo:
    """Run Ghidra auto-analysis, bounded by the analysis timeout (kills worker on expiry).

    Args:
        ctx: Injected collaborators.
        args: Validated ``session_analyze`` arguments.

    Returns:
        Updated :class:`SessionInfo` after analysis.
    """
    ctx.sessions.authorize(args.session_id)
    return ctx.port.analyze(args.session_id, args)


def _handle_session_status(ctx: ToolContext, args: s._SessionScopedIn) -> s.SessionInfo:
    """Report a session's state/TTL (no binary content).

    Args:
        ctx: Injected collaborators.
        args: Validated session-scoped arguments.

    Returns:
        The authorized session's :class:`SessionInfo`.
    """
    return ctx.sessions.authorize(args.session_id)


def _handle_session_close(ctx: ToolContext, args: s.SessionCloseIn) -> s.SessionCloseOut:
    """Evict the session now: kill the worker and verified-wipe the store (ADR-002).

    Authorizes first so an unknown/foreign id yields the BOLA-safe ``session-invalid`` envelope
    rather than silently succeeding.

    Args:
        ctx: Injected collaborators.
        args: Validated ``session_close`` arguments.

    Returns:
        :class:`SessionCloseOut` reporting whether the store was verified-wiped.
    """
    ctx.sessions.authorize(args.session_id)
    wiped = ctx.sessions.evict(args.session_id, reason="close")
    _log.info(
        "tool.session_close",
        extra={"tool": "session_close", "session": args.session_id, "store_wiped": wiped},
    )
    return s.SessionCloseOut(session_id=args.session_id, store_wiped=wiped)


# =====================================================================================
# Code handlers
# =====================================================================================
def _handle_decompile_function(
    ctx: ToolContext, args: s.DecompileFunctionIn
) -> s.DecompiledFunction:
    """Decompile one function (output is untrusted; wrapped by the adapter)."""
    ctx.sessions.authorize(args.session_id)
    v.validate_name(args.function)
    return ctx.port.decompile_function(args.session_id, args)


def _handle_disassemble(ctx: ToolContext, args: s.DisassembleIn) -> s.DisassembleOut:
    """Disassemble a bounded range or function."""
    ctx.sessions.authorize(args.session_id)
    if args.start is not None:
        v.parse_address(args.start)
    if args.function is not None:
        v.validate_name(args.function)
    if args.start is None and args.function is None:
        raise _require("either 'start' or 'function' must be provided")
    return ctx.port.disassemble(args.session_id, args)


def _handle_list_functions(ctx: ToolContext, args: s.ListFunctionsIn) -> s.FunctionListOut:
    """List functions (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id)
    if args.name_contains is not None:
        v.validate_name(args.name_contains)
    return ctx.port.list_functions(args.session_id, args)


def _handle_get_function(ctx: ToolContext, args: s.GetFunctionIn) -> s.FunctionDetail:
    """Get one function's detail."""
    ctx.sessions.authorize(args.session_id)
    v.validate_name(args.function)
    return ctx.port.get_function(args.session_id, args)


# =====================================================================================
# Cross-reference handlers
# =====================================================================================
def _handle_xrefs_to(ctx: ToolContext, args: s.XrefsIn) -> s.XrefsOut:
    """References TO a target."""
    ctx.sessions.authorize(args.session_id)
    v.validate_name(args.target)
    return ctx.port.xrefs_to(args.session_id, args)


def _handle_xrefs_from(ctx: ToolContext, args: s.XrefsIn) -> s.XrefsOut:
    """References FROM a target."""
    ctx.sessions.authorize(args.session_id)
    v.validate_name(args.target)
    return ctx.port.xrefs_from(args.session_id, args)


# =====================================================================================
# Strings / symbols / data / types handlers
# =====================================================================================
def _handle_list_strings(ctx: ToolContext, args: s.ListStringsIn) -> s.StringListOut:
    """List defined strings (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id)
    return ctx.port.list_strings(args.session_id, args)


def _handle_list_symbols(ctx: ToolContext, args: s.ListSymbolsIn) -> s.SymbolListOut:
    """List symbols (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id)
    if args.name_contains is not None:
        v.validate_name(args.name_contains)
    return ctx.port.list_symbols(args.session_id, args)


def _handle_get_symbol(ctx: ToolContext, args: s.GetSymbolIn) -> s.Symbol:
    """Resolve one symbol by name or address."""
    ctx.sessions.authorize(args.session_id)
    v.validate_name(args.identifier)
    return ctx.port.get_symbol(args.session_id, args)


def _handle_list_data(ctx: ToolContext, args: s.ListDataIn) -> s.DataListOut:
    """List defined data (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id)
    return ctx.port.list_data(args.session_id, args)


def _handle_get_data_type(ctx: ToolContext, args: s.GetDataTypeIn) -> s.DataType:
    """Resolve one data type by name."""
    ctx.sessions.authorize(args.session_id)
    v.validate_name(args.name)
    return ctx.port.get_data_type(args.session_id, args)


# =====================================================================================
# Comments handler (read-only)
# =====================================================================================
def _handle_get_comments(ctx: ToolContext, args: s.GetCommentsIn) -> s.CommentListOut:
    """Read comments (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id)
    if args.address is not None:
        v.parse_address(args.address)
    return ctx.port.get_comments(args.session_id, args)


# =====================================================================================
# Memory / bytes / search handlers
# =====================================================================================
def _handle_memory_map(ctx: ToolContext, args: s.MemoryMapIn) -> s.MemoryMapOut:
    """List memory blocks/segments."""
    ctx.sessions.authorize(args.session_id)
    return ctx.port.memory_map(args.session_id, args)


def _handle_read_bytes(ctx: ToolContext, args: s.ReadBytesIn) -> s.ReadBytesOut:
    """Bounded raw byte read (offset/length overflow-guarded before the worker)."""
    ctx.sessions.authorize(args.session_id)
    offset = v.parse_address(args.address)
    v.validate_byte_range(offset, args.length)
    return ctx.port.read_bytes(args.session_id, args)


def _handle_search_bytes(ctx: ToolContext, args: s.SearchBytesIn) -> s.SearchBytesOut:
    """Bounded byte-pattern search (pattern validated as hex with optional ``??`` wildcards)."""
    ctx.sessions.authorize(args.session_id)
    v.validate_byte_pattern(args.pattern_hex)
    return ctx.port.search_bytes(args.session_id, args)


def _handle_search_strings(ctx: ToolContext, args: s.SearchStringsIn) -> s.SearchStringsOut:
    """Bounded defined-string search."""
    ctx.sessions.authorize(args.session_id)
    v.validate_query(args.query)
    return ctx.port.search_strings(args.session_id, args)


# =====================================================================================
# Metadata handler
# =====================================================================================
def _handle_program_metadata(ctx: ToolContext, args: s.ProgramMetadataIn) -> s.ProgramMetadata:
    """High-level program metadata (no binary content beyond format-reported, wrapped fields)."""
    ctx.sessions.authorize(args.session_id)
    return ctx.port.program_metadata(args.session_id, args)


# =====================================================================================
# Local helpers
# =====================================================================================
def _require(detail: str) -> GhidraMcpError:
    """Build a fail-closed ``VALIDATION`` error for a cross-field requirement.

    Used for argument relationships pydantic field constraints can't express (e.g. "exactly one
    of A or B"). The detail is safe (no client values echoed — std-owasp-llm LLM01).

    Args:
        detail: A safe, value-free description of the unmet requirement.

    Returns:
        A :class:`GhidraMcpError` wrapping a ``validation-error`` envelope.
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


# Map of tool name → (handler, input-schema). The input schema is the handler's single argument
# type, from which FastMCP derives the tool's JSON schema. The output schema is the return type.
_HANDLERS: dict[str, tuple[Callable[[ToolContext, Any], Any], type[s._In]]] = {
    "session_create": (_handle_session_create, s.SessionCreateIn),
    "session_import": (_handle_session_import, s.SessionImportIn),
    "session_analyze": (_handle_session_analyze, s.SessionAnalyzeIn),
    "session_status": (_handle_session_status, s._SessionScopedIn),
    "session_close": (_handle_session_close, s.SessionCloseIn),
    "decompile_function": (_handle_decompile_function, s.DecompileFunctionIn),
    "disassemble": (_handle_disassemble, s.DisassembleIn),
    "list_functions": (_handle_list_functions, s.ListFunctionsIn),
    "get_function": (_handle_get_function, s.GetFunctionIn),
    "xrefs_to": (_handle_xrefs_to, s.XrefsIn),
    "xrefs_from": (_handle_xrefs_from, s.XrefsIn),
    "list_strings": (_handle_list_strings, s.ListStringsIn),
    "list_symbols": (_handle_list_symbols, s.ListSymbolsIn),
    "get_symbol": (_handle_get_symbol, s.GetSymbolIn),
    "list_data": (_handle_list_data, s.ListDataIn),
    "get_data_type": (_handle_get_data_type, s.GetDataTypeIn),
    "get_comments": (_handle_get_comments, s.GetCommentsIn),
    "memory_map": (_handle_memory_map, s.MemoryMapIn),
    "read_bytes": (_handle_read_bytes, s.ReadBytesIn),
    "search_bytes": (_handle_search_bytes, s.SearchBytesIn),
    "search_strings": (_handle_search_strings, s.SearchStringsIn),
    "program_metadata": (_handle_program_metadata, s.ProgramMetadataIn),
}


def build_handlers(ctx: ToolContext) -> dict[str, Callable[[Any], Any]]:
    """Build the name → bound-handler map for the full Tier-1 catalog.

    Each returned handler closes over ``ctx`` and takes a single, already-validated ``*In`` model
    (matching how FastMCP invokes a structured tool). Its ``__signature__``/``__annotations__`` are
    set to the tool's concrete input schema so the MCP SDK can derive the tool's JSON schema. The
    map is exhaustive over :data:`TIER1_TOOL_NAMES` (asserted below and in tests).

    Args:
        ctx: The injected collaborators (config, session manager, Ghidra port).

    Returns:
        A mapping of tool name to a single-argument handler callable.

    Raises:
        RuntimeError: If the handler table drifts from :data:`TIER1_TOOL_NAMES` (programmer error —
            fail fast at startup).
    """
    if set(_HANDLERS) != set(TIER1_TOOL_NAMES):
        # Fail closed: the allow-list and the handler table MUST be identical.
        raise RuntimeError("tool handler table does not match the frozen Tier-1 allow-list")

    bound: dict[str, Callable[[Any], Any]] = {}
    for name, (handler, in_schema) in _HANDLERS.items():
        bound[name] = _bind(handler, ctx, in_schema)
    return bound


def _bind(
    handler: Callable[[ToolContext, Any], Any],
    ctx: ToolContext,
    in_schema: type[s._In],
) -> Callable[..., Any]:
    """Bind a ``(ctx, model)`` handler to a flat-kwargs tool callable that re-validates input.

    The returned callable's synthesized signature exposes the tool's input model **fields** as
    top-level keyword parameters, so the MCP SDK derives a flat input JSON schema (clients pass
    ``{session_id, address, length}``, matching ``docs/contracts/tool-catalog.md``). Inside, the
    keyword arguments are reconstructed into the frozen ``in_schema`` model, which re-applies the
    full pydantic contract (field bounds AND ``extra="forbid"``) as a defense-in-depth boundary
    pass; only then is the typed ``(ctx, model)`` handler invoked.

    Args:
        handler: The ``(ctx, model)`` handler operating on the validated input model.
        ctx: The context to close over.
        in_schema: The tool's frozen input model (its fields define the parameter signature).

    Returns:
        A flat-kwargs callable suitable for FastMCP registration.
    """

    def _bound(**kwargs: Any) -> Any:
        # Reconstruct the frozen input model — re-applies all pydantic constraints and rejects any
        # unexpected field (extra="forbid"). A validation failure surfaces as a pydantic error the
        # server shell maps to a VALIDATION envelope (fail closed).
        model = in_schema(**kwargs)
        return handler(ctx, model)

    _bound.__signature__ = _signature_from_model(in_schema)  # type: ignore[attr-defined]
    _bound.__annotations__ = _annotations_from_model(in_schema)
    _bound.__name__ = f"tool_{in_schema.__name__}"
    return _bound


def _signature_from_model(model: type[s._In]) -> inspect.Signature:
    """Build a keyword-only signature exposing ``model``'s fields as parameters.

    Required fields (no default) become required keyword-only parameters; optional fields carry
    their default so the SDK marks them optional. Annotations come from the model's field types.

    Args:
        model: The pydantic input model.

    Returns:
        An :class:`inspect.Signature` whose parameters mirror the model's fields.
    """
    parameters: list[inspect.Parameter] = []
    for field_name, field in model.model_fields.items():
        annotation = field.annotation if field.annotation is not None else Any
        default = inspect.Parameter.empty if field.is_required() else field.get_default()
        parameters.append(
            inspect.Parameter(
                field_name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=annotation,
            )
        )
    return inspect.Signature(parameters=parameters, return_annotation=inspect.Signature.empty)


def _annotations_from_model(model: type[s._In]) -> dict[str, Any]:
    """Return the ``__annotations__`` mapping for a synthesized handler over ``model``'s fields.

    Args:
        model: The pydantic input model.

    Returns:
        A mapping of field name to annotation (resolved from the model's pydantic field info).
    """
    return {
        name: (field.annotation if field.annotation is not None else Any)
        for name, field in model.model_fields.items()
    }


def register_tools(
    registrar: _ToolRegistrar,
    ctx: ToolContext,
    *,
    wrap: Callable[[str, Callable[[Any], Any]], Callable[[Any], Any]] | None = None,
) -> None:
    """Register the full Tier-1 tool catalog with the MCP server.

    Binds every name in :data:`TIER1_TOOL_NAMES` to its context-bound handler and registers it with
    ``registrar``. Registration is exhaustive and matches the frozen catalog exactly (asserted in
    :func:`build_handlers` and in tests) — there is no dynamic/arbitrary tool surface (PLAN §2).

    Args:
        registrar: The FastMCP application (or any object exposing :class:`_ToolRegistrar`).
        ctx: The injected collaborators for the handlers.
        wrap: Optional ``(tool_name, handler) -> handler`` decorator applied to each handler before
            registration (the server shell injects its error boundary here, keeping transport/error
            concerns out of the registry — separation of concerns). The wrapper MUST preserve the
            handler's ``__signature__``/``__annotations__`` so the SDK can still introspect it.

    Raises:
        RuntimeError: If the handler table drifts from the frozen allow-list (fail fast).
    """
    handlers = build_handlers(ctx)
    for name in TIER1_TOOL_NAMES:
        fn = handlers[name]
        if wrap is not None:
            fn = wrap(name, fn)
        registrar.add_tool(fn, name=name)
    _log.info("tools.registered", extra={"count": len(TIER1_TOOL_NAMES)})
