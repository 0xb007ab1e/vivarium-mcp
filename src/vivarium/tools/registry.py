"""Tier-1 tool registry — the explicit allow-list of exposed tools (WS1).

There is no dynamic tool discovery: the catalog is a fixed, reviewed allow-list (PLAN §2). This
module binds each catalog tool in :data:`TIER1_TOOL_NAMES` to a handler and registers them with the
FastMCP server (the count is asserted in the schema/registry tests, so it stays the single source).

Each handler is a thin **imperative shell** step (topic-architecture-patterns) that:

1. Receives an already-pydantic-validated ``*In`` model (FastMCP validates against the frozen
   schema: ``extra="forbid"`` rejects unknown fields; ``frozen`` makes them immutable).
2. Applies the *semantic* boundary validation pydantic can't express — address syntax, name
   charset, byte-range overflow — via :mod:`vivarium.core.validation` (trust boundary 1).
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

import functools
import inspect
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import anyio
from mcp.server.fastmcp import Context

from vivarium.config import Config
from vivarium.core import validation as v
from vivarium.core.envelope import DataOrigin, wrap
from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.ghidra.port import GhidraPort, OnProgress
from vivarium.jobs import streaming as st
from vivarium.logging import get_logger
from vivarium.server.auth import CAP_READ, CAP_WRITE, Principal
from vivarium.sessions.manager import SessionManager
from vivarium.tools import schemas as s

_log = get_logger(__name__)

#: The implicit local-operator principal (stdio / single-principal default — ADR-006/ADR-017).
#: A module-level constant (frozen, immutable) so it can be a dataclass default without RUF009.
_LOCAL_PRINCIPAL = Principal(id="local")

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
    "get_pcode",
    "get_high_pcode",
    "data_flow_slice",
    "recover_struct",
    "deobfuscate_strings",
    "stack_frame",
    "basic_blocks",
    "list_data_types",
    "function_hash",
    "bsim_similarity",
    "find_similar_functions",
    "version_track",
    "binary_diff",
    "bsim_search_corpus",
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
    "emulate",
    "demangle",
    "search_bytes",
    "search_strings",
    # metadata
    "program_metadata",
    # call graph / semantic-naming support (v1.1 — ADR-007; READ-ONLY)
    "call_graph",
    "callees",
    "callers",
    "analysis_order",
    "function_context",
    # Tier-2 reporting / metrics (v1.1 — ADR-008; READ-ONLY)
    "cyclomatic_complexity",
    "list_imports",
    "list_exports",
    "coverage",
    "ioc_scan",
    "crypto_constant_scan",
    "secret_scan",
    "call_graph_metrics",
    "program_summary",
    # Function ID library-match identification (ADR-042 Phase 1; READ-ONLY)
    "identify_functions",
    # mutation / write tools (v1.1 — ADR-012; GATED by per-session write-consent)
    "session_enable_writes",
    "session_disable_writes",
    "session_undo",
    "rename_function",
    "rename_symbol",
    "set_comment",
    # structural writes (v1.1 — ADR-013 Phase A; additionally GATED by allow_structural)
    "rename_local_variable",
    "rename_parameter",
    # structural type-aware writes (v1.1 — ADR-014 Phase B; additionally GATED by allow_structural)
    "set_function_signature",
    "apply_data_type",
    # bundled type-archive application (v1.8 — ADR-051; additionally GATED by allow_structural)
    "apply_type_archive",
    # composite-type creation (v1.1 — ADR-015 Phase C; additionally GATED by allow_structural)
    "define_struct",
    "define_union",
    # multi-type composite batch (v1.2 — ADR-021; additionally GATED by allow_structural)
    "define_types",
    # composite deletion (v1.4 — ADR-031; session-authored only; GATED by allow_structural)
    "delete_type",
    # cross-session annotation persistence (v1.2 — ADR-018; export=read-only, import=GATED by
    # write-consent + allow_structural for structural entries)
    "session_export_annotations",
    "session_import_annotations",
    # streaming extraction (v1.x — ADR-040; READ-ONLY, output-only; pull-based job + cursor)
    "start_decompile_stream",
    "fetch_job_results",
    "job_status",
    "cancel_job",
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
        principal: The static **server-derived** identity for this context (ADR-017). Used for
            stdio (the implicit local operator) and as the fallback when no per-request resolver is
            wired. Never client-supplied. Defaults to the local operator (single-principal stdio).
        resolve_principal: Optional per-request resolver (HTTP). When set, :attr:`caller_id` calls
            it to obtain the **current request's** authenticated principal (built by the auth
            middleware from the request, then stashed on the ASGI scope) — so one shared context
            serves many principals, each owning only its own sessions. ``None`` ⇒ static principal.

    Note:
        Handlers MUST read :attr:`caller_id` (never ``principal.id`` directly) so the per-request
        resolver is honored — that is the single seam that keeps HTTP multi-principal while stdio
        stays the local operator.
    """

    config: Config
    sessions: SessionManager
    port: GhidraPort
    principal: Principal = _LOCAL_PRINCIPAL
    resolve_principal: Callable[[], Principal] | None = None

    @property
    def caller_id(self) -> str:
        """The current call's server-derived principal id (the session ``owner``/``caller`` key).

        Returns the per-request resolver's principal id when wired (HTTP), else the static
        :attr:`principal` id (stdio / tests). Identity is always server-derived — never from client
        input (BOLA / ``std-owasp-api`` API1).
        """
        if self.resolve_principal is not None:
            return self.resolve_principal().id
        return self.principal.id

    @property
    def caller_capabilities(self) -> frozenset[str]:
        """The current call's principal capabilities (ADR-033) — read/write per-tool authZ.

        Mirrors :attr:`caller_id`: the per-request resolver's principal capabilities when wired
        (HTTP), else the static principal's (stdio/tests — full). Server-derived, never client
        input. The dispatch chokepoint denies a tool whose :func:`required_capability` is absent.
        """
        if self.resolve_principal is not None:
            return self.resolve_principal().capabilities
        return self.principal.capabilities


# =====================================================================================
# Per-tool capability authorization (ADR-033). A tool requires `write` iff it mutates the program/
# session-write state; everything else requires `read`. WRITE_TOOLS is the single source of truth
# (asserted complete vs. the catalog in tests). Enforced at the dispatch chokepoint, server-side,
# every call — before any handler work (complete mediation; std-owasp-api API5).
# =====================================================================================
WRITE_TOOLS: frozenset[str] = frozenset(
    {
        # write-consent management + undo (ADR-012)
        "session_enable_writes",
        "session_disable_writes",
        "session_undo",
        # annotation writes (ADR-012)
        "rename_function",
        "rename_symbol",
        "set_comment",
        # structural writes (ADR-013/014/015/021)
        "rename_local_variable",
        "rename_parameter",
        "set_function_signature",
        "apply_data_type",
        "apply_type_archive",
        "define_struct",
        "define_union",
        "define_types",
        # composite deletion (ADR-031)
        "delete_type",
        # annotation import = replay of gated writes (ADR-018)
        "session_import_annotations",
    }
)


def required_capability(tool_name: str) -> str:
    """Return a tool's required capability: ``write`` for a mutator, else ``read`` (ADR-033)."""
    return CAP_WRITE if tool_name in WRITE_TOOLS else CAP_READ


def _authorize_capability(ctx: ToolContext, tool_name: str) -> None:
    """Deny the call fail-closed if the principal lacks the tool's required capability (ADR-033).

    The per-tool authZ chokepoint, evaluated server-side before any handler work (complete
    mediation). On a stdio/bearer/mTLS principal — or an OAuth deployment that did not configure a
    write-scope — every principal is full-capability, so this is a no-op (the pre-ADR-033 behavior).
    A scope-narrowed OAuth read-only token is rejected here for any ``write`` tool with a
    ``FORBIDDEN`` envelope (ADR-036; 403) — consistent with the write-consent denial, which moved to
    the same type. The denial is logged redacted (tool + principal + missing capability, never the
    token).

    Args:
        ctx: The injected collaborators (its per-request principal supplies the capabilities).
        tool_name: The catalog tool name being invoked.

    Raises:
        GhidraMcpError: ``FORBIDDEN`` when the required capability is absent.
    """
    required = required_capability(tool_name)
    if required in ctx.caller_capabilities:
        return
    _log.warning(
        "tool.authz_denied",
        extra={
            "tool": tool_name,
            "principal_id": ctx.caller_id,
            "required_capability": required,
        },
    )
    # FORBIDDEN envelope (403, ADR-036): the caller is authenticated but the token lacks the
    # capability this tool requires — a permission denial, not a malformed request (validation) and
    # not an existence question (session-invalid). The specific reason rides in the value-free
    # detail (never the token / scope contents).
    raise GhidraMcpError(
        ErrorEnvelope(
            type=ErrorType.FORBIDDEN,
            title="Forbidden",
            detail="The access token lacks the capability required for this tool.",
            status=403,
            retryable=False,
        )
    )


# =====================================================================================
# Session lifecycle handlers (server-side; not worker RPC)
# =====================================================================================
def _handle_session_create(ctx: ToolContext, args: s.SessionCreateIn) -> s.SessionInfo:
    """Open a new session (no binary, no worker yet).

    Args:
        ctx: Injected collaborators.
        args: Validated ``session_create`` arguments.

    Returns:
        The new session's :class:`~vivarium.tools.schemas.SessionInfo`.
    """
    info = ctx.sessions.create(owner=ctx.caller_id, label=args.label)
    _log.info(
        "tool.session_create",
        extra={
            "tool": "session_create",
            "session": info.session_id,
            "principal_id": ctx.caller_id,
        },
    )
    return info


def _handle_session_import(ctx: ToolContext, args: s.SessionImportIn) -> s.SessionInfo:
    """Import a binary into the session's worker for analysis.

    ``source_ref`` must be a path to a file **under the server's import root**
    (``VIVARIUM_IMPORT_ROOT``) — NOT arbitrary bytes and NOT any host path. Example: with the root
    at ``/srv/imports``, pass ``source_ref="/srv/imports/firmware.bin"`` (or a path relative to it).
    It is rejected (``validation``) when it is outside the import root, not found, or malformed, and
    (``limit-exceeded``) when it is over the size cap.

    **Headerless raw/firmware images** (no ELF/PE header — e.g. bare-metal MCU dumps) need loader
    hints (ADR-045): set ``loader="binary"`` with ``processor`` (a supported Ghidra ``LanguageID``
    such as ``ARM:LE:32:Cortex`` or ``RISCV:LE:32:RV32GC``) and ``base_addr`` (the image load
    address), plus optional ``entry``. For normal ELF/PE files omit all hints (``loader`` defaults
    to ``auto``). See the ``vivarium://docs/importing`` resource for the full how-to.

    The size cap is enforced BEFORE any byte reaches Ghidra (DoS — PLAN §3 F7). The actual byte
    resolution + path confinement of ``source_ref`` is the adapter's responsibility (CWE-22),
    behind the port; the server only asserts the session is live first.

    The session lifecycle is owned **server-side** by the :class:`SessionManager`: its
    ``created_at``/``expires_at``/``state``/``session_id`` are authoritative and are overlaid onto
    the worker's reply, which contributes only ``binary_sha256`` (the worker is untrusted and never
    dictates session timing/identity/state — ADR-001/005, master §2).

    Args:
        ctx: Injected collaborators.
        args: Validated ``session_import`` arguments.

    Returns:
        Updated :class:`SessionInfo` after import, with authoritative lifecycle fields.
    """
    authoritative = ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    # Spawn the session's hardened worker on first import (idempotent; the manager owns worker
    # lifetime — ADR-002). Without this the adapter has no worker socket for the session and the
    # import fails closed as worker-unavailable. Owner-scoped (ADR-017): only the owning principal
    # can spawn this session's worker.
    ctx.sessions.ensure_worker(args.session_id, caller=ctx.caller_id)
    imported = ctx.port.import_binary(args.session_id, args)
    # Persist the worker-computed program hash on the session (ADR-001: the server never parses the
    # binary — it overlays the worker's digest). This is the session's authoritative program
    # identity that the annotation-import path binds against (ADR-018 TB8). Owner-scoped.
    #
    # Alongside the load-bearing hash, stamp the ADVISORY import provenance in the SAME chokepoint:
    # the server-resolved byte size (computed pre-Ghidra by the adapter — no binary parse, ADR-001)
    # and the basename label of the resolved ref. Both are non-load-bearing provenance only (they
    # fill the export document's advisory ``binary.name``/``binary.size`` — never trusted for authZ
    # or binding); ``name`` is a label, not a path, so it carries no traversal meaning (CWE-22).
    if imported.binary_sha256 is not None:
        ctx.sessions.record_binary_hash(
            args.session_id,
            imported.binary_sha256,
            size=imported.binary_size,
            name=Path(args.source_ref).name,
            caller=ctx.caller_id,
        )
    return _merge_session_info(authoritative, imported)


def _handle_session_analyze(
    ctx: ToolContext,
    args: s.SessionAnalyzeIn,
    *,
    on_progress: OnProgress | None = None,
) -> s.SessionInfo:
    """Run Ghidra auto-analysis, bounded by the analysis timeout (kills worker on expiry).

    As with import, the :class:`SessionManager` owns the session lifecycle: its authoritative
    ``created_at``/``expires_at``/``state``/``session_id`` are overlaid onto the worker's reply,
    which contributes only ``binary_sha256``. A hostile/buggy worker cannot forge session timing,
    identity, or lifecycle state.

    Args:
        ctx: Injected collaborators.
        args: Validated ``session_analyze`` arguments.
        on_progress: Optional ADR-030 Phase-2 client-relay callback, threaded to the adapter. When
            non-``None`` the worker emits ``$/progress`` frames and the adapter forwards each to
            this callback (the async binding bridges it to ``Context.report_progress``); ``None``
            (stdio / no ``progressToken``) is byte-for-byte the pre-Phase-2 path.

    Returns:
        Updated :class:`SessionInfo` after analysis, with authoritative lifecycle fields including
        the effective ``analysis_profile`` (ADR-029 B) just recorded.
    """
    authoritative = ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    analyzed = ctx.port.analyze(args.session_id, args, on_progress=on_progress)
    # Echo the effective analyzer profile (ADR-029 B) on the session AFTER a successful analyze, so
    # a client/operator can see which preset actually ran (the input profile is otherwise
    # unobservable). Owner-scoped via the same chokepoint. The returned (merged) info reflects it by
    # overlaying the validated input profile — the manager was just stamped with the same value, so
    # a later ``session_status`` is consistent; the worker contributes only ``binary_sha256``.
    ctx.sessions.record_analysis_profile(args.session_id, args.profile, caller=ctx.caller_id)
    merged = _merge_session_info(authoritative, analyzed)
    return merged.model_copy(update={"analysis_profile": args.profile})


def _merge_session_info(authoritative: s.SessionInfo, worker: s.SessionInfo) -> s.SessionInfo:
    """Overlay the manager's authoritative lifecycle fields onto a worker-returned ``SessionInfo``.

    The server-side :class:`SessionManager` is the single source of truth for a session's identity
    and lifecycle (``session_id``, ``created_at``, ``expires_at``, ``state``); the out-of-process
    worker is untrusted (ADR-001/005) and contributes only the server-relevant ``binary_sha256`` it
    computed over the imported input. Overlaying the manager's fields prevents a hostile/buggy
    worker from forging session timing, identity, or lifecycle state (defense in depth — master §2).

    Args:
        authoritative: The :class:`SessionInfo` the session manager returned from ``authorize``.
        worker: The :class:`SessionInfo` the Ghidra adapter returned (worker-supplied).

    Returns:
        A frozen :class:`SessionInfo` carrying the manager's lifecycle fields and the worker's
        ``binary_sha256``.
    """
    return authoritative.model_copy(update={"binary_sha256": worker.binary_sha256})


def _handle_session_status(ctx: ToolContext, args: s._SessionScopedIn) -> s.SessionInfo:
    """Report a session's state/TTL (no binary content).

    Args:
        ctx: Injected collaborators.
        args: Validated session-scoped arguments.

    Returns:
        The authorized session's :class:`SessionInfo`.
    """
    return ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)


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
    # Owner-scoped close (ADR-017): pass the caller so the evict is gated by the same ownership
    # chokepoint — a foreign caller cannot tear down another principal's session (BOLA-safe).
    wiped = ctx.sessions.evict(args.session_id, reason="close", caller=ctx.caller_id)
    _log.info(
        "tool.session_close",
        extra={
            "tool": "session_close",
            "session": args.session_id,
            "principal_id": ctx.caller_id,
            "store_wiped": wiped,
        },
    )
    return s.SessionCloseOut(session_id=args.session_id, store_wiped=wiped)


# =====================================================================================
# Code handlers
# =====================================================================================
def _handle_decompile_function(
    ctx: ToolContext, args: s.DecompileFunctionIn
) -> s.DecompiledFunction:
    """Decompile one function (output is untrusted; wrapped by the adapter)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.decompile_function(args.session_id, args)


def _handle_disassemble(ctx: ToolContext, args: s.DisassembleIn) -> s.DisassembleOut:
    """Disassemble a bounded range or function."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.start is not None:
        v.parse_address(args.start)
    if args.function is not None:
        v.validate_name(args.function)
    if args.start is None and args.function is None:
        raise _require("either 'start' or 'function' must be provided")
    return ctx.port.disassemble(args.session_id, args)


def _handle_get_pcode(ctx: ToolContext, args: s.GetPcodeIn) -> s.GetPcodeOut:
    """List lifted low p-code for a bounded range or function (read-only — ADR-052)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.start is not None:
        v.parse_address(args.start)
    if args.function is not None:
        v.validate_name(args.function)
    if args.start is None and args.function is None:
        raise _require("either 'start' or 'function' must be provided")
    return ctx.port.get_pcode(args.session_id, args)


def _handle_get_high_pcode(ctx: ToolContext, args: s.GetHighPcodeIn) -> s.GetHighPcodeOut:
    """Return a function's decompiler-refined high (SSA) p-code (read-only — ADR-053)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.get_high_pcode(args.session_id, args)


def _handle_data_flow_slice(ctx: ToolContext, args: s.DataFlowSliceIn) -> s.DataFlowSliceOut:
    """Return a bounded intra-function def-use slice from a seed (read-only — ADR-064)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.data_flow_slice(args.session_id, args)


def _handle_recover_struct(ctx: ToolContext, args: s.RecoverStructIn) -> s.RecoverStructOut:
    """Propose a struct layout from access patterns off a base pointer (read-only — ADR-069)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.recover_struct(args.session_id, args)


def _handle_deobfuscate_strings(
    ctx: ToolContext, args: s.DeobfuscateStringsIn
) -> s.DeobfuscateStringsOut:
    """Recover hidden (stack-string) strings from a function/program scan (read-only — ADR-068)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.function is not None:
        v.validate_name(args.function)
    return ctx.port.deobfuscate_strings(args.session_id, args)


def _handle_stack_frame(ctx: ToolContext, args: s.StackFrameIn) -> s.StackFrameOut:
    """Return a function's recovered stack-frame layout (read-only — ADR-054)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.stack_frame(args.session_id, args)


def _handle_basic_blocks(ctx: ToolContext, args: s.BasicBlocksIn) -> s.BasicBlocksOut:
    """Return a function's basic blocks + successor edges (read-only — ADR-055)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.basic_blocks(args.session_id, args)


def _handle_list_data_types(ctx: ToolContext, args: s.ListDataTypesIn) -> s.DataTypeListOut:
    """List the program's data types, paginated (read-only — ADR-056)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.name_contains is not None:
        v.validate_name(args.name_contains)
    return ctx.port.list_data_types(args.session_id, args)


def _handle_function_hash(ctx: ToolContext, args: s.FunctionHashIn) -> s.FunctionHashOut:
    """Return a function's Ghidra match-hash fingerprints (read-only — ADR-057)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.function_hash(args.session_id, args)


def _handle_bsim_similarity(ctx: ToolContext, args: s.BsimSimilarityIn) -> s.BsimSimilarityOut:
    """Return the BSim cosine similarity between two functions (read-only — ADR-058)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function_a)
    v.validate_name(args.function_b)
    return ctx.port.bsim_similarity(args.session_id, args)


def _handle_find_similar_functions(
    ctx: ToolContext, args: s.FindSimilarFunctionsIn
) -> s.FindSimilarFunctionsOut:
    """Rank the program's functions by BSim similarity to a target (read-only — ADR-059)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.find_similar_functions(args.session_id, args)


def _handle_version_track(ctx: ToolContext, args: s.VersionTrackIn) -> s.VersionTrackOut:
    """Correlate functions between two confined binaries via Ghidra VT (read-only — ADR-060).

    Loads + analyzes TWO binaries in the session's worker (a capability, gated exactly like
    ``session_import``: confined import root + size cap, worker-only per ADR-001), so — like import
    — it ensures the owning principal's worker is spawned. It does NOT touch the session's own
    program (both refs are loaded fresh + wiped), so it needs no write-consent on the session
    (ADR-060 D3/D7). The two ``source_ref``s are confined + size-capped server-side in the adapter
    (CWE-22/CWE-400) — the handler does not path-validate them here.
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    # Spawn the session's hardened worker if not already up (owner-scoped, ADR-017): version_track
    # loads its own binaries and does not require a prior session_import, so the worker may not
    # exist yet. Idempotent when a worker is already running for the session.
    ctx.sessions.ensure_worker(args.session_id, caller=ctx.caller_id)
    return ctx.port.version_track(args.session_id, args)


def _handle_binary_diff(ctx: ToolContext, args: s.BinaryDiffIn) -> s.BinaryDiffOut:
    """Function-granularity diff of two confined binaries (read-only — ADR-067).

    Loads + analyzes TWO binaries in the session's worker (a capability, gated exactly like
    ``session_import``/``version_track``: confined import root + size cap, worker-only per ADR-001).
    Like version_track it ensures the owning principal's worker is spawned (it loads its own
    binaries, no prior session_import needed) and does NOT touch the session's own program (refs
    are loaded fresh + wiped), so it needs no write-consent. The two refs are confined + size-capped
    server-side in the adapter (CWE-22/CWE-400).
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    ctx.sessions.ensure_worker(args.session_id, caller=ctx.caller_id)
    return ctx.port.binary_diff(args.session_id, args)


def _handle_bsim_search_corpus(
    ctx: ToolContext, args: s.BsimSearchCorpusIn
) -> s.BsimSearchCorpusOut:
    """Cross-binary BSim search over an ephemeral corpus (read-only w.r.t. the session — ADR-062).

    Loads + analyzes the target + a bounded reference corpus in the session's worker (a capability,
    gated like ``session_import``: confined import root + size cap, worker-only per ADR-001), so —
    like import/version_track — it ensures the owning principal's worker. It does NOT touch the
    session's own program (all binaries are fresh throwaways), so it needs no write-consent. Every
    ``target_ref``/``reference_refs`` path is confined + size-capped server-side in the adapter
    (CWE-22/CWE-400) — the handler does not path-validate them here.
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    ctx.sessions.ensure_worker(args.session_id, caller=ctx.caller_id)
    return ctx.port.bsim_search_corpus(args.session_id, args)


def _handle_list_functions(ctx: ToolContext, args: s.ListFunctionsIn) -> s.FunctionListOut:
    """List functions (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.name_contains is not None:
        v.validate_name(args.name_contains)
    return ctx.port.list_functions(args.session_id, args)


def _handle_get_function(ctx: ToolContext, args: s.GetFunctionIn) -> s.FunctionDetail:
    """Get one function's detail."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.get_function(args.session_id, args)


# =====================================================================================
# Cross-reference handlers
# =====================================================================================
def _handle_xrefs_to(ctx: ToolContext, args: s.XrefsIn) -> s.XrefsOut:
    """References TO a target."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.target)
    return ctx.port.xrefs_to(args.session_id, args)


def _handle_xrefs_from(ctx: ToolContext, args: s.XrefsIn) -> s.XrefsOut:
    """References FROM a target."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.target)
    return ctx.port.xrefs_from(args.session_id, args)


# =====================================================================================
# Strings / symbols / data / types handlers
# =====================================================================================
def _handle_list_strings(ctx: ToolContext, args: s.ListStringsIn) -> s.StringListOut:
    """List defined strings (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.list_strings(args.session_id, args)


def _handle_list_symbols(ctx: ToolContext, args: s.ListSymbolsIn) -> s.SymbolListOut:
    """List symbols (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.name_contains is not None:
        v.validate_name(args.name_contains)
    return ctx.port.list_symbols(args.session_id, args)


def _handle_get_symbol(ctx: ToolContext, args: s.GetSymbolIn) -> s.Symbol:
    """Resolve one symbol by name or address."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.identifier)
    return ctx.port.get_symbol(args.session_id, args)


def _handle_list_data(ctx: ToolContext, args: s.ListDataIn) -> s.DataListOut:
    """List defined data (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.list_data(args.session_id, args)


def _handle_get_data_type(ctx: ToolContext, args: s.GetDataTypeIn) -> s.DataType:
    """Resolve one data type by name."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.name)
    return ctx.port.get_data_type(args.session_id, args)


# =====================================================================================
# Comments handler (read-only)
# =====================================================================================
def _handle_get_comments(ctx: ToolContext, args: s.GetCommentsIn) -> s.CommentListOut:
    """Read comments (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.address is not None:
        v.parse_address(args.address)
    return ctx.port.get_comments(args.session_id, args)


# =====================================================================================
# Memory / bytes / search handlers
# =====================================================================================
def _handle_memory_map(ctx: ToolContext, args: s.MemoryMapIn) -> s.MemoryMapOut:
    """List memory blocks/segments."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.memory_map(args.session_id, args)


def _handle_read_bytes(ctx: ToolContext, args: s.ReadBytesIn) -> s.ReadBytesOut:
    """Bounded raw byte read (offset/length overflow-guarded before the worker)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    offset = v.parse_address(args.address)
    v.validate_byte_range(offset, args.length)
    return ctx.port.read_bytes(args.session_id, args)


def _handle_emulate(ctx: ToolContext, args: s.EmulateIn) -> s.EmulateOut:
    """Bounded p-code emulation (ADR-049) — read-effect-only; addresses validated pre-worker.

    The schema already bounds step/region/size caps; here we authorize the session (BOLA) and
    parse-check every address the client supplied (start/stop_at/write+read memory) so a malformed
    address fails closed as VALIDATION before the worker. The emulator runs a HOSTILE program in a
    p-code interpreter (no native exec / no I/O) bounded by max_steps + the wall-clock kill; the
    output register/memory values are wrapped UNTRUSTED by the adapter (ADR-005).
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.parse_address(args.start)
    if args.stop_at is not None:
        v.parse_address(args.stop_at)
    for write in args.write_memory or ():
        v.parse_address(write.address)
    for read in args.read_memory or ():
        v.parse_address(read.address)
    return ctx.port.emulate(args.session_id, args)


def _handle_demangle(ctx: ToolContext, args: s.DemangleIn) -> s.DemangleOut:
    """Demangle a C++ symbol (ADR-050) — read-only, program-independent, session-authorized.

    The mangled string is HOSTILE binary-derived input; the schema length-bounds it (DoS guard) and
    the worker wall-clock kill backs that. No program is touched; the demangled name is wrapped
    UNTRUSTED by the adapter (ADR-005). Authorization (BOLA) still applies — the caller must own the
    session the mangled symbol came from.
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.demangle(args.session_id, args)


def _handle_search_bytes(ctx: ToolContext, args: s.SearchBytesIn) -> s.SearchBytesOut:
    """Bounded byte-pattern search (pattern validated as hex with optional ``??`` wildcards)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_byte_pattern(args.pattern_hex)
    return ctx.port.search_bytes(args.session_id, args)


def _handle_search_strings(ctx: ToolContext, args: s.SearchStringsIn) -> s.SearchStringsOut:
    """Bounded defined-string search."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_query(args.query)
    return ctx.port.search_strings(args.session_id, args)


# =====================================================================================
# Metadata handler
# =====================================================================================
def _handle_program_metadata(ctx: ToolContext, args: s.ProgramMetadataIn) -> s.ProgramMetadata:
    """High-level program metadata (no binary content beyond format-reported, wrapped fields)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.program_metadata(args.session_id, args)


# =====================================================================================
# Call-graph / semantic-naming handlers (v1.1 — ADR-007; READ-ONLY, output-only)
# =====================================================================================
# These follow the same imperative-shell pattern as the Tier-1 handlers: authorize the session
# (BOLA), apply semantic validation the schema can't express, then delegate to the injected port.
# The graph *extraction* the port performs is worker-only (ADR-001); the leaf-first *ordering* the
# ``analysis_order`` path returns is computed by the PURE server-side core (core.callgraph) inside
# the adapter — no JVM on the server. None of these mutate the Ghidra DB (output-only).
def _handle_call_graph(ctx: ToolContext, args: s.CallGraphIn) -> s.CallGraphOut:
    """Extract the bounded function call adjacency (resolved edges + unresolved callers)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.root is not None:
        v.validate_name(args.root)
    return ctx.port.call_graph(args.session_id, args)


def _handle_callees(ctx: ToolContext, args: s.CalleesIn) -> s.CallNeighborsOut:
    """List the functions a given function directly calls (one hop, paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.callees(args.session_id, args)


def _handle_callers(ctx: ToolContext, args: s.CallersIn) -> s.CallNeighborsOut:
    """List the functions that directly call a given function (one hop, paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.callers(args.session_id, args)


def _handle_analysis_order(ctx: ToolContext, args: s.AnalysisOrderIn) -> s.AnalysisOrderOut:
    """Leaf-first reverse-topological analysis order over the call graph (ADR-007).

    The adjacency is extracted by the worker; the ordering is computed by the pure server-side core
    (:mod:`vivarium.core.callgraph`) within the adapter — no JVM on the server (ADR-001).
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.root is not None:
        v.validate_name(args.root)
    return ctx.port.analysis_order(args.session_id, args)


def _handle_function_context(ctx: ToolContext, args: s.FunctionContextIn) -> s.FunctionContext:
    """Assemble the per-function naming/synthesis context bundle (server-side aggregation)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.function_context(args.session_id, args)


# =====================================================================================
# Tier-2 reporting / metrics handlers (v1.1 — ADR-008). READ-ONLY: authorize → validate → delegate.
# Derivation is pure-core in the adapter; only raw extraction touches the worker (ADR-001).
# =====================================================================================
def _handle_cyclomatic_complexity(
    ctx: ToolContext, args: s.CyclomaticComplexityIn
) -> s.CyclomaticComplexity:
    """McCabe cyclomatic complexity of one function."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    v.validate_name(args.function)
    return ctx.port.cyclomatic_complexity(args.session_id, args)


def _handle_list_imports(ctx: ToolContext, args: s.ListImportsIn) -> s.ImportListOut:
    """List imported symbols/functions (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.list_imports(args.session_id, args)


def _handle_list_exports(ctx: ToolContext, args: s.ListExportsIn) -> s.ExportListOut:
    """List exported symbols/entry points (paginated/bounded)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.list_exports(args.session_id, args)


def _handle_coverage(ctx: ToolContext, args: s.CoverageIn) -> s.CoverageOut:
    """Defined-code/data byte coverage of the program."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.coverage(args.session_id, args)


def _handle_ioc_scan(ctx: ToolContext, args: s.IocScanIn) -> s.IocScanOut:
    """Heuristic IOC scan over defined strings (pure core over list_strings)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.ioc_scan(args.session_id, args)


def _handle_crypto_constant_scan(
    ctx: ToolContext, args: s.CryptoConstantScanIn
) -> s.CryptoConstantScanOut:
    """Heuristic crypto-constant search (signature table over search_bytes)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.crypto_constant_scan(args.session_id, args)


def _handle_secret_scan(ctx: ToolContext, args: s.SecretScanIn) -> s.SecretScanOut:
    """Heuristic firmware-secret scan over defined strings (pure, redacted — ADR-072)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.secret_scan(args.session_id, args)


def _handle_call_graph_metrics(
    ctx: ToolContext, args: s.CallGraphMetricsIn
) -> s.CallGraphMetricsOut:
    """Structural call-graph metrics (pure core over call_graph)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    if args.root is not None:
        v.validate_name(args.root)
    return ctx.port.call_graph_metrics(args.session_id, args)


def _handle_program_summary(ctx: ToolContext, args: s.ProgramSummaryIn) -> s.ProgramSummary:
    """One-shot aggregate triage report (server-side aggregation)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.program_summary(args.session_id, args)


# =====================================================================================
# Function ID library-match identification handler (ADR-042 Phase 1). READ-ONLY: authorize →
# delegate. The matched name/library are binary-derived → Untrusted-wrapped by the adapter; the
# `limit`/`truncated` bound is enforced server-side in the adapter (and mirrored worker-side). No
# semantic input validation is needed beyond the schema bounds (no address/name argument).
# =====================================================================================
def _handle_identify_functions(
    ctx: ToolContext, args: s.IdentifyFunctionsIn
) -> s.IdentifyFunctionsOut:
    """Match functions against library FID databases (best-effort, untrusted hints — ADR-042)."""
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    return ctx.port.identify_functions(args.session_id, args)


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


# =====================================================================================
# Mutation / write handlers (v1.1 — ADR-012). GATED: a session is read-only by default;
# `session_enable_writes` is the single human-in-the-loop consent gate (LLM08). Every write
# handler: authorize + require_write_consent → validate the attacker-influenced inputs → delegate
# to the port (the worker writes inside one transaction) → audit intent + outcome (sizes/flags
# only, NEVER the value or binary content). No handler runs Ghidra in-process (ADR-001).
# =====================================================================================
def _handle_session_enable_writes(
    ctx: ToolContext, args: s.SessionEnableWritesIn
) -> s.SessionWriteStateOut:
    """Grant write consent to a session — the human-in-the-loop mutation gate (ADR-012 §3)."""
    info = ctx.sessions.enable_writes(
        args.session_id, allow_structural=args.allow_structural, caller=ctx.caller_id
    )
    _log.info(
        "tool.session_enable_writes",
        extra={
            "tool": "session_enable_writes",
            "session": args.session_id,
            "allow_structural": args.allow_structural,
        },
    )
    return s.SessionWriteStateOut(
        session_id=args.session_id,
        writes_enabled=info.writes_enabled,
        allow_structural=info.allow_structural,
    )


def _handle_session_disable_writes(
    ctx: ToolContext, args: s.SessionDisableWritesIn
) -> s.SessionWriteStateOut:
    """Revoke write consent for a session (return it to read-only)."""
    info = ctx.sessions.disable_writes(args.session_id, caller=ctx.caller_id)
    _log.info(
        "tool.session_disable_writes",
        extra={"tool": "session_disable_writes", "session": args.session_id},
    )
    return s.SessionWriteStateOut(
        session_id=args.session_id,
        writes_enabled=info.writes_enabled,
        allow_structural=info.allow_structural,
    )


def _handle_session_undo(ctx: ToolContext, args: s.SessionUndoIn) -> s.SessionUndoOut:
    """Undo the last committed mutation transaction (requires write consent — ADR-012 §4)."""
    ctx.sessions.require_write_consent(args.session_id, caller=ctx.caller_id)
    result = ctx.port.undo(args.session_id, args)
    _log.info(
        "tool.session_undo",
        extra={"tool": "session_undo", "session": args.session_id, "undone": result.undone},
    )
    return result


def _handle_rename_function(ctx: ToolContext, args: s.RenameFunctionIn) -> s.RenameResult:
    """Rename one function (write; gated by consent + write-name allow-list — ADR-012)."""
    ctx.sessions.require_write_consent(args.session_id, caller=ctx.caller_id)
    v.validate_write_name(args.new_name)  # reject attacker-influenced markup/path/etc.
    _log.info(
        "tool.rename_function.intent",
        extra={
            "tool": "rename_function",
            "session": args.session_id,
            "target_len": len(args.function),
            "new_name_len": len(args.new_name),
        },
    )
    result = ctx.port.rename_function(args.session_id, args)
    _log.info(
        "tool.rename_function.outcome",
        extra={"tool": "rename_function", "session": args.session_id, "applied": result.applied},
    )
    return result


def _handle_rename_symbol(ctx: ToolContext, args: s.RenameSymbolIn) -> s.RenameSymbolResult:
    """Rename one data/label/global symbol (write; gated by consent + allow-list — ADR-012)."""
    ctx.sessions.require_write_consent(args.session_id, caller=ctx.caller_id)
    v.validate_write_name(args.new_name)
    _log.info(
        "tool.rename_symbol.intent",
        extra={
            "tool": "rename_symbol",
            "session": args.session_id,
            "target_len": len(args.identifier),
            "new_name_len": len(args.new_name),
        },
    )
    result = ctx.port.rename_symbol(args.session_id, args)
    _log.info(
        "tool.rename_symbol.outcome",
        extra={"tool": "rename_symbol", "session": args.session_id, "applied": result.applied},
    )
    return result


def _handle_set_comment(ctx: ToolContext, args: s.SetCommentIn) -> s.SetCommentResult:
    """Set or clear one comment (write; gated; text normalized on the way in — ADR-012)."""
    ctx.sessions.require_write_consent(args.session_id, caller=ctx.caller_id)
    v.parse_address(args.address)  # validate/confine the target address (CWE-22/190)
    if args.text is not None:
        # Normalize the attacker-influenced comment on the way IN (stored-injection defense);
        # write the normalized value, not the raw input (the frozen model is copied).
        args = args.model_copy(update={"text": v.validate_comment_text(args.text)})
    _log.info(
        "tool.set_comment.intent",
        extra={
            "tool": "set_comment",
            "session": args.session_id,
            "comment_type": args.comment_type,
            "text_len": 0 if args.text is None else len(args.text),
            "clears": args.text is None,
        },
    )
    result = ctx.port.set_comment(args.session_id, args)
    if result.applied:
        # Record (or, on a clear, drop) the comment TARGET in the session change-log so export reads
        # only this session's authored comments — never auto-generated ones (ADR-027 D2). Identity
        # key only: the worker-normalized address + the closed-vocabulary slot — NOT the text. A
        # clear (text is None) drops the key. Only on applied=True (rejected writes are not logged).
        ctx.sessions.record_comment_target(
            args.session_id,
            address=result.address,
            comment_type=result.comment_type,
            cleared=args.text is None,
            caller=ctx.caller_id,
        )
    _log.info(
        "tool.set_comment.outcome",
        extra={"tool": "set_comment", "session": args.session_id, "applied": result.applied},
    )
    return result


# --- structural writes (v1.1 — ADR-013 Phase A). Same gate as annotation writes PLUS the
# allow_structural opt-in (require_write_consent(structural=True)); name-only (no type change).
def _handle_rename_local_variable(
    ctx: ToolContext, args: s.RenameLocalVariableIn
) -> s.StructuralRenameResult:
    """Rename a function-local variable (structural; gated by allow_structural — ADR-013)."""
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    v.validate_name(args.function)  # function selector (read-path baseline)
    v.validate_target_ref(args.variable)  # local selector (bounded, control-free)
    v.validate_write_name(args.new_name)  # persisted name → strict allow-list
    _log.info(
        "tool.rename_local_variable.intent",
        extra={
            "tool": "rename_local_variable",
            "session": args.session_id,
            "function_len": len(args.function),
            "variable_len": len(args.variable),
            "new_name_len": len(args.new_name),
        },
    )
    result = ctx.port.rename_local_variable(args.session_id, args)
    _log.info(
        "tool.rename_local_variable.outcome",
        extra={
            "tool": "rename_local_variable",
            "session": args.session_id,
            "applied": result.applied,
        },
    )
    return result


def _handle_rename_parameter(
    ctx: ToolContext, args: s.RenameParameterIn
) -> s.StructuralRenameResult:
    """Rename a function parameter (structural; gated by allow_structural — ADR-013)."""
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    v.validate_name(args.function)
    v.validate_target_ref(args.parameter)
    v.validate_write_name(args.new_name)
    _log.info(
        "tool.rename_parameter.intent",
        extra={
            "tool": "rename_parameter",
            "session": args.session_id,
            "function_len": len(args.function),
            "parameter_len": len(args.parameter),
            "new_name_len": len(args.new_name),
        },
    )
    result = ctx.port.rename_parameter(args.session_id, args)
    _log.info(
        "tool.rename_parameter.outcome",
        extra={"tool": "rename_parameter", "session": args.session_id, "applied": result.applied},
    )
    return result


# --- structural type-aware writes (v1.1 — ADR-014 Phase B). Same gate as Phase A (the
# allow_structural opt-in) PLUS structured-input validation: the signature/type is validated as a
# resolved TypeRef + bounded ParamSpec + closed-vocab convention BEFORE the worker — NO C string is
# parsed (validate_signature / validate_type_ref / validate_calling_convention; ADR-014 §2/§3).
def _handle_set_function_signature(
    ctx: ToolContext, args: s.SetFunctionSignatureIn
) -> s.SetFunctionSignatureResult:
    """Set a function's structured signature (structural; gated by allow_structural — ADR-014)."""
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    v.validate_signature(args)  # function selector + bounded params + resolved TypeRefs + cc
    _log.info(
        "tool.set_function_signature.intent",
        extra={
            "tool": "set_function_signature",
            "session": args.session_id,
            "function_len": len(args.function),
            "param_count": len(args.parameters),
            "has_calling_convention": args.calling_convention is not None,
        },
    )
    result = ctx.port.set_function_signature(args.session_id, args)
    _log.info(
        "tool.set_function_signature.outcome",
        extra={
            "tool": "set_function_signature",
            "session": args.session_id,
            "applied": result.applied,
        },
    )
    return result


def _handle_apply_data_type(ctx: ToolContext, args: s.ApplyDataTypeIn) -> s.ApplyDataTypeResult:
    """Apply a resolvable type at an address (structural; gated by allow_structural — ADR-014)."""
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    v.parse_address(args.address)  # validate/confine the target address (CWE-22/190)
    v.validate_type_ref(args.type)  # resolved TypeRef shape/bounds (worker not-founds an unknown)
    _log.info(
        "tool.apply_data_type.intent",
        extra={
            "tool": "apply_data_type",
            "session": args.session_id,
            "address_len": len(args.address),
            "clear_existing": args.clear_existing,
        },
    )
    result = ctx.port.apply_data_type(args.session_id, args)
    _log.info(
        "tool.apply_data_type.outcome",
        extra={"tool": "apply_data_type", "session": args.session_id, "applied": result.applied},
    )
    return result


def _handle_apply_type_archive(
    ctx: ToolContext, args: s.ApplyTypeArchiveIn
) -> s.ApplyTypeArchiveResult:
    """Apply a bundled type archive's signatures (structural; gated by allow_structural — ADR-051).

    A whole-program structural write: it applies a bundled GDT library's function prototypes to the
    same-named functions. The ``archive`` name is a closed Literal (no arbitrary path — CWE-22); the
    worker resolves it to a ``.gdt`` in the pinned Ghidra install and wraps the apply in one txn
    (``session_undo`` reverts it). No binary-derived value is echoed back (only a count).
    """
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    _log.info(
        "tool.apply_type_archive.intent",
        extra={"tool": "apply_type_archive", "session": args.session_id, "archive": args.archive},
    )
    result = ctx.port.apply_type_archive(args.session_id, args)
    _log.info(
        "tool.apply_type_archive.outcome",
        extra={
            "tool": "apply_type_archive",
            "session": args.session_id,
            "applied": result.applied,
            "functions_updated": result.functions_updated,
        },
    )
    return result


# --- composite-type creation (v1.1 — ADR-015 Phase C). Same gate as Phase B (the allow_structural
# opt-in) PLUS structured-input validation: a composite is validated as a bounded FieldSpec list of
# resolved TypeRefs BEFORE the worker — NO C string is parsed (validate_composite; ADR-015 §2/§4).
# The recursion crux (self-embed) is rejected at the boundary; the worker pre-registers the empty
# type inside one transaction, name-collision-REJECTs, size-checks, and rolls back any failure.
def _handle_define_struct(ctx: ToolContext, args: s.DefineStructIn) -> s.DefineStructResult:
    """Create a new struct from a structured field list (structural; gated — ADR-015)."""
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    v.validate_composite(args, kind="struct")  # name + bounded fields + resolved TypeRefs + no self
    _log.info(
        "tool.define_struct.intent",
        extra={
            "tool": "define_struct",
            "session": args.session_id,
            "name_len": len(args.name),
            "field_count": len(args.fields),
            "packed": args.packed,
        },
    )
    result = ctx.port.define_struct(args.session_id, args)
    if result.applied:
        # Record the created composite NAME in the session change-log so export reads only this
        # session's authored composites — never Ghidra auto-analysis structs (ADR-027 D1 option 2).
        # Identity (the name we set + validated), not a binary-derived value. Only on applied=True.
        ctx.sessions.record_composite_target(
            args.session_id, name=result.name, caller=ctx.caller_id
        )
    _log.info(
        "tool.define_struct.outcome",
        extra={"tool": "define_struct", "session": args.session_id, "applied": result.applied},
    )
    return result


def _handle_define_union(ctx: ToolContext, args: s.DefineUnionIn) -> s.DefineUnionResult:
    """Create a new union from a structured field list (structural; gated — ADR-015)."""
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    v.validate_composite(args, kind="union")  # name + bounded fields + resolved TypeRefs + no self
    _log.info(
        "tool.define_union.intent",
        extra={
            "tool": "define_union",
            "session": args.session_id,
            "name_len": len(args.name),
            "field_count": len(args.fields),
        },
    )
    result = ctx.port.define_union(args.session_id, args)
    if result.applied:
        # Record the created composite NAME in the session change-log (ADR-027 D1 option 2) — see
        # _handle_define_struct. Identity only, applied=True only.
        ctx.sessions.record_composite_target(
            args.session_id, name=result.name, caller=ctx.caller_id
        )
    _log.info(
        "tool.define_union.outcome",
        extra={"tool": "define_union", "session": args.session_id, "applied": result.applied},
    )
    return result


# --- multi-type composite batch (v1.2 — ADR-021). Same structural gate as ADR-015 PLUS the
# batch-aware validator: a batch is validated as a bounded list of per-type-valid composites with
# intra-batch UNIQUE names AND the BY-VALUE CYCLE DETECTOR (validate_types_batch) BEFORE the worker
# — NO C string is parsed. The worker pre-registers ALL empties inside ONE transaction, name-
# collision-REJECTs each, batch-total size-checks, and rolls back the WHOLE batch on any failure.
def _handle_define_types(ctx: ToolContext, args: s.DefineTypesIn) -> s.DefineTypesResult:
    """Create a batch of interdependent composites in one transaction (structural; gated)."""
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    v.validate_types_batch(
        args
    )  # per-type valid + intra-batch unique names + by-value cycle detect
    # Audit the SHAPE only — never field/type contents (those are attacker-influenced and persisted;
    # log opaque sizes/counts — topic-logging-observability, master §5).
    _log.info(
        "tool.define_types.intent",
        extra={
            "tool": "define_types",
            "session": args.session_id,
            "type_count": len(args.types),
            "name_lens": [len(t.name) for t in args.types],
            "field_counts": [len(t.fields) for t in args.types],
        },
    )
    result = ctx.port.define_types(args.session_id, args)
    if result.applied:
        # The batch commits atomically (applied reflects the whole transaction). Record EACH created
        # composite NAME in the session change-log so export reads only this session's authored
        # composites (ADR-027 D1 option 2). Identity (the names we set + validated), not values.
        for defined in result.types:
            ctx.sessions.record_composite_target(
                args.session_id, name=defined.name, caller=ctx.caller_id
            )
    _log.info(
        "tool.define_types.outcome",
        extra={
            "tool": "define_types",
            "session": args.session_id,
            "type_count": len(result.types),
            "applied": result.applied,
        },
    )
    return result


# --- composite deletion (v1.4 — ADR-031). Same structural gate as ADR-015 (write consent +
# allow_structural). The load-bearing safety control is the SERVER-SIDE authority check: only a
# composite THIS session created (recorded in the ADR-027 change-log) may be deleted, so an
# injection can at worst delete the current session's own work — never a Ghidra-recovered/built-in
# type (the redefine-in-use data-poisoning vector ADR-015 §6 rejected). Delete proceeds even if the
# type is in use; dependents revert to undefined and the count is reported (ADR-031 D3).
def _handle_delete_type(ctx: ToolContext, args: s.DeleteTypeIn) -> s.DeleteTypeResult:
    """Delete a session-authored composite by name (structural; gated — ADR-031)."""
    ctx.sessions.require_write_consent(args.session_id, structural=True, caller=ctx.caller_id)
    v.validate_write_name(args.name)  # untrusted lookup key → strict allow-list/bounds
    # Server-side authority (ADR-031 D2): a name that is not session-authored is rejected with NO
    # worker call. NOT_FOUND (not VALIDATION): a value-free "no such session-authored type" that
    # never reveals whether the name exists elsewhere in the program (no information disclosure).
    if not ctx.sessions.is_composite_target(args.session_id, name=args.name, caller=ctx.caller_id):
        raise GhidraMcpError(
            ErrorEnvelope(
                type=ErrorType.NOT_FOUND,
                title="No such session-authored type",
                detail="The named type was not created by this session and cannot be deleted.",
                status=404,
                retryable=False,
            )
        )
    _log.info(
        "tool.delete_type.intent",
        extra={"tool": "delete_type", "session": args.session_id, "name_len": len(args.name)},
    )
    result = ctx.port.delete_type(args.session_id, args)
    if result.deleted:
        # Drop the name from the change-log so a later export never references a deleted type and
        # the name is free to re-create (creation's collision check now passes) — ADR-031 D4.
        ctx.sessions.forget_composite_target(args.session_id, name=args.name, caller=ctx.caller_id)
    _log.info(
        "tool.delete_type.outcome",
        extra={
            "tool": "delete_type",
            "session": args.session_id,
            "deleted": result.deleted,
            "dependents_reverted": result.dependents_reverted,
        },
    )
    return result


# =====================================================================================
# Cross-session annotation persistence (v1.2 — ADR-018; TB8). Export is READ-ONLY + owner-scoped;
# import is the NEW trust boundary: a client-supplied, offline-tamperable document REPLAYED as
# writes. Import adds NO new write primitive — it schema-validates → hash-verifies → consent-gates →
# (per entry) re-validates via the live validators → replays via the EXISTING write handlers (each
# its own Ghidra transaction). The server persists nothing (stateless — ADR-002 preserved).
# =====================================================================================
def _handle_session_export_annotations(
    ctx: ToolContext, args: s.SessionExportAnnotationsIn
) -> s.SessionExportAnnotationsOut:
    """Read out the session's USER_DEFINED annotations (read-only, owner-scoped — ADR-018).

    No write consent (it is a read). Owner-scoped via ``authorize`` (a foreign id is BOLA-safe
    ``SESSION_INVALID``). The adapter wraps binary-derived strings as ``Untrusted`` and the worker
    bounds the entry count; here the server overlays the session's authoritative program hash as the
    document's ``binary.sha256`` binding (never trusting the worker for the binding key).
    """
    info = ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    # Read the session's change-log (ADR-027 D4): comments + composites authored by THIS session's
    # gated write tools. Export reads ONLY these targets (identity keys, no values) instead of
    # blind-enumerating, which over-included Ghidra auto-analysis content (F7). Symbols/signatures
    # stay source-type-enumerated worker-side (steps 2-4 unchanged). The targets are server-built;
    # the client never influences which targets are read (owner-scoped via authorize above).
    comment_targets, composite_targets = ctx.sessions.export_targets(
        args.session_id, caller=ctx.caller_id
    )
    targets = s.ExportTargets(
        comments=[
            # The change-log only ever stores the closed comment-slot vocabulary (recorded from a
            # validated SetCommentResult.comment_type); cast narrows str→Literal at this boundary.
            s.ExportCommentTarget(
                address=addr,
                comment_type=cast(Literal["EOL", "PRE", "POST", "PLATE", "REPEATABLE"], ctype),
            )
            for addr, ctype in comment_targets
        ],
        composites=list(composite_targets),
    )
    result = ctx.port.export_annotations(args.session_id, args, targets=targets)
    # Overlay the server-authoritative binary hash (the session's recorded program identity) onto
    # the document binding — the worker contributes the annotations, never the binding key. The
    # advisory provenance (``name``/``size``, ADR-018) is filled from the session's recorded import
    # metadata: ``size`` from the (now-surfaced) ``SessionInfo.binary_size`` and ``name`` from the
    # owner-scoped manager accessor. Both are advisory only (the schema docstring states they are
    # never trusted for application); the ``sha256`` binding stays authoritative. No binary parse
    # (ADR-001): all three are server-side metadata.
    document = result.document
    if info.binary_sha256 is not None:
        # ``name`` is the advisory basename label (server-derived from the client-supplied
        # ``source_ref``); the exported field is contractually ``Untrusted[str]`` (ADR-005), so wrap
        # it through the single chokepoint — which also neutralizes any hostile control/bidi/zero-
        # width bytes in a client-chosen filename (CWE-20). Tagged ``BINARY``: on export a value is
        # read back out and treated as untrusted regardless of who authored it (ADR-005; over-
        # tagging advisory provenance is conservative — it is never trusted for application).
        # ``size`` is a safe server scalar (resolved input byte count; no binary parse — ADR-001).
        binary_name = ctx.sessions.binary_name(args.session_id, caller=ctx.caller_id)
        document = document.model_copy(
            update={
                "binary": document.binary.model_copy(
                    update={
                        "sha256": info.binary_sha256,
                        "name": (
                            wrap(binary_name, origin=DataOrigin.BINARY)
                            if binary_name is not None
                            else None
                        ),
                        "size": info.binary_size,
                    }
                )
            }
        )
    _log.info(
        "tool.session_export_annotations",
        extra={
            "tool": "session_export_annotations",
            "session": args.session_id,
            "principal_id": ctx.caller_id,
            "entry_count": len(document.entries),
        },
    )
    return s.SessionExportAnnotationsOut(document=document)


def _import_outcome_reason(exc: GhidraMcpError) -> str:
    """Map a per-entry replay error to a short, safe outcome reason (never echoes a value).

    Args:
        exc: The :class:`GhidraMcpError` raised by re-validation or the replay handler.

    Returns:
        A short, safe reason slug (the envelope's error-type value — closed vocabulary).
    """
    return exc.envelope.type.value


# Per-``kind`` replay: each lambda re-validates the entry via the SAME live validator the write tool
# uses, then delegates to the EXISTING write handler — proving import adds NO new write primitive.
# (The handlers themselves re-check consent + re-validate; the explicit validate call here is the
# fail-fast per-entry boundary pass that the outcome report needs to classify a rejection.)
def _replay_entry(ctx: ToolContext, sid: str, entry: s.Entry) -> None:
    """Re-validate ONE document entry then replay it via the existing gated write handler (ADR-018).

    Re-validates through :func:`vivarium.core.validation.validate_entry` (the live validators),
    then reconstructs the entry's matching ``*In`` model and calls the EXISTING write handler — no
    new write primitive, no new worker RPC. Each handler opens its own Ghidra transaction (rollback
    on failure). The document supplies only proposed writes; nothing in it is trusted.

    Args:
        ctx: Injected collaborators.
        sid: The (already-authorized, hash-bound, consent-checked) target session id.
        entry: One typed :class:`Entry` from the validated document.

    Raises:
        GhidraMcpError: ``VALIDATION``/``NOT_FOUND``/``ANALYSIS_FAILED``/... from re-validation or
            the replayed write (mapped to a per-entry outcome by the caller).
    """
    v.validate_entry(entry)  # live re-validation (the same validators the write tools use)
    if isinstance(entry, s.RenameFunctionEntry):
        _handle_rename_function(
            ctx,
            s.RenameFunctionIn(session_id=sid, function=entry.function, new_name=entry.new_name),
        )
    elif isinstance(entry, s.RenameSymbolEntry):
        _handle_rename_symbol(
            ctx,
            s.RenameSymbolIn(session_id=sid, identifier=entry.identifier, new_name=entry.new_name),
        )
    elif isinstance(entry, s.RenameLocalVariableEntry):
        _handle_rename_local_variable(
            ctx,
            s.RenameLocalVariableIn(
                session_id=sid,
                function=entry.function,
                variable=entry.variable,
                new_name=entry.new_name,
            ),
        )
    elif isinstance(entry, s.RenameParameterEntry):
        _handle_rename_parameter(
            ctx,
            s.RenameParameterIn(
                session_id=sid,
                function=entry.function,
                parameter=entry.parameter,
                new_name=entry.new_name,
            ),
        )
    elif isinstance(entry, s.SetCommentEntry):
        _handle_set_comment(
            ctx,
            s.SetCommentIn(
                session_id=sid,
                address=entry.address,
                comment_type=entry.comment_type,
                text=entry.text,
            ),
        )
    elif isinstance(entry, s.SetFunctionSignatureEntry):
        _handle_set_function_signature(
            ctx,
            s.SetFunctionSignatureIn(
                session_id=sid,
                function=entry.function,
                return_type=entry.return_type,
                parameters=entry.parameters,
                calling_convention=entry.calling_convention,
            ),
        )
    elif isinstance(entry, s.ApplyDataTypeEntry):
        _handle_apply_data_type(
            ctx,
            s.ApplyDataTypeIn(
                session_id=sid,
                address=entry.address,
                type=entry.type,
                clear_existing=entry.clear_existing,
            ),
        )
    elif isinstance(entry, s.DefineTypesEntry):
        # ADR-032: replay the interdependent-composite batch via the existing define_types handler
        # (pre-registration resolves mutually-recursive pointers + any ordering). The live handler
        # re-checks structural consent + validate_types_batch + one worker transaction.
        _handle_define_types(ctx, s.DefineTypesIn(session_id=sid, types=entry.types))
    elif isinstance(entry, s.DefineStructEntry):
        _handle_define_struct(
            ctx,
            s.DefineStructIn(
                session_id=sid, name=entry.name, fields=entry.fields, packed=entry.packed
            ),
        )
    else:  # DefineUnionEntry — the union is exhaustive (the discriminated union admits no other)
        _handle_define_union(
            ctx, s.DefineUnionIn(session_id=sid, name=entry.name, fields=entry.fields)
        )


def _handle_session_import_annotations(
    ctx: ToolContext, args: s.SessionImportAnnotationsIn
) -> s.SessionImportAnnotationsOut:
    """Replay an untrusted annotation document into a same-binary session (the TB8 path — ADR-018).

    The new trust boundary. In order, fail-closed: (a) **schema-validate** the document (version,
    bounds, hash presence, every entry re-validated); (b) **verify the hash binding** —
    ``document.binary.sha256`` must equal the session's recorded program hash, else fail closed; (c)
    **gate on write consent** (and, if any entry is structural, ``allow_structural``) exactly like a
    live write; (d) **per entry**: re-validate + replay via the existing gated write handler (its
    own Ghidra transaction); (e) return a per-entry outcome report; **audit** count + principal +
    session + per-entry outcome (sizes/flags only — never the imported values).
    """
    sid = args.session_id
    document = args.document
    # (a) Schema-validate the FULLY-untrusted document (version, bounds, hash presence, per-entry
    #     re-validation via the live validators) — fail closed on anything unexpected.
    v.validate_annotation_document(document)
    # (b) Authorize (owner-scoped, BOLA-safe) + verify the binary-hash binding. A document minted
    #     for a different/forged binary is meaningless and dangerous → fail closed.
    info = ctx.sessions.authorize(sid, caller=ctx.caller_id)
    if info.binary_sha256 is None or info.binary_sha256.lower() != document.binary.sha256.lower():
        raise GhidraMcpError(
            ErrorEnvelope(
                type=ErrorType.VALIDATION,
                title="Invalid arguments",
                detail="annotation document does not match this session's binary",
                status=400,
                retryable=False,
            )
        )
    # (c) Consent gate — exactly like live writes (LLM08): write consent always; allow_structural
    #     additionally when ANY entry is structural (importing does not bypass the human gate).
    has_structural = any(e.kind in s.STRUCTURAL_ENTRY_KINDS for e in document.entries)
    ctx.sessions.require_write_consent(sid, caller=ctx.caller_id)
    if has_structural:
        ctx.sessions.require_write_consent(sid, structural=True, caller=ctx.caller_id)
    # (d) Per-entry re-validate + replay via the EXISTING gated write handlers (best-effort; each
    #     its own transaction). A per-entry failure is recorded, not fatal (matches the per-write
    #     transaction model). A non-GhidraMcpError is unexpected and propagates (fail closed).
    outcomes: list[s.ImportedEntryOutcome] = []
    applied_count = 0
    for index, entry in enumerate(document.entries):
        try:
            _replay_entry(ctx, sid, entry)
        except GhidraMcpError as exc:
            outcomes.append(
                s.ImportedEntryOutcome(
                    index=index, kind=entry.kind, applied=False, reason=_import_outcome_reason(exc)
                )
            )
            continue
        applied_count += 1
        outcomes.append(s.ImportedEntryOutcome(index=index, kind=entry.kind, applied=True))
    total = len(document.entries)
    # (e) Audit: count + principal + session + per-entry outcome — sizes/flags only, never values.
    _log.info(
        "tool.session_import_annotations",
        extra={
            "tool": "session_import_annotations",
            "session": sid,
            "principal_id": ctx.caller_id,
            "total": total,
            "applied": applied_count,
            "rejected": total - applied_count,
            "had_structural": has_structural,
        },
    )
    return s.SessionImportAnnotationsOut(
        session_id=sid,
        total=total,
        applied=applied_count,
        rejected=total - applied_count,
        outcomes=outcomes,
    )


# =====================================================================================
# Streaming extraction (ADR-040 — pull-based job + cursor; READ-ONLY, output-only)
# =====================================================================================
# Each handler follows the catalog pattern: validate (pydantic, done by dispatch) → BOLA authorize
# (the session-ownership chokepoint) → enforce caps BEFORE delegation → delegate to the port (which
# delegates to the injected StreamingJobManager — itself re-authorizing) → map the SERVER-SIDE
# result shape to the FROZEN client-facing ``*Out``. The double authorize (handler + manager) is
# defense in depth / complete mediation; the per-chunk untrusted envelope is preserved by passing
# the already-``Untrusted``-wrapped fields straight through (never unwrapped here).
#
# Worker incremental emit is increment 2b: against a real worker the port's ``decompile_stream``
# fails closed ``worker-unavailable`` (no chunks produced); these handlers + the job machinery are
# exercised hermetically via ``FakeGhidraPort``'s deterministic synthetic stream.


def _to_server_stream_start(args: s.StartDecompileStreamIn) -> st.DecompileStreamIn:
    """Translate the client ``start_decompile_stream`` args to the server-side start shape.

    The client names a function set (or omits it for "all"). When an explicit set is supplied, the
    names are forwarded so the worker decompiles EXACTLY those (real name-filtering — increment 2b)
    and the produced-chunk bound equals the (already length-capped) list length. When omitted, the
    server-side producer windows the program's functions by ``offset``/``limit`` (the decompile
    total cap applies).

    Args:
        args: The validated client-facing start arguments.

    Returns:
        The server-side :class:`vivarium.jobs.streaming.DecompileStreamIn` for the adapter.
    """
    if args.functions is not None:
        return st.DecompileStreamIn(
            session_id=args.session_id,
            offset=0,
            limit=len(args.functions),
            functions=list(args.functions),
        )
    return st.DecompileStreamIn(session_id=args.session_id)


def _handle_start_decompile_stream(
    ctx: ToolContext, args: s.StartDecompileStreamIn
) -> s.JobStartOut:
    """Start a bulk-decompile streaming job; return its opaque handle + initial state (ADR-040).

    Authorizes the session (BOLA), bounds the requested function set BEFORE delegating, starts the
    job (the manager enforces one-active-job-per-session under the bounded buffer), then snapshots
    status to report the initial state + total estimate — never any binary content.

    Args:
        ctx: Injected collaborators.
        args: The validated client-facing start arguments.

    Returns:
        A :class:`vivarium.tools.schemas.JobStartOut` with the handle, total estimate, and state.

    Raises:
        GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe), ``LIMIT_EXCEEDED`` (already active), or
            ``WORKER_UNAVAILABLE`` (streaming off / worker emit not wired this increment).
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    server_args = _to_server_stream_start(args)
    job_id = ctx.port.start_decompile_stream(args.session_id, server_args, caller=ctx.caller_id)
    handle = st.JobHandleIn(session_id=args.session_id, job_id=job_id)
    status = ctx.port.job_status(args.session_id, handle, caller=ctx.caller_id)
    return s.JobStartOut(
        job=job_id,
        total_estimate=status.total,
        state=status.state.value,
    )


def _handle_fetch_job_results(ctx: ToolContext, args: s.FetchJobResultsIn) -> s.JobResultsOut:
    """Pull the next bounded, ordered batch of chunks by cursor (ADR-040 fetch).

    Authorizes the session (BOLA), then delegates to the job manager (which re-authorizes + verifies
    the job belongs to the session). The fetch ``limit`` is already pydantic-bounded (default 32,
    max 256). Each chunk's binary-derived fields stay :class:`Untrusted` — passed straight through
    into the client ``DecompiledChunk`` (the per-chunk envelope rule, never unwrapped).

    Args:
        ctx: Injected collaborators.
        args: The validated client-facing fetch arguments.

    Returns:
        A :class:`vivarium.tools.schemas.JobResultsOut` batch + resume cursor + terminality.

    Raises:
        GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe), ``VALIDATION`` (cursor ahead of stream), or
            ``WORKER_UNAVAILABLE`` (streaming off).
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    result = ctx.port.fetch_job_results(
        args.session_id,
        st.FetchJobResultsIn(
            session_id=args.session_id, job_id=args.job, cursor=args.cursor, limit=args.limit
        ),
        caller=ctx.caller_id,
    )
    chunks = [
        s.DecompiledChunk(
            seq=c.seq,
            address=c.function.address,
            name=c.function.name,
            code=c.function.c_code,
            signature=c.function.signature,
        )
        for c in result.chunks
    ]
    # `truncated` (the requested set exceeded the decompile total cap and was honestly bounded —
    # ADR-040 D8) is now wired through from the worker's terminal summary via the job's shared
    # terminal holder (increment 2b); the count cap is also enforced at input validation, never
    # silently cut.
    return s.JobResultsOut(
        chunks=chunks,
        next_cursor=result.cursor,
        done=result.done,
        truncated=result.truncated,
    )


def _handle_job_status(ctx: ToolContext, args: s.JobStatusIn) -> s.JobStatusOut:
    """Return a job's server-authored status — counters/state only, NO binary content (ADR-040).

    Authorizes the session (BOLA), delegates to the manager (re-authorizes + verifies ownership),
    and maps the server-side status to the client shape. No binary-derived field is ever present.

    Args:
        ctx: Injected collaborators.
        args: The validated client-facing status arguments.

    Returns:
        A :class:`vivarium.tools.schemas.JobStatusOut` snapshot.

    Raises:
        GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) or ``WORKER_UNAVAILABLE`` (no stream).
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    handle = st.JobHandleIn(session_id=args.session_id, job_id=args.job)
    status = ctx.port.job_status(args.session_id, handle, caller=ctx.caller_id)
    return s.JobStatusOut(
        state=status.state.value,
        phase=status.state.value,
        done=status.state in st._TERMINAL_STATES,
        total=status.total,
        buffered=status.buffered,
        eta_seconds=status.eta_seconds,
        started_at=status.elapsed_seconds,
    )


def _handle_cancel_job(ctx: ToolContext, args: s.CancelJobIn) -> s.CancelJobOut:
    """Cancel a job (free the worker early); return an idempotent terminal ack (ADR-040).

    Authorizes the session (BOLA), delegates to the manager (re-authorizes + verifies ownership),
    which marks the job cancelled, discards its buffer, and clears the active-job slot. Idempotent.

    Args:
        ctx: Injected collaborators.
        args: The validated client-facing cancel arguments.

    Returns:
        A :class:`vivarium.tools.schemas.CancelJobOut` with ``cancelled=True`` (job now terminal).

    Raises:
        GhidraMcpError: ``SESSION_INVALID`` (BOLA-safe) or ``WORKER_UNAVAILABLE`` (no stream).
    """
    ctx.sessions.authorize(args.session_id, caller=ctx.caller_id)
    handle = st.JobHandleIn(session_id=args.session_id, job_id=args.job)
    status = ctx.port.cancel_job(args.session_id, handle, caller=ctx.caller_id)
    return s.CancelJobOut(cancelled=status.state in st._TERMINAL_STATES)


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
    "get_pcode": (_handle_get_pcode, s.GetPcodeIn),
    "get_high_pcode": (_handle_get_high_pcode, s.GetHighPcodeIn),
    "data_flow_slice": (_handle_data_flow_slice, s.DataFlowSliceIn),
    "recover_struct": (_handle_recover_struct, s.RecoverStructIn),
    "deobfuscate_strings": (_handle_deobfuscate_strings, s.DeobfuscateStringsIn),
    "stack_frame": (_handle_stack_frame, s.StackFrameIn),
    "basic_blocks": (_handle_basic_blocks, s.BasicBlocksIn),
    "list_data_types": (_handle_list_data_types, s.ListDataTypesIn),
    "function_hash": (_handle_function_hash, s.FunctionHashIn),
    "bsim_similarity": (_handle_bsim_similarity, s.BsimSimilarityIn),
    "find_similar_functions": (_handle_find_similar_functions, s.FindSimilarFunctionsIn),
    "version_track": (_handle_version_track, s.VersionTrackIn),
    "binary_diff": (_handle_binary_diff, s.BinaryDiffIn),
    "bsim_search_corpus": (_handle_bsim_search_corpus, s.BsimSearchCorpusIn),
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
    "emulate": (_handle_emulate, s.EmulateIn),
    "demangle": (_handle_demangle, s.DemangleIn),
    "search_bytes": (_handle_search_bytes, s.SearchBytesIn),
    "search_strings": (_handle_search_strings, s.SearchStringsIn),
    "program_metadata": (_handle_program_metadata, s.ProgramMetadataIn),
    "call_graph": (_handle_call_graph, s.CallGraphIn),
    "callees": (_handle_callees, s.CalleesIn),
    "callers": (_handle_callers, s.CallersIn),
    "analysis_order": (_handle_analysis_order, s.AnalysisOrderIn),
    "function_context": (_handle_function_context, s.FunctionContextIn),
    "cyclomatic_complexity": (_handle_cyclomatic_complexity, s.CyclomaticComplexityIn),
    "list_imports": (_handle_list_imports, s.ListImportsIn),
    "list_exports": (_handle_list_exports, s.ListExportsIn),
    "coverage": (_handle_coverage, s.CoverageIn),
    "ioc_scan": (_handle_ioc_scan, s.IocScanIn),
    "crypto_constant_scan": (_handle_crypto_constant_scan, s.CryptoConstantScanIn),
    "secret_scan": (_handle_secret_scan, s.SecretScanIn),
    "call_graph_metrics": (_handle_call_graph_metrics, s.CallGraphMetricsIn),
    "program_summary": (_handle_program_summary, s.ProgramSummaryIn),
    # Function ID library-match identification (ADR-042 Phase 1; READ-ONLY)
    "identify_functions": (_handle_identify_functions, s.IdentifyFunctionsIn),
    # mutation / write tools (v1.1 — ADR-012; gated by per-session write-consent)
    "session_enable_writes": (_handle_session_enable_writes, s.SessionEnableWritesIn),
    "session_disable_writes": (_handle_session_disable_writes, s.SessionDisableWritesIn),
    "session_undo": (_handle_session_undo, s.SessionUndoIn),
    "rename_function": (_handle_rename_function, s.RenameFunctionIn),
    "rename_symbol": (_handle_rename_symbol, s.RenameSymbolIn),
    "set_comment": (_handle_set_comment, s.SetCommentIn),
    # structural writes (v1.1 — ADR-013 Phase A; gated additionally by allow_structural)
    "rename_local_variable": (_handle_rename_local_variable, s.RenameLocalVariableIn),
    "rename_parameter": (_handle_rename_parameter, s.RenameParameterIn),
    # structural type-aware writes (v1.1 — ADR-014 Phase B; gated additionally by allow_structural)
    "set_function_signature": (_handle_set_function_signature, s.SetFunctionSignatureIn),
    "apply_data_type": (_handle_apply_data_type, s.ApplyDataTypeIn),
    "apply_type_archive": (_handle_apply_type_archive, s.ApplyTypeArchiveIn),
    # composite-type creation (v1.1 — ADR-015 Phase C; gated additionally by allow_structural)
    "define_struct": (_handle_define_struct, s.DefineStructIn),
    "define_union": (_handle_define_union, s.DefineUnionIn),
    "define_types": (_handle_define_types, s.DefineTypesIn),
    "delete_type": (_handle_delete_type, s.DeleteTypeIn),
    # cross-session annotation persistence (v1.2 — ADR-018; export=read-only, import=gated)
    "session_export_annotations": (
        _handle_session_export_annotations,
        s.SessionExportAnnotationsIn,
    ),
    "session_import_annotations": (
        _handle_session_import_annotations,
        s.SessionImportAnnotationsIn,
    ),
    # streaming extraction (v1.x — ADR-040; READ-ONLY, output-only; pull-based job + cursor)
    "start_decompile_stream": (_handle_start_decompile_stream, s.StartDecompileStreamIn),
    "fetch_job_results": (_handle_fetch_job_results, s.FetchJobResultsIn),
    "job_status": (_handle_job_status, s.JobStatusIn),
    "cancel_job": (_handle_cancel_job, s.CancelJobIn),
}


def build_handlers(ctx: ToolContext) -> dict[str, Callable[..., Any]]:
    """Build the name → bound-handler map for the full Tier-1 catalog.

    Each returned handler closes over ``ctx`` and exposes the tool's input-model **fields** as
    flat keyword parameters (matching how FastMCP invokes a structured tool); it reconstructs and
    re-validates the ``*In`` model internally. Its ``__signature__``/``__annotations__`` are set to
    those fields so the MCP SDK can derive the tool's JSON schema. The map is exhaustive over
    :data:`TIER1_TOOL_NAMES` (asserted below and in tests).

    Args:
        ctx: The injected collaborators (config, session manager, Ghidra port).

    Returns:
        A mapping of tool name to a flat-keyword-arguments handler callable.

    Raises:
        RuntimeError: If the handler table drifts from :data:`TIER1_TOOL_NAMES` (programmer error —
            fail fast at startup).
    """
    if set(_HANDLERS) != set(TIER1_TOOL_NAMES):
        # Fail closed: the allow-list and the handler table MUST be identical.
        raise RuntimeError("tool handler table does not match the frozen Tier-1 allow-list")

    bound: dict[str, Callable[..., Any]] = {}
    for name, (handler, in_schema) in _HANDLERS.items():
        bound[name] = _bind(handler, ctx, in_schema, name)
    # session_analyze is the ONE tool with a localized async binding (ADR-030 Phase 2): it accepts
    # the injected MCP Context and, when a progressToken is present, offloads the blocking analysis
    # to a worker thread and relays worker progress to the client. Every other tool keeps the
    # uniform synchronous flat-kwargs binding above. Replacing it here keeps the special case in one
    # place and out of the generic _bind.
    bound["session_analyze"] = _bind_analyze(ctx)
    return bound


def _progress_token(context: Context[Any, Any, Any] | None) -> Any | None:
    """Return the current request's MCP ``progressToken`` if the client supplied one, else ``None``.

    Reads it from the live FastMCP request context's ``_meta`` (mirrors ``Context.report_progress``
    which no-ops without a token). Defensive: missing context / request-context / meta all fail
    closed to ``None`` (no relay) so a non-FastMCP or token-less call takes the unchanged path.

    Args:
        context: The injected MCP :class:`Context`, or ``None`` (direct/test invocation).

    Returns:
        The opaque progress token, or ``None`` when no client progress was requested.
    """
    if context is None:
        return None
    try:
        meta = context.request_context.meta
    except (AttributeError, ValueError):
        # ValueError: FastMCP raises it from request_context outside a request (defensive).
        return None
    return meta.progressToken if meta is not None else None


def _bind_analyze(ctx: ToolContext) -> Callable[..., Any]:
    """Bind ``session_analyze`` to an async, Context-aware tool callable (ADR-030 Phase 2).

    Like :func:`_bind` it exposes the input model's fields as flat keyword parameters and
    re-validates them into the frozen :class:`~vivarium.tools.schemas.SessionAnalyzeIn`. It adds
    one injected parameter — ``context: Context`` — so FastMCP passes the live request context, and
    the synthesized callable is **async** so the event loop stays free to deliver notifications.

    Behaviour by activation (ratified: async-offload, token-gated):

    - **No ``progressToken``** (stdio, or an HTTP client that didn't ask) → run the handler
      **inline** (synchronously, on the loop) exactly as before Phase 2 — zero change to the
      no-progress path (the loop-blocking analysis is the long-standing behaviour for analyze).
    - **``progressToken`` present** → offload the blocking handler to a worker thread via
      :func:`anyio.to_thread.run_sync` so the loop can flush notifications, and pass a relay that
      bridges each worker progress frame back onto the loop via :func:`anyio.from_thread.run` →
      :meth:`Context.report_progress`. SAFE fields only (percent + closed-vocabulary phase as the
      message); the relay is best-effort (a send failure never aborts the analysis).

    Args:
        ctx: The injected collaborators to close over.

    Returns:
        An async flat-kwargs callable carrying a Context-augmented synthesized signature.
    """
    in_schema = s.SessionAnalyzeIn

    async def _bound(*, context: Context[Any, Any, Any] | None = None, **kwargs: Any) -> Any:
        # Per-tool capability authZ (ADR-033) — analyze requires `read`; checked before any work.
        _authorize_capability(ctx, "session_analyze")
        model = in_schema(**kwargs)
        token = _progress_token(context)
        # In-flight liveness marker (ADR-025 / F4), same contract as _bind: refresh the idle clock
        # for the whole (possibly 18-26 min) call so analyze cannot idle-evict itself. analyze
        # always carries a session_id (required field), so this path always applies.
        ctx.sessions.begin_call(model.session_id, caller=ctx.caller_id)
        try:
            if token is None or context is None:
                # No client progress requested → byte-for-byte the pre-Phase-2 path (sync on loop;
                # the worker still emits log-only frames iff args.progress was set — Phase 1).
                return _handle_session_analyze(ctx, model)

            # Bind the coroutine method here, where ``context`` is narrowed non-None (mypy does not
            # propagate that narrowing into the nested closure below).
            report = context.report_progress

            def _relay(percent: int | None, phase: str) -> None:
                # Bridge the worker-thread callback back onto the event loop to send the MCP
                # notification. percent is None when the worker has no estimate yet → skip (cannot
                # report a number); phase rides along as the (safe, closed-vocabulary) message.
                if percent is None:
                    return
                try:
                    anyio.from_thread.run(functools.partial(report, float(percent), 100.0, phase))
                except Exception:
                    _log.warning("analyze.progress_relay_failed", extra={"tool": "session_analyze"})

            return await anyio.to_thread.run_sync(
                functools.partial(_handle_session_analyze, ctx, model, on_progress=_relay)
            )
        finally:
            ctx.sessions.end_call(model.session_id, caller=ctx.caller_id)

    _bound.__signature__ = _signature_from_model(in_schema, with_context=True)  # type: ignore[attr-defined]
    annotations = _annotations_from_model(in_schema)
    annotations["context"] = Context
    _bound.__annotations__ = annotations
    _bound.__name__ = f"tool_{in_schema.__name__}"
    return _bound


def _bind(
    handler: Callable[[ToolContext, Any], Any],
    ctx: ToolContext,
    in_schema: type[s._In],
    tool_name: str,
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
        tool_name: The catalog name; its :func:`required_capability` is enforced per call (ADR-033).

    Returns:
        A flat-kwargs callable suitable for FastMCP registration.
    """

    def _bound(**kwargs: Any) -> Any:
        # Per-tool capability authZ (ADR-033) — server-side, before any work (complete mediation).
        _authorize_capability(ctx, tool_name)
        # Reconstruct the frozen input model — re-applies all pydantic constraints and rejects any
        # unexpected field (extra="forbid"). A validation failure surfaces as a pydantic error the
        # server shell maps to a VALIDATION envelope (fail closed).
        model = in_schema(**kwargs)
        # In-flight liveness (ADR-025 / F4): mark a session-scoped call in-flight for its whole
        # duration so a long single operation (e.g. an 18-26 min ``analyze``) cannot idle-evict
        # itself. ``begin_call``/``end_call`` are best-effort markers keyed on the session id (the
        # handler's own ``authorize`` remains the sole authorization gate — marking in-flight never
        # grants access); they refresh the idle clock at call start AND end. ``session_create`` and
        # any non-session tool have no ``session_id`` and are skipped. Paired in a ``finally`` so
        # the mark is always cleared even on error (no leaked in-flight blocking future eviction).
        session_id = getattr(model, "session_id", None)
        if session_id is None:
            return handler(ctx, model)
        ctx.sessions.begin_call(session_id, caller=ctx.caller_id)
        try:
            return handler(ctx, model)
        finally:
            ctx.sessions.end_call(session_id, caller=ctx.caller_id)

    _bound.__signature__ = _signature_from_model(in_schema)  # type: ignore[attr-defined]
    _bound.__annotations__ = _annotations_from_model(in_schema)
    _bound.__name__ = f"tool_{in_schema.__name__}"
    return _bound


def _signature_from_model(model: type[s._In], *, with_context: bool = False) -> inspect.Signature:
    """Build a keyword-only signature exposing ``model``'s fields as parameters.

    Required fields (no default) become required keyword-only parameters; optional fields carry
    their default so the SDK marks them optional. Annotations come from the model's field types.

    When ``with_context`` is set, a trailing ``context: Context`` keyword-only parameter is appended
    (ADR-030 Phase 2). FastMCP detects it by annotation (``issubclass(ann, Context)``) and injects
    the live request context while EXCLUDING it from the tool's input JSON schema — so the client
    surface is unchanged. It defaults to ``None`` only to keep the callable directly invokable in
    tests; at runtime FastMCP always supplies the real Context.

    Args:
        model: The pydantic input model.
        with_context: Whether to append the injected ``context`` parameter.

    Returns:
        An :class:`inspect.Signature` whose parameters mirror the model's fields (plus ``context``).
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
    if with_context:
        parameters.append(
            inspect.Parameter(
                "context",
                inspect.Parameter.KEYWORD_ONLY,
                default=None,
                annotation=Context,
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
    wrap: Callable[[str, Callable[..., Any]], Callable[..., Any]] | None = None,
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
