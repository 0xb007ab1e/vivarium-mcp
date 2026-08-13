"""JVM/Ghidra bridge — RUNS ONLY INSIDE THE WORKER CONTAINER (WS2).

WARNING (ADR-001): this module is the ONLY code permitted to touch the JVM / PyGhidra / a binary,
and it executes ONLY INSIDE THE WORKER container — NEVER in the MCP server process. It is
intentionally excluded from server-side coverage (``[tool.coverage.run] omit``) and must never be
imported by ``server``, ``sessions``, ``core``, or ``tools``. An import-linter / test guard (WS5)
enforces this boundary.

Inside the worker it: bootstraps headless Ghidra (12.1.2 / JDK 21), imports + analyzes the binary
under the bridge's own bounds, and serves the internal RPC by mapping requests to Ghidra API calls
and returning structured, size-capped results to the server, which wraps them as untrusted.

Structure (testability without Ghidra): all JVM/PyGhidra symbols are imported **inside functions**
(never at module import time), and each Ghidra-touching operation is a small ``_gh_*`` method on
:class:`PyGhidraBackend`. The JVM-free RPC framing/dispatch/loop lives in :mod:`worker.dispatch`
and :mod:`worker.server`, so the protocol path is unit-tested with a fake backend. The exact
PyGhidra API binding is validated against the pinned image's javadoc at WS3 image build (ADR-003
open item).

A separate worker entrypoint (``worker/`` — WS2/WS3) hosts this bridge and the RPC server loop.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from typing import Any, ClassVar

# Bounds the bridge enforces itself (defense-in-depth; the server also caps before calling).
_MAX_RESULT_COUNT = 10_000
_MAX_READ_BYTES = 1_048_576  # 1 MiB
# Defensive per-instruction ceiling on emitted p-code ops (v1.8 — ADR-052 get_pcode). A SLEIGH
# instruction lifts to a bounded op count, but cap it so one instruction can't balloon the response.
_MAX_PCODE_OPS_PER_INSN = 256
# Max FID match candidates the worker ever returns from identify_functions (v1.x — ADR-042 Phase 1;
# mirrors rpc_client._IDENTIFY_MATCH_BUDGET). Defense-in-depth: the FID service can emit many
# candidates per function on a large binary; the worker clamps + sets truncated, the server caps
# again to the caller's bounded `limit` (CWE-400).
_MAX_IDENTIFY_MATCHES = 10_000
# Call-graph extraction caps (v1.1 — ADR-007): mirror the schema/threat-model §8 ceilings, NOT the
# generic 10k result cap — otherwise the worker would silently clamp even its own 40k edge default
# down to 10k, contradicting the documented contract (the server schema remains authoritative).
_MAX_GRAPH_NODES = 50_000
_MAX_GRAPH_EDGES = 200_000
_MAX_GRAPH_DEPTH = 256
_DEFAULT_MAX_FRAME_BYTES = 4 * 1024 * 1024  # 4 MiB (mirrors security.limits default)
# Composite-type construction caps (v1.1 — ADR-015 §2.5): mirror schemas._MAX_COMPOSITE_SIZE. The
# total computed size of an assembled struct/union is bounded INSIDE the txn after each member's
# DataType.getLength() is known (the running-sum backstop against the recursion/fan-out DoS).
_MAX_COMPOSITE_SIZE = 1_048_576  # 1 MiB
# Max composites in one define_types batch (ADR-021/ADR-032; mirror schemas._MAX_TYPES_PER_BATCH).
# Bounds the export round-trip batch — >64 session-authored composites fail closed (CWE-400).
_MAX_TYPES_PER_BATCH = 64
# Annotation-document schema version the worker emits on export (ADR-018; bumped 1 → 2 in ADR-032 —
# composites round-trip as one define_types batch entry; mirrors schemas.ANNOTATION_SCHEMA_VERSION).
# The server overlays the authoritative binary hash.
_ANNOTATION_SCHEMA_VERSION = 2

# Analyzer-depth profile presets (v1.4 — ADR-029 B). PURE data: a profile → {analyzer-option-name:
# enabled} overlay applied to the program's analysis options BEFORE auto-analysis runs.
#
# DEFAULT-IS-NO-OP guarantee: the ``default`` profile maps to an EMPTY overlay, and the analyze path
# only opens/touches the options object when the overlay is non-empty — so an omitted/``default``
# profile runs the IDENTICAL code path (a bare ``pyghidra.analyze(program)``) as before this
# increment, with Ghidra's stock per-format defaults untouched.
#
# ``light`` DISABLES the most expensive analyzers (the ones that dominate time/heap on a huge
# binary): Decompiler Parameter ID (a full decompile of every function), and the aggressive
# discovery passes (aggressive instruction finder, decompiler switch recovery, embedded-media/
# data-reference scans). ``deep`` ENABLES the fuller set (param ID + the aggressive finders) on top
# of the stock defaults.
#
# REQUIRES-LIVE-VERIFICATION: the exact option NAMES and their on/off semantics are Ghidra 12.1.2
# analyzer labels and MUST be confirmed against the pinned image (the ADR-028 harness + a real-
# worker run) before merge — the strings below are the documented Ghidra analyzer names but the JVM
# is the authority. The option-SETTING call itself is a JVM edge (``# pragma: no cover``); this
# table and its selector are pure and unit-tested.
_PROFILE_DEFAULT = "default"
_PROFILE_PRESETS: dict[str, dict[str, bool]] = {
    # No overlay → stock Ghidra defaults, identical to pre-ADR-029 behaviour (no-op).
    _PROFILE_DEFAULT: {},
    # REQUIRES-LIVE-VERIFICATION (option names + semantics on 12.1.2).
    "light": {
        "Decompiler Parameter ID": False,
        "Aggressive Instruction Finder": False,
        "Decompiler Switch Analysis": False,
        "Embedded Media": False,
        "Create Address Tables": False,
    },
    # REQUIRES-LIVE-VERIFICATION (option names + semantics on 12.1.2).
    "deep": {
        "Decompiler Parameter ID": True,
        "Aggressive Instruction Finder": True,
        "Decompiler Switch Analysis": True,
    },
}


def _analyzer_options_for_profile(profile: str | None) -> dict[str, bool]:
    """Map an analyzer-depth ``profile`` to its option overlay (PURE — ADR-029 B; unit-tested).

    Returns a COPY (callers must not mutate the shared preset). An unknown/``None`` profile falls
    back to the ``default`` (empty) overlay — fail safe: a bad value can only ever yield the stock,
    no-op analysis, never silently weaken or widen it. The default overlay is empty, which the
    analyze path uses to take the byte-for-byte unchanged code path (no options object is touched).

    Args:
        profile: The profile name (``default``/``light``/``deep``), or ``None``.

    Returns:
        A fresh ``{analyzer-option-name: enabled}`` overlay (empty for ``default``/unknown).
    """
    preset = _PROFILE_PRESETS.get(profile or _PROFILE_DEFAULT, _PROFILE_PRESETS[_PROFILE_DEFAULT])
    return dict(preset)


def _missing_profile_options(overlay: dict[str, bool], available: Iterable[str]) -> list[str]:
    """Return preset option names absent from ``available`` (PURE — ADR-035; unit-tested).

    The *decision* half of the analyzer-option existence guard: given a profile ``overlay`` and the
    set of analyzer-option names the running Ghidra build actually exposes, return the overlay names
    that are **not** present (sorted, for a stable diagnostic). An empty result means every preset
    option exists and the overlay is safe to apply. A non-empty result is a fail-closed condition
    (a stale preset vs this Ghidra build — see :meth:`_GhidraSession._gh_analyze`).

    The JVM *enumeration* that produces ``available`` (``Options.getOptionNames()``) is the
    ``# pragma: no cover`` edge; this membership decision is pure and hermetically tested.

    Args:
        overlay: The ``{analyzer-option-name: enabled}`` overlay for the selected profile.
        available: The analyzer-option names the program's analysis options expose.

    Returns:
        The sorted overlay option names missing from ``available`` (empty if all present).
    """
    available_set = set(available)
    return sorted(name for name in overlay if name not in available_set)


def _monitor_percent(value: int, maximum: int) -> int | None:
    """Map a Ghidra ``TaskMonitor`` (value, maximum) to a SAFE percent ``0..100`` (PURE; ADR-030).

    Returns ``None`` when there is no usable denominator (an indeterminate monitor with
    ``maximum <= 0``) so the progress frame honestly reports "no estimate" rather than a fake 0.
    Otherwise clamps ``round(100 * value / maximum)`` into ``[0, 100]`` so a monitor that briefly
    reports value > maximum (Ghidra does, transiently) can never emit an out-of-range percent the
    server would reject (fail closed → never trip the per-frame validation). Pure + unit-tested; the
    monitor object that calls it is the ``# pragma: no cover`` JVM edge.

    Args:
        value: The monitor's current progress value.
        maximum: The monitor's maximum (``<= 0`` means indeterminate).

    Returns:
        A percent in ``0..100``, or ``None`` when no estimate is available.
    """
    if maximum <= 0:
        return None
    percent = round(100 * value / maximum)
    return max(0, min(100, percent))


def _require(params: dict[str, Any], key: str) -> Any:
    """Fetch a required param or raise a worker ``invalid-params`` error.

    Args:
        params: The request params.
        key: The required key.

    Returns:
        The param value.

    Raises:
        WorkerError: ``invalid-params`` if the key is absent.
    """
    from worker.dispatch import CODE_INVALID_PARAMS, WorkerError

    if key not in params:
        raise WorkerError(CODE_INVALID_PARAMS, f"missing required parameter: {key}")
    return params[key]


class PyGhidraBackend:
    """Concrete :class:`worker.dispatch.GhidraBackend` backed by PyGhidra/headless Ghidra.

    Instances hold the open Ghidra program/project for one session. Every method returns a plain,
    JSON-serializable, **size-capped** dict matching the corresponding output schema (the server
    wraps binary-derived fields in the untrusted envelope; the worker returns plain values).

    Note:
        Ghidra API calls are isolated in private ``_gh_*`` helpers that import PyGhidra lazily, so
        the public methods (parameter handling, capping, shaping) are reviewable and the JVM is the
        only un-unit-testable edge. The precise PyGhidra symbol names are confirmed against the
        pinned image (ADR-003) during WS3 worker-image build.
    """

    def __init__(self) -> None:
        """Initialize an empty backend (no program loaded until ``import_binary``)."""
        self._program: Any | None = None
        self._project: Any | None = None
        #: ADR-048: retained ``LoadResults`` from the ProgramLoader builder (fat-slice path) so its
        #: consumer keeps the program alive; ``None`` for the open_program paths.
        self._loaded: Any | None = None
        #: Hex SHA-256 of the imported binary (server-computed digest of input — safe scalar).
        self._sha256: str | None = None
        #: Whether Ghidra auto-analysis has completed for the open program.
        self._analyzed: bool = False

    # --- lifecycle ---------------------------------------------------------------------------
    def import_binary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Import the binary referenced by the (server-confined) source ref into the project.

        Args:
            params: ``{"source_ref": str, "expected_sha256": str | None}`` for the auto path, plus
                the optional ADR-045 loader hints ``{"loader": "binary", "processor": str,
                "base_addr": int, "entry": int | None}`` when the client requested a raw import. The
                server has already resolved/confined the path, enforced the size cap, and validated
                the hint combination + the processor allow-list BEFORE this call; the worker
                re-validates the language against the installed set (defense in depth, ADR-045 §D2).
                When no ``loader`` key is present the call is byte-for-byte the pre-ADR-045 path.

        Returns:
            A plain ``SessionInfo``-shaped dict.
        """
        source_ref = _require(params, "source_ref")
        loader = params.get("loader")
        if loader == "binary":
            return self._gh_import(
                str(source_ref),
                loader="binary",
                processor=str(_require(params, "processor")),
                base_addr=int(_require(params, "base_addr")),
                entry=None if params.get("entry") is None else int(params["entry"]),
            )
        if loader in ("intel-hex", "motorola-hex"):
            # ADR-046: hex loaders need only a processor; addresses come from the records.
            return self._gh_import(
                str(source_ref), loader=str(loader), processor=str(_require(params, "processor"))
            )
        if loader in ("dex", "apk"):
            # ADR-047: self-describing — force the loader; the format supplies processor + layout.
            return self._gh_import(str(source_ref), loader=str(loader))
        if loader == "macho":
            # ADR-047 force + ADR-048 optional fat-slice `processor`.
            proc = params.get("processor")
            return self._gh_import(
                str(source_ref), loader="macho", processor=None if proc is None else str(proc)
            )
        return self._gh_import(str(source_ref))

    def analyze(
        self,
        params: dict[str, Any],
        *,
        emit_progress: Callable[[int | None, str], None] | None = None,
    ) -> dict[str, Any]:
        """Run Ghidra auto-analysis on the imported program.

        Args:
            params: ``{"timeout_seconds": int | None, "profile"?: str, "progress"?: bool}`` — the
                server kills the worker on its own deadline (the timeout is an in-worker budget
                hint); ``profile`` (ADR-029 B; additive, absent for the default) selects the
                analyzer-depth preset; ``progress`` (ADR-030 Phase 1; additive) is the opt-in the
                dispatch reads to decide whether to supply ``emit_progress``.
            emit_progress: Supplied by the dispatch ONLY for an opted-in request (ADR-030 Phase 1).
                When ``None`` (the default, and every non-opted-in call) analysis runs the
                byte-for-byte unchanged bare ``pyghidra.analyze`` with NO progress monitor.

        Returns:
            A plain ``SessionInfo``-shaped dict.
        """
        return self._gh_analyze(
            params.get("timeout_seconds"), params.get("profile"), emit_progress=emit_progress
        )

    # --- read-only operations ----------------------------------------------------------------
    def decompile_function(self, params: dict[str, Any]) -> dict[str, Any]:
        """Decompile one function (by address or name)."""
        return self._gh_decompile(str(_require(params, "function")))

    # --- streaming bulk decompile (v1.x — ADR-040 Phase 2; emits $/chunk per function) ---
    def start_decompile_stream(
        self,
        params: dict[str, Any],
        *,
        emit_chunk: Callable[[int, str, dict[str, Any]], None] | None = None,
        poll_cancel: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        """Stream a bounded bulk decompile, emitting one ``$/chunk`` per function (ADR-040 Phase 2).

        Decompiles the requested function set (an explicit ``functions`` list of addresses/names, or
        a bounded ``offset``/``limit`` window of the program's functions when none is named),
        emitting one ``$/chunk`` (``kind:"function"``) per function via ``emit_chunk`` as it is
        produced, then returns the terminal summary. The per-function decompiler is disposed each
        iteration (the ADR-002 memory discipline). Read-only/output-only (ADR-001).

        Mid-stream cancellation (ADR-041): ``poll_cancel`` is the dispatch-supplied predicate the
        decompile loop consults BETWEEN functions. It is a non-blocking check for a server→worker
        ``$/cancel`` notification; when it returns ``True`` the stream stops at the next function
        boundary and ends with ``done: True`` having emitted the chunks produced so far (an honest
        partial — the server has already marked the job cancelled). The backend calls a plain
        callable only — it NEVER touches the socket (ADR-001: dispatch owns ``conn``). When
        ``poll_cancel`` is ``None`` (a fake/no-poll path) the stream runs to completion.

        Args:
            params: ``{"functions"?: list[str], "offset"?: int, "limit"?: int}`` — server-validated.
            emit_chunk: The dispatch-supplied socket-bound emitter (``None`` for a fake/no-emit
                path, which then produces only the terminal summary).
            poll_cancel: The dispatch-supplied non-blocking cancel poll (``None`` ⇒ never cancels).

        Returns:
            A plain ``{"total": int, "truncated": bool, "done": True}`` terminal summary.
        """
        functions = params.get("functions")
        names: list[str] | None = None
        if isinstance(functions, list):
            # Each identifier is an untrusted address/name; coerce to str defensively (the server
            # already length/charset-validated them). An explicit set bounds the produced count to
            # its length (already client-capped); the window bounds apply only when none is named.
            names = [str(fn) for fn in functions]
        offset = max(0, int(params.get("offset", 0)))
        limit = _clamp_count(int(params.get("limit", 100)))
        # is_cancelled defers to the dispatch-supplied poll; with no poll (fake path) it is a
        # constant False so the stream runs to completion. A new closure per call — no per-instance
        # cancel state survives between streams (the cancel signal now lives on the socket).
        is_cancelled = poll_cancel if poll_cancel is not None else (lambda: False)
        return self._gh_decompile_stream(
            names, offset, limit, emit_chunk=emit_chunk, is_cancelled=is_cancelled
        )

    def disassemble(self, params: dict[str, Any]) -> dict[str, Any]:
        """Disassemble a bounded range or function."""
        cap = _clamp_count(params.get("max_instructions", 256))
        return self._gh_disassemble(params.get("start"), params.get("function"), cap)

    def get_pcode(self, params: dict[str, Any]) -> dict[str, Any]:
        """List lifted low p-code for a bounded range or function (read-only — ADR-052)."""
        cap = _clamp_count(params.get("max_instructions", 256))
        return self._gh_get_pcode(params.get("start"), params.get("function"), cap)

    def get_high_pcode(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a function's decompiler-refined high (SSA) p-code (read-only — ADR-053)."""
        cap = _clamp_count(params.get("max_ops", 256))
        return self._gh_get_high_pcode(str(_require(params, "function")), cap)

    def stack_frame(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a function's recovered stack-frame layout (read-only — ADR-054)."""
        return self._gh_stack_frame(str(_require(params, "function")))

    def basic_blocks(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a function's basic blocks + successor edges (read-only — ADR-055)."""
        cap = _clamp_count(params.get("max_blocks", 256))
        return self._gh_basic_blocks(str(_require(params, "function")), cap)

    def list_data_types(self, params: dict[str, Any]) -> dict[str, Any]:
        """List the program's data types, paginated (read-only — ADR-056)."""
        offset, limit = _page(params)
        return self._gh_list_data_types(offset, limit, params.get("name_contains"))

    def list_functions(self, params: dict[str, Any]) -> dict[str, Any]:
        """List functions (paginated/bounded)."""
        offset, limit = _page(params)
        return self._gh_list_functions(offset, limit, params.get("name_contains"))

    def get_function(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get one function's detail."""
        return self._gh_get_function(str(_require(params, "function")))

    def xrefs_to(self, params: dict[str, Any]) -> dict[str, Any]:
        """References TO a target."""
        offset, limit = _page(params)
        return self._gh_xrefs(str(_require(params, "target")), offset, limit, to=True)

    def xrefs_from(self, params: dict[str, Any]) -> dict[str, Any]:
        """References FROM a target."""
        offset, limit = _page(params)
        return self._gh_xrefs(str(_require(params, "target")), offset, limit, to=False)

    def list_strings(self, params: dict[str, Any]) -> dict[str, Any]:
        """List defined strings (paginated/bounded)."""
        offset, limit = _page(params)
        return self._gh_list_strings(offset, limit, int(params.get("min_length", 4)))

    def list_symbols(self, params: dict[str, Any]) -> dict[str, Any]:
        """List symbols (paginated/bounded)."""
        offset, limit = _page(params)
        return self._gh_list_symbols(offset, limit, params.get("name_contains"))

    def get_symbol(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve one symbol."""
        return self._gh_get_symbol(str(_require(params, "identifier")))

    def list_data(self, params: dict[str, Any]) -> dict[str, Any]:
        """List defined data (paginated/bounded)."""
        offset, limit = _page(params)
        return self._gh_list_data(offset, limit)

    def get_data_type(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve one data type."""
        return self._gh_get_data_type(str(_require(params, "name")))

    def get_comments(self, params: dict[str, Any]) -> dict[str, Any]:
        """Read comments (paginated/bounded)."""
        offset, limit = _page(params)
        return self._gh_get_comments(offset, limit, params.get("address"))

    def memory_map(self, params: dict[str, Any]) -> dict[str, Any]:
        """List memory blocks/segments."""
        return self._gh_memory_map()

    def read_bytes(self, params: dict[str, Any]) -> dict[str, Any]:
        """Bounded raw byte read."""
        length = _clamp_read(int(_require(params, "length")))
        return self._gh_read_bytes(str(_require(params, "address")), length)

    def emulate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Bounded p-code emulation (ADR-049). The server has bounded step/region/size caps."""
        return self._gh_emulate(
            start=str(_require(params, "start")),
            set_registers=dict(params.get("set_registers") or {}),
            write_memory=list(params.get("write_memory") or []),
            max_steps=int(params.get("max_steps", 100_000)),
            stop_at=(None if params.get("stop_at") is None else str(params["stop_at"])),
            read_registers=list(params.get("read_registers") or []),
            read_memory=list(params.get("read_memory") or []),
        )

    def demangle(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve a mangled C++ symbol to a readable name (ADR-050). Program-independent."""
        return self._gh_demangle(
            mangled=str(_require(params, "mangled")),
            scheme=str(params.get("scheme", "auto")),
        )

    def search_bytes(self, params: dict[str, Any]) -> dict[str, Any]:
        """Bounded byte-pattern search."""
        offset, limit = _page(params)
        return self._gh_search_bytes(str(_require(params, "pattern_hex")), offset, limit)

    def search_strings(self, params: dict[str, Any]) -> dict[str, Any]:
        """Bounded defined-string search."""
        offset, limit = _page(params)
        return self._gh_search_strings(str(_require(params, "query")), offset, limit)

    def program_metadata(self, params: dict[str, Any]) -> dict[str, Any]:
        """High-level program metadata."""
        return self._gh_program_metadata()

    def call_graph(self, params: dict[str, Any]) -> dict[str, Any]:
        """Extract the bounded function call adjacency (v1.1 — ADR-007).

        Args:
            params: ``{"root": str | None, "max_depth": int, "max_nodes": int, "max_edges": int}``.

        Returns:
            ``{"nodes": [...], "edges": [...], "unresolved_callers": [...], "truncated": bool}``.
        """
        max_nodes = max(1, min(int(params.get("max_nodes", 10_000)), _MAX_GRAPH_NODES))
        max_edges = max(1, min(int(params.get("max_edges", 40_000)), _MAX_GRAPH_EDGES))
        max_depth = max(1, min(int(params.get("max_depth", 8)), _MAX_GRAPH_DEPTH))
        return self._gh_call_graph(params.get("root"), max_depth, max_nodes, max_edges)

    def referenced_strings(self, params: dict[str, Any]) -> dict[str, Any]:
        """List the (bounded) defined-string values a function references (v1.1 — ADR-007).

        A function's referenced string literals are a strong semantic-naming signal. The server
        wraps each returned value in the BINARY-origin untrusted envelope (ADR-005).

        Args:
            params: ``{"function": str, "max_strings": int}``.

        Returns:
            ``{"strings": [str, ...], "truncated": bool}`` — plain string values, capped.
        """
        max_strings = _clamp_count(int(params.get("max_strings", 64)))
        return self._gh_referenced_strings(str(_require(params, "function")), max_strings)

    def function_cfg(self, params: dict[str, Any]) -> dict[str, Any]:
        """CFG block/edge counts for one function (v1.1 — ADR-008; for cyclomatic complexity).

        Args:
            params: ``{"function": str}``.

        Returns:
            ``{"address", "name", "block_count", "edge_count", "incomplete"}``.
        """
        return self._gh_function_cfg(str(_require(params, "function")))

    def imports(self, params: dict[str, Any]) -> dict[str, Any]:
        """List imported symbols/functions (paginated/bounded) — v1.1 (ADR-008)."""
        offset, limit = _page(params)
        return self._gh_imports(offset, limit)

    def exports(self, params: dict[str, Any]) -> dict[str, Any]:
        """List exported symbols/entry points (paginated/bounded) — v1.1 (ADR-008)."""
        offset, limit = _page(params)
        return self._gh_exports(offset, limit)

    def coverage(self, params: dict[str, Any]) -> dict[str, Any]:
        """Defined-code/data byte counts for program coverage — v1.1 (ADR-008)."""
        return self._gh_coverage()

    def identify_functions(self, params: dict[str, Any]) -> dict[str, Any]:
        """Match functions against library FID databases — v1.x (ADR-042 Phase 1; READ-ONLY).

        Runs the Ghidra Function ID service over the analyzed program and returns one row per
        surviving candidate (multiplicity is honest — a function may match several library
        candidates above the score threshold). Bounded by :data:`_MAX_IDENTIFY_MATCHES` (the server
        further caps to the caller's ``limit``); ``min_score`` (when supplied) raises the floor
        above Ghidra's FID default threshold.

        Args:
            params: ``{"limit": int, "min_score"?: float}`` (``limit`` already bounded by the
                server; ``min_score`` absent ⇒ the worker uses the FID default score threshold).

        Returns:
            ``{"matches": [{"address","matched_name","library","score"}], "truncated": bool}``
            (plain; the server wraps ``matched_name``/``library`` as untrusted — binary-derived).
        """
        limit = _clamp_identify(int(params.get("limit", _MAX_IDENTIFY_MATCHES)))
        min_score = params.get("min_score")
        return self._gh_identify_functions(limit, None if min_score is None else float(min_score))

    # --- mutation operations (v1.1 — ADR-012; transaction-wrapped, fail-closed) --------------
    # Each write resolves the target with an existing read-only resolver, then performs a single
    # Ghidra write inside one transaction (commit on success, roll back + re-raise on any failure
    # — ADR-012 §4, topic-error-handling fail-closed). The server has already validated the name/
    # address/comment-type as hostile input (ADR-012 §7) and checked write consent (§3); the worker
    # never interpolates a value into a script — it calls a typed Java setter (no runScript path).
    def rename_function(self, params: dict[str, Any]) -> dict[str, Any]:
        """Rename one function (write; gated by session write-consent at the server — ADR-012).

        Args:
            params: ``{"function": str, "new_name": str}`` (target + server-validated new name).

        Returns:
            ``{"address", "old_name", "new_name", "applied"}`` (plain; the server wraps
            ``old_name`` as untrusted — it is the prior binary-derived name).
        """
        function = str(_require(params, "function"))
        new_name = str(_require(params, "new_name"))
        return self._gh_rename_function(function, new_name)

    def rename_symbol(self, params: dict[str, Any]) -> dict[str, Any]:
        """Rename one data/label/global symbol (write — ADR-012).

        Args:
            params: ``{"identifier": str, "new_name": str}``.

        Returns:
            ``{"address", "old_name", "new_name", "kind", "applied"}`` (plain; ``old_name``
            wrapped by the server).
        """
        identifier = str(_require(params, "identifier"))
        new_name = str(_require(params, "new_name"))
        return self._gh_rename_symbol(identifier, new_name)

    def set_comment(self, params: dict[str, Any]) -> dict[str, Any]:
        """Set or clear one comment at an address (write — ADR-012).

        Args:
            params: ``{"address": str, "comment_type": str, "text": str | None}`` (``text`` of
                ``None`` clears the comment; ``comment_type`` is one of the five closed kinds).

        Returns:
            ``{"address", "comment_type", "applied"}`` (plain — no binary-derived field).
        """
        address = str(_require(params, "address"))
        comment_type = str(_require(params, "comment_type"))
        text = params.get("text")
        return self._gh_set_comment(address, comment_type, None if text is None else str(text))

    def undo(self, params: dict[str, Any]) -> dict[str, Any]:
        """Undo the last committed mutation transaction in this session (convenience — ADR-012).

        Args:
            params: ``{}`` (session-scoped; no parameters).

        Returns:
            ``{"undone": bool}`` (plain) — ``False`` when there was nothing to undo.
        """
        return self._gh_undo()

    def rename_local_variable(self, params: dict[str, Any]) -> dict[str, Any]:
        """Rename one function-local variable (write; HighFunction path, name-only — ADR-013).

        Args:
            params: ``{"function": str, "variable": str, "new_name": str}``.

        Returns:
            ``{"address", "function", "old_name", "new_name", "applied"}`` (plain; the server wraps
            ``function``/``old_name`` as untrusted).
        """
        function = str(_require(params, "function"))
        variable = str(_require(params, "variable"))
        new_name = str(_require(params, "new_name"))
        return self._gh_rename_high_variable(function, variable, new_name, is_parameter=False)

    def rename_parameter(self, params: dict[str, Any]) -> dict[str, Any]:
        """Rename one function parameter (write; HighFunction path, name-only — ADR-013).

        Args:
            params: ``{"function": str, "parameter": str, "new_name": str}``.

        Returns:
            ``{"address", "function", "old_name", "new_name", "applied"}`` (plain).
        """
        function = str(_require(params, "function"))
        parameter = str(_require(params, "parameter"))
        new_name = str(_require(params, "new_name"))
        return self._gh_rename_high_variable(function, parameter, new_name, is_parameter=True)

    def set_function_signature(self, params: dict[str, Any]) -> dict[str, Any]:
        """Set a function's structured signature (write; resolved types, one txn — ADR-014).

        Args:
            params: ``{"function": str, "return_type": TypeRef, "parameters": [ParamSpec],
                "calling_convention": str | None}`` where ``TypeRef`` is
                ``{"base", "named", "pointer_levels", "array_len"}`` and ``ParamSpec`` is
                ``{"name", "type": TypeRef}``. The worker resolves each ``TypeRef`` against the
                ``DataTypeManager`` (NO C parser) before the transaction.

        Returns:
            ``{"address", "function", "old_signature", "new_signature", "applied"}`` (plain; the
            server wraps the signature fields as untrusted).
        """
        function = str(_require(params, "function"))
        return_type = _require(params, "return_type")
        parameters = _require(params, "parameters")
        calling_convention = params.get("calling_convention")
        return self._gh_set_function_signature(
            function,
            return_type,
            parameters,
            None if calling_convention is None else str(calling_convention),
        )

    def apply_data_type(self, params: dict[str, Any]) -> dict[str, Any]:
        """Apply a resolvable type at an address (write; resolved type, one txn — ADR-014).

        Args:
            params: ``{"address": str, "type": TypeRef, "clear_existing": bool}``. The worker
                resolves the ``TypeRef`` (NO C parser) and confines the address to the memory map
                before the transaction.

        Returns:
            ``{"address", "type_name", "size", "applied"}`` (plain; the server wraps ``type_name``).
        """
        address = str(_require(params, "address"))
        type_ref = _require(params, "type")
        clear_existing = bool(params.get("clear_existing", False))
        return self._gh_apply_data_type(address, type_ref, clear_existing)

    def apply_type_archive(self, params: dict[str, Any]) -> dict[str, Any]:
        """Apply a bundled Ghidra Data Type archive (write; one txn — ADR-051).

        Args:
            params: ``{"archive": str}`` — an allow-listed bundled-GDT name. The worker maps it to a
                ``.gdt`` inside the pinned Ghidra install; NO client path is opened (CWE-22).

        Returns:
            ``{"archive", "functions_updated", "applied"}`` (plain; all fields SAFE).
        """
        return self._gh_apply_type_archive(str(_require(params, "archive")))

    def define_struct(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create a new struct from a resolved field list (write; one txn — ADR-015 §3).

        Args:
            params: ``{"name": str, "fields": [FieldSpec], "packed": bool}`` where ``FieldSpec`` is
                ``{"name", "type": TypeRef, "offset": int | None}``. The worker pre-registers the
                empty struct, resolves each ``TypeRef`` (NO C parser), adds members (size-checked),
                REJECTs a name collision, and finalizes — all inside one transaction.

        Returns:
            ``{"name", "kind", "size", "field_count", "applied"}`` (plain server/worker scalars).
        """
        name = str(_require(params, "name"))
        fields = _require(params, "fields")
        packed = bool(params.get("packed", False))
        return self._gh_define_struct(name, fields, packed)

    def define_union(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create a new union from a resolved field list (write; one txn — ADR-015 §3).

        Args:
            params: ``{"name": str, "fields": [FieldSpec]}`` (a union ignores ``offset``/``packed``;
                all members overlay at offset 0). The worker pre-registers the empty union, resolves
                each ``TypeRef`` (NO C parser), adds members (size-checked), REJECTs a name
                collision, and finalizes — all inside one transaction.

        Returns:
            ``{"name", "kind", "size", "field_count", "applied"}`` (plain server/worker scalars).
        """
        name = str(_require(params, "name"))
        fields = _require(params, "fields")
        return self._gh_define_union(name, fields)

    def define_types(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create a BATCH of interdependent composites in ONE transaction (write — ADR-021).

        Args:
            params: ``{"types": [{"kind": "struct"|"union", "name": str, "fields": [FieldSpec],
                "packed": bool}]}``. The worker REJECTs a name collision for EACH batch name vs the
                existing program (read-only, before the txn), then inside ONE transaction
                pre-registers ALL empty composites (so an in-batch ``named`` ref resolves), resolves
                + adds each type's members (batch-total size-checked), and finalizes — ANY failure
                rolls back the WHOLE batch (no partial type). The server has already run the
                by-value cycle detector at the boundary. NO C string is parsed.

        Returns:
            ``{"types": [{"name", "kind", "size", "field_count"}], "applied": bool}`` (plain).
        """
        types = _require(params, "types")
        return self._gh_define_types(types)

    def delete_type(self, params: dict[str, Any]) -> dict[str, Any]:
        """Delete a composite by name in one transaction, reporting reverted dependents (ADR-031).

        Args:
            params: ``{"name": str}``. The server has already validated the name AND confirmed it is
                session-authored (ADR-031 D2) — the worker only ever receives a name the server
                authorized. The worker resolves it (read-only), rejects a non-composite/built-in
                (defense in depth), counts dependents (read-only, before the write), and removes it
                inside one transaction (rollback on failure).

        Returns:
            ``{"name", "deleted", "dependents_reverted"}`` (plain server/worker scalars).
        """
        name = str(_require(params, "name"))
        return self._gh_delete_type(name)

    # --- annotation persistence (v1.2 — ADR-018; export read-out ONLY) -----------------------
    def export_annotations(self, params: dict[str, Any]) -> dict[str, Any]:
        """Enumerate the program's USER_DEFINED annotations as a plain document (read-only — v1.2).

        Args:
            params: ``{"targets": {"comments": [{address, comment_type}], "composites": [name]}}``
                (ADR-027 D4) — the server-supplied change-log selection of comment + composite
                targets to read. Symbols/signatures take no targets (source-type-enumerated). A
                missing/empty ``targets`` means no comments/composites are exported.

        Returns:
            ``{"schema_version", "binary": {"sha256", "size"}, "entries": [...]}`` — the program's
            USER_DEFINED annotations only, dependency-ordered, bounded (over the cap →
            ``limit-exceeded``). The server wraps binary-derived strings as untrusted + overlays the
            authoritative binary hash.
        """
        comment_targets, composite_targets = _parse_export_targets(params)
        return self._gh_export_annotations(comment_targets, composite_targets)

    # --- JVM edge (PyGhidra calls live ONLY here; imported lazily) ---------------------------
    # NOTE: these helpers are the worker-only JVM boundary. They are excluded from server unit
    # coverage and exercised only by the integration suite against a real pinned worker image. The
    # exact PyGhidra symbol bindings are confirmed at WS3 image build (ADR-003 open item).
    #
    # integration-validate (Ghidra 12.1.2 / PyGhidra javadoc — confirm when the image builds):
    #   * pyghidra.open_program(path) -> context manager yielding a FlatProgramAPI whose
    #     .getCurrentProgram() returns the ghidra.program.model.listing.Program. WS2 holds the
    #     opened context + program on self across calls; the WS3 launcher owns lifetime/teardown.
    #   * ghidra.app.decompiler.DecompInterface: .openProgram(prog), .decompileFunction(fn,t,mon).
    #   * ghidra.util.task.ConsoleTaskMonitor / TaskMonitor.DUMMY for a no-progress monitor.
    #   * pyghidra.analyze(program) / AutoAnalysisManager — the exact auto-analysis trigger
    #     (pyghidra helper vs AutoAnalysisManager.reAnalyzeAll) is the last symbol to pin.
    # Each helper converts every Ghidra object to a plain str/int/bool before returning (no Java
    # object leaks the boundary); addresses render via ``str(addr)`` (Ghidra's canonical hex form).

    def _gh_import(
        self,
        source_ref: str,
        *,
        loader: str | None = None,
        processor: str | None = None,
        base_addr: int | None = None,
        entry: int | None = None,
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Import a binary file into a transient Ghidra project (PyGhidra).

        Opens the (server-confined, size-checked) file with PyGhidra and retains the program/
        context on ``self`` for subsequent analyze/query calls. Returns a ``SessionInfo``-shaped
        dict contributing ``state`` + ``binary_sha256``; the server overlays the authoritative
        ids/timestamps (placeholders here satisfy the model's required scalars).

        When ``loader`` is ``None`` (the default auto path) the ``open_program`` call is
        byte-for-byte the pre-ADR-045 behavior — Ghidra's opinion/container loaders detect an
        ELF/PE. When ``loader == "binary"`` (ADR-045, F1) the ``BinaryLoader`` is driven with the
        allow-listed ``processor`` ``LanguageID`` and the raw image is rebased to ``base_addr``
        (optionally seeding an entry point). The server has already validated the hints; the worker
        re-validates the language implicitly — an uninstalled ``LanguageID`` makes ``open_program``
        raise, which is translated to a category-safe ``not-found`` (defense in depth, ADR-045 §D2).

        Args:
            source_ref: The server-resolved, confined input path.
            loader: ``None``/``"auto"`` for the container path; ``"binary"`` for a raw image.
            processor: The allow-listed Ghidra ``LanguageID`` (required when ``loader`` is binary).
            base_addr: The image base to rebase the raw image to (required when ``loader ==
                "binary"``).
            entry: Optional entry-point offset to seed as an external entry point.

        Returns:
            A plain ``SessionInfo``-shaped dict.

        Raises:
            WorkerError: ``not-found`` if a raw import names a ``LanguageID`` not installed in this
                Ghidra build, or the ``BinaryLoader`` could not load the image.
        """
        import hashlib  # stdlib — digest the bytes the worker actually opened

        import pyghidra

        sha256 = hashlib.sha256()
        with open(source_ref, "rb") as handle:  # noqa: PTH123 — confined path from the server
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                sha256.update(chunk)
        self._sha256 = sha256.hexdigest()
        self._analyzed = False

        # Hold the opened-program context on self so analyze() and the read-only ops reuse it.
        # project_location MUST be a WRITABLE dir: PyGhidra otherwise defaults the project next to
        # the binary (e.g. /bin/true_ghidra) → read-only rootfs → PermissionError. Point it at the
        # per-session worker store (writable tmpfs mounted by deploy/; created in the image).
        # Found via the in-worker analyze smoke against a real ELF.
        project_dir = os.environ.get("VIVARIUM_WORKER_PROJECT_DIR", "/work/project")

        if loader == "binary":
            self._open_raw_binary(
                source_ref, project_dir, str(processor), int(base_addr or 0), entry
            )
        elif loader in ("intel-hex", "motorola-hex"):
            self._open_named_loader(source_ref, project_dir, str(loader), str(processor))
        elif loader == "macho" and processor is not None:
            # ADR-048: select a fat/universal Mach-O slice by LanguageID (needs the ProgramLoader
            # builder — open_program ignores `language` for slice selection).
            self._open_macho_slice(source_ref, project_dir, str(processor))
        elif loader in ("dex", "macho", "apk"):
            # Self-describing (ADR-047): force the loader, no language (the format carries it).
            self._open_named_loader(source_ref, project_dir, str(loader), None)
        else:
            # AUTO path — byte-for-byte the pre-ADR-045 call (opinion/container loaders).
            ctx = pyghidra.open_program(
                source_ref,
                project_location=project_dir,
                project_name="session",
                analyze=False,
            )
            program = ctx.__enter__()
            self._project = ctx  # retain the ctx manager for the launcher to close on evict
            self._program = getattr(program, "getCurrentProgram", lambda: program)()
        return _session_info_dict("importing", self._sha256, analysis_complete=False)

    def _open_raw_binary(
        self,
        source_ref: str,
        project_dir: str,
        processor: str,
        base_addr: int,
        entry: int | None,
    ) -> None:  # pragma: no cover - JVM edge
        """Open a headerless raw image via ``BinaryLoader`` and rebase it (ADR-045, F1).

        Drives PyGhidra's ``BinaryLoader`` with the allow-listed ``processor`` ``LanguageID`` (an
        uninstalled id makes ``open_program`` raise → translated to ``not-found``), retains the
        program/context on ``self`` exactly like the auto path, then rebases the loaded image to
        ``base_addr`` (BinaryLoader maps at 0 by default) and optionally marks ``entry`` as an
        external entry point — both inside one Ghidra transaction (ADR-012 §4).

        Args:
            source_ref: The server-resolved, confined input path.
            project_dir: The writable per-session project location.
            processor: The allow-listed ``LanguageID``.
            base_addr: The image base to rebase to.
            entry: Optional entry-point offset to seed.

        Raises:
            WorkerError: ``not-found`` if the language is not installed or the image cannot load.
        """
        import pyghidra
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        try:
            ctx = pyghidra.open_program(
                source_ref,
                project_location=project_dir,
                project_name="session",
                analyze=False,
                language=processor,
                loader="ghidra.app.util.opinion.BinaryLoader",
            )
            program = ctx.__enter__()
        except Exception as exc:
            # The server already allow-listed `processor`; a failure here means the LanguageID is
            # not installed in this pinned build OR BinaryLoader rejected the raw image. Fail closed
            # with a category-safe slug (the original exception is chained server-side only).
            raise WorkerError(
                CODE_NOT_FOUND, "processor language not installed or raw image could not be loaded"
            ) from exc

        self._project = ctx  # retain the ctx manager for the launcher to close on evict
        prog = getattr(program, "getCurrentProgram", lambda: program)()
        self._program = prog

        space = prog.getAddressFactory().getDefaultAddressSpace()

        def _rebase() -> None:
            prog.setImageBase(space.getAddress(base_addr), True)
            if entry is not None:
                prog.getSymbolTable().addExternalEntryPoint(space.getAddress(entry))

        self._in_transaction("session_import (raw layout)", _rebase)

    #: Client loader hint -> Ghidra loader class. Hex formats (ADR-046) take a ``processor``;
    #: self-describing container formats (ADR-047) take none (the format carries it).
    _NAMED_LOADERS: ClassVar[dict[str, str]] = {
        "intel-hex": "ghidra.app.util.opinion.IntelHexLoader",
        "motorola-hex": "ghidra.app.util.opinion.MotorolaHexLoader",
        "dex": "ghidra.app.util.opinion.DexLoader",
        "macho": "ghidra.app.util.opinion.MachoLoader",
        "apk": "ghidra.app.util.opinion.ApkLoader",
    }

    #: Allow-listed type-archive name -> path RELATIVE to ``GHIDRA_INSTALL_DIR`` (ADR-051). The name
    #: is a closed set (mirrored by the ``_TYPE_ARCHIVE_NAMES`` schema Literal); NO client path is
    #: ever opened (CWE-22). These ship inside the pinned Ghidra install.
    _TYPE_ARCHIVES: ClassVar[dict[str, str]] = {
        "generic_clib": "Ghidra/Features/Base/data/typeinfo/generic/generic_clib.gdt",
        "generic_clib_64": "Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt",
        "windows_vs12_32": "Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_32.gdt",
        "windows_vs12_64": "Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_64.gdt",
        "mac_osx": "Ghidra/Features/Base/data/typeinfo/mac_10.9/mac_osx.gdt",
    }

    def _open_named_loader(
        self, source_ref: str, project_dir: str, loader: str, processor: str | None
    ) -> None:  # pragma: no cover - JVM edge
        """Open via an explicitly-named Ghidra loader (ADR-046 hex / ADR-047 self-describing).

        Drives the mapped loader class (:data:`_NAMED_LOADERS`). When ``processor`` is given (hex
        loaders — Intel-HEX / SREC carry addresses but no arch) it is passed as ``language``; when
        ``None`` (self-describing — DEX / Mach-O carry their own processor + layout) no language is
        passed. There is **no rebase**: the loader lays memory out itself. Retains the program/
        context on ``self`` exactly like the other paths.

        Args:
            source_ref: The server-resolved, confined input path.
            project_dir: The writable per-session project location.
            loader: The client loader token (mapped via :data:`_NAMED_LOADERS`).
            processor: The allow-listed ``LanguageID`` for the hex loaders, or ``None`` for the
                self-describing loaders.

        Raises:
            WorkerError: ``not-found`` if the (given) language is not installed or the file cannot
                be loaded by the selected loader.
        """
        import pyghidra
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        loader_class = self._NAMED_LOADERS[loader]
        open_kwargs: dict[str, Any] = {
            "project_location": project_dir,
            "project_name": "session",
            "analyze": False,
            "loader": loader_class,
        }
        if processor is not None:
            open_kwargs["language"] = processor
        try:
            ctx = pyghidra.open_program(source_ref, **open_kwargs)
            program = ctx.__enter__()
        except Exception as exc:
            raise WorkerError(
                CODE_NOT_FOUND,
                f"loader='{loader}' could not load the image (unsupported/absent language, "
                "or the file did not match the format)",
            ) from exc

        self._project = ctx  # retain the ctx manager for the launcher to close on evict
        self._program = getattr(program, "getCurrentProgram", lambda: program)()

    def _open_macho_slice(
        self, source_ref: str, project_dir: str, processor: str
    ) -> None:  # pragma: no cover - JVM edge
        """Load a specific fat/universal Mach-O **slice** by ``LanguageID`` (ADR-048).

        ``open_program`` ignores its ``language`` arg for Mach-O slice selection (it always takes
        the default slice), so this uses the lower-level ``pyghidra.program_loader()`` builder,
        which DOES honor ``language`` to pick the matching ``LoadSpec`` (verified). The project is
        opened
        under ``project_dir`` — the per-session store the server verified-wipes on eviction
        (ADR-002) — so this path inherits the same teardown guarantee as the others (eviction = kill
        worker + wipe the store dir, independent of the loader API). Retains the project ctx + the
        loaded program + the ``LoadResults`` on ``self`` (the last so its consumer keeps the program
        alive).

        Args:
            source_ref: The server-resolved, confined input path.
            project_dir: The writable per-session project location (the wiped store).
            processor: The allow-listed ``LanguageID`` naming the desired slice.

        Raises:
            WorkerError: ``not-found`` if no slice matches the language or the file cannot load.
        """
        import jpype
        import pyghidra
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        # Unlike open_program (self-starts the JVM), the program_loader() builder needs the JVM
        # running first. start() is idempotent (a no-op once started).
        pyghidra.start()
        try:
            project_ctx = pyghidra.open_project(project_dir, "session", create=True)
            project = project_ctx.__enter__()
            loaded = (
                pyghidra.program_loader()
                .source(source_ref)
                .project(project)
                .loaders(jpype.JClass("ghidra.app.util.opinion.MachoLoader"))
                .language(processor)
                .load()
            )
            program = loaded.getPrimaryDomainObject()
        except Exception as exc:
            raise WorkerError(
                CODE_NOT_FOUND,
                "no Mach-O slice matched the requested processor, or the file could not be loaded",
            ) from exc

        self._project = project_ctx  # retain (server kills+wipes on evict; process death frees it)
        self._loaded = loaded  # keep the LoadResults' consumer alive so the program is not released
        self._program = program

    def _gh_analyze(
        self,
        timeout_seconds: int | None,
        profile: str | None = None,
        *,
        emit_progress: Callable[[int | None, str], None] | None = None,
    ) -> dict[str, Any]:  # pragma: no cover
        """Run Ghidra auto-analysis on the open program.

        Args:
            timeout_seconds: In-worker budget hint (the server enforces the hard deadline by
                killing the worker; this is advisory).
            profile: Analyzer-depth preset (ADR-029 B). The default/``None`` applies NO option
                overlay — a byte-for-byte no-op: the same bare ``pyghidra.analyze(program)`` as
                before this increment runs, with the options object never touched.
            emit_progress: When supplied (ADR-030 Phase 1, opted-in request), analysis runs under a
                custom :class:`TaskMonitor` that calls this with (percent, closed-phase) so the
                dispatch streams ``$/progress`` frames. When ``None`` (default + non-opted-in) the
                IDENTICAL bare ``pyghidra.analyze(program)`` as before this increment runs — no
                monitor object is constructed (the default-is-no-op guarantee).

        Returns:
            A plain ``SessionInfo``-shaped dict reporting the ``ready`` state.

        Raises:
            WorkerError: ``analysis-failed`` if no program is loaded.
        """
        from worker.dispatch import CODE_ANALYSIS_FAILED, CODE_INTERNAL, WorkerError

        if self._program is None:
            raise WorkerError(CODE_ANALYSIS_FAILED, "no program imported for analysis")
        # integration-validate: confirm the auto-analysis entrypoint on 12.1.2 — pyghidra exposes an
        # analysis helper; otherwise ghidra.app.plugin.core.analysis.AutoAnalysisManager
        # .getAnalysisManager(program).reAnalyzeAll(None) inside a started transaction. The WS3
        # launcher supplies the wall-clock kill; this call runs synchronously to completion.
        import pyghidra

        # ADR-029 B profile overlay. PURE selector → option map (unit-tested); the option-SETTING is
        # the JVM edge below. DEFAULT-IS-NO-OP: an empty overlay skips the options block entirely,
        # so the default path is the identical bare ``analyze`` call as before this increment.
        overlay = _analyzer_options_for_profile(profile)
        if overlay:
            # REQUIRES-LIVE-VERIFICATION: the analysis-options accessor + the per-analyzer option
            # names/semantics are Ghidra 12.1.2 JVM edges — confirm via the pinned image (ADR-028
            # harness + real-worker run) before merge. ``Program.ANALYSIS_PROPERTIES`` is the
            # documented options group auto-analysis reads; toggling a named analyzer there
            # disables/enables it for the ``analyze`` run that follows.
            options = self._program.getOptions(self._program.ANALYSIS_PROPERTIES)
            # ADR-035 existence guard: Ghidra's ``setBoolean`` silently CREATES an unknown option,
            # so a renamed/typo'd preset name would become a silent no-op (the profile quietly stops
            # taking effect). Fail closed instead — verify every preset name exists before applying.
            # The membership decision is the PURE ``_missing_profile_options`` (unit-tested); the
            # ``getOptionNames()`` enumeration is the JVM edge. A miss is a SERVER defect (a stale
            # preset vs this Ghidra build), so it maps to ``internal-error`` (redacted template, no
            # option names echoed). Paired with the ADR-028 profile gate, this makes a Ghidra
            # option rename a deterministic red instead of silent drift.
            available = options.getOptionNames()
            missing = _missing_profile_options(overlay, available)
            if missing:
                # The client envelope stays generic (internal-error); the missing names go ONLY into
                # the redacted, log-only ``data.detail`` (ADR-024) so a red ADR-028 nightly says
                # exactly WHICH option drifted. The names are our own preset constants (not
                # binary-derived), so they are safe to log.
                raise WorkerError(
                    CODE_INTERNAL,
                    "analyzer profile references option(s) not available in this Ghidra build",
                    detail=f"analyzer profile option(s) absent in this Ghidra build: {missing}",
                )
            for option_name, enabled in overlay.items():
                options.setBoolean(option_name, enabled)
        if emit_progress is None:
            # DEFAULT / non-opted-in: byte-for-byte the same bare call as before ADR-030. No monitor
            # object is constructed and no frame is emitted — identical RPC + analysis to today.
            pyghidra.analyze(self._program)
        else:
            self._run_monitored_analysis(emit_progress)
        self._analyzed = True
        return _session_info_dict("ready", self._sha256, analysis_complete=True)

    # C901: PyGhidra analysis+monitor sequencing across the JVM boundary (ADR-001) — only
    # live-regression covers it; decomposing risks the careful PyGhidra call ordering.
    def _run_monitored_analysis(  # noqa: C901
        self, emit_progress: Callable[[int | None, str], None]
    ) -> None:  # pragma: no cover - JVM edge
        """Run auto-analysis under a custom progress ``TaskMonitor`` (ADR-030 Phase 1, opted-in).

        REQUIRES-LIVE-VERIFICATION (flag like F2/F7 — the PM live-verifies on a real worker before
        merge): the exact way to run Ghidra 12.1.2 auto-analysis with a *caller-supplied*
        ``TaskMonitor`` is a JVM binding the unit suite cannot exercise. The chosen,
        most-likely-real binding (and its documented fallback) is:

          1. Build a custom ``ghidra.util.task.TaskMonitorAdapter`` subclass whose ``setProgress`` /
             ``setMaximum`` / ``setMessage`` overrides compute a percent and emit a SAFE phase —
             NEVER forwarding the free-form ``setMessage`` text (it embeds attacker-controlled
             symbol names — master §5). Phase 1 maps to a single closed ``analyzing`` phase +
             percent (a clean importing/finalizing split is not reliably exposed by the analysis
             monitor, so the safe catch-all is used; the percent still gives real liveness).
          2. Drive a *monitored* analysis. ``pyghidra.analyze(program)`` does NOT accept a monitor
             on 12.1.2, so this drops to the manager path inside a started transaction:
             ``AutoAnalysisManager.getAnalysisManager(program)`` →
             ``mgr.reAnalyzeAll(None)`` / ``mgr.startAnalysis(monitor)`` (CONFIRM the exact
             monitored entrypoint + whether a transaction wrap is required against the pinned
             javadoc).

        If live verification shows the manager path differs, ONLY this method changes — the framing,
        the dispatch threading, the bounds, and the redaction (all unit-tested) are unaffected. The
        default (no-opt-in) path in :meth:`_gh_analyze` does NOT touch any of this.

        Args:
            emit_progress: The dispatch-supplied emitter (percent, closed-phase) → ``$/progress``.
        """
        import jpype
        from ghidra.app.plugin.core.analysis import (  # type: ignore[import-not-found]
            AutoAnalysisManager,
        )
        from ghidra.util.task import TaskMonitor  # type: ignore[import-not-found]

        program = self._require_program()

        # JPype CANNOT subclass a Java CLASS (e.g. TaskMonitorAdapter) — "Java classes cannot be
        # extended in Python". So we implement the TaskMonitor INTERFACE via ``jpype.JProxy`` over a
        # plain Python object: Java dispatches each monitor call to the matching method below. Only
        # the methods Ghidra's analysis actually invokes need to exist; the rest are safe no-ops.
        class _MonitorImpl:
            """Plain Python impl of the ``TaskMonitor`` interface → SAFE (percent, phase) emit."""

            def __init__(self) -> None:
                self._maximum = 0
                self._progress = 0

            def _emit(self) -> None:
                # CLOSED phase + percent ONLY — the free-form ``setMessage`` text is NEVER read here
                # (it embeds attacker-controlled symbol names — master §5 redaction).
                emit_progress(_monitor_percent(self._progress, self._maximum), "analyzing")

            def initialize(self, maximum: Any, *_: Any) -> None:
                self._maximum = int(maximum) if maximum else 0
                self._progress = 0

            def setMaximum(self, maximum: Any) -> None:  # noqa: N802
                self._maximum = int(maximum) if maximum else 0

            def getMaximum(self) -> int:  # noqa: N802
                return self._maximum

            def setProgress(self, value: Any) -> None:  # noqa: N802
                self._progress = int(value) if value else 0
                self._emit()

            def incrementProgress(self, n: Any = 1) -> None:  # noqa: N802
                self._progress += int(n) if n else 0
                self._emit()

            def getProgress(self) -> int:  # noqa: N802
                return self._progress

            def setMessage(self, _message: Any) -> None:  # noqa: N802
                self._emit()  # phase heartbeat only — message text dropped

            def getMessage(self) -> str:  # noqa: N802
                return ""

            def isCancelled(self) -> bool:  # noqa: N802
                return False

            def checkCancelled(self) -> None:  # noqa: N802
                return None

            def checkCanceled(self) -> None:  # noqa: N802 - older Ghidra spelling
                return None

            def setIndeterminate(self, _flag: Any) -> None:  # noqa: N802
                return None

            def isIndeterminate(self) -> bool:  # noqa: N802
                return self._maximum <= 0

            def cancel(self) -> None:
                return None

            def clearCancelled(self) -> None:  # noqa: N802
                return None

            def clearCanceled(self) -> None:  # noqa: N802 - older Ghidra spelling
                return None

            def setCancelEnabled(self, _flag: Any) -> None:  # noqa: N802
                return None

            def isCancelEnabled(self) -> bool:  # noqa: N802
                return True

            def setShowProgressValue(self, _flag: Any) -> None:  # noqa: N802
                return None

            def addCancelledListener(self, _listener: Any) -> None:  # noqa: N802
                return None

            def removeCancelledListener(self, _listener: Any) -> None:  # noqa: N802
                return None

        monitor = jpype.JProxy(TaskMonitor, inst=_MonitorImpl())
        manager = AutoAnalysisManager.getAnalysisManager(program)
        transaction = program.startTransaction("auto-analysis (monitored)")
        try:
            manager.reAnalyzeAll(program.getMemory())
            manager.startAnalysis(monitor)
        finally:
            program.endTransaction(transaction, True)

    def _gh_decompile(self, function: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Decompile a function with the Ghidra DecompInterface.

        Args:
            function: Function entry address (hex) or name.

        Returns:
            ``{"address", "name", "c_code", "signature"}`` (all plain strings).

        Raises:
            WorkerError: ``not-found`` if the function does not resolve; ``analysis-failed`` if the
                decompiler returns no result.
        """
        from ghidra.app.decompiler import DecompInterface  # type: ignore[import-not-found]

        # NOTE: no per-line ignore on ghidra.util.task here — mypy already records it as
        # missing-ignored at its first import (in _run_monitored_analysis, above), so a second
        # ignore on the same module is "unused" (same rule as _gh_search_bytes).
        from ghidra.util.task import ConsoleTaskMonitor
        from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

        program = self._require_program()
        func = self._resolve_function(function)
        decompiler = DecompInterface()
        try:
            decompiler.openProgram(program)
            results = decompiler.decompileFunction(func, 0, ConsoleTaskMonitor())
            if results is None or not results.decompileCompleted():
                raise WorkerError(CODE_ANALYSIS_FAILED, "decompilation did not complete")
            decompiled = results.getDecompiledFunction()
            c_code = decompiled.getC() if decompiled is not None else ""
        finally:
            decompiler.dispose()
        return {
            "address": str(func.getEntryPoint()),
            "name": str(func.getName()),
            "c_code": _to_text(c_code),
            "signature": _to_text(func.getPrototypeString(False, False)),
        }

    def _gh_get_high_pcode(
        self, function: str, cap: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM
        """Return a function's decompiler-refined high (SSA) p-code (ADR-053).

        Decompiles the function and iterates ``HighFunction.getPcodeOps()`` — the SSA, dead-code-
        eliminated, constant-folded IR (e.g. ``mov eax,5; add eax,3`` collapses to a single
        ``COPY 0x8``). Read-only: the program DB is not touched; the decompiler is disposed in a
        ``finally`` (ADR-002 memory discipline, same lifecycle as ``_gh_decompile``). Each op's
        seqnum address is a safe scalar; the rendered op text is decompiler-derived (server wraps it
        untrusted). Bounded by ``cap`` ops.

        Args:
            function: Function name or entry address (hex).
            cap: Maximum high p-code ops to return (already clamped).

        Returns:
            ``{"ops": [{"address", "op"}, ...], "truncated": bool}``.

        Raises:
            WorkerError: ``not-found`` if the function does not resolve; ``analysis-failed`` if the
                decompiler did not complete or produced no high function.
        """
        # DecompInterface + ConsoleTaskMonitor are recorded missing-ignored at their first import
        # (in _gh_decompile, above), so no per-line ignore here (a second would be "unused").
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

        program = self._require_program()
        func = self._resolve_function(function)
        decompiler = DecompInterface()
        try:
            decompiler.openProgram(program)
            results = decompiler.decompileFunction(func, 0, ConsoleTaskMonitor())
            if results is None or not results.decompileCompleted():
                raise WorkerError(CODE_ANALYSIS_FAILED, "decompilation did not complete")
            high = results.getHighFunction()
            if high is None:
                raise WorkerError(CODE_ANALYSIS_FAILED, "no high p-code produced")
            ops: list[dict[str, Any]] = []
            truncated = False
            iterator = high.getPcodeOps()
            while iterator.hasNext():
                if len(ops) >= cap:
                    truncated = True
                    break
                op = iterator.next()
                ops.append({"address": str(op.getSeqnum().getTarget()), "op": _to_text(str(op))})
        finally:
            decompiler.dispose()
        return {"ops": ops, "truncated": truncated}

    def _gh_stack_frame(self, function: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Return a function's recovered stack-frame layout (ADR-054).

        Reads ``Function.getStackFrame()`` — the locals + stack parameters the Stack analyzer
        populated during auto-analysis (each with its frame offset, name, type, and size).
        Read-only: the program DB is not touched. A not-yet-analyzed function has an empty variable
        list (not an error — ``session_analyze`` first). Names/types are Ghidra/binary-derived
        (server wraps them untrusted); offsets/sizes are safe scalars.

        Args:
            function: Function name or entry address (hex).

        Returns:
            ``{"frame_size": int, "variables": [{"name", "stack_offset", "data_type", "size",
            "is_parameter"}, ...]}``.

        Raises:
            WorkerError: ``not-found`` if the function does not resolve.
        """
        func = self._resolve_function(function)  # requires a loaded program (guards, fail-closed)
        frame = func.getStackFrame()
        variables: list[dict[str, Any]] = []
        for var in frame.getStackVariables():
            offset = int(var.getStackOffset())
            data_type = var.getDataType()
            variables.append(
                {
                    "name": _to_text(var.getName()),
                    "stack_offset": offset,
                    "data_type": _to_text(data_type.getName()) if data_type is not None else "",
                    "size": int(var.getLength()),
                    "is_parameter": bool(frame.isParameterOffset(offset)),
                }
            )
        return {"frame_size": int(frame.getFrameSize()), "variables": variables}

    def _gh_basic_blocks(self, function: str, cap: int) -> dict[str, Any]:  # pragma: no cover - JVM
        """Return a function's basic blocks + intraprocedural successor edges (ADR-055).

        Walks ``BasicBlockModel`` over the resolved function's body (the same model
        :meth:`_gh_function_cfg` uses for complexity COUNTS) and emits each block's address range +
        the start addresses of its successors that stay inside the function. Read-only: the program
        DB is not touched. All fields are server-normalized addresses / counts (no untrusted content
        — no instruction text is returned). Bounded by ``cap`` blocks.

        Args:
            function: Function name or entry address (hex).
            cap: Maximum basic blocks to return (already clamped).

        Returns:
            ``{"blocks": [{"address", "end_address", "size", "successors": [hex]}, ...],
            "truncated": bool}``.

        Raises:
            WorkerError: ``not-found`` if the function does not resolve.
        """
        # This is the FIRST BasicBlockModel import in the file (so it carries the missing-ignore);
        # ghidra.util.task is already missing-ignored at its first import (in _gh_decompile), so no
        # per-line ignore on it (a second would be "unused" — mypy unused-ignore).
        from ghidra.program.model.block import BasicBlockModel  # type: ignore[import-not-found]
        from ghidra.util.task import TaskMonitor

        func = self._resolve_function(function)  # requires a loaded program (guards, fail-closed)
        body = func.getBody()
        model = BasicBlockModel(self._require_program())
        monitor = TaskMonitor.DUMMY
        blocks: list[dict[str, Any]] = []
        truncated = False
        iterator = model.getCodeBlocksContaining(body, monitor)
        while iterator.hasNext():
            if len(blocks) >= cap:
                truncated = True
                break
            block = iterator.next()
            successors: list[str] = []
            destinations = block.getDestinations(monitor)
            while destinations.hasNext():
                dest = destinations.next().getDestinationBlock()
                # Only intraprocedural edges (a flow leaving the function is not a CFG edge here).
                if dest is not None and body.contains(dest.getFirstStartAddress()):
                    successors.append(str(dest.getFirstStartAddress()))
            blocks.append(
                {
                    "address": str(block.getFirstStartAddress()),
                    "end_address": str(block.getMaxAddress()),
                    "size": int(block.getNumAddresses()),
                    "successors": successors,
                }
            )
        return {"blocks": blocks, "truncated": truncated}

    def _gh_decompile_stream(  # pragma: no cover - JVM edge
        self,
        names: list[str] | None,
        offset: int,
        limit: int,
        *,
        emit_chunk: Callable[[int, str, dict[str, Any]], None] | None,
        is_cancelled: Callable[[], bool],
    ) -> dict[str, Any]:
        """Decompile a bounded function set, emitting one ``$/chunk`` per function (ADR-040 P2).

        Iterates the target functions in a stable order, decompiles each with a freshly-opened
        ``DecompInterface`` that is **disposed in a ``finally`` per function** (the ADR-002 memory
        discipline — no decompiler context outlives its function), and calls ``emit_chunk(seq,
        "function", payload)`` for each as it is produced. ``seq`` is a 0-based, gap-free, monotonic
        counter the server uses as the cursor unit.

        Function set:
        - ``names`` given → exactly those functions (each resolved by address/name); ``offset``/
          ``limit`` are ignored (the explicit list IS the bound, already client-capped). A name that
          does not resolve is skipped (best-effort; it still counts toward neither produced nor
          truncated — a missing name is not a worker fault).
        - ``names`` is ``None`` → the program's functions in entry order, the
          ``[offset, offset+limit)`` window; ``truncated`` is ``True`` iff more functions existed
          beyond the window.

        Cancellation (ADR-040 D6 / ADR-041): ``is_cancelled()`` is checked BEFORE each function so a
        cancel stops production promptly; the call then returns ``done: True`` with the chunks
        produced so far (an honest partial — the server marks the job cancelled). The predicate is
        the dispatch-supplied non-blocking ``$/cancel`` poll (ADR-041) — the backend only calls it
        and never touches the socket itself (ADR-001 boundary).

        Args:
            names: Explicit function identifiers (addresses/names), or ``None`` to window the
                program's function set.
            offset: Window start index (only used when ``names`` is ``None``).
            limit: Window size cap (only used when ``names`` is ``None``).
            emit_chunk: The socket-bound chunk emitter, or ``None`` (no frames emitted then).
            is_cancelled: A predicate the loop polls between functions for early stop.

        Returns:
            A plain ``{"total": int, "truncated": bool, "done": True}`` terminal summary, where
            ``total`` is the number of functions actually streamed.
        """
        # NOTE: both ghidra.app.decompiler.DecompInterface and ghidra.util.task.ConsoleTaskMonitor
        # are recorded missing-ignored at their first import (in _gh_decompile /
        # _run_monitored_analysis); a second per-line ignore here would be flagged "unused".
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        program = self._require_program()
        funcs, truncated = self._stream_target_functions(names, offset, limit)

        seq = 0
        for func in funcs:
            if is_cancelled():
                # Honest early stop: the chunks already emitted stand; the server marks the job
                # cancelled. Do NOT report truncated for a cancel (a client choice, not a cap).
                return {"total": seq, "truncated": False, "done": True}
            payload = self._decompile_one(program, func, DecompInterface, ConsoleTaskMonitor)
            if emit_chunk is not None:
                emit_chunk(seq, "function", payload)
            seq += 1
        return {"total": seq, "truncated": truncated, "done": True}

    def _stream_target_functions(  # pragma: no cover - JVM edge
        self, names: list[str] | None, offset: int, limit: int
    ) -> tuple[list[Any], bool]:
        """Resolve the ordered function set to stream + whether the window truncated (ADR-040).

        Args:
            names: Explicit identifiers, or ``None`` to window the program's functions.
            offset: Window start (only when ``names`` is ``None``).
            limit: Window cap (only when ``names`` is ``None``).

        Returns:
            ``(functions, truncated)`` — the ordered functions to decompile and the honesty flag
            (``True`` only when an unnamed window left functions beyond it; an explicit list is
            never "truncated" — it is exactly the requested set).
        """
        program = self._require_program()
        if names is not None:
            resolved: list[Any] = []
            for name in names:
                func = self._try_resolve_function(name)
                if func is not None:
                    resolved.append(func)
            return resolved, False
        all_funcs = list(program.getFunctionManager().getFunctions(True))
        window = all_funcs[offset : offset + limit]
        truncated = (offset + limit) < len(all_funcs)
        return window, truncated

    def _try_resolve_function(self, function: str) -> Any | None:  # pragma: no cover - JVM edge
        """Resolve a function by address/name, returning ``None`` instead of raising (stream path).

        The streaming path skips a non-resolving name rather than aborting the whole stream for one
        bad identifier (best-effort over a bounded set). Mirrors :meth:`_resolve_function` but
        non-raising.

        Args:
            function: An address (hex) or a function name.

        Returns:
            The matching Ghidra ``Function``, or ``None`` if none matches.
        """
        from worker.dispatch import WorkerError

        try:
            return self._resolve_function(function)
        except WorkerError:
            return None

    @staticmethod
    def _decompile_one(  # pragma: no cover - JVM edge
        program: Any, func: Any, decomp_interface_cls: Any, monitor_cls: Any
    ) -> dict[str, Any]:
        """Decompile one resolved function with a per-function decompiler (dispose in ``finally``).

        Mirrors :meth:`_gh_decompile`'s decompiler lifecycle but takes an already-resolved function
        and the (lazily-imported) JVM classes so the streaming loop imports them once. The
        ``DecompInterface`` is opened and **disposed per function** (ADR-002 memory discipline). A
        function whose decompilation does not complete yields an empty ``c_code`` rather than
        aborting the stream (best-effort partial — the server still envelopes it honestly).

        Args:
            program: The open Ghidra program.
            func: The resolved Ghidra ``Function`` to decompile.
            decomp_interface_cls: The ``DecompInterface`` class (lazily imported by the caller).
            monitor_cls: The ``ConsoleTaskMonitor`` class (lazily imported by the caller).

        Returns:
            ``{"address", "name", "c_code", "signature"}`` (all plain strings).
        """
        decompiler = decomp_interface_cls()
        try:
            decompiler.openProgram(program)
            results = decompiler.decompileFunction(func, 0, monitor_cls())
            c_code = ""
            if results is not None and results.decompileCompleted():
                decompiled = results.getDecompiledFunction()
                c_code = decompiled.getC() if decompiled is not None else ""
        finally:
            decompiler.dispose()
        return {
            "address": str(func.getEntryPoint()),
            "name": str(func.getName()),
            "c_code": _to_text(c_code),
            "signature": _to_text(func.getPrototypeString(False, False)),
        }

    def _gh_disassemble(
        self, start: str | None, function: str | None, cap: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Disassemble a bounded range or function via the Listing API.

        Args:
            start: Optional start address (hex) for a raw range.
            function: Optional function name/address (takes precedence over ``start``).
            cap: Maximum instructions to return (already clamped).

        Returns:
            ``{"instructions": [...], "truncated": bool}``.

        Raises:
            WorkerError: ``invalid-params`` if neither ``start`` nor ``function`` is given.
        """
        from worker.dispatch import CODE_INVALID_PARAMS, WorkerError

        program = self._require_program()
        listing = program.getListing()
        if function is not None:
            func = self._resolve_function(function)
            iterator = listing.getInstructions(func.getBody(), True)
        elif start is not None:
            begin = self._parse_address(start)
            iterator = listing.getInstructions(begin, True)
        else:
            raise WorkerError(CODE_INVALID_PARAMS, "disassemble requires start or function")

        instructions: list[dict[str, Any]] = []
        truncated = False
        for instr in iterator:
            if len(instructions) >= cap:
                truncated = True
                break
            instructions.append(
                {
                    "address": str(instr.getAddress()),
                    "mnemonic": _to_text(instr.getMnemonicString()),
                    "operands": _to_text(_instruction_operands(instr)),
                    "bytes_hex": _bytes_to_hex(instr.getBytes()),
                }
            )
        return {"instructions": instructions, "truncated": truncated}

    def _gh_get_pcode(
        self, start: str | None, function: str | None, cap: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List the lifted low p-code per instruction over a bounded range/function (ADR-052).

        Read-only: lifts each instruction to its raw p-code ops (``Instruction.getPcode()``) — the
        same IR ``emulate`` interprets — and renders each op as text. NOTHING is executed and the
        program DB is not touched. Bounded exactly like ``disassemble`` (``cap`` instructions); each
        instruction's op list is additionally capped (a defensive per-instruction ceiling).

        Args:
            start: Optional start address (hex) for a raw range.
            function: Optional function name/address (takes precedence over ``start``).
            cap: Maximum instructions to return (already clamped).

        Returns:
            ``{"instructions": [{"address", "mnemonic", "pcode": [str]}, ...], "truncated": bool}``.

        Raises:
            WorkerError: ``invalid-params`` if neither ``start`` nor ``function`` is given.
        """
        from worker.dispatch import CODE_INVALID_PARAMS, WorkerError

        program = self._require_program()
        listing = program.getListing()
        if function is not None:
            func = self._resolve_function(function)
            iterator = listing.getInstructions(func.getBody(), True)
        elif start is not None:
            iterator = listing.getInstructions(self._parse_address(start), True)
        else:
            raise WorkerError(CODE_INVALID_PARAMS, "get_pcode requires start or function")

        instructions: list[dict[str, Any]] = []
        truncated = False
        for instr in iterator:
            if len(instructions) >= cap:
                truncated = True
                break
            ops = [_to_text(str(op)) for op in instr.getPcode()[:_MAX_PCODE_OPS_PER_INSN]]
            instructions.append(
                {
                    "address": str(instr.getAddress()),
                    "mnemonic": _to_text(instr.getMnemonicString()),
                    "pcode": ops,
                }
            )
        return {"instructions": instructions, "truncated": truncated}

    def _gh_list_functions(
        self, offset: int, limit: int, name_contains: str | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List functions via FunctionManager (paginated/bounded).

        Args:
            offset: Zero-based start index into the (optionally filtered) function set.
            limit: Maximum functions to return (already clamped).
            name_contains: Optional case-insensitive substring filter.

        Returns:
            ``{"functions": [...], "total": int, "truncated": bool}``.
        """
        program = self._require_program()
        needle = name_contains.lower() if name_contains else None
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for func in program.getFunctionManager().getFunctions(True):
            name = str(func.getName())
            if needle is not None and needle not in name.lower():
                continue
            total += 1
            index = total - 1
            if index < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            rows.append(
                {
                    "address": str(func.getEntryPoint()),
                    "name": name,
                    "size": int(func.getBody().getNumAddresses()),
                }
            )
        return {"functions": rows, "total": total, "truncated": truncated}

    def _gh_get_function(self, function: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Resolve one function's detail.

        Args:
            function: Function entry address (hex) or name.

        Returns:
            ``{"address", "name", "signature", "size", "is_thunk", "calling_convention"?}``.
        """
        func = self._resolve_function(function)
        convention = func.getCallingConventionName()
        result: dict[str, Any] = {
            "address": str(func.getEntryPoint()),
            "name": str(func.getName()),
            "signature": _to_text(func.getPrototypeString(False, False)),
            "size": int(func.getBody().getNumAddresses()),
            "is_thunk": bool(func.isThunk()),
        }
        if convention is not None:
            result["calling_convention"] = _to_text(convention)
        return result

    def _gh_xrefs(
        self, target: str, offset: int, limit: int, *, to: bool
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List references to/from a target via ReferenceManager (paginated/bounded).

        Args:
            target: Address (hex) or function name to find references for.
            offset: Zero-based start index into the reference set.
            limit: Maximum references to return (already clamped).
            to: ``True`` for references TO the target, ``False`` for references FROM it.

        Returns:
            ``{"xrefs": [{"from_address","to_address","ref_type"}], "total", "truncated"}``.
        """
        program = self._require_program()
        address = self._resolve_address(target)
        ref_mgr = program.getReferenceManager()
        iterator = ref_mgr.getReferencesTo(address) if to else ref_mgr.getReferencesFrom(address)
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for ref in iterator:
            index = total
            total += 1
            if index < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            rows.append(
                {
                    "from_address": str(ref.getFromAddress()),
                    "to_address": str(ref.getToAddress()),
                    "ref_type": str(ref.getReferenceType().getName()),
                }
            )
        return {"xrefs": rows, "total": total, "truncated": truncated}

    def _gh_list_strings(
        self, offset: int, limit: int, min_length: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List defined strings via the Listing DataIterator (paginated/bounded).

        Args:
            offset: Zero-based start index into the matching-string set.
            limit: Maximum strings to return (already clamped).
            min_length: Minimum string length (in characters) to include.

        Returns:
            ``{"strings": [{"address","value","length"}], "total", "truncated"}``.
        """
        program = self._require_program()
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for data in program.getListing().getDefinedData(True):
            value = _string_value(data)
            if value is None or len(value) < min_length:
                continue
            index = total
            total += 1
            if index < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            rows.append(
                {
                    "address": str(data.getAddress()),
                    "value": value,
                    "length": int(data.getLength()),
                }
            )
        return {"strings": rows, "total": total, "truncated": truncated}

    def _gh_list_symbols(
        self, offset: int, limit: int, name_contains: str | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List symbols via SymbolTable (paginated/bounded).

        Args:
            offset: Zero-based start index into the (optionally filtered) symbol set.
            limit: Maximum symbols to return (already clamped).
            name_contains: Optional case-insensitive substring filter.

        Returns:
            ``{"symbols": [{"address","name","kind","namespace"?}], "total", "truncated"}``.
        """
        program = self._require_program()
        needle = name_contains.lower() if name_contains else None
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for symbol in program.getSymbolTable().getAllSymbols(True):
            name = str(symbol.getName())
            if needle is not None and needle not in name.lower():
                continue
            index = total
            total += 1
            if index < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            rows.append(_symbol_dict(symbol))
        return {"symbols": rows, "total": total, "truncated": truncated}

    def _gh_get_symbol(self, identifier: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Resolve one symbol by name or address.

        Args:
            identifier: Symbol name or address (hex).

        Returns:
            ``{"address","name","kind","namespace"?}``.

        Raises:
            WorkerError: ``not-found`` if no symbol matches.
        """
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        table = program.getSymbolTable()
        # Prefer an address hit; fall back to a name lookup (global namespace).
        addr = self._try_parse_address(identifier)
        if addr is not None:
            symbol = table.getPrimarySymbol(addr)
            if symbol is not None:
                return _symbol_dict(symbol)
        for symbol in table.getSymbols(identifier):
            return _symbol_dict(symbol)
        raise WorkerError(CODE_NOT_FOUND, "symbol not found")

    def _gh_list_data(self, offset: int, limit: int) -> dict[str, Any]:  # pragma: no cover
        """List defined data items via the Listing (paginated/bounded).

        Args:
            offset: Zero-based start index into the defined-data set.
            limit: Maximum data items to return (already clamped).

        Returns:
            ``{"data": [{"address","data_type","value_repr","length"}], "total", "truncated"}``.
        """
        program = self._require_program()
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for data in program.getListing().getDefinedData(True):
            index = total
            total += 1
            if index < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            rows.append(
                {
                    "address": str(data.getAddress()),
                    "data_type": _to_text(data.getDataType().getName()),
                    "value_repr": _to_text(data.getDefaultValueRepresentation()),
                    "length": int(data.getLength()),
                }
            )
        return {"data": rows, "total": total, "truncated": truncated}

    def _gh_get_data_type(self, name: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Resolve a data type via DataTypeManager.

        Args:
            name: Data-type name.

        Returns:
            ``{"name","kind","size","definition"}``.

        Raises:
            WorkerError: ``not-found`` if the type does not resolve.
        """
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        manager = program.getDataTypeManager()
        for data_type in manager.getAllDataTypes():
            if str(data_type.getName()) == name:
                return {
                    "name": _to_text(data_type.getName()),
                    "kind": _data_type_kind(data_type),
                    "size": int(data_type.getLength()),
                    "definition": _to_text(_data_type_definition(data_type)),
                }
        raise WorkerError(CODE_NOT_FOUND, "data type not found")

    def _gh_list_data_types(
        self, offset: int, limit: int, name_contains: str | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List the program's data types via DataTypeManager (paginated/bounded — ADR-056).

        Iterates ``DataTypeManager.getAllDataTypes()`` — the types established in this session
        (defined/applied/analysis-added) — and emits lightweight summary rows (name/kind/size), NOT
        the full rendered definition (fetch that per type via ``get_data_type``). Read-only. Mirrors
        :meth:`_gh_list_functions`'s pagination + optional case-insensitive substring filter.

        Args:
            offset: Zero-based start index into the (optionally filtered) type set.
            limit: Maximum types to return (already clamped).
            name_contains: Optional case-insensitive substring filter.

        Returns:
            ``{"data_types": [{"name", "kind", "size"}, ...], "total": int, "truncated": bool}``.
        """
        program = self._require_program()
        needle = name_contains.lower() if name_contains else None
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for data_type in program.getDataTypeManager().getAllDataTypes():
            name = str(data_type.getName())
            if needle is not None and needle not in name.lower():
                continue
            total += 1
            if (total - 1) < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            rows.append(
                {
                    "name": _to_text(data_type.getName()),
                    "kind": _data_type_kind(data_type),
                    "size": int(data_type.getLength()),
                }
            )
        return {"data_types": rows, "total": total, "truncated": truncated}

    def _gh_get_comments(
        self, offset: int, limit: int, address: str | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Read comments via the Listing comment API (paginated/bounded).

        Args:
            offset: Zero-based start index into the comment set.
            limit: Maximum comments to return (already clamped).
            address: Optional address (hex) to scope comments to; omit for all comments.

        Returns:
            ``{"comments": [{"address","comment_type","text"}], "total", "truncated"}``.
        """
        from ghidra.program.model.listing import CodeUnit  # type: ignore[import-not-found]

        program = self._require_program()
        listing = program.getListing()
        comment_types = (
            (CodeUnit.EOL_COMMENT, "EOL"),
            (CodeUnit.PRE_COMMENT, "PRE"),
            (CodeUnit.POST_COMMENT, "POST"),
            (CodeUnit.PLATE_COMMENT, "PLATE"),
            (CodeUnit.REPEATABLE_COMMENT, "REPEATABLE"),
        )
        # integration-validate: Listing.getCommentAddressIterator(AddressSetView, forward) and the
        # CodeUnit.*_COMMENT type constants on 12.1.2; AddressFactory.getAddressSet(start, end)
        # yields a single-address set for the scoped case.
        if address is not None:
            scoped = self._parse_address(address)
            addr_iter = program.getAddressFactory().getAddressSet(scoped, scoped)
            iterator = listing.getCommentAddressIterator(addr_iter, True)
        else:
            iterator = listing.getCommentAddressIterator(program.getMemory(), True)

        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for comment_addr in iterator:
            for type_id, label in comment_types:
                text = listing.getComment(type_id, comment_addr)
                if text is None:
                    continue
                index = total
                total += 1
                if index < offset:
                    continue
                if len(rows) >= limit:
                    truncated = True
                    continue
                rows.append(
                    {
                        "address": str(comment_addr),
                        "comment_type": label,
                        "text": _to_text(text),
                    }
                )
        return {"comments": rows, "total": total, "truncated": truncated}

    def _gh_memory_map(self) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List memory blocks via the Memory API.

        Returns:
            ``{"blocks": [{"name","start","end","size","permissions","initialized"}]}``.
        """
        program = self._require_program()
        blocks: list[dict[str, Any]] = []
        for block in program.getMemory().getBlocks():
            blocks.append(
                {
                    "name": _to_text(block.getName()),
                    "start": str(block.getStart()),
                    "end": str(block.getEnd()),
                    "size": int(block.getSize()),
                    "permissions": _block_permissions(block),
                    "initialized": bool(block.isInitialized()),
                }
            )
        return {"blocks": blocks}

    def _get_bytes(
        self, memory: Any, address: Any, length: int
    ) -> tuple[bytes, int]:  # pragma: no cover - JVM edge
        """Read up to ``length`` bytes at ``address``, returning ``(data, count_read)``.

        **jpype correctness (#292):** ``Memory.getBytes(Address, byte[])`` fills the array **in
        place**, so it MUST be a real Java ``byte[]`` (``jpype.JArray(JByte)``). Passing a Python
        ``bytearray`` makes jpype marshal a **copy** for the call — ``getBytes`` fills the copy and
        returns the count, but the fill never propagates back, so the Python buffer stays all-zero
        (the caller sees the right length but zero data). That silent zero-fill is exactly the
        correctness trap ADR-005 warns against. Java bytes are signed; mask to unsigned on the way
        out. On ``MemoryAccessException`` (reading past initialized memory) fall back to a
        byte-by-byte read so ``count_read < length`` is honest (drives ``truncated``).

        Args:
            memory: The program ``Memory``.
            address: The start ``Address``.
            length: Number of bytes to attempt (already clamped by the caller).

        Returns:
            A ``(data, count_read)`` tuple; ``data`` is exactly ``count_read`` bytes.
        """
        import jpype

        buffer = jpype.JArray(jpype.JByte)(length)
        try:
            read = int(memory.getBytes(address, buffer))
            return bytes(int(buffer[i]) & 0xFF for i in range(read)), read
        except Exception:
            # Past initialized memory / a block gap — read what is actually there, honestly.
            out = bytearray()
            for index in range(length):
                try:
                    out.append(int(memory.getByte(address.add(index))) & 0xFF)
                except Exception:
                    break
            return bytes(out), len(out)

    def _gh_read_bytes(self, address: str, length: int) -> dict[str, Any]:  # pragma: no cover
        """Read a bounded byte range via Memory.getBytes (confined to the map).

        Args:
            address: Start address (hex).
            length: Number of bytes to read (already clamped to ``_MAX_READ_BYTES``).

        Returns:
            ``{"address","data"(hex),"length","truncated"}``. ``truncated`` is ``True`` when fewer
            bytes than requested were available (end of an initialized block).
        """
        program = self._require_program()
        start = self._parse_address(address)
        data, read = self._get_bytes(program.getMemory(), start, length)
        return {
            "address": str(start),
            "data": data.hex(),
            "length": read,
            "truncated": read < length,
        }

    def _gh_search_bytes(
        self, pattern_hex: str, offset: int, limit: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Search for a byte pattern via Memory.findBytes (paginated/bounded).

        Args:
            pattern_hex: Hex byte pattern with optional ``"??"`` wildcards (already validated).
            offset: Zero-based start index into the match set.
            limit: Maximum matches to return (already clamped).

        Returns:
            ``{"matches": [{"address","context_hex"(hex)}], "total", "truncated"}``.
        """
        program = self._require_program()
        values, masks = _pattern_to_bytes_and_mask(pattern_hex)
        memory = program.getMemory()
        context_len = len(values)
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        # integration-validate: Memory.findBytes(start, values, masks, forward, monitor) returns the
        # next match Address or null; confirm the exact overload on 12.1.2 (TaskMonitor.DUMMY).
        # NOTE: no per-line ignore here — mypy already records ghidra.util.task as missing-ignored
        # at its first import (in _gh_decompile); a second ignore on the same module is "unused".
        from ghidra.util.task import TaskMonitor

        cursor = program.getMinAddress()
        while cursor is not None and total < _MAX_RESULT_COUNT:
            match = memory.findBytes(cursor, values, masks, True, TaskMonitor.DUMMY)
            if match is None:
                break
            index = total
            total += 1
            if index < offset:
                pass  # already paged past
            elif len(rows) < limit:
                rows.append(
                    {
                        "address": str(match),
                        "context_hex": self._read_context_hex(memory, match, context_len),
                    }
                )
            else:
                truncated = True  # more matched than the page allows
            cursor = match.add(1)
        return {"matches": rows, "total": total, "truncated": truncated}

    def _gh_search_strings(
        self, query: str, offset: int, limit: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Search defined strings by case-insensitive substring (paginated/bounded).

        Args:
            query: Case-insensitive substring to match (already validated; not a regex).
            offset: Zero-based start index into the match set.
            limit: Maximum strings to return (already clamped).

        Returns:
            ``{"strings": [{"address","value","length"}], "total", "truncated"}`` (same shape as
            ``list_strings``).
        """
        program = self._require_program()
        needle = query.lower()
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for data in program.getListing().getDefinedData(True):
            value = _string_value(data)
            if value is None or needle not in value.lower():
                continue
            index = total
            total += 1
            if index < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            rows.append(
                {
                    "address": str(data.getAddress()),
                    "value": value,
                    "length": int(data.getLength()),
                }
            )
        return {"strings": rows, "total": total, "truncated": truncated}

    def _gh_program_metadata(self) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Collect high-level program metadata.

        Returns:
            A plain ``ProgramMetadata``-shaped dict.
        """
        program = self._require_program()
        language = program.getLanguage()
        entry = self._entry_point(program)
        return {
            "sha256": self._sha256 or "",
            "size_bytes": int(program.getMemory().getNumAddresses()),
            "format": _to_text(program.getExecutableFormat()),
            "architecture": _to_text(language.getLanguageID().getIdAsString()),
            "endianness": "big" if language.isBigEndian() else "little",
            "compiler": _to_text(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            "entry_point": (str(entry) if entry is not None else None),
            "function_count": int(program.getFunctionManager().getFunctionCount()),
            "analysis_complete": bool(self._analyzed),
        }

    # C901: PyGhidra call-graph enumeration across the JVM boundary (ADR-001) — live-regression-only
    # coverage; decomposition risks the bounded BFS/ref-iteration ordering.
    def _gh_call_graph(  # noqa: C901
        self, root: str | None, max_depth: int, max_nodes: int, max_edges: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Extract a bounded resolved-call adjacency (v1.1 — ADR-007; worker-only per ADR-001).

        Walks the FunctionManager + Listing/ReferenceManager to build a bounded adjacency: nodes are
        functions in scope, edges are resolved caller-entry -> callee-entry calls. Functions with an
        UNRESOLVED outgoing call site (indirect/virtual/computed whose target does not resolve to a
        concrete function) are flagged (``has_unresolved_calls``) and listed in
        ``unresolved_callers`` — surfaced, never silently dropped (ADR-005 honesty; threat-model
        TB4). External/imported/thunk functions are marked ``is_external`` so the client does NOT
        re-infer their KNOWN names. Stops at ``max_nodes``/``max_edges`` (and ``max_depth`` for a
        scoped ``root``) and sets ``truncated`` (DoS cap). Returns plain JSON-serializable values
        only (no Java object crosses the boundary); the server wraps the untrusted ``name`` fields.

        Args:
            root: Optional function (entry address hex or name) to scope reachability from; ``None``
                walks the whole program.
            max_depth: Maximum forward call depth from ``root`` (ignored when ``root`` is ``None``).
            max_nodes: Hard cap on emitted nodes.
            max_edges: Hard cap on distinct emitted edges.

        Returns:
            ``{"nodes": [...], "edges": [...], "unresolved_callers": [...], "truncated": bool}``.
        """
        # integration-validate (Ghidra 12.1.2 javadoc — confirm at the gated image build):
        #   FunctionManager.getFunctions(bool) / getFunctionAt / getFunctionContaining;
        #   Function.getEntryPoint/getName/getBody/isExternal/isThunk; Listing.getInstructions(
        #   AddressSetView, bool); Instruction.getFlowType().isCall() / getReferencesFrom();
        #   Reference.getReferenceType().isCall() / getToAddress().
        program = self._require_program()
        manager = program.getFunctionManager()
        listing = program.getListing()
        ref_mgr = program.getReferenceManager()

        # --- phase 1: the in-scope node set (capped at max_nodes → truncated) ---
        nodes: dict[str, Any] = {}  # entry-hex -> Function (insertion order = deterministic)
        truncated = False

        def _add(func: Any) -> bool:
            """Add a function to the node set; return False (and signal truncation) if capped."""
            entry = str(func.getEntryPoint())
            if entry in nodes:
                return True
            if len(nodes) >= max_nodes:
                return False
            nodes[entry] = func
            return True

        if root is None:
            for func in manager.getFunctions(True):
                if not _add(func):
                    truncated = True
                    break
        else:
            seed = self._resolve_function(str(root))
            _add(seed)
            frontier = [seed]
            depth = 0
            while frontier and depth < max_depth:
                nxt: list[Any] = []
                for caller in frontier:
                    for callee in self._iter_call_sites(caller, listing, ref_mgr, manager):
                        if callee is None:
                            continue
                        was_known = str(callee.getEntryPoint()) in nodes
                        if not _add(callee):
                            truncated = True
                        elif not was_known:
                            nxt.append(callee)
                frontier = nxt
                depth += 1

        # --- phase 2: resolved edges over the final node set + per-node unresolved flag ---
        edges: list[dict[str, str]] = []
        seen_edges: set[tuple[str, str]] = set()
        unresolved_callers: list[str] = []
        node_rows: list[dict[str, Any]] = []
        for entry, func in nodes.items():
            has_unresolved = False
            for callee in self._iter_call_sites(func, listing, ref_mgr, manager):
                if callee is None:
                    has_unresolved = True
                    continue
                callee_entry = str(callee.getEntryPoint())
                if callee_entry not in nodes:
                    continue  # resolved but beyond the scope/depth boundary — not "unresolved"
                key = (entry, callee_entry)
                if key in seen_edges:
                    continue
                if len(edges) >= max_edges:
                    truncated = True
                    continue
                seen_edges.add(key)
                edges.append({"from_address": entry, "to_address": callee_entry})
            if has_unresolved:
                unresolved_callers.append(entry)
            node_rows.append(
                {
                    "address": entry,
                    "name": _to_text(func.getName()),
                    "is_external": bool(func.isExternal()) or bool(func.isThunk()),
                    "has_unresolved_calls": has_unresolved,
                }
            )
        return {
            "nodes": node_rows,
            "edges": edges,
            "unresolved_callers": unresolved_callers,
            "truncated": truncated,
        }

    def _iter_call_sites(
        self, func: Any, listing: Any, ref_mgr: Any, manager: Any
    ) -> Any:  # pragma: no cover - JVM edge
        """Yield one target per call site in ``func``: a callee ``Function`` or ``None``.

        Iterates the function's call instructions; for each, the resolved call target is yielded
        as a Ghidra ``Function``. A call site whose target cannot be resolved to a concrete
        function (indirect/virtual/computed — e.g. ``call rax``) yields ``None`` so the caller can
        flag an unresolved edge (ADR-005 honesty; never silently dropped).

        Args:
            func: The caller Ghidra ``Function``.
            listing: The program ``Listing``.
            ref_mgr: The program ``ReferenceManager`` (reserved for call-ref fallbacks).
            manager: The program ``FunctionManager`` (resolves a target address to a function).

        Yields:
            A callee ``Function`` for each resolved call site, or ``None`` for an unresolved one.
        """
        del ref_mgr  # call targets come from the instruction's own references; kept for symmetry
        for instr in listing.getInstructions(func.getBody(), True):
            if not bool(instr.getFlowType().isCall()):
                continue
            target = None
            for ref in instr.getReferencesFrom():
                if not bool(ref.getReferenceType().isCall()):
                    continue
                fn = manager.getFunctionAt(ref.getToAddress())
                if fn is None:
                    fn = manager.getFunctionContaining(ref.getToAddress())
                if fn is not None:
                    target = fn
                    break
            yield target

    def _gh_referenced_strings(
        self, function: str, max_strings: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List the (bounded) defined-string values ``function`` references (v1.1 — ADR-007).

        Scans the function body's outgoing references; any reference whose target is defined data
        with a string value contributes that value (de-duplicated by target address, capped at
        ``max_strings`` → ``truncated``). Plain string values only; the server wraps each in the
        BINARY-origin untrusted envelope (ADR-005).

        Args:
            function: Function entry address (hex) or name.
            max_strings: Hard cap on returned string values (already clamped).

        Returns:
            ``{"strings": [str, ...], "truncated": bool}``.
        """
        # integration-validate: ReferenceManager.getReferenceSourceIterator(AddressSetView, bool) /
        # getReferencesFrom(Address); Listing.getDataContaining(Address); Data.hasStringValue().
        program = self._require_program()
        func = self._resolve_function(function)
        listing = program.getListing()
        ref_mgr = program.getReferenceManager()
        seen: set[str] = set()
        values: list[str] = []
        truncated = False
        for src in ref_mgr.getReferenceSourceIterator(func.getBody(), True):
            for ref in ref_mgr.getReferencesFrom(src):
                to_addr = ref.getToAddress()
                key = str(to_addr)
                if key in seen:
                    continue
                data = listing.getDataContaining(to_addr)
                value = _string_value(data) if data is not None else None
                if value is None:
                    continue
                seen.add(key)
                if len(values) >= max_strings:
                    truncated = True
                    continue
                values.append(value)
        return {"strings": values, "truncated": truncated}

    # --- Tier-2 metric extraction (v1.1 — ADR-008; worker-only JVM edge per ADR-001) -------------
    # Built against the pinned image; like every other ``_gh_*`` helper these are coverage-omitted
    # and exercised only by the real-worker integration suite (the symbol bindings are confirmed at
    # the gated image build — ADR-003). Each returns plain JSON-serializable values; the server
    # computes the metrics in the pure cores and wraps binary-derived names (ADR-005).
    def _gh_function_cfg(self, function: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Per-function CFG block/edge counts (v1.1 — ADR-008; for cyclomatic complexity).

        Walks ``BasicBlockModel`` over the resolved function to count basic blocks (CFG nodes) and
        control-flow edges; ``incomplete`` flags a block whose flow could not be fully resolved (the
        server then treats McCabe ``E - N + 2`` as a lower bound). The pure core
        (:mod:`vivarium.core.metrics`) computes the complexity from these counts.

        Args:
            function: Function entry address (hex) or name.

        Returns:
            ``{"address", "name", "block_count", "edge_count", "incomplete"}``.
        """
        # integration-validate (Ghidra 12.1.2 javadoc — confirm at the gated image build):
        #   ghidra.program.model.block.BasicBlockModel(program);
        #   model.getCodeBlocksContaining(func.getBody(), monitor) -> CodeBlock iterator;
        #   CodeBlock.getNumDestinations(monitor) counts outgoing CFG edges;
        #   ghidra.util.task.TaskMonitor.DUMMY as the no-progress monitor.
        # (BasicBlockModel is missing-ignored at its FIRST import in _gh_basic_blocks, above.)
        from ghidra.program.model.block import BasicBlockModel

        # ghidra.util.task is already missing-ignored at its first import (in _gh_decompile); a
        # second per-line ignore on the same module would be "unused" (mypy unused-ignore).
        from ghidra.util.task import TaskMonitor

        program = self._require_program()
        func = self._resolve_function(function)
        model = BasicBlockModel(program)
        monitor = TaskMonitor.DUMMY
        block_count = 0
        edge_count = 0
        incomplete = False
        blocks = model.getCodeBlocksContaining(func.getBody(), monitor)
        while blocks.hasNext():
            block = blocks.next()
            block_count += 1
            destinations = block.getDestinations(monitor)
            while destinations.hasNext():
                ref = destinations.next()
                # Count only edges whose destination is inside this function's body; a flow that
                # leaves the function (call/return/tail) is not an intraprocedural CFG edge. A
                # destination block we cannot resolve flags the CFG as incomplete (honesty — the
                # complexity is then a lower bound).
                dest = ref.getDestinationBlock()
                if dest is None:
                    incomplete = True
                    continue
                if func.getBody().contains(dest.getFirstStartAddress()):
                    edge_count += 1
        return {
            "address": str(func.getEntryPoint()),
            "name": _to_text(func.getName()),
            "block_count": block_count,
            "edge_count": edge_count,
            "incomplete": incomplete,
        }

    def _gh_imports(self, offset: int, limit: int) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Imported symbols via the SymbolTable external-symbol iterator (paginated/bounded).

        Args:
            offset: Zero-based start index into the import set.
            limit: Maximum imports to return (already clamped).

        Returns:
            ``{"imports": [{"name","library"?,"address"?}], "total", "truncated"}``.
        """
        # integration-validate: SymbolTable.getExternalSymbols() -> Symbol iterator;
        #   Symbol.getName(); Symbol.getParentNamespace().getName() is the source library/module for
        #   an external symbol; Symbol.getAddress() (may be an EXTERNAL-space address).
        program = self._require_program()
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for symbol in program.getSymbolTable().getExternalSymbols():
            index = total
            total += 1
            if index < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            namespace = symbol.getParentNamespace()
            row: dict[str, Any] = {"name": _to_text(symbol.getName())}
            if namespace is not None and not bool(namespace.isGlobal()):
                row["library"] = _to_text(namespace.getName())
            address = symbol.getAddress()
            if address is not None:
                row["address"] = str(address)
            rows.append(row)
        return {"imports": rows, "total": total, "truncated": truncated}

    def _gh_exports(self, offset: int, limit: int) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Exported symbols / entry points via the SymbolTable (paginated/bounded).

        Args:
            offset: Zero-based start index into the export set.
            limit: Maximum exports to return (already clamped).

        Returns:
            ``{"exports": [{"name","address"}], "total", "truncated"}``.
        """
        # integration-validate: SymbolTable.getExternalEntryPointIterator() -> Address iterator of
        #   exported entry points; SymbolTable.getPrimarySymbol(addr).getName() for the label.
        program = self._require_program()
        table = program.getSymbolTable()
        rows: list[dict[str, Any]] = []
        total = 0
        truncated = False
        for address in table.getExternalEntryPointIterator():
            index = total
            total += 1
            if index < offset:
                continue
            if len(rows) >= limit:
                truncated = True
                continue
            symbol = table.getPrimarySymbol(address)
            name = _to_text(symbol.getName()) if symbol is not None else ""
            rows.append({"name": name, "address": str(address)})
        return {"exports": rows, "total": total, "truncated": truncated}

    def _gh_coverage(self) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Defined-code/data byte counts via the Listing (server computes ratios in the pure core).

        Returns:
            ``{"total_bytes","defined_code_bytes","defined_data_bytes","function_count"}``.
        """
        # integration-validate: Listing.getInstructions(true) -> Instruction iterator (each
        #   .getLength() bytes); Listing.getDefinedData(true) -> Data iterator (.getLength());
        #   Memory.getNumAddresses() for the addressable total; FunctionManager.getFunctionCount().
        program = self._require_program()
        listing = program.getListing()
        defined_code_bytes = 0
        for instr in listing.getInstructions(True):
            defined_code_bytes += int(instr.getLength())
        defined_data_bytes = 0
        for data in listing.getDefinedData(True):
            defined_data_bytes += int(data.getLength())
        return {
            "total_bytes": int(program.getMemory().getNumAddresses()),
            "defined_code_bytes": defined_code_bytes,
            "defined_data_bytes": defined_data_bytes,
            "function_count": int(program.getFunctionManager().getFunctionCount()),
        }

    def _gh_identify_functions(
        self, limit: int, min_score: float | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Run the Ghidra Function ID service and shape the library matches (ADR-042 Phase 1).

        One row per surviving candidate (a function may match several library candidates above the
        threshold — multiplicity is honest). Candidates scoring below the effective threshold
        (``min_score`` when supplied, else the FID default) are dropped; the result is clamped to
        ``limit`` with a ``truncated`` flag (no silent loss — ADR-005).

        Args:
            limit: Maximum match rows to return (already bounded by the caller/server).
            min_score: Minimum FID overall score to include, or ``None`` to use the FID default
                score threshold.

        Returns:
            ``{"matches": [{"address","matched_name","library","score"}], "truncated": bool}``.
        """
        # FID service path — signature VERIFIED live against Ghidra 12.1.2 (the live integration
        # test caught the original two-arg call; processProgram needs a FidQueryService +
        # threshold):
        #   svc.openFidQueryService(Language, processLibraries=False) -> FidQueryService (active);
        #   svc.processProgram(Program, FidQueryService, scoreThreshold, TaskMonitor)
        #     -> List<FidSearchResult>. FidSearchResult has PUBLIC FIELDS .function (a Function;
        #     .getEntryPoint().toString() = address) and .matches (List<FidMatch>). FidMatch:
        #     getOverallScore() -> float; getFunctionRecord().getName() = library function name;
        #     getLibraryRecord() -> getLibraryFamilyName()/Version()/Variant().
        #   Threshold default: svc.getDefaultScoreThreshold(). The query service MUST be closed.
        from ghidra.feature.fid.service import FidService  # type: ignore[import-not-found]

        # NOTE: ghidra.util.task is already missing-import-ignored at its first import site
        # (_run_monitored_analysis / _gh_decompile), so a second per-line ignore here would be
        # flagged "unused" — import ConsoleTaskMonitor without one (mirrors _gh_decompile_stream).
        from ghidra.util.task import ConsoleTaskMonitor

        program = self._require_program()
        service = FidService()
        threshold = float(service.getDefaultScoreThreshold()) if min_score is None else min_score
        language = program.getLanguage()
        if not service.canProcess(language):
            # No FID database covers this processor → no matches (well-formed empty result).
            return {"matches": [], "truncated": False}
        query_service = service.openFidQueryService(language, False)
        rows: list[dict[str, Any]] = []
        truncated = False
        try:
            monitor = ConsoleTaskMonitor()
            results = service.processProgram(program, query_service, threshold, monitor)
            for search_result in results:
                address = str(search_result.function.getEntryPoint().toString())
                for match in search_result.matches:
                    score = float(match.getOverallScore())
                    if score < threshold:
                        continue
                    if len(rows) >= limit:
                        truncated = True
                        break
                    library = match.getLibraryRecord()
                    rows.append(
                        {
                            "address": address,
                            "matched_name": _to_text(match.getFunctionRecord().getName()),
                            "library": _to_text(
                                f"{library.getLibraryFamilyName()} "
                                f"{library.getLibraryVersion()} "
                                f"{library.getLibraryVariant()}"
                            ),
                            "score": score,
                        }
                    )
                if len(rows) >= limit:
                    truncated = True
                    break
        finally:
            query_service.close()
        return {"matches": rows, "truncated": truncated}

    # --- private JVM helpers (lazy imports only; never at module scope) -----------------------
    # --- mutation JVM edges (ADR-012; one transaction per write, roll back on failure) -------
    def _gh_rename_function(
        self, function: str, new_name: str
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Rename a function inside one transaction (commit on success; roll back on failure).

        Args:
            function: The target function (entry address hex or current name).
            new_name: The server-validated new name to set.

        Returns:
            ``{"address", "old_name", "new_name", "applied"}`` (plain).

        Raises:
            WorkerError: ``not-found`` if the function does not resolve; ``analysis-failed`` if the
                rename raised (the transaction is rolled back first — fail closed).
        """
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]

        func = self._resolve_function(function)
        old_name = _to_text(func.getName())
        address = str(func.getEntryPoint())

        def _write() -> None:
            func.setName(new_name, SourceType.USER_DEFINED)

        self._in_transaction("rename_function", _write)
        return {
            "address": address,
            "old_name": old_name,
            "new_name": new_name,
            "applied": True,
        }

    def _gh_rename_symbol(
        self, identifier: str, new_name: str
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Rename a symbol inside one transaction (commit on success; roll back on failure).

        Args:
            identifier: The target symbol (address hex or current name).
            new_name: The server-validated new name to set.

        Returns:
            ``{"address", "old_name", "new_name", "kind", "applied"}`` (plain).

        Raises:
            WorkerError: ``not-found`` if no symbol matches; ``analysis-failed`` on a rolled-back
                write.
        """
        from ghidra.program.model.symbol import SourceType
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        table = program.getSymbolTable()
        symbol = None
        addr = self._try_parse_address(identifier)
        if addr is not None:
            symbol = table.getPrimarySymbol(addr)
        if symbol is None:
            for candidate in table.getSymbols(identifier):
                symbol = candidate
                break
        if symbol is None:
            raise WorkerError(CODE_NOT_FOUND, "symbol not found")
        old_name = _to_text(symbol.getName())
        address = str(symbol.getAddress())
        kind = str(symbol.getSymbolType())

        def _write() -> None:
            symbol.setName(new_name, SourceType.USER_DEFINED)

        self._in_transaction("rename_symbol", _write)
        return {
            "address": address,
            "old_name": old_name,
            "new_name": new_name,
            "kind": kind,
            "applied": True,
        }

    def _gh_set_comment(
        self, address: str, comment_type: str, text: str | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Set/clear one comment at an address inside one transaction (roll back on failure).

        Args:
            address: The target address (hex).
            comment_type: One of ``EOL``/``PRE``/``POST``/``PLATE``/``REPEATABLE`` (closed kinds).
            text: The comment text, or ``None`` to clear the comment.

        Returns:
            ``{"address", "comment_type", "applied"}`` (plain).

        Raises:
            WorkerError: ``invalid-params`` if the comment kind is unknown; ``analysis-failed`` on
                a rolled-back write.
        """
        from ghidra.program.model.listing import CodeUnit
        from worker.dispatch import CODE_INVALID_PARAMS, WorkerError

        program = self._require_program()
        kinds = {
            "EOL": CodeUnit.EOL_COMMENT,
            "PRE": CodeUnit.PRE_COMMENT,
            "POST": CodeUnit.POST_COMMENT,
            "PLATE": CodeUnit.PLATE_COMMENT,
            "REPEATABLE": CodeUnit.REPEATABLE_COMMENT,
        }
        type_id = kinds.get(comment_type)
        if type_id is None:  # defense in depth: the server schema already allow-lists the kind
            raise WorkerError(CODE_INVALID_PARAMS, "unknown comment type")
        addr = self._parse_address(address)
        listing = program.getListing()

        def _write() -> None:
            listing.setComment(addr, type_id, text)

        self._in_transaction("set_comment", _write)
        return {"address": str(addr), "comment_type": comment_type, "applied": True}

    def _gh_undo(self) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Undo the last committed transaction on the open program, if any.

        Returns:
            ``{"undone": bool}`` — ``False`` when there is nothing to undo.

        Raises:
            WorkerError: ``analysis-failed`` if no program is loaded or the undo raised.
        """
        from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

        program = self._require_program()
        if not bool(program.canUndo()):
            return {"undone": False}
        try:
            program.undo()
        except Exception as exc:
            raise WorkerError(CODE_ANALYSIS_FAILED, "undo failed") from exc
        return {"undone": True}

    def _gh_rename_high_variable(
        self, function: str, target: str, new_name: str, *, is_parameter: bool
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Rename a decompiler local/parameter via the HighFunction path (name-only — ADR-013 §2b).

        Decompiles the function to obtain its ``HighFunction``, selects the target ``HighSymbol`` by
        its assigned name (parameters only when ``is_parameter``) and renames it inside one
        transaction with a **null** data type (no type change — Phase A). PyGhidra symbol bindings
        (``HighFunctionDBUtil.updateDBVariable``, ``getLocalSymbolMap``) are confirmed at the WS3
        image build (ADR-003 open item), like the other ``_gh_*`` helpers.

        Args:
            function: Owning function (entry address hex or current name).
            target: The local/parameter selector (the decompiler-assigned name).
            new_name: The server-validated new name to set.
            is_parameter: Restrict the search to parameters (``rename_parameter``) vs locals.

        Returns:
            ``{"address", "function", "old_name", "new_name", "applied"}`` (plain).

        Raises:
            WorkerError: ``not-found`` if the function or target symbol does not resolve;
                ``analysis-failed`` if decompilation or the rename fails (rolled back).
        """
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.pcode import (  # type: ignore[import-not-found]
            HighFunctionDBUtil,
        )
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor
        from worker.dispatch import CODE_ANALYSIS_FAILED, CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        func = self._resolve_function(function)
        address = str(func.getEntryPoint())
        func_name = _to_text(func.getName())

        decompiler = DecompInterface()
        try:
            decompiler.openProgram(program)
            results = decompiler.decompileFunction(func, 0, ConsoleTaskMonitor())
            # Require a COMPLETED decompile (mirrors the read path _gh_decompile) — a timed-out/
            # partial result can return a non-None but incomplete HighFunction (review finding 2).
            if results is None or not results.decompileCompleted():
                raise WorkerError(CODE_ANALYSIS_FAILED, "decompilation did not complete")
            high = results.getHighFunction()
            if high is None:
                raise WorkerError(
                    CODE_ANALYSIS_FAILED, "decompilation did not produce a high function"
                )
            symbol = None
            for candidate in high.getLocalSymbolMap().getSymbols():
                if _to_text(candidate.getName()) != target:
                    continue
                if bool(candidate.isParameter()) != is_parameter:
                    continue  # params vs locals, selected per is_parameter
                symbol = candidate
                break
            if symbol is None:
                raise WorkerError(CODE_NOT_FOUND, "local/parameter not found")
            old_name = _to_text(symbol.getName())
            tool = "rename_parameter" if is_parameter else "rename_local_variable"
            # Name-only: pass a null DataType (no type change — ADR-013 §1). One transaction (§4).
            self._in_transaction(
                tool,
                lambda: HighFunctionDBUtil.updateDBVariable(
                    symbol, new_name, None, SourceType.USER_DEFINED
                ),
            )
        finally:
            decompiler.dispose()
        return {
            "address": address,
            "function": func_name,
            "old_name": old_name,
            "new_name": new_name,
            "applied": True,
        }

    # --- structural type-aware write JVM edges (ADR-014 Phase B; resolve→assemble→one txn) -----
    # The TypeRef resolution is read-only and runs BEFORE startTransaction (ADR-014 §4): an
    # unresolvable type is a clean not-found with no transaction opened. NO CParser/DataTypeParser
    # is ever instantiated — every Ghidra type object is assembled from already-resolved DataType
    # handles looked up in the DataTypeManager (the same lookup _gh_get_data_type uses).
    _BASE_TYPE_VOCAB = frozenset(
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

    def _gh_resolve_type_ref(self, ref: dict[str, Any]) -> Any:  # pragma: no cover - JVM edge
        """Resolve a structured ``TypeRef`` to a Ghidra ``DataType`` (read-only — ADR-014 §2.1).

        Resolves the leaf (a closed ``base`` mapped to a built-in, or a ``named`` type looked up in
        the ``DataTypeManager`` — must already exist), then wraps it in bounded
        ``PointerDataType``/``ArrayDataType`` modifiers. NEVER parses a string.

        Args:
            ref: ``{"base", "named", "pointer_levels", "array_len"}`` (server-validated shape).

        Returns:
            The resolved Ghidra ``DataType``.

        Raises:
            WorkerError: ``not-found`` if a ``named`` type does not exist; ``invalid-params`` on a
                malformed/out-of-vocab ref (defense in depth — the server already allow-listed it).
        """
        from ghidra.program.model.data import (  # type: ignore[import-not-found]
            ArrayDataType,
            BooleanDataType,
            CharDataType,
            DoubleDataType,
            FloatDataType,
            IntegerDataType,
            LongDataType,
            LongLongDataType,
            PointerDataType,
            ShortDataType,
            SignedByteDataType,
            UnsignedCharDataType,
            UnsignedIntegerDataType,
            UnsignedLongDataType,
            UnsignedLongLongDataType,
            UnsignedShortDataType,
            VoidDataType,
            WideCharDataType,
        )
        from worker.dispatch import CODE_INVALID_PARAMS, CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        manager = program.getDataTypeManager()
        base = ref.get("base")
        named = ref.get("named")
        if (base is None) == (named is None):
            raise WorkerError(CODE_INVALID_PARAMS, "type reference must set exactly one leaf")

        leaf: Any
        if base is not None:
            if base not in self._BASE_TYPE_VOCAB:
                raise WorkerError(CODE_INVALID_PARAMS, "type reference base not in the allow-list")
            builtins = {
                "void": VoidDataType,
                "bool": BooleanDataType,
                "char": CharDataType,
                "uchar": UnsignedCharDataType,
                "wchar_t": WideCharDataType,
                "int8": SignedByteDataType,
                "uint8": UnsignedCharDataType,
                "int16": ShortDataType,
                "uint16": UnsignedShortDataType,
                "int32": IntegerDataType,
                "uint32": UnsignedIntegerDataType,
                "int64": LongLongDataType,
                "uint64": UnsignedLongLongDataType,
                "int": IntegerDataType,
                "uint": UnsignedIntegerDataType,
                "long": LongDataType,
                "ulong": UnsignedLongDataType,
                "float": FloatDataType,
                "double": DoubleDataType,
            }
            leaf = builtins[str(base)].dataType
        else:
            leaf = None
            for data_type in manager.getAllDataTypes():
                if str(data_type.getName()) == str(named):
                    leaf = data_type
                    break
            if leaf is None:
                raise WorkerError(CODE_NOT_FOUND, "named type not found")

        for _ in range(int(ref.get("pointer_levels") or 0)):
            leaf = PointerDataType(leaf)
        array_len = ref.get("array_len")
        if array_len is not None:
            leaf = ArrayDataType(leaf, int(array_len), leaf.getLength())
        return leaf

    def _gh_set_function_signature(
        self,
        function: str,
        return_type: dict[str, Any],
        parameters: list[dict[str, Any]],
        calling_convention: str | None,
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Set a function's signature from resolved types inside one transaction (ADR-014 §1).

        Resolves the return type + each parameter type (read-only, before the transaction), builds
        ``ParameterImpl`` handles, then applies via ``Function.updateFunction`` inside one
        transaction (commit-time re-flow re-renders callers — the corrected ``_in_transaction``
        rolls back on a write/commit failure). NO C string is parsed.

        Args:
            function: The target function (entry address hex or current name).
            return_type: The return type as a ``TypeRef`` dict.
            parameters: Ordered ``[{"name", "type": TypeRef}]`` (server-validated names + shapes).
            calling_convention: A closed-allow-list convention name, or ``None`` (leave unchanged).

        Returns:
            ``{"address", "function", "old_signature", "new_signature", "applied"}`` (plain).

        Raises:
            WorkerError: ``not-found`` if the function or a ``named`` type does not resolve;
                ``invalid-params`` for an unknown convention; ``analysis-failed`` on a rolled-back
                write.
        """
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType
        from worker.dispatch import CODE_INVALID_PARAMS, WorkerError

        program = self._require_program()
        func = self._resolve_function(function)
        address = str(func.getEntryPoint())
        func_name = _to_text(func.getName())
        old_signature = _to_text(func.getPrototypeString(False, False))

        # Resolve everything BEFORE the transaction (fail closed with no txn opened — ADR-014 §4).
        resolved_return = self._gh_resolve_type_ref(return_type)
        params: list[Any] = []
        for spec in parameters:
            dt = self._gh_resolve_type_ref(_require(spec, "type"))
            params.append(ParameterImpl(str(_require(spec, "name")), dt, program))
        if calling_convention is not None:
            known = {str(c) for c in program.getCompilerSpec().getCallingConventions()}
            if calling_convention != "default" and calling_convention not in known:
                raise WorkerError(CODE_INVALID_PARAMS, "calling convention not known for program")

        def _write() -> None:
            func.updateFunction(
                None if calling_convention is None else calling_convention,
                resolved_return,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,
                SourceType.USER_DEFINED,
                *params,
            )

        self._in_transaction("set_function_signature", _write)
        new_signature = _to_text(func.getPrototypeString(False, False))
        return {
            "address": address,
            "function": func_name,
            "old_signature": old_signature,
            "new_signature": new_signature,
            "applied": True,
        }

    def _gh_apply_data_type(
        self, address: str, type_ref: dict[str, Any], clear_existing: bool
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Apply a resolvable type at an address inside one transaction (ADR-014 §1).

        Resolves the ``TypeRef`` and validates the address *form* before the txn (read-only);
        **map-confinement** is enforced inside the txn at ``DataUtilities.createData`` (an
        out-of-map / footprint overrun raises → rolled back → ``analysis-failed``). No C is parsed.

        Args:
            address: The target address (hex).
            type_ref: The type to apply as a ``TypeRef`` dict.
            clear_existing: Whether to clear conflicting defined data first.

        Returns:
            ``{"address", "type_name", "size", "applied"}`` (plain).

        Raises:
            WorkerError: ``not-found`` if the ``named`` type does not resolve; ``invalid-params``
                on a bad address; ``analysis-failed`` on a rolled-back write (incl.
                conflict-without-clear / out-of-map footprint).
        """
        from ghidra.program.model.data import DataUtilities
        from ghidra.program.model.data.DataUtilities import (  # type: ignore[import-not-found]
            ClearDataMode,
        )

        program = self._require_program()
        dt = self._gh_resolve_type_ref(type_ref)  # before the txn (fail closed, no partial write)
        addr = self._parse_address(address)
        clear_mode = (
            ClearDataMode.CLEAR_ALL_CONFLICT_DATA
            if clear_existing
            else ClearDataMode.CHECK_FOR_SPACE
        )
        applied_holder: dict[str, Any] = {}

        def _write() -> None:
            data = DataUtilities.createData(program, addr, dt, dt.getLength(), False, clear_mode)
            applied_holder["name"] = _to_text(data.getDataType().getName())
            applied_holder["size"] = int(data.getLength())

        self._in_transaction("apply_data_type", _write)
        return {
            "address": str(addr),
            "type_name": applied_holder["name"],
            "size": applied_holder["size"],
            "applied": True,
        }

    def _snapshot_function_protos(self, program: Any) -> dict[str, str]:  # pragma: no cover - JVM
        """Map every function's entry -> its prototype string (for a before/after apply diff)."""
        out: dict[str, str] = {}
        it = program.getFunctionManager().getFunctions(True)
        while it.hasNext():
            fn = it.next()
            out[str(fn.getEntryPoint())] = str(fn.getSignature().getPrototypeString())
        return out

    def _gh_apply_type_archive(self, archive: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Apply a bundled Ghidra Data Type archive's function signatures (ADR-051), one txn.

        Resolves the allow-listed ``archive`` name to a ``.gdt`` in the pinned Ghidra install
        (``GHIDRA_INSTALL_DIR``) — NEVER a client path (CWE-22). Opens it read-only and runs
        ``ApplyFunctionDataTypesCmd`` over the whole program, applying each archive function proto
        to the same-named program function (pulling in referenced types). The write is wrapped in
        one transaction so ``session_undo`` reverts it atomically. ``functions_updated`` is a
        before/after prototype diff. The archive is always closed.

        Args:
            archive: The allow-listed bundled-archive name (validated against ``_TYPE_ARCHIVES``).

        Returns:
            ``{"archive", "functions_updated", "applied"}`` (plain; all SAFE scalars).

        Raises:
            WorkerError: ``not-found`` if the archive name is unknown or its bundled file is absent.
        """
        from pathlib import Path

        from ghidra.app.cmd.function import (  # type: ignore[import-not-found]
            ApplyFunctionDataTypesCmd,
        )
        from ghidra.program.model.data import FileDataTypeManager
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor
        from java.io import File as JFile  # type: ignore[import-not-found]
        from java.util import ArrayList  # type: ignore[import-not-found]
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        rel = self._TYPE_ARCHIVES.get(archive)
        if rel is None:  # defense in depth — the schema Literal already closes the set
            raise WorkerError(CODE_NOT_FOUND, f"unknown type archive: {archive}")
        path = Path(os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")) / rel
        if not path.is_file():
            raise WorkerError(CODE_NOT_FOUND, f"type archive not found: {archive}")

        dtm = FileDataTypeManager.openFileArchive(JFile(str(path)), False)
        try:
            before = self._snapshot_function_protos(program)
            managers = ArrayList()
            managers.add(dtm)

            def _write() -> None:
                cmd = ApplyFunctionDataTypesCmd(managers, None, SourceType.IMPORTED, False, True)
                cmd.applyTo(program, TaskMonitor.DUMMY)

            self._in_transaction("apply_type_archive", _write)
            after = self._snapshot_function_protos(program)
        finally:
            dtm.close()

        updated = sum(1 for entry, proto in after.items() if before.get(entry) != proto)
        return {"archive": archive, "functions_updated": updated, "applied": True}

    def _gh_define_struct(
        self, name: str, fields: list[dict[str, Any]], packed: bool
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Create a new struct from a resolved field list inside one transaction (ADR-015 §3).

        Mirrors the ADR-015 ratified recursion model: name-collision REJECT + member resolution +
        the size cap all happen read-only BEFORE the txn (``_reject_oversized_resolved``), so a
        rejectable input fails-closed before the type is opened — the **all-or-nothing** guarantee
        is by construction, since in this program a failed write does NOT roll back ``addDataType``
        (#182; the in-txn size check is only a backstop for the self-pointer-size edge). Then INSIDE
        the one transaction: pre-register the empty ``StructureDataType`` (so a self-``named``
        pointer resolves) + add each member. NO C string is parsed.

        Args:
            name: The new struct's name (server-validated identifier).
            fields: The ordered ``[{"name", "type": TypeRef, "offset": int | None}]`` member list.
            packed: Whether to pack the struct (no alignment padding).

        Returns:
            ``{"name", "kind": "struct", "size", "field_count", "applied"}`` (plain scalars).

        Raises:
            WorkerError: ``analysis-failed`` on a name collision or a rolled-back write;
                ``not-found`` if a member ``TypeRef`` does not resolve; ``limit-exceeded`` if the
                total computed size exceeds ``_MAX_COMPOSITE_SIZE``.
        """
        from ghidra.program.model.data import CategoryPath, StructureDataType

        program = self._require_program()
        manager = program.getDataTypeManager()
        self._reject_type_collision(manager, name)

        # Resolve every member type BEFORE the txn (read-only fail-closed — no partial type opened),
        # EXCEPT a self-``named`` pointer, which can only resolve against the pre-registered type.
        resolved = self._resolve_composite_fields(name, fields)
        # Size-check pre-txn too (#182): a failed write does NOT roll back addDataType in this
        # program, so reject an oversized define BEFORE opening the type — never leave a partial.
        self._reject_oversized_resolved(resolved)

        result_holder: dict[str, Any] = {}

        def _write() -> None:
            struct = StructureDataType(CategoryPath.ROOT, name, 0, manager)
            if packed:
                struct.setPackingEnabled(True)
            # Pre-register the empty struct so a self-``named`` pointer member resolves (§3).
            registered = manager.addDataType(struct, None)
            total = 0
            for field, dt in self._iter_composite_members(name, fields, resolved, registered):
                length = int(dt.getLength())
                total += max(length, 0)
                if total > _MAX_COMPOSITE_SIZE:
                    self._raise_composite_too_large()  # backstop (self-pointer edge — see pre-txn)
                offset = field.get("offset")
                if offset is None:
                    registered.add(dt, length, str(field["name"]), None)
                else:
                    registered.insertAtOffset(int(offset), dt, length, str(field["name"]), None)
            result_holder["size"] = int(registered.getLength())
            result_holder["field_count"] = int(registered.getNumComponents())

        self._in_transaction("define_struct", _write)
        return {
            "name": name,
            "kind": "struct",
            "size": result_holder["size"],
            "field_count": result_holder["field_count"],
            "applied": True,
        }

    def _gh_define_union(
        self, name: str, fields: list[dict[str, Any]]
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Create a new union from a resolved field list inside one transaction (ADR-015 §3).

        Same ratified model as :meth:`_gh_define_struct`: name-collision REJECT + member resolution
        + size cap all read-only BEFORE the txn (fail-closed before the type is opened — the
        all-or-nothing guarantee is by construction, #182), then pre-register the empty
        ``UnionDataType`` inside the one txn (so a self-``named`` pointer resolves) + add each
        member. A union overlays all members at offset 0 (``offset`` is ignored). NO C string is
        parsed.

        Args:
            name: The new union's name (server-validated identifier).
            fields: The ``[{"name", "type": TypeRef}]`` member list (``offset`` ignored).

        Returns:
            ``{"name", "kind": "union", "size", "field_count", "applied"}`` (plain scalars).

        Raises:
            WorkerError: ``analysis-failed`` on a name collision or a rolled-back write;
                ``not-found`` if a member ``TypeRef`` does not resolve; ``limit-exceeded`` if the
                total computed size exceeds ``_MAX_COMPOSITE_SIZE``.
        """
        from ghidra.program.model.data import CategoryPath, UnionDataType

        program = self._require_program()
        manager = program.getDataTypeManager()
        self._reject_type_collision(manager, name)
        resolved = self._resolve_composite_fields(name, fields)
        # Size-check pre-txn (#182): reject an oversized union before opening it — abort does not
        # roll back addDataType in this program, so the partial must never be created.
        self._reject_oversized_resolved(resolved)

        result_holder: dict[str, Any] = {}

        def _write() -> None:
            union = UnionDataType(CategoryPath.ROOT, name, manager)
            registered = manager.addDataType(union, None)
            total = 0
            for field, dt in self._iter_composite_members(name, fields, resolved, registered):
                length = int(dt.getLength())
                # A union overlays members; its size is the max member size — but bound the running
                # SUM too so a flood of large members is rejected (ADR-015 §3 backstop).
                total += max(length, 0)
                if total > _MAX_COMPOSITE_SIZE:
                    self._raise_composite_too_large()  # backstop (self-pointer edge — see pre-txn)
                registered.add(dt, length, str(field["name"]), None)
            result_holder["size"] = int(registered.getLength())
            result_holder["field_count"] = int(registered.getNumComponents())

        self._in_transaction("define_union", _write)
        return {
            "name": name,
            "kind": "union",
            "size": result_holder["size"],
            "field_count": result_holder["field_count"],
            "applied": True,
        }

    def _gh_delete_type(self, name: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Delete a composite by name inside one transaction, reporting dependents (ADR-031).

        The server has already validated the name AND confirmed it is session-authored (ADR-031 D2);
        this is the JVM edge that performs the removal. Resolution, the composite/built-in guard,
        and the read-only dependent count all happen BEFORE the transaction (fail closed, no partial
        state); only ``DataTypeManager.remove`` is transacted (rollback on failure).

        ``dependents_reverted`` is a **best-effort** count of the data types that directly reference
        the target (``DataType.getParents()``) — the read-only signal available pre-removal.
        REQUIRES-LIVE-VERIFICATION of ``getParents()`` + ``DataTypeManager.remove(dt, monitor)`` on
        Ghidra 12.1.2 (a JVM edge unit tests cannot exercise — the F2/F7/ADR-030 lesson).

        Args:
            name: The server-validated, session-authored composite name to delete.

        Returns:
            ``{"name", "deleted", "dependents_reverted"}`` (plain server/worker scalars).

        Raises:
            WorkerError: ``not-found`` if no type of that name exists; ``analysis-failed`` if the
                resolved type is not a composite (defense in depth) or the removal rolled back.
        """
        from ghidra.program.model.data import Structure, Union
        from ghidra.util.task import TaskMonitor
        from worker.dispatch import CODE_ANALYSIS_FAILED, CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        manager = program.getDataTypeManager()

        # Resolve by a full `getAllDataTypes()` name scan — mirroring `_reject_type_collision`
        # (robust across categories), NOT the illustrative `getDataType(ROOT, name)` of ADR-031 D5.
        # Session-authored composites are created at ROOT, so both find them; the scan is the
        # conservative choice and keeps the two type-name lookups consistent.
        target = None
        for data_type in manager.getAllDataTypes():
            if str(data_type.getName()) == name:
                target = data_type
                break
        if target is None:
            raise WorkerError(CODE_NOT_FOUND, "no type of that name exists")
        # Defense in depth: the server only authorizes session-authored composites, but never trust
        # a desync — refuse anything that is not a struct/union (no built-in/pointer/array/typedef).
        if not isinstance(target, (Structure, Union)):
            raise WorkerError(CODE_ANALYSIS_FAILED, "not a composite type")
        # Read-only dependent count BEFORE the write (best-effort: parent data types using it).
        dependents = len(list(target.getParents()))

        removed_holder: dict[str, bool] = {}

        def _write() -> None:
            removed_holder["removed"] = bool(manager.remove(target, TaskMonitor.DUMMY))

        self._in_transaction("delete_type", _write)
        return {
            "name": name,
            "deleted": removed_holder.get("removed", False),
            "dependents_reverted": dependents,
        }

    # C901: PyGhidra type-definition application across the JVM boundary (ADR-001) —
    # live-regression-only coverage; the DataTypeManager transaction ordering must stay intact.
    def _gh_define_types(  # noqa: C901
        self, types: list[dict[str, Any]]
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Create a BATCH of interdependent composites in ONE transaction (ADR-021).

        Generalizes :meth:`_gh_define_struct` / :meth:`_gh_define_union` from one composite to a
        batch. BEFORE the txn (read-only, fail-closed — the all-or-nothing guarantee by
        construction, #182): name-collision REJECT for EACH batch name, then resolve every
        non-in-batch member ref (an unknown ref → ``not-found``) and cap the batch-total size
        (``limit-exceeded``) — so a rejectable batch fails before any composite is opened (in this
        program a failed write does NOT roll back ``addDataType``). Then INSIDE the one transaction:
        pre-register EVERY empty composite (struct/union per ``kind``) so an in-batch ``named`` ref
        resolves, and add each type's members against the pre-registered handles + existing/base
        types (the in-txn checks remain as backstops). The server has already rejected by-value
        cycles at the boundary (the cycle detector). NO C string is parsed.

        Args:
            types: The batch ``[{"kind", "name", "fields": [FieldSpec], "packed": bool}]``.

        Returns:
            ``{"types": [{"name", "kind", "size", "field_count"}], "applied": True}`` (plain).

        Raises:
            WorkerError: ``analysis-failed`` on a name collision or a rolled-back write;
                ``not-found`` if a member ``TypeRef`` does not resolve; ``limit-exceeded`` if the
                batch-total computed size exceeds ``_MAX_COMPOSITE_SIZE``.
        """
        from ghidra.program.model.data import (
            ArrayDataType,
            CategoryPath,
            PointerDataType,
            StructureDataType,
            UnionDataType,
        )

        program = self._require_program()
        manager = program.getDataTypeManager()
        batch_names = {str(_require(spec, "name")) for spec in types}
        for name in batch_names:
            self._reject_type_collision(manager, name)  # read-only, before the txn (no partial)

        # Pre-validate every member ref BEFORE the txn (#182): in this program a failed batch does
        # NOT roll back its pre-registered composites (abort/remove are ineffective on the DTM), so
        # any rejectable input must fail BEFORE the first addDataType. In-batch ``named`` refs
        # resolve against pre-registered handles inside the txn; every OTHER ref must resolve
        # against an existing/base type NOW (an unknown ref → ``not-found``, matching the doc), and
        # the batch-total size over the resolvable members is capped here (``limit-exceeded``).
        # The in-txn checks remain as backstops for in-batch pointer sizes.
        pre_total = 0
        for spec in types:
            for field in _require(spec, "fields"):
                ref = _require(field, "type")
                if ref.get("named") in batch_names:
                    continue  # in-batch ref — resolved in _write against a pre-registered handle
                pre_total += max(int(self._gh_resolve_type_ref(ref).getLength()), 0)
                if pre_total > _MAX_COMPOSITE_SIZE:
                    self._raise_composite_too_large()

        result_holder: dict[str, list[dict[str, Any]]] = {"types": []}

        def _resolve_member(type_ref: dict[str, Any], registered: dict[str, Any]) -> Any:
            """Resolve one member to a ``DataType``, preferring a pre-registered batch handle."""
            named = type_ref.get("named")
            if (
                named in registered
            ):  # an in-batch reference — resolve against the pre-registered type
                leaf = registered[named]
                pointer_levels = int(type_ref.get("pointer_levels") or 0)
                if pointer_levels == 0:
                    # A by-value embed of a batch member is a cycle the boundary already rejects;
                    # be self-protecting (defense in depth — the detector is the primary control).
                    from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

                    raise WorkerError(
                        CODE_ANALYSIS_FAILED, "by-value batch self/cyclic reference is rejected"
                    )
                for _ in range(pointer_levels):
                    leaf = PointerDataType(leaf)
                array_len = type_ref.get("array_len")
                if array_len is not None:
                    leaf = ArrayDataType(leaf, int(array_len), leaf.getLength())
                return leaf
            return self._gh_resolve_type_ref(type_ref)  # existing/base/derived program type

        def _write() -> None:
            registered: dict[str, Any] = {}
            # Pre-register EVERY empty composite first so any in-batch named ref resolves (§D2).
            for spec in types:
                name = str(_require(spec, "name"))
                if str(spec.get("kind")) == "union":
                    empty: Any = UnionDataType(CategoryPath.ROOT, name, manager)
                else:
                    empty = StructureDataType(CategoryPath.ROOT, name, 0, manager)
                    if bool(spec.get("packed", False)):
                        empty.setPackingEnabled(True)
                registered[name] = manager.addDataType(empty, None)
            # Resolve + add each type's members; bound the BATCH-TOTAL computed size (§Bounds).
            total = 0
            for spec in types:
                name = str(_require(spec, "name"))
                handle = registered[name]
                for field in _require(spec, "fields"):
                    dt = _resolve_member(_require(field, "type"), registered)
                    length = int(dt.getLength())
                    total += max(length, 0)
                    if total > _MAX_COMPOSITE_SIZE:
                        self._raise_composite_too_large()
                    offset = field.get("offset")
                    if str(spec.get("kind")) != "union" and offset is not None:
                        handle.insertAtOffset(int(offset), dt, length, str(field["name"]), None)
                    else:
                        handle.add(dt, length, str(field["name"]), None)
            for spec in types:
                name = str(_require(spec, "name"))
                handle = registered[name]
                result_holder["types"].append(
                    {
                        "name": name,
                        "kind": str(spec.get("kind")),
                        "size": int(handle.getLength()),
                        "field_count": int(handle.getNumComponents()),
                    }
                )

        self._in_transaction("define_types", _write)
        return {"types": result_holder["types"], "applied": True}

    # --- annotation-persistence JVM edge (ADR-018/ADR-027; export read-out, read-only) ----------
    # C901: PyGhidra annotation-export enumeration across the JVM boundary (ADR-001) —
    # live-regression-only coverage; the symbol/comment walk + count invariants must stay together.
    def _gh_export_annotations(  # noqa: C901
        self,
        comment_targets: list[tuple[str, str]],
        composite_targets: list[str],
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Export user-authored annotations, dependency-ordered + bounded (ADR-018/ADR-027 hybrid).

        Reads (read-only, no transaction) and emits plain entries in a **dependency-safe order**:
        composites/types first (``define_struct``/``define_union``), then the signatures/applies
        that may reference them, then the renames, then comments (mirrors the document shape so
        import can replay in order). Bounded by ``_MAX_RESULT_COUNT`` — over the cap →
        ``limit-exceeded`` (no silent truncation). The values are plain; the server wraps each
        binary-derived string as untrusted and overlays the authoritative ``binary.sha256``.

        **Provenance (ADR-027 hybrid):**

        - **Symbols + signatures (steps 2-4):** enumerate the program filtered by
          ``SourceType.USER_DEFINED`` (``Symbol.getSource()`` / ``Function.getSignatureSource()``) —
          Ghidra's authoritative provenance signal. **Unchanged** by ADR-027. Step 4 additionally
          skips address-less USER_DEFINED symbols via :func:`_is_address_keyable` (ADR-024 F2 — a
          null ``getAddress()`` otherwise collapsed the whole export).
        - **Composites (step 1) + comments (step 5):** Ghidra exposes NO reliable user-vs-auto
          signal for these (program-local composites include auto-analysis structs; comments carry
          no source-type at all — the F7 leak). So they are read ONLY for the server-supplied
          ``comment_targets`` / ``composite_targets`` — the session change-log of what THIS
          session's gated writes authored (ADR-027 D2/D4). Empty lists ⇒ none emitted.

        Every Ghidra binding below is REQUIRES-LIVE-VERIFICATION (the F2 lesson; confirmed at the WS
        image build + the blind Mode-B known-count regression run):

        - composite lookup-by-name: ``DataTypeManager.getDataType(CategoryPath.ROOT, name)`` returns
          the user-created composite (user composites land under the root category — ADR-015 uses
          ``CategoryPath.ROOT`` on create). A name not found / not a Structure|Union is skipped.
        - targeted comment read: ``Listing.getComment(type_id, addr)`` for a server-supplied address
          returns the slot's text or ``None`` (a cleared slot reads ``None`` and is skipped).
        - ``Symbol.getSource()`` / ``Function.getSignatureSource()`` == ``SourceType.USER_DEFINED``
          discriminate user from auto for symbols/signatures.

        Args:
            comment_targets: ``(address, comment_type)`` pairs from the session change-log to read.
            composite_targets: composite NAMES from the session change-log to look up + export.

        Returns:
            ``{"schema_version", "binary": {"sha256", "size"}, "entries": [...]}`` (plain).

        Raises:
            WorkerError: ``limit-exceeded`` if the user-defined annotation count exceeds the cap.
        """
        from ghidra.program.model.data import CategoryPath, Structure, Union
        from ghidra.program.model.listing import CodeUnit
        from ghidra.program.model.symbol import SourceType, SymbolType
        from worker.dispatch import CODE_LIMIT_EXCEEDED, WorkerError

        program = self._require_program()
        entries: list[dict[str, Any]] = []

        def _emit(entry: dict[str, Any]) -> None:
            if len(entries) >= _MAX_RESULT_COUNT:
                raise WorkerError(
                    CODE_LIMIT_EXCEEDED, "user-defined annotation count exceeds the maximum"
                )
            entries.append(entry)

        # 1) Composite types FIRST, as ONE `define_types` batch entry (ADR-032) — so mutually-
        #    recursive POINTER composites (and any acyclic-but-misordered dependency) round-trip via
        #    the import handler's pre-registration, which individual define_struct/union entries
        #    could not (no replay order resolves a pointer cycle). Emitted before the signatures/
        #    applies that may reference the types. ADR-027: look up ONLY the change-log's named
        #    composites (membership in the log IS the user-authored signal). REQUIRES LIVE
        #    VERIFICATION: getDataType(CategoryPath.ROOT, name).
        manager = program.getDataTypeManager()
        composite_specs: list[dict[str, Any]] = []
        for name in composite_targets:
            data_type = manager.getDataType(CategoryPath.ROOT, name)
            if data_type is None:
                continue  # named composite not found (e.g. since removed) — skip, never guess
            if not isinstance(data_type, (Structure, Union)):
                continue  # name now resolves to a non-composite — skip
            fields = _composite_fields_export(data_type)
            if fields is None:
                continue  # not field-reconstructable (e.g. derived/aliased) — skip, never guess
            kind = "union" if isinstance(data_type, Union) else "struct"
            composite_specs.append(
                {"kind": kind, "name": _to_text(data_type.getName()), "fields": fields}
            )
        if composite_specs:
            # ADR-032 D2: a define_types batch is bounded (CWE-400). >64 reconstructable session-
            # authored composites cannot round-trip as one atomic batch → fail closed (the live
            # writes that created them still succeeded; only the round-trip is refused).
            if len(composite_specs) > _MAX_TYPES_PER_BATCH:
                raise WorkerError(
                    CODE_LIMIT_EXCEEDED,
                    "session-authored composite count exceeds the round-trip batch maximum",
                )
            _emit({"kind": "define_types", "types": composite_specs})

        # 2) USER_DEFINED function signatures (set_function_signature) — after the types they use.
        listing = program.getListing()
        for func in listing.getFunctions(True):
            if str(func.getSignatureSource()) != str(SourceType.USER_DEFINED):
                continue
            _emit(_function_signature_export(func))

        # 3) USER_DEFINED function renames (rename_function) — name-only renames of functions.
        for func in listing.getFunctions(True):
            symbol = func.getSymbol()
            if symbol is None or str(symbol.getSource()) != str(SourceType.USER_DEFINED):
                continue
            _emit(
                {
                    "kind": "rename_function",
                    "function": str(func.getEntryPoint()),
                    "new_name": _to_text(func.getName()),
                }
            )

        # 4) USER_DEFINED non-function symbol renames (rename_symbol).
        for symbol in program.getSymbolTable().getAllSymbols(False):
            if str(symbol.getSource()) != str(SourceType.USER_DEFINED):
                continue
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                continue  # function renames already emitted in step 3
            # ADR-018 rename_symbol is ADDRESS-KEYED: a USER_DEFINED symbol with no concrete memory
            # address (namespace/class/library/global/external) returns a null getAddress() and can
            # never be a rename_symbol target — skip it rather than str(None-Java-ref) crashing the
            # whole export into an opaque worker error (ADR-024 F2). The guard is fetched ONCE.
            addr = symbol.getAddress()
            if not _is_address_keyable(addr):
                continue
            _emit(
                {
                    "kind": "rename_symbol",
                    "identifier": str(addr),
                    "new_name": _to_text(symbol.getName()),
                }
            )

        # 5) Comments (set_comment) — ADR-027: read ONLY the change-log's targeted slots (comments
        #    carry NO source-type, so blind enumeration leaked 1138 auto-comments — F7). For each
        #    logged (address, comment_type), re-read the CURRENT value live (ADR-001: value stays
        #    worker-sourced; the change-log holds only the identity key). A cleared slot reads None
        #    and is skipped. REQUIRES LIVE VERIFICATION: Listing.getComment(type_id, addr) for an
        #    arbitrary supplied address.
        slot_type_id = {
            "EOL": CodeUnit.EOL_COMMENT,
            "PRE": CodeUnit.PRE_COMMENT,
            "POST": CodeUnit.POST_COMMENT,
            "PLATE": CodeUnit.PLATE_COMMENT,
            "REPEATABLE": CodeUnit.REPEATABLE_COMMENT,
        }
        for address, label in comment_targets:
            type_id = slot_type_id.get(label)
            if type_id is None:
                continue  # unknown slot label (closed vocab upstream) — skip, fail-closed
            comment_addr = self._try_parse_address(address)
            if comment_addr is None:
                continue  # unparsable address (should not happen — server-normalized) — skip
            text = listing.getComment(type_id, comment_addr)
            if text is None:
                continue  # slot empty / since-cleared — nothing to export
            _emit(
                {
                    "kind": "set_comment",
                    "address": str(comment_addr),
                    "comment_type": label,
                    "text": _to_text(text),
                }
            )

        return {
            "schema_version": _ANNOTATION_SCHEMA_VERSION,
            "binary": {"sha256": self._sha256 or "", "size": None},
            "entries": entries,
        }

    def _reject_type_collision(  # pragma: no cover - JVM edge
        self, manager: Any, name: str
    ) -> None:
        """Fail-closed REJECT if a type of ``name`` already exists (ADR-015 §6).

        A read-only ``DataTypeManager`` lookup BEFORE assembly: a collision surfaces
        ``analysis-failed`` with no write (never a silent replace/rename — the redefine-in-use
        re-render / data-poisoning vector is closed by construction).

        Args:
            manager: The program's ``DataTypeManager``.
            name: The candidate composite name.

        Raises:
            WorkerError: ``analysis-failed`` if a type of that name already exists.
        """
        from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

        for data_type in manager.getAllDataTypes():
            if str(data_type.getName()) == name:
                raise WorkerError(CODE_ANALYSIS_FAILED, "a type of that name already exists")

    def _resolve_composite_fields(
        self, name: str, fields: list[dict[str, Any]]
    ) -> dict[int, Any]:  # pragma: no cover - JVM edge
        """Resolve each member's ``TypeRef`` BEFORE the txn, deferring self-``named`` refs (§3).

        A member whose ``TypeRef`` names the composite itself cannot resolve until the empty type is
        pre-registered inside the transaction, so it is left out of this pre-resolution map and
        resolved later by :meth:`_iter_composite_members` against the registered handle.

        Args:
            name: The composite's own (not-yet-registered) name.
            fields: The member list.

        Returns:
            A map of member index → resolved ``DataType`` for every NON-self member.

        Raises:
            WorkerError: ``not-found`` if a non-self member ``TypeRef`` does not resolve.
        """
        resolved: dict[int, Any] = {}
        for index, field in enumerate(fields):
            type_ref = _require(field, "type")
            if type_ref.get("named") == name:
                continue  # a self-``named`` ref — resolved post-registration (pointer-to-self)
            resolved[index] = self._gh_resolve_type_ref(type_ref)
        return resolved

    def _iter_composite_members(
        self,
        name: str,
        fields: list[dict[str, Any]],
        resolved: dict[int, Any],
        registered: Any,
    ) -> Any:  # pragma: no cover - JVM edge
        """Yield ``(field, DataType)`` per member, resolving self-``named`` refs vs. ``registered``.

        Args:
            name: The composite's own name (now pre-registered as ``registered``).
            fields: The member list.
            resolved: The pre-resolved non-self member types (by index).
            registered: The pre-registered (empty) composite handle for self-references.

        Yields:
            ``(field, DataType)`` pairs in declaration order.
        """
        from ghidra.program.model.data import ArrayDataType, PointerDataType

        for index, field in enumerate(fields):
            if index in resolved:
                yield field, resolved[index]
                continue
            # A self-``named`` member: pointer-to-self is allowed; a by-value self-embed
            # (incl. array-of-self, ``pointer_levels == 0``) is rejected at the boundary — re-assert
            # here so the worker is self-protecting (defense in depth, ADR-015 §3 / Phase-C F3).
            type_ref = _require(field, "type")
            if int(type_ref.get("pointer_levels") or 0) == 0:
                from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

                raise WorkerError(CODE_ANALYSIS_FAILED, "by-value self-embedding type is rejected")
            leaf = registered
            for _ in range(int(type_ref.get("pointer_levels") or 0)):
                leaf = PointerDataType(leaf)
            array_len = type_ref.get("array_len")
            if array_len is not None:
                leaf = ArrayDataType(leaf, int(array_len), leaf.getLength())
            yield field, leaf

    def _raise_composite_too_large(self) -> None:  # pragma: no cover - JVM edge
        """Raise ``limit-exceeded`` for an over-cap composite size (ADR-015 §3 backstop)."""
        from worker.dispatch import CODE_LIMIT_EXCEEDED, WorkerError

        raise WorkerError(CODE_LIMIT_EXCEEDED, "composite size exceeds the maximum")

    def _in_transaction(self, tool_name: str, write: Callable[[], None]) -> None:
        """Run ``write`` inside one Ghidra transaction; commit on success, roll back on failure.

        One tool call == one transaction == one undoable unit (ADR-012 §4; no batching). The commit
        runs **inside** the ``try`` because Ghidra performs end-of-transaction fixups there (the
        decompiler/analysis manager re-flows dependent state — esp. for a structural write), so the
        commit itself can raise. On **any** failure — in ``write`` or the commit — the transaction
        is rolled back (``endTransaction(commit=False)``, best-effort/suppressed so a secondary
        failure never masks the cause) and a safe ``analysis-failed`` is raised: never a dangling
        transaction, never a raw exception across the boundary (CWE-460 — fail closed, ADR-013 §4,
        topic-error-handling / topic-resource-management). The original exception is chained
        server-side only.

        Pure control flow over the program's transaction API (``startTransaction`` /
        ``endTransaction``) — unit-tested with a fake program; the JVM-symbol edges that *call* this
        (the ``_gh_*`` write helpers) stay coverage-omitted.

        Args:
            tool_name: The transaction description (the calling tool's name).
            write: The single Ghidra write to perform inside the transaction.

        Raises:
            WorkerError: ``analysis-failed`` if the write or the commit raised (after rolling back).
        """
        import contextlib

        from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

        program = self._require_program()
        txn = program.startTransaction(tool_name)
        try:
            write()
            program.endTransaction(txn, True)  # commit (end-of-txn fixups can raise — CWE-460)
        except Exception as exc:
            with contextlib.suppress(Exception):
                program.endTransaction(txn, False)  # best-effort rollback; cleanup must not throw
            raise WorkerError(CODE_ANALYSIS_FAILED, "write failed and was rolled back") from exc

    def _reject_oversized_resolved(
        self, resolved: dict[int, Any]
    ) -> None:  # pragma: no cover - JVM
        """Pre-txn batch-total size cap over PRE-RESOLVED members (#182 / ADR-021 §D2).

        Validating the size BEFORE the transaction is the all-or-nothing fix: in this program a
        failed structural write does **not** roll back its ``DataTypeManager.addDataType`` calls
        (neither ``endTransaction(commit=False)`` nor a follow-up ``remove`` undoes them — observed
        live, issue #182), so the only robust guarantee is to never open the partial. The members
        are already resolved read-only by :meth:`_resolve_composite_fields` before the txn, so
        their lengths are known here. Raises the precise ``limit-exceeded`` (matching the handler
        docstrings — the in-txn check had masked it as ``analysis-failed``).

        Self-``named`` pointer members (deferred, not in ``resolved``) add only a pointer each and
        are intentionally NOT summed here — undercounting is conservative (never falsely rejects a
        valid type); the in-txn check remains the backstop for that pathological self-pointer edge.

        Args:
            resolved: index → resolved ``DataType`` for the non-self members (pre-txn).

        Raises:
            WorkerError: ``limit-exceeded`` if the running member-size sum exceeds the cap.
        """
        total = 0
        for data_type in resolved.values():
            total += max(int(data_type.getLength()), 0)
            if total > _MAX_COMPOSITE_SIZE:
                self._raise_composite_too_large()

    def _require_program(self) -> Any:  # pragma: no cover - JVM edge
        """Return the open program or raise a safe ``analysis-failed`` error.

        Returns:
            The open Ghidra ``Program``.

        Raises:
            WorkerError: ``analysis-failed`` if no program is loaded.
        """
        from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

        if self._program is None:
            raise WorkerError(CODE_ANALYSIS_FAILED, "no program loaded")
        return self._program

    def _parse_address(self, value: str) -> Any:  # pragma: no cover - JVM edge
        """Parse a hex address string into a Ghidra ``Address`` (default address space).

        Args:
            value: An address string (hex, optional ``0x`` prefix).

        Returns:
            A Ghidra ``Address``.

        Raises:
            WorkerError: ``invalid-params`` if the address cannot be parsed.
        """
        from worker.dispatch import CODE_INVALID_PARAMS, WorkerError

        program = self._require_program()
        text = value[2:] if value[:2].lower() == "0x" else value
        try:
            addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(int(text, 16))
        except Exception as exc:
            raise WorkerError(CODE_INVALID_PARAMS, "could not parse address") from exc
        if addr is None:
            raise WorkerError(CODE_INVALID_PARAMS, "could not parse address")
        return addr

    def _gh_emulate(  # noqa: C901 — one bounded emulator loop over the p-code edge
        self,
        *,
        start: str,
        set_registers: dict[str, Any],
        write_memory: list[dict[str, Any]],
        max_steps: int,
        stop_at: str | None,
        read_registers: list[Any],
        read_memory: list[dict[str, Any]],
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Run bounded Ghidra p-code emulation and return register/memory readbacks (ADR-049).

        Ghidra's ``EmulatorHelper`` INTERPRETS lifted p-code — no native execution, no syscalls,
        no I/O — a hostile program cannot escape; the program DB is not mutated. Seeds the PC (and
        ``set_registers``/``write_memory``), steps up to ``max_steps`` (stopping at ``stop_at``, a
        halt, or a fault), then reads back the requested registers/memory. The emulator is always
        disposed. Register/memory VALUES are binary-derived — the server wraps them untrusted.

        Args:
            start: Start address (hex) — the initial PC.
            set_registers: ``{register_name: int}`` presets.
            write_memory: ``[{"address": hex, "data_hex": str}]`` pre-run writes.
            max_steps: Hard p-code step cap (already server-clamped).
            stop_at: Optional stop address (hex).
            read_registers: Register names to read back.
            read_memory: ``[{"address": hex, "length": int}]`` ranges to read back.

        Returns:
            ``{"steps_executed", "stop_reason", "registers": [...], "memory": [...]}``.

        Raises:
            WorkerError: ``not-found`` if a named register does not exist.
        """
        from ghidra.app.emulator import EmulatorHelper  # type: ignore[import-not-found]
        from ghidra.util.task import TaskMonitor
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        emu = EmulatorHelper(program)
        try:
            emu.writeRegister(emu.getPCRegister(), self._parse_address(start).getOffset())
            for name, value in set_registers.items():
                try:
                    emu.writeRegister(str(name), int(value))
                except Exception as exc:
                    raise WorkerError(CODE_NOT_FOUND, f"unknown register: {name}") from exc
            for write in write_memory:
                emu.writeMemory(
                    self._parse_address(str(write["address"])),
                    bytes.fromhex(str(write["data_hex"])),
                )

            stop_addr = self._parse_address(stop_at) if stop_at is not None else None
            steps = 0
            stop_reason = "max-steps"
            while steps < max_steps:
                try:
                    stepped = bool(emu.step(TaskMonitor.DUMMY))
                except Exception:  # p-code fault (bad access, unimplemented op) — stop, no leak
                    stop_reason = "fault"
                    break
                steps += 1
                if not stepped:
                    stop_reason = "halted"
                    break
                if stop_addr is not None and emu.getExecutionAddress() == stop_addr:
                    stop_reason = "stop-address"
                    break

            regs: list[dict[str, Any]] = []
            for name in read_registers:
                try:
                    raw = int(str(emu.readRegister(str(name))))
                except Exception as exc:
                    raise WorkerError(CODE_NOT_FOUND, f"unknown register: {name}") from exc
                regs.append({"name": str(name), "value": format(raw & ((1 << 512) - 1), "x")})

            mems: list[dict[str, Any]] = []
            for read in read_memory:
                addr = self._parse_address(str(read["address"]))
                length = int(read["length"])
                data, count = self._get_bytes_via(emu, addr, length)
                mems.append({"address": str(addr), "data": data.hex(), "length": count})

            return {
                "steps_executed": steps,
                "stop_reason": stop_reason,
                "registers": regs,
                "memory": mems,
            }
        finally:
            emu.dispose()

    def _gh_demangle(
        self, mangled: str, scheme: str
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Demangle a C++ symbol with Ghidra's concrete demanglers (ADR-050). Program-independent.

        Tries the requested ``scheme`` (``auto`` = GNU/Itanium then MSVC). Each demangler is a pure
        string transform — no program is loaded or mutated (read-only). A string that is not a
        mangled name in a tried scheme yields ``demangled=None`` (not an error). The JVM is started
        idempotently since this can be the first worker call.

        Args:
            mangled: The mangled symbol string (already length-bounded by the server).
            scheme: ``auto`` | ``gnu`` | ``msvc``.

        Returns:
            ``{"demangled": str | None, "scheme": "gnu" | "msvc" | None}``.
        """
        import pyghidra

        pyghidra.start()  # idempotent; the demanglers need the JVM but no program.
        from ghidra.app.util.demangler.gnu import GnuDemangler  # type: ignore[import-not-found]
        from ghidra.app.util.demangler.microsoft import (  # type: ignore[import-not-found]
            MicrosoftDemangler,
        )

        def _try(demangler: Any) -> str | None:
            try:
                result = demangler.demangle(mangled)
            except Exception:  # a name the demangler rejects is simply "not this scheme".
                return None
            if result is None:
                return None
            signature = result.getSignature()
            return None if signature is None else str(signature).strip()

        order: list[tuple[str, Any]] = []
        if scheme in ("auto", "gnu"):
            order.append(("gnu", GnuDemangler()))
        if scheme in ("auto", "msvc"):
            order.append(("msvc", MicrosoftDemangler()))

        for name, demangler in order:
            demangled = _try(demangler)
            if demangled:
                return {"demangled": demangled, "scheme": name}
        return {"demangled": None, "scheme": None}

    def _get_bytes_via(self, emu: Any, address: Any, length: int) -> tuple[bytes, int]:
        # pragma: no cover - JVM edge
        """Read ``length`` bytes from the emulator state as unsigned bytes (jpype-correct, #292).

        ``EmulatorHelper.readMemory(Address, int)`` returns a Java ``byte[]``; convert its signed
        bytes to unsigned Python bytes. On a memory fault return what was read (honest short read).
        """
        try:
            buf = emu.readMemory(address, length)
            return bytes(int(buf[i]) & 0xFF for i in range(len(buf))), len(buf)
        except Exception:
            return b"", 0

    def _try_parse_address(self, value: str) -> Any | None:  # pragma: no cover - JVM edge
        """Parse a hex address, returning ``None`` instead of raising on failure.

        Args:
            value: A candidate address string.

        Returns:
            A Ghidra ``Address`` or ``None`` if ``value`` is not a valid address.
        """
        from worker.dispatch import WorkerError

        try:
            return self._parse_address(value)
        except WorkerError:
            return None

    def _resolve_function(self, function: str) -> Any:  # pragma: no cover - JVM edge
        """Resolve a function by entry address (hex) or by name.

        Args:
            function: An address (hex) or a function name.

        Returns:
            The matching Ghidra ``Function``.

        Raises:
            WorkerError: ``not-found`` if no function matches.
        """
        from worker.dispatch import CODE_NOT_FOUND, WorkerError

        program = self._require_program()
        manager = program.getFunctionManager()
        addr = self._try_parse_address(function)
        if addr is not None:
            func = manager.getFunctionAt(addr) or manager.getFunctionContaining(addr)
            if func is not None:
                return func
        for func in manager.getFunctions(True):
            if str(func.getName()) == function:
                return func
        raise WorkerError(CODE_NOT_FOUND, "function not found")

    def _resolve_address(self, target: str) -> Any:  # pragma: no cover - JVM edge
        """Resolve a target (hex address or function name) to a Ghidra ``Address``.

        Args:
            target: An address (hex) or a function name.

        Returns:
            The resolved ``Address`` (a function's entry point when a name is given).

        Raises:
            WorkerError: ``not-found`` if a name does not resolve to a function.
        """
        addr = self._try_parse_address(target)
        if addr is not None:
            return addr
        return self._resolve_function(target).getEntryPoint()

    def _read_context_hex(
        self, memory: Any, address: Any, length: int
    ) -> str:  # pragma: no cover - JVM edge
        """Read up to ``length`` bytes at ``address`` and return lowercase hex (best-effort).

        Args:
            memory: The program ``Memory``.
            address: The match start ``Address``.
            length: Number of context bytes (the pattern length).

        Returns:
            Lowercase hex of the bytes actually read (may be shorter at a block boundary).
        """
        data, _read = self._get_bytes(memory, address, max(1, min(length, _MAX_READ_BYTES)))
        return data.hex()

    def _entry_point(self, program: Any) -> Any | None:  # pragma: no cover - JVM edge
        """Return the program entry-point ``Address`` if one is defined.

        Args:
            program: The open Ghidra ``Program``.

        Returns:
            The first ``entry`` symbol address, or ``None``.
        """
        for symbol in program.getSymbolTable().getExternalEntryPointIterator():
            return symbol
        return None


# --- module-level shaping helpers (JVM-free framing of plain values) -------------------------
# The ``_session_info_dict`` placeholders for ids/timestamps are overlaid by the server with its
# authoritative session clock (the worker has no session clock); the worker contributes only
# ``state`` + ``binary_sha256`` (+ analysis state via the read-only metadata tool). The remaining
# helpers convert Java objects to plain str/int/bool so no JVM object can leak across the boundary.

# Placeholder epoch the server overlays with its own authoritative session timestamps.
_PLACEHOLDER_EPOCH = 0


def _session_info_dict(
    state: str, binary_sha256: str | None, *, analysis_complete: bool
) -> dict[str, Any]:
    """Build a plain ``SessionInfo``-shaped dict for an import/analyze result.

    The worker has no authoritative session clock or id; it contributes the lifecycle ``state``
    and the input ``binary_sha256``. The server overlays ``session_id``/``created_at``/
    ``expires_at`` (placeholders here satisfy the model's required scalars on validation).

    Args:
        state: Lifecycle state (e.g. ``"importing"``, ``"ready"``).
        binary_sha256: Hex SHA-256 of the imported binary, or ``None``.
        analysis_complete: Whether auto-analysis has finished (advisory; reflected in metadata).

    Returns:
        A plain ``SessionInfo``-shaped dict.
    """
    return {
        "session_id": "",  # server overlays the authoritative opaque id
        "state": state,
        "created_at": _PLACEHOLDER_EPOCH,  # server overlays its session-open clock
        "expires_at": _PLACEHOLDER_EPOCH,  # server overlays the TTL-eviction clock
        "binary_sha256": binary_sha256,
        "analysis_complete": analysis_complete,
    }


def _to_text(value: object) -> str:
    """Coerce a (possibly Java) value to a plain UTF-8-safe Python ``str``.

    Args:
        value: A Java string/object or ``None``.

    Returns:
        The value as a Python ``str`` (empty for ``None``), with undecodable bytes replaced.
    """
    if value is None:
        return ""
    text = str(value)
    # Round-trip through UTF-8 with replacement so any lone surrogate / undecodable unit from a
    # hostile binary becomes a safe replacement char rather than crossing the boundary raw.
    return text.encode("utf-8", "replace").decode("utf-8", "replace")


def _is_address_keyable(addr: Any) -> bool:
    """Return whether a symbol's address can key an address-based ``rename_symbol`` (ADR-018).

    ADR-018's ``rename_symbol`` export entry is **address-keyed**: an entry's ``identifier`` is a
    concrete memory address that import replays against. A USER_DEFINED symbol that is not bound to
    a memory address (namespace/class/library/global/external symbols) has ``getAddress()`` return
    a null Java reference (or a non-memory ``Address`` such as a register/stack/external slot),
    which cannot be a ``rename_symbol`` target — so it is skipped, not crashed on (the prior code
    passed such a null straight into ``str(...)``/downstream use, throwing and collapsing the whole
    export into an opaque ``internal worker error`` — ADR-024 F2).

    Pure + duck-typed so the guard logic is hermetically unit-testable without a JVM: ``addr`` only
    needs to answer ``is None`` and (when present) expose ``isMemoryAddress()``.

    Args:
        addr: A Ghidra ``Address`` (or a null reference / ``None``) from ``Symbol.getAddress()``.

    Returns:
        ``True`` only when ``addr`` is a non-null memory address; ``False`` otherwise (fail closed).
    """
    if addr is None:
        return False
    try:
        return bool(addr.isMemoryAddress())
    except Exception:
        # A malformed/foreign Address answers "not keyable" rather than crashing the export.
        return False


def _bytes_to_hex(raw: Any) -> str:
    """Convert a Java/Python byte array to lowercase hex.

    Args:
        raw: A ``bytes``/``bytearray`` or a Java signed-byte array.

    Returns:
        Lowercase hex of the bytes.
    """
    return bytes((b & 0xFF) for b in raw).hex()


def _instruction_operands(instr: Any) -> str:  # pragma: no cover - JVM edge
    """Render an instruction's operands as a single comma-joined string.

    Args:
        instr: A Ghidra ``Instruction``.

    Returns:
        The operand text (``""`` when there are no operands).
    """
    parts = [str(instr.getDefaultOperandRepresentation(i)) for i in range(instr.getNumOperands())]
    return ", ".join(parts)


def _string_value(data: Any) -> str | None:  # pragma: no cover - JVM edge
    """Extract a defined-data item's string value, or ``None`` if it is not a string.

    Args:
        data: A Ghidra ``Data`` item from the Listing.

    Returns:
        The UTF-8-safe string value, or ``None`` when the item is not a string type.
    """
    if not bool(data.hasStringValue()):
        return None
    return _to_text(data.getValue())


def _symbol_dict(symbol: Any) -> dict[str, Any]:  # pragma: no cover - JVM edge
    """Shape one symbol into a plain dict (address/name/kind/optional namespace).

    Args:
        symbol: A Ghidra ``Symbol``.

    Returns:
        ``{"address","name","kind","namespace"?}`` (namespace omitted for the global namespace).
    """
    namespace = symbol.getParentNamespace()
    result: dict[str, Any] = {
        "address": str(symbol.getAddress()),
        "name": _to_text(symbol.getName()),
        "kind": str(symbol.getSymbolType()),
    }
    if namespace is not None and not bool(namespace.isGlobal()):
        result["namespace"] = _to_text(namespace.getName())
    return result


def _data_type_kind(data_type: Any) -> str:  # pragma: no cover - JVM edge
    """Classify a data type into a coarse, safe kind string.

    Args:
        data_type: A Ghidra ``DataType``.

    Returns:
        A lowercase kind (e.g. ``"struct"``, ``"enum"``, ``"typedef"``, ``"pointer"``, ``"other"``).
    """
    # integration-validate: confirm the concrete DataType subclasses on 12.1.2; class-name suffix
    # matching keeps this JVM-free and avoids importing each type at module scope.
    name = type(data_type).__name__.lower()
    for kind in ("structure", "union", "enum", "typedef", "pointer", "array", "function"):
        if kind in name:
            return "struct" if kind == "structure" else kind
    return "other"


def _data_type_definition(data_type: Any) -> str:  # pragma: no cover - JVM edge
    """Render a data type's definition text.

    Uses the DataType's ``toString()`` (Ghidra renders a struct/enum/typedef layout there), which
    every ``DataType`` implements — so no fragile attribute probing is needed.

    Args:
        data_type: A Ghidra ``DataType``.

    Returns:
        A rendered definition string.
    """
    # integration-validate: confirm DataType.toString() renders the layout on 12.1.2; if a richer
    # renderer is preferred, swap to it here (single chokepoint, JVM-free fallback to the name).
    return _to_text(data_type)


def _type_ref_export(data_type: Any) -> dict[str, Any] | None:  # pragma: no cover - JVM edge
    """Render a Ghidra ``DataType`` back into a structured ``TypeRef`` dict, or ``None`` (ADR-018).

    Only the round-trippable shapes the write tools accept are emitted: a closed ``base`` built-in
    or a ``named`` reference, wrapped in bounded pointer/array modifiers. Anything we cannot model
    as a structured ``TypeRef`` (so import could not re-resolve it) returns ``None`` — the entry is
    then skipped, never guessed (export honesty; no incomplete-but-plausible artifact).

    Args:
        data_type: A Ghidra ``DataType``.

    Returns:
        ``{"base"|"named", "pointer_levels", "array_len"}`` or ``None`` if not representable.
    """
    from ghidra.program.model.data import Array, Pointer

    pointer_levels = 0
    array_len: int | None = None
    current = data_type
    # Peel one array level (the write-tool TypeRef supports a single fixed-length array dimension).
    if isinstance(current, Array):
        array_len = int(current.getNumElements())
        current = current.getDataType()
    while isinstance(current, Pointer):
        pointer_levels += 1
        current = current.getDataType()
        if pointer_levels > 8:  # mirror _MAX_POINTER_DEPTH — not round-trippable beyond it
            return None
    leaf_name = _to_text(current.getName())
    base = leaf_name if leaf_name in PyGhidraBackend._BASE_TYPE_VOCAB else None
    ref: dict[str, Any] = {
        "base": base,
        "named": None if base is not None else leaf_name,
        "pointer_levels": pointer_levels,
        "array_len": array_len,
    }
    return ref


def _parse_export_targets(
    params: dict[str, Any],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Extract the server-supplied export selection from the RPC params (ADR-027 D4) — PURE.

    No JVM, no I/O — unit-testable hermetically (unlike the ``_gh_*`` edge). Reads the additive
    ``targets`` param shaped by the server (``rpc_client._export_annotations_params``): identity
    keys only — comment ``(address, comment_type)`` pairs and composite names — never a value. A
    missing or empty ``targets`` yields two empty lists (export emits no comments/composites — the
    F7 fix; no blind enumeration). Defensive against absent keys (fail-closed to empty; no raise).

    Args:
        params: The ``export_annotations`` RPC params dict.

    Returns:
        ``(comment_targets, composite_targets)`` — a list of ``(address, comment_type)`` pairs and a
        list of composite names.
    """
    raw_targets = params.get("targets") or {}
    comment_targets = [
        (str(c["address"]), str(c["comment_type"])) for c in (raw_targets.get("comments") or [])
    ]
    composite_targets = [str(name) for name in (raw_targets.get("composites") or [])]
    return comment_targets, composite_targets


# NOTE: the former ``_composite_export_kind`` (program-local-archive proxy) is REMOVED by ADR-027.
# Program-local was too loose — Ghidra auto-analysis also creates program-local structs (switch
# tables, RTTI), so it leaked 13 auto-structs (F7). Composite selection is now the session change-
# log (membership IS the user-authored signal); ``_gh_export_annotations`` step 1 looks up the
# named targets directly and inlines the Structure/Union → kind classification.


def _composite_fields_export(data_type: Any) -> list[dict[str, Any]] | None:  # pragma: no cover
    """Render a composite's members as exportable ``FieldSpec`` dicts, or ``None`` (ADR-018).

    Each member's type is rendered via :func:`_type_ref_export`; if any member is not representable
    as a structured ``TypeRef``, the whole composite is skipped (``None``) rather than emitting a
    partial/unfaithful definition.

    Args:
        data_type: A Ghidra ``Structure``/``Union``.

    Returns:
        A list of ``{"name", "type", "offset"}`` dicts, or ``None`` if any member is unrenderable.
    """
    from ghidra.program.model.data import Structure

    fields: list[dict[str, Any]] = []
    is_struct = isinstance(data_type, Structure)
    for component in data_type.getDefinedComponents():
        ref = _type_ref_export(component.getDataType())
        if ref is None:
            return None
        fields.append(
            {
                "name": _to_text(component.getFieldName()),
                "type": ref,
                "offset": int(component.getOffset()) if is_struct else None,
            }
        )
    return fields or None


def _function_signature_export(func: Any) -> dict[str, Any]:  # pragma: no cover - JVM edge
    """Render a USER_DEFINED function signature as a ``set_function_signature`` export entry.

    Args:
        func: A Ghidra ``Function`` whose signature source is ``USER_DEFINED``.

    Returns:
        A plain ``set_function_signature`` entry dict (types rendered as structured TypeRefs;
        an unrenderable type falls back to the opaque ``void`` base so the entry stays valid).
    """
    void_ref = {"base": "void", "named": None, "pointer_levels": 0, "array_len": None}
    return_ref = _type_ref_export(func.getReturnType()) or void_ref
    parameters: list[dict[str, Any]] = []
    for param in func.getParameters():
        parameters.append(
            {
                "name": _to_text(param.getName()),
                "type": _type_ref_export(param.getDataType()) or void_ref,
            }
        )
    convention = func.getCallingConventionName()
    return {
        "kind": "set_function_signature",
        "function": str(func.getEntryPoint()),
        "return_type": return_ref,
        "parameters": parameters,
        "calling_convention": None if convention is None else str(convention),
    }


def _block_permissions(block: Any) -> str:  # pragma: no cover - JVM edge
    """Render a memory block's permissions as an ``rwx``-style string.

    Args:
        block: A Ghidra ``MemoryBlock``.

    Returns:
        A permission string (e.g. ``"r-x"``); a dash marks an absent permission.
    """
    return (
        ("r" if bool(block.isRead()) else "-")
        + ("w" if bool(block.isWrite()) else "-")
        + ("x" if bool(block.isExecute()) else "-")
    )


def _pattern_to_bytes_and_mask(pattern_hex: str) -> tuple[bytes, bytes]:
    """Convert a validated hex pattern (with ``"??"`` wildcards) to (values, masks) byte arrays.

    Each output byte pairs with a mask byte: ``0xff`` for a fixed byte (match exactly) and ``0x00``
    for a wildcard (match anything), as ``Memory.findBytes`` expects.

    Args:
        pattern_hex: A validated hex pattern (pairs of hex digits or ``"??"``; spaces allowed).

    Returns:
        A ``(values, masks)`` tuple of equal-length byte strings.
    """
    compact = pattern_hex.replace(" ", "")
    values = bytearray()
    masks = bytearray()
    for i in range(0, len(compact), 2):
        pair = compact[i : i + 2]
        if pair == "??":
            values.append(0)
            masks.append(0x00)
        else:
            values.append(int(pair, 16))
            masks.append(0xFF)
    return bytes(values), bytes(masks)


def _page(params: dict[str, Any]) -> tuple[int, int]:
    """Extract and clamp ``(offset, limit)`` from request params (defense-in-depth).

    Args:
        params: The request params.

    Returns:
        A clamped ``(offset, limit)`` tuple.
    """
    offset = max(0, int(params.get("offset", 0)))
    limit = _clamp_count(int(params.get("limit", 100)))
    return offset, limit


def _clamp_count(value: int) -> int:
    """Clamp a result-count request to ``[1, _MAX_RESULT_COUNT]``.

    Args:
        value: The requested count.

    Returns:
        The clamped count.
    """
    return max(1, min(int(value), _MAX_RESULT_COUNT))


def _clamp_read(value: int) -> int:
    """Clamp a byte-read length to ``[1, _MAX_READ_BYTES]``.

    Args:
        value: The requested length.

    Returns:
        The clamped length.
    """
    return max(1, min(int(value), _MAX_READ_BYTES))


def _clamp_identify(value: int) -> int:
    """Clamp a FID match-count request to ``[1, _MAX_IDENTIFY_MATCHES]`` (ADR-042; CWE-400).

    Args:
        value: The requested match count.

    Returns:
        The clamped count.
    """
    return max(1, min(int(value), _MAX_IDENTIFY_MATCHES))


#: Writable tmpfs scratch dir the bundled FID DBs are copied into before attach (ADR-043 D3 — the
#: bundled dir is on the read-only rootfs; ``addUserFidFile`` needs a writable, valid packed path).
#: Mirrors the worker image's HOME / java.io.tmpdir tmpfs (Containerfile.worker).
_FID_WRITABLE_SCRATCH = "/tmp/ghidra"  # noqa: S108  # nosec B108 — worker tmpfs (ro rootfs)


def _fid_log(event: str, **fields: object) -> None:  # pragma: no cover - worker stderr sink
    """Emit a redaction-safe structured FID-attach log line to the worker's stderr sink.

    The worker runs offline; stderr is its only diagnostic sink (``worker/__main__.py``). Fields are
    redaction-safe scalars only (DB file names, counts, outcomes — never binary content or secrets,
    topic-logging-observability). One JSON-ish line per event.

    Args:
        event: The event name (e.g. ``fid_dbs_attached`` / ``fid_db_skipped``).
        **fields: Redaction-safe scalar fields to attach.
    """
    import json
    import sys

    payload = {"event": event, **fields}
    print(json.dumps(payload, default=str), file=sys.stderr, flush=True)


def _fid_attach_one(writable_copy: Any) -> bool:  # pragma: no cover - JVM edge
    """Attach + activate one writable packed ``.fidbf`` via the Ghidra FID manager (ADR-043 D3).

    The PROVEN activation recipe (O1 spike): ``FidFileManager.getInstance().addUserFidFile(File)``
    on a WRITABLE, valid packed path (returns ``None`` on a read-only/invalid/corrupt path) →
    ``FidFile.setActive(True)``. A pre-built populated DB activates on a single attach (no re-add).

    Args:
        writable_copy: The :class:`pathlib.Path` of the writable packed-DB copy.

    Returns:
        ``True`` when attached + activated; ``False`` when the manager rejected the file
        (``addUserFidFile`` returned ``None``) — the orchestration then skips it (fail-soft).
    """
    from ghidra.feature.fid.db import FidFileManager  # type: ignore[import-not-found]
    from java.io import File

    manager = FidFileManager.getInstance()
    fid_file = manager.addUserFidFile(File(str(writable_copy)))
    if fid_file is None:
        return False
    fid_file.setActive(True)
    return True


def _attach_bundled_fid_dbs() -> None:  # pragma: no cover - JVM edge wiring
    """Boot PyGhidra (program-independent), then attach the bundled ELF FID DBs (ADR-043).

    Runs once at worker startup, BEFORE serving RPC. The pure dir-scan/iteration/fail-soft logic
    lives in :mod:`vivarium.ghidra._fid_attach` (hermetically unit-tested); this wrapper supplies
    the JVM edges (``pyghidra.start`` + :func:`_fid_attach_one`) and the config
    (``VIVARIUM_FID_DB_DIR``).
    Fail-soft end to end: no bundled dir / no DBs ⇒ a clean no-op; a bad DB is logged + skipped; a
    JVM/attach failure never crashes the worker (the worker still serves, just with fewer matches —
    identical to the pre-Phase-2 baseline).
    """
    from vivarium.ghidra._fid_attach import DEFAULT_FID_DB_DIR, attach_bundled_fid_dbs

    db_dir = os.environ.get("VIVARIUM_FID_DB_DIR", DEFAULT_FID_DB_DIR)
    # Pre-flight discovery so we only pay the JVM-start cost when DBs are actually bundled.
    from vivarium.ghidra._fid_attach import discover_fid_dbs

    if not discover_fid_dbs(db_dir):
        return
    try:
        import pyghidra

        pyghidra.start(verbose=False)
    except Exception as exc:
        _fid_log("fid_attach_skipped", reason=type(exc).__name__)
        return
    attach_bundled_fid_dbs(
        db_dir,
        _FID_WRITABLE_SCRATCH,
        attach_one=_fid_attach_one,
        log=_fid_log,
    )


def worker_main() -> int:
    """Entry point for the in-container worker RPC server (WS2).

    Reads its socket path and frame cap from the environment (set by the WS3 worker launcher),
    attaches the bundled ELF FID databases (ADR-043 Phase 2 — fail-soft, no-op if none bundled),
    constructs the PyGhidra backend, and serves the single server connection until shutdown/EOF.
    Runs ONLY in the worker container; never invoked from the server (ADR-001).

    Returns:
        Worker process exit code.
    """
    from worker.server import run_server  # local import: worker-only path

    socket_path = os.environ["VIVARIUM_RPC_SOCKET"]
    max_frame_bytes = int(
        os.environ.get("VIVARIUM_MAX_RESPONSE_BYTES", str(_DEFAULT_MAX_FRAME_BYTES))
    )
    # ADR-043 Phase 2: activate the bundled ELF FID DBs before serving (one-time startup attach;
    # no per-request cost). Fail-soft — a missing/bad DB never blocks the worker from serving.
    _attach_bundled_fid_dbs()
    backend = PyGhidraBackend()
    return run_server(socket_path, backend, max_frame_bytes=max_frame_bytes)
