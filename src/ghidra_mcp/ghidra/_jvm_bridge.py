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
from collections.abc import Callable
from typing import Any

# Bounds the bridge enforces itself (defense-in-depth; the server also caps before calling).
_MAX_RESULT_COUNT = 10_000
_MAX_READ_BYTES = 1_048_576  # 1 MiB
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
# Annotation-document schema version the worker emits on export (v1.2 — ADR-018; mirrors
# schemas.ANNOTATION_SCHEMA_VERSION). The server overlays the authoritative binary hash.
_ANNOTATION_SCHEMA_VERSION = 1


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
        #: Hex SHA-256 of the imported binary (server-computed digest of input — safe scalar).
        self._sha256: str | None = None
        #: Whether Ghidra auto-analysis has completed for the open program.
        self._analyzed: bool = False

    # --- lifecycle ---------------------------------------------------------------------------
    def import_binary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Import the binary referenced by the (server-confined) source ref into the project.

        Args:
            params: ``{"source_ref": str, "expected_sha256": str | None}``. The server has already
                resolved/confined the path and enforced the size cap BEFORE this call.

        Returns:
            A plain ``SessionInfo``-shaped dict.
        """
        source_ref = _require(params, "source_ref")
        return self._gh_import(str(source_ref))

    def analyze(self, params: dict[str, Any]) -> dict[str, Any]:
        """Run Ghidra auto-analysis on the imported program.

        Args:
            params: ``{"timeout_seconds": int | None}`` (the server kills the worker on its own
                deadline; this is the in-worker budget hint).

        Returns:
            A plain ``SessionInfo``-shaped dict.
        """
        return self._gh_analyze(params.get("timeout_seconds"))

    # --- read-only operations ----------------------------------------------------------------
    def decompile_function(self, params: dict[str, Any]) -> dict[str, Any]:
        """Decompile one function (by address or name)."""
        return self._gh_decompile(str(_require(params, "function")))

    def disassemble(self, params: dict[str, Any]) -> dict[str, Any]:
        """Disassemble a bounded range or function."""
        cap = _clamp_count(params.get("max_instructions", 256))
        return self._gh_disassemble(params.get("start"), params.get("function"), cap)

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

    def _gh_import(self, source_ref: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Import a binary file into a transient Ghidra project (PyGhidra).

        Opens the (server-confined, size-checked) file with PyGhidra and retains the program/
        context on ``self`` for subsequent analyze/query calls. Returns a ``SessionInfo``-shaped
        dict contributing ``state`` + ``binary_sha256``; the server overlays the authoritative
        ids/timestamps (placeholders here satisfy the model's required scalars).

        Args:
            source_ref: The server-resolved, confined input path.

        Returns:
            A plain ``SessionInfo``-shaped dict.
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
        project_dir = os.environ.get("GHIDRA_MCP_WORKER_PROJECT_DIR", "/work/project")
        ctx = pyghidra.open_program(
            source_ref,
            project_location=project_dir,
            project_name="session",
            analyze=False,
        )
        program = ctx.__enter__()
        self._project = ctx  # retain the context manager for the worker launcher to close on evict
        self._program = getattr(program, "getCurrentProgram", lambda: program)()
        return _session_info_dict("importing", self._sha256, analysis_complete=False)

    def _gh_analyze(self, timeout_seconds: int | None) -> dict[str, Any]:  # pragma: no cover
        """Run Ghidra auto-analysis on the open program.

        Args:
            timeout_seconds: In-worker budget hint (the server enforces the hard deadline by
                killing the worker; this is advisory).

        Returns:
            A plain ``SessionInfo``-shaped dict reporting the ``ready`` state.

        Raises:
            WorkerError: ``analysis-failed`` if no program is loaded.
        """
        from worker.dispatch import CODE_ANALYSIS_FAILED, WorkerError

        if self._program is None:
            raise WorkerError(CODE_ANALYSIS_FAILED, "no program imported for analysis")
        # integration-validate: confirm the auto-analysis entrypoint on 12.1.2 — pyghidra exposes an
        # analysis helper; otherwise ghidra.app.plugin.core.analysis.AutoAnalysisManager
        # .getAnalysisManager(program).reAnalyzeAll(None) inside a started transaction. The WS3
        # launcher supplies the wall-clock kill; this call runs synchronously to completion.
        import pyghidra

        pyghidra.analyze(self._program)
        self._analyzed = True
        return _session_info_dict("ready", self._sha256, analysis_complete=True)

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
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import-not-found]
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
        memory = program.getMemory()
        buffer = bytearray(length)
        # integration-validate: Memory.getBytes(addr, byte[]) returns the count read and throws
        # MemoryAccessException past initialized memory — clamp to what is actually readable.
        try:
            read = int(memory.getBytes(start, buffer))
        except Exception:
            read = 0
            for index in range(length):
                try:
                    buffer[index] = int(memory.getByte(start.add(index))) & 0xFF
                    read += 1
                except Exception:
                    break
        data = bytes(buffer[:read])
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

    def _gh_call_graph(
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
        (:mod:`ghidra_mcp.core.metrics`) computes the complexity from these counts.

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
        from ghidra.program.model.block import BasicBlockModel  # type: ignore[import-not-found]

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

    def _gh_define_struct(
        self, name: str, fields: list[dict[str, Any]], packed: bool
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Create a new struct from a resolved field list inside one transaction (ADR-015 §3).

        Mirrors the ADR-015 ratified recursion model: name-collision REJECT (read-only lookup before
        the txn), then INSIDE the one transaction — pre-register the empty ``StructureDataType``
        (so a self-``named`` pointer resolves), resolve + add each member (size-checked against
        ``_MAX_COMPOSITE_SIZE``), and let ``_in_transaction`` finalize/roll back. Any failure rolls
        back and removes the pre-registered type (no partial/orphan type). NO C string is parsed.

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
                    self._raise_composite_too_large()
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

        Same ratified model as :meth:`_gh_define_struct` (name-collision REJECT, pre-register empty
        ``UnionDataType`` inside the one txn so a self-``named`` pointer resolves, resolve + add
        each member size-checked, finalize/roll back). A union overlays all members at offset 0
        (``offset`` is ignored). NO C string is parsed.

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
                    self._raise_composite_too_large()
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

    def _gh_define_types(
        self, types: list[dict[str, Any]]
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Create a BATCH of interdependent composites in ONE transaction (ADR-021).

        Generalizes :meth:`_gh_define_struct` / :meth:`_gh_define_union` from one composite to a
        batch: name-collision REJECT for EACH batch name vs the existing program (read-only, before
        the txn), then INSIDE the one transaction — pre-register EVERY empty composite (struct/union
        per ``kind``) so an in-batch ``named`` ref (pointer OR by-value) resolves, resolve + add
        each type's members against the pre-registered handles + existing/base types (batch-total
        size-checked against ``_MAX_COMPOSITE_SIZE``), and let ``_in_transaction`` finalize/roll
        back. ANY failure rolls back the WHOLE batch (no partial/orphan type — ``_in_transaction``
        does ``endTransaction(False)`` on exception). The server has already rejected by-value
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
    def _gh_export_annotations(
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

        # 1) Composite types FIRST (define_struct/define_union) — dependency-safe so a later
        #    signature/apply that references the composite has it available on replay. ADR-027:
        #    look up ONLY the change-log's named composites (membership in the log IS the user-
        #    authored signal — NOT the too-loose program-local-archive proxy that leaked auto
        #    structs). REQUIRES LIVE VERIFICATION: getDataType(CategoryPath.ROOT, name).
        manager = program.getDataTypeManager()
        for name in composite_targets:
            data_type = manager.getDataType(CategoryPath.ROOT, name)
            if data_type is None:
                continue  # named composite not found (e.g. since removed) — skip, never guess
            if not isinstance(data_type, (Structure, Union)):
                continue  # name now resolves to a non-composite — skip
            fields = _composite_fields_export(data_type)
            if fields is None:
                continue  # not field-reconstructable (e.g. derived/aliased) — skip, never guess
            kind = "define_union" if isinstance(data_type, Union) else "define_struct"
            _emit({"kind": kind, "name": _to_text(data_type.getName()), "fields": fields})

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
        buffer = bytearray(max(1, min(length, _MAX_READ_BYTES)))
        try:
            read = int(memory.getBytes(address, buffer))
        except Exception:
            read = 0
        return bytes(buffer[:read]).hex()

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


def worker_main() -> int:
    """Entry point for the in-container worker RPC server (WS2).

    Reads its socket path and frame cap from the environment (set by the WS3 worker launcher),
    constructs the PyGhidra backend, and serves the single server connection until shutdown/EOF.
    Runs ONLY in the worker container; never invoked from the server (ADR-001).

    Returns:
        Worker process exit code.
    """
    from worker.server import run_server  # local import: worker-only path

    socket_path = os.environ["GHIDRA_MCP_RPC_SOCKET"]
    max_frame_bytes = int(
        os.environ.get("GHIDRA_MCP_MAX_RESPONSE_BYTES", str(_DEFAULT_MAX_FRAME_BYTES))
    )
    backend = PyGhidraBackend()
    return run_server(socket_path, backend, max_frame_bytes=max_frame_bytes)
