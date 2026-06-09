"""JVM/Ghidra bridge — RUNS ONLY INSIDE THE WORKER CONTAINER (WS2).

WARNING (ADR-001): this module is the ONLY code permitted to touch the JVM / PyGhidra / a binary,
and it executes ONLY INSIDE THE WORKER container — NEVER in the MCP server process. It is
intentionally excluded from server-side coverage (``[tool.coverage.run] omit``) and must never be
imported by ``server``, ``sessions``, ``core``, or ``tools``. An import-linter / test guard (WS5)
enforces this boundary.

Inside the worker it: bootstraps headless Ghidra (11.x / JDK 21), imports + analyzes the binary
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

    # --- Tier-2 metric extraction (RESERVED — v1.1 ADR-008; built by the WS2-style fan-out against
    # the pinned Ghidra image, validated only in the real-worker integration suite; ADR-001). -----
    def _gh_function_cfg(self, function: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """RESERVED STUB (v1.1 — ADR-008): per-function CFG block/edge counts.

        Walks ``BasicBlockModel`` over the resolved function to count basic blocks (CFG nodes) and
        control-flow edges; ``incomplete`` flags unresolved flow. The server computes McCabe
        ``E - N + 2`` from these counts in the pure core (:mod:`ghidra_mcp.core.metrics`).

        Args:
            function: Function entry address (hex) or name.

        Returns:
            ``{"address", "name", "block_count", "edge_count", "incomplete"}``.

        Raises:
            NotImplementedError: Always — built by the fan-out against the pinned Ghidra image.
        """
        raise NotImplementedError(
            "RESERVED (v1.1 ADR-008): function_cfg extraction — pending pinned-image build"
        )

    def _gh_imports(self, offset: int, limit: int) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """RESERVED STUB (v1.1 — ADR-008): imported symbols via ExternalManager/SymbolTable.

        Returns ``{"imports": [{"name","library"?,"address"?}], "total", "truncated"}`` (paginated).

        Raises:
            NotImplementedError: Always — built by the fan-out against the pinned Ghidra image.
        """
        raise NotImplementedError(
            "RESERVED (v1.1 ADR-008): imports extraction — pending pinned-image build"
        )

    def _gh_exports(self, offset: int, limit: int) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """RESERVED STUB (v1.1 — ADR-008): exported symbols/entry points via SymbolTable.

        Returns ``{"exports": [{"name","address"}], "total", "truncated"}`` (paginated).

        Raises:
            NotImplementedError: Always — built by the fan-out against the pinned Ghidra image.
        """
        raise NotImplementedError(
            "RESERVED (v1.1 ADR-008): exports extraction — pending pinned-image build"
        )

    def _gh_coverage(self) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """RESERVED STUB (v1.1 — ADR-008): defined-code/data byte counts via the Listing.

        Returns ``{"total_bytes", "defined_code_bytes", "defined_data_bytes", "function_count"}``;
        the server computes ratios + ``undefined_bytes`` in the pure core.

        Raises:
            NotImplementedError: Always — built by the fan-out against the pinned Ghidra image.
        """
        raise NotImplementedError(
            "RESERVED (v1.1 ADR-008): coverage extraction — pending pinned-image build"
        )

    # --- private JVM helpers (lazy imports only; never at module scope) -----------------------
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
