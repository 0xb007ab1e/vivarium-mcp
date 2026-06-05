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

    # --- JVM edge (PyGhidra calls live ONLY here; imported lazily) ---------------------------
    # NOTE: these helpers are the worker-only JVM boundary. They are excluded from server unit
    # coverage and exercised only by the integration suite against a real pinned worker image. The
    # exact PyGhidra symbol bindings are confirmed at WS3 image build (ADR-003 open item).
    def _gh_import(self, source_ref: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Import a binary file into a transient Ghidra project (PyGhidra)."""
        import pyghidra  # noqa: F401 — lazy, worker-only

        raise NotImplementedError("WS3 image build: bind pyghidra.open_program against pinned API")

    def _gh_analyze(self, timeout_seconds: int | None) -> dict[str, Any]:  # pragma: no cover
        """Run Ghidra auto-analysis on the open program."""
        raise NotImplementedError("WS3 image build: invoke analyzeAll against pinned API")

    def _gh_decompile(self, function: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Decompile a function with the Ghidra DecompInterface."""
        raise NotImplementedError("WS3 image build: bind DecompInterface against pinned API")

    def _gh_disassemble(
        self, start: str | None, function: str | None, cap: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Disassemble a bounded range or function via the Listing API."""
        raise NotImplementedError("WS3 image build: bind Listing instructions against pinned API")

    def _gh_list_functions(
        self, offset: int, limit: int, name_contains: str | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List functions via FunctionManager."""
        raise NotImplementedError("WS3 image build: bind FunctionManager against pinned API")

    def _gh_get_function(self, function: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Resolve one function's detail."""
        raise NotImplementedError("WS3 image build: bind function lookup against pinned API")

    def _gh_xrefs(
        self, target: str, offset: int, limit: int, *, to: bool
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List references to/from a target via ReferenceManager."""
        raise NotImplementedError("WS3 image build: bind ReferenceManager against pinned API")

    def _gh_list_strings(
        self, offset: int, limit: int, min_length: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List defined strings via the DataIterator/Listing."""
        raise NotImplementedError("WS3 image build: bind defined-string iteration")

    def _gh_list_symbols(
        self, offset: int, limit: int, name_contains: str | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List symbols via SymbolTable."""
        raise NotImplementedError("WS3 image build: bind SymbolTable against pinned API")

    def _gh_get_symbol(self, identifier: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Resolve one symbol by name or address."""
        raise NotImplementedError("WS3 image build: bind symbol resolution against pinned API")

    def _gh_list_data(self, offset: int, limit: int) -> dict[str, Any]:  # pragma: no cover
        """List defined data items via the Listing."""
        raise NotImplementedError("WS3 image build: bind defined-data iteration")

    def _gh_get_data_type(self, name: str) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Resolve a data type via DataTypeManager."""
        raise NotImplementedError("WS3 image build: bind DataTypeManager against pinned API")

    def _gh_get_comments(
        self, offset: int, limit: int, address: str | None
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Read comments via the Listing comment API."""
        raise NotImplementedError("WS3 image build: bind comment iteration against pinned API")

    def _gh_memory_map(self) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """List memory blocks via the Memory API."""
        raise NotImplementedError("WS3 image build: bind Memory blocks against pinned API")

    def _gh_read_bytes(self, address: str, length: int) -> dict[str, Any]:  # pragma: no cover
        """Read a bounded byte range via Memory.getBytes (confined to the map)."""
        raise NotImplementedError("WS3 image build: bind Memory.getBytes against pinned API")

    def _gh_search_bytes(
        self, pattern_hex: str, offset: int, limit: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Search for a byte pattern via Memory.findBytes (bounded)."""
        raise NotImplementedError("WS3 image build: bind Memory.findBytes against pinned API")

    def _gh_search_strings(
        self, query: str, offset: int, limit: int
    ) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Search defined strings (substring) — bounded."""
        raise NotImplementedError("WS3 image build: bind string search against pinned API")

    def _gh_program_metadata(self) -> dict[str, Any]:  # pragma: no cover - JVM edge
        """Collect high-level program metadata."""
        raise NotImplementedError("WS3 image build: bind program metadata against pinned API")


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
