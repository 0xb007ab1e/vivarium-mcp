"""JVM/Ghidra bridge — RUNS ONLY INSIDE THE WORKER CONTAINER (stub, WS2).

WARNING (ADR-001): this module is the ONLY code permitted to touch the JVM / PyGhidra / a binary,
and it executes ONLY inside the hardened, network-isolated worker container — NEVER in the MCP
server process. It is intentionally excluded from server-side coverage
(``[tool.coverage.run] omit``) and must never be imported by ``server``, ``sessions``, ``core``,
or ``tools``. An import-linter / test guard (WS5) enforces this boundary.

Inside the worker it: bootstraps headless Ghidra (11.x / JDK 21), imports + analyzes the binary
under the bridge's own bounds, and serves the internal RPC by mapping requests to Ghidra API calls
and returning structured, size-capped results to the server, which wraps them as untrusted.

A separate worker entrypoint (``worker/`` — WS2/WS3) hosts this bridge and the RPC server loop.
"""

from __future__ import annotations


def worker_main() -> int:
    """Entry point for the in-container worker RPC server (stub, WS2).

    Returns:
        Worker process exit code.

    Note:
        STUB (WS2). Runs ONLY in the worker container. Bootstraps headless Ghidra and serves the
        internal RPC over the per-session Unix domain socket. Never invoked from the server.
    """
    raise NotImplementedError("WS2: implement in-worker Ghidra RPC server (worker-only)")
