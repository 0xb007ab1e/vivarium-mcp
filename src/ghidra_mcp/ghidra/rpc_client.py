"""RPC adapter: spawns hardened workers and speaks the internal protocol (stub, WS2).

Concrete :class:`ghidra_mcp.ghidra.port.GhidraPort` implementation. It:

- Spawns/kills the worker as a hardened container (non-root, ro-rootfs, all caps dropped, seccomp,
  **no network**, gVisor runtime, CPU/mem/pids limits — ADR-004; runtime args owned by WS3/deploy).
- Connects to the worker over the internal RPC transport (JSON-RPC 2.0 over a per-session Unix
  domain socket — see ``docs/contracts/rpc-protocol.md``); length-prefixed framing.
- Enforces per-call timeouts and **kills the worker** on timeout (no hung JVM).
- Treats the worker as a fault domain: a worker crash/poison maps to ``WORKER_UNAVAILABLE`` and
  triggers eviction; it never destabilizes the server.

This module runs IN THE SERVER process and MUST NOT import the JVM bridge (ADR-001). It only ever
sends/receives bytes over the socket.

WS0 ships the stub + frozen behavior contract; WS2 implements it.
"""

from __future__ import annotations


class RpcGhidraAdapter:
    """JSON-RPC-over-UDS adapter to per-session Ghidra workers (stub, WS2).

    Implements :class:`ghidra_mcp.ghidra.port.GhidraPort`. Construction takes the resolved config
    (worker image digest, runtime, socket dir, timeouts) via dependency injection.

    Note:
        STUB (WS2). Methods are intentionally omitted here; WS2 implements the full ``GhidraPort``
        surface. Listed as a stub so the package imports cleanly and the architecture is visible.
    """

    def __init__(self) -> None:
        """Initialize the adapter.

        Note:
            STUB (WS2). WS2 injects config (image digest, runtime, socket dir, limits).
        """
        raise NotImplementedError("WS2: implement RPC adapter construction + GhidraPort methods")
