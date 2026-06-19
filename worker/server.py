"""In-container UDS RPC server bootstrap for the Ghidra worker (WS2).

Binds the per-session Unix domain socket with restrictive permissions, accepts the single server
connection, and serves it via :func:`worker.dispatch.serve_connection`. JVM-free: the backend is
injected, so this bootstrap is testable without Ghidra. The concrete backend wiring (PyGhidra) is
done by :func:`vivarium.ghidra._jvm_bridge.worker_main`, which calls :func:`run_server`.

Security (rpc-protocol.md §2, ADR-004): the socket is created at ``0600`` (owner-only) inside the
private socket dir; the worker has **no network**; the socket is the only ingress.
"""

from __future__ import annotations

import contextlib
import os
import socket
import stat
from pathlib import Path

from worker.dispatch import GhidraBackend, serve_connection

#: Owner read/write only — no group/other access to the RPC socket (rpc-protocol.md §2).
_SOCKET_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600


def bind_socket(socket_path: str, *, accept_timeout_s: float | None = None) -> socket.socket:
    """Create, bind, and listen on the per-session UDS with owner-only permissions.

    Args:
        socket_path: Filesystem path for the UDS (``<dir>/<sid>.sock``).
        accept_timeout_s: Optional accept timeout; ``None`` blocks until the server connects.

    Returns:
        A listening :class:`socket.socket` (backlog 1 — single sole client).
    """
    sock_file = Path(socket_path)
    # Remove a stale socket from a prior crashed worker, if any (idempotent bind).
    with contextlib.suppress(FileNotFoundError):
        sock_file.unlink()
    # Restrictive umask so the socket is created without group/other bits even before chmod.
    old_umask = os.umask(0o077)
    try:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(socket_path)
    finally:
        os.umask(old_umask)
    sock_file.chmod(_SOCKET_MODE)
    srv.listen(1)
    if accept_timeout_s is not None:
        srv.settimeout(accept_timeout_s)
    return srv


def run_server(socket_path: str, backend: GhidraBackend, *, max_frame_bytes: int) -> int:
    """Bind the UDS, accept the sole connection, serve it, then clean up. Returns an exit code.

    Args:
        socket_path: Path for the per-session UDS.
        backend: The JVM-touching backend (injected; PyGhidra inside the real worker).
        max_frame_bytes: Hard frame cap (both directions).

    Returns:
        Process exit code (``0`` on clean shutdown).
    """
    srv = bind_socket(socket_path)
    try:
        conn, _ = srv.accept()
        try:
            serve_connection(conn, backend, max_frame_bytes=max_frame_bytes)
        finally:
            with contextlib.suppress(OSError):
                conn.close()
    finally:
        with contextlib.suppress(OSError):
            srv.close()
        with contextlib.suppress(FileNotFoundError, OSError):
            Path(socket_path).unlink()
    return 0
