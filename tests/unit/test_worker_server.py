"""Unit tests for the worker UDS bootstrap (``worker/server.py``) — JVM-free, hermetic (gap N6).

``bind_socket`` is the worker's sole-ingress security boundary (rpc-protocol.md §2 / ADR-004): it
must create the per-session Unix socket **owner-only (0600)** under a restrictive umask, and
idempotently clear a stale socket left by a crashed prior worker. This logic was 0%-covered and the
whole ``worker/`` package sat outside the coverage gate; these tests close that gap. No JVM, no
network, no real sleep — a throwaway ``tmp_path`` UDS only.
"""

from __future__ import annotations

import os
import socket
import stat
import threading
from pathlib import Path
from typing import cast
from unittest.mock import Mock

from worker.dispatch import GhidraBackend
from worker.server import bind_socket, run_server


def test_bind_socket_creates_owner_only_socket(tmp_path: Path) -> None:
    """The per-session UDS is created with mode 0600 — no group/other access (rpc-protocol §2)."""
    path = tmp_path / "s.sock"
    srv = bind_socket(str(path))
    try:
        assert path.is_socket()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        srv.close()


def test_bind_socket_unlinks_stale_socket(tmp_path: Path) -> None:
    """A leftover file at the path (crashed prior worker) is removed so the bind is idempotent."""
    path = tmp_path / "s.sock"
    path.write_bytes(b"")  # stale regular file occupying the path
    srv = bind_socket(str(path))
    try:
        assert path.is_socket()  # replaced by a fresh socket, not an EADDRINUSE failure
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        srv.close()


def test_bind_socket_restores_umask(tmp_path: Path) -> None:
    """The process umask is restored after bind (the 0o077 tightening is scoped to the bind)."""
    sentinel = 0o022
    prev = os.umask(sentinel)
    try:
        srv = bind_socket(str(tmp_path / "s.sock"))
        srv.close()
        current = os.umask(sentinel)  # reading umask requires a set; we put back the sentinel
        assert current == sentinel  # bind_socket left the umask as we had set it
    finally:
        os.umask(prev)


def test_run_server_serves_then_cleans_up_socket(tmp_path: Path) -> None:
    """``run_server`` accepts the sole client, serves until EOF, then unlinks the socket (cleanup).

    The client connects and closes immediately, so ``serve_connection`` observes EOF and returns
    without ever invoking the backend (a ``Mock`` stands in). The test asserts the clean exit code
    and that the socket file is removed in ``run_server``'s ``finally``.
    """
    path = tmp_path / "s.sock"
    rc: list[int] = []

    def _serve() -> None:
        rc.append(run_server(str(path), cast(GhidraBackend, Mock()), max_frame_bytes=4096))

    server_thread = threading.Thread(target=_serve)
    server_thread.start()
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # The bind happens before accept(); retry the connect until the socket is listening.
        connected = False
        for _ in range(500):
            try:
                client.connect(str(path))
                connected = True
                break
            except (FileNotFoundError, ConnectionRefusedError):
                continue
        assert connected, "run_server did not begin listening"
        client.close()  # immediate EOF → serve_connection returns → run_server cleans up
    finally:
        server_thread.join(timeout=5)

    assert not server_thread.is_alive()
    assert rc == [0]
    assert not path.exists()  # socket file unlinked on clean shutdown
