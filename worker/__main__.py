"""Worker container entrypoint launcher (WS3).

Runs ONLY inside the hardened, network-isolated worker container (ADR-001/003/004). This is the
process the container ``ENTRYPOINT`` invokes (``python -m worker``). It is intentionally tiny,
pure-stdlib, and offline: it reconciles the per-session socket path from the environment the
``deploy/`` runtime contract injects, then hands off to the JVM/PyGhidra bridge's
:func:`vivarium.ghidra._jvm_bridge.worker_main`.

Env contract (must match ``deploy/worker-run.sh`` + ``rpc-protocol.md`` §2):

- ``VIVARIUM_SESSION_ID`` (required) — the opaque, high-entropy session id. The per-session UDS
  is named ``<sid>.sock`` (BOLA defense: the socket name carries the session identity).
- ``VIVARIUM_RPC_SOCKET_DIR`` (optional, default ``/run/vivarium``) — the private, owner-only
  directory the ``deploy/`` layer bind-mounts for this session's socket.

The launcher derives ``VIVARIUM_RPC_SOCKET = <dir>/<sid>.sock`` and exports it because that is
the single variable :func:`worker_main` reads. Keeping the derivation here (not in the bridge)
means the socket-path/permission wiring stays a WS3 deploy concern, per the rpc-protocol.md §8
split ("protocol frozen; concrete mount/permission wiring is WS3").

Fail-closed: a missing/empty ``VIVARIUM_SESSION_ID`` exits non-zero **before** any JVM work, so
the server maps the closed socket to ``worker-unavailable`` and evicts (rpc-protocol.md §6). No
shell is involved; the entrypoint is a single Python process for a clean SIGKILL fault domain.
"""

from __future__ import annotations

import os
import sys

#: Default per-session UDS directory (mirrors the Containerfile + rpc-protocol.md §2 default).
_DEFAULT_SOCKET_DIR = "/run/vivarium"


def _resolve_socket_path(environ: dict[str, str]) -> str:
    """Derive the per-session UDS path from the environment (fail-closed on a missing id).

    Args:
        environ: The process environment (``os.environ`` in production; injectable for tests).

    Returns:
        The absolute per-session socket path ``<dir>/<session_id>.sock``.

    Raises:
        ValueError: If ``VIVARIUM_SESSION_ID`` is missing or empty (fail closed — the worker
            must not start without a session identity).
    """
    session_id = environ.get("VIVARIUM_SESSION_ID", "").strip()
    if not session_id:
        raise ValueError("VIVARIUM_SESSION_ID is required")
    socket_dir = environ.get("VIVARIUM_RPC_SOCKET_DIR", "").strip() or _DEFAULT_SOCKET_DIR
    # Join without os.path so a hostile/whitespace dir can't traverse: the id is server-minted and
    # opaque, the dir is deploy-controlled; a simple join matches rpc-protocol.md §2 exactly.
    return f"{socket_dir.rstrip('/')}/{session_id}.sock"


def main(argv: list[str] | None = None) -> int:
    """Reconcile the socket path from env, then run the worker RPC server.

    Exports ``VIVARIUM_RPC_SOCKET`` (the variable
    :func:`vivarium.ghidra._jvm_bridge.worker_main` reads) and propagates that function's exit
    code. Imports the bridge lazily so this launcher stays importable for unit tests without the
    JVM/PyGhidra present (the import only resolves inside the real worker image).

    Args:
        argv: Unused (the worker takes no positional args; the session id arrives via env per the
            ``deploy/worker-run.sh`` contract). Accepted for a conventional ``main`` signature.

    Returns:
        The worker process exit code (``0`` on clean shutdown; non-zero on fatal error →
        ``worker-unavailable`` → server eviction).
    """
    del argv  # the entrypoint contract is env-only (deploy/worker-run.sh)
    try:
        socket_path = _resolve_socket_path(dict(os.environ))
    except ValueError as exc:
        # No host detail; this message stays in worker logs (the socket never opens, so the server
        # observes only an unavailable worker). stderr is the worker's only diagnostic sink offline.
        print(f"worker: fatal: {exc}", file=sys.stderr)
        return 2
    os.environ["VIVARIUM_RPC_SOCKET"] = socket_path

    # Lazy import: worker_main pulls in the JVM/PyGhidra edge, which exists only in the worker
    # image. Keeping it here lets the launcher's path-reconciliation be unit-tested JVM-free.
    from vivarium.ghidra._jvm_bridge import worker_main

    return worker_main()


if __name__ == "__main__":  # pragma: no cover - process entrypoint (exercised by the container)
    raise SystemExit(main(sys.argv[1:]))
