"""Concrete container worker launcher (ADR-009) — the WS3 spawn the adapter injects.

The :class:`ghidra_mcp.ghidra.rpc_client.RpcGhidraAdapter` depends on an abstract ``WorkerLauncher``
(``(session_id, socket_path) -> WorkerProcess``) so it stays runtime-agnostic. This module is the
concrete realization that translates the audited
``deploy/worker-run.sh`` hardening (ADR-004) into a ``podman run`` **argument list** (never
``shell=True``) and returns a killable :class:`ContainerWorkerProcess`.

It NEVER loads the JVM or parses a binary (ADR-001) — it only spawns/kills the out-of-process,
network-isolated worker container and arranges the two shared surfaces:

  * the **per-session UDS dir** (``dirname(socket_path)``) — bind-mounted read-write so the worker
    binds its own ``<sid>.sock``; isolated per session (a hostile worker sees no sibling sockets);
  * the confined, read-only **import root** — where candidate binaries live; the worker opens the
    ``source_ref`` (a path under the root) the server passes over RPC. The server enforces the
    size cap and path-confinement (CWE-22) BEFORE the worker is contacted (see
    :func:`make_confined_resolver`).

All collaborators (the subprocess ``runner``) are injectable so the argv construction + lifecycle
are unit-tested without a real container engine; the real spawn is validated by the gated
``e2e-groundtruth`` / integration runs.
"""

from __future__ import annotations

import subprocess  # nosec B404 - argv lists only, never shell=True (see _default_runner)
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ghidra_mcp.ghidra.rpc_client import WorkerProcess

#: A subprocess runner: takes an argv list, returns the completed process. Injected so tests can
#: assert the exact command (and simulate failures) with no real engine.
Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:  # pragma: no cover
    """Run ``argv`` capturing output, never raising on non-zero (the caller inspects rc).

    The real-subprocess default; tests inject a fake runner, so this thin shim is excluded from
    coverage (exercised only by the gated real-engine e2e/integration runs).
    """
    # argv is a fixed list (no shell, no string interpolation into a command line); all elements
    # are our own constants + the manifest-pinned image + server-minted ids.
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603  # nosec B603


@dataclass(frozen=True, slots=True)
class ContainerWorkerProcess:
    """A spawned worker container handle the adapter can SIGKILL (``WorkerProcess``).

    Attributes:
        container_name: Deterministic per-session container name (``ghidra-mcp-worker-<sid>``).
        engine: Container CLI (``podman``).
        runner: Injected subprocess runner.
    """

    container_name: str
    engine: str
    runner: Runner

    def kill(self) -> None:
        """Forcibly remove the worker container (SIGKILL + remove). Idempotent — ignores errors."""
        self.runner([self.engine, "rm", "-f", self.container_name])

    def is_alive(self) -> bool:
        """Whether the container is still running (``inspect`` State.Running)."""
        r = self.runner([self.engine, "inspect", "-f", "{{.State.Running}}", self.container_name])
        return r.returncode == 0 and r.stdout.strip() == "true"


class WorkerLaunchError(RuntimeError):
    """The worker container failed to spawn (boundary-safe message; no host detail)."""


@dataclass(frozen=True, slots=True)
class ContainerWorkerLauncher:
    """Builds the hardened ``podman run`` for one session and returns its :class:`WorkerProcess`.

    Realizes ``deploy/worker-run.sh`` (ADR-004) as code. Construction takes the deployment knobs
    (image, runtime, the host import root, resource bounds); calling it spawns one detached worker.

    Attributes:
        worker_image: Pinned-by-digest worker image (ADR-003).
        import_root: Host dir (read-only mount) under which ``source_ref`` inputs must live.
        runtime: OCI runtime (``runsc`` for gVisor — ADR-004; falls back at deploy if absent).
        engine: Container CLI (``podman``).
        mem / cpus / pids / tmpfs_scratch / tmpfs_project: Resource bounds (F7 DoS).
        analysis_timeout_s: Passed to the worker as defense-in-depth (it enforces its own too).
        seccomp: Seccomp profile (``RuntimeDefault``; stricter is opt-in after validation).
        runner: Injected subprocess runner (default real ``subprocess``).
    """

    worker_image: str
    import_root: str
    runtime: str = "runsc"
    engine: str = "podman"
    mem: str = "4g"
    cpus: str = "2"
    pids: int = 512
    tmpfs_scratch: str = "2g"
    tmpfs_project: str = "4g"
    analysis_timeout_s: int = 600
    seccomp: str = "RuntimeDefault"
    runner: Runner = field(default=_default_runner)

    def __call__(self, session_id: str, socket_path: str) -> WorkerProcess:
        """Spawn the hardened worker for ``session_id``; the worker binds ``socket_path``.

        Args:
            session_id: Opaque, high-entropy session id (also the container name + socket name).
            socket_path: Host path of the per-session UDS (``<dir>/<sid>/<sid>.sock``); its parent
                dir is created (0700) and bind-mounted as the worker's only writable surface.

        Returns:
            A running :class:`ContainerWorkerProcess`.

        Raises:
            WorkerLaunchError: If the engine returns non-zero (fail closed → server evicts).
        """
        sess_dir = Path(socket_path).parent
        sess_dir.mkdir(parents=True, exist_ok=True)
        sess_dir.chmod(0o700)  # server-owned, private (no other session/worker may read it)
        name = f"ghidra-mcp-worker-{session_id}"

        argv = [
            self.engine,
            "run",
            "--name",
            name,
            "--rm",
            "--detach",
            # gVisor user-space kernel around the hostile JVM (ADR-004 strong tier).
            "--runtime",
            self.runtime,
            # No network / no egress — removes the exfiltration path entirely.
            "--network",
            "none",
            # Non-root (image USER is 65532); rootless maps to an unprivileged host uid.
            "--user",
            "65532:65532",
            "--userns",
            "keep-id",
            # Drop ALL capabilities; a headless analyzer needs none.
            "--cap-drop",
            "ALL",
            # No setuid privilege escalation; seccomp filter (RuntimeDefault, verified to load).
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            f"seccomp={self.seccomp}",
            # Immutable rootfs; writable scratch + per-session project store ONLY via tmpfs
            # (noexec,nosuid,nodev; mode=1777 so the non-root worker can write under ro-rootfs).
            "--read-only",
            "--tmpfs",
            # In-container mount spec, NOT a host temp path — the worker's scratch tmpfs (ADR-004).
            f"/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size={self.tmpfs_scratch}",  # noqa: S108  # nosec B108
            "--tmpfs",
            f"/work/project:rw,noexec,nosuid,nodev,mode=1777,size={self.tmpfs_project}",
            # Resource bounds (F7): OOM/pids/cpu caps; OOM-kill → server evicts.
            "--memory",
            self.mem,
            "--memory-swap",
            self.mem,
            "--cpus",
            self.cpus,
            "--pids-limit",
            str(self.pids),
            "--oom-kill-disable=false",
            # The ONLY writable shared surface: this session's private UDS dir (rpc-protocol §2).
            "--volume",
            f"{sess_dir}:/run/ghidra-mcp:rw,Z",
            # The hostile input(s): confined import root, READ-ONLY, at the SAME path so the
            # server-passed source_ref (a host path under the root) resolves inside the container.
            "--volume",
            f"{self.import_root}:{self.import_root}:ro,Z",
            # Minimal, explicit env (no host env leakage).
            "--env",
            f"GHIDRA_MCP_SESSION_ID={session_id}",
            "--env",
            "GHIDRA_MCP_RPC_SOCKET_DIR=/run/ghidra-mcp",
            "--env",
            f"GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS={self.analysis_timeout_s}",
            "--env-host=false",
            self.worker_image,
        ]
        result = self.runner(argv)
        if result.returncode != 0:
            # Boundary-safe: no host detail beyond the engine's own (already non-sensitive) message.
            raise WorkerLaunchError(f"worker launch failed (rc={result.returncode})")
        return ContainerWorkerProcess(container_name=name, engine=self.engine, runner=self.runner)


def make_confined_resolver(import_root: str) -> Callable[[str], int]:
    """Build a ``SourceResolver`` that confines ``source_ref`` under ``import_root`` (CWE-22).

    Returns the input's byte size (for the pre-Ghidra size cap) ONLY if it resolves to a real file
    strictly under ``import_root`` after symlink resolution; otherwise raises ``OSError`` so the
    adapter fails it closed as ``VALIDATION`` before any worker is contacted.

    Args:
        import_root: The host directory inputs must live under.

    Returns:
        A resolver ``(source_ref) -> int`` (byte size).
    """
    root = Path(import_root).resolve()

    def resolve(source_ref: str) -> int:
        candidate = Path(source_ref).resolve()
        if not candidate.is_relative_to(root):
            msg = "source_ref escapes the import root"
            raise OSError(msg)
        return candidate.stat().st_size

    return resolve
