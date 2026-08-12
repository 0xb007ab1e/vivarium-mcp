"""Concrete container worker launcher (ADR-009) — the WS3 spawn the adapter injects.

The :class:`vivarium.ghidra.rpc_client.RpcGhidraAdapter` depends on an abstract ``WorkerLauncher``
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

from vivarium.ghidra.rpc_client import SourceRefError, WorkerProcess
from vivarium.logging import get_logger

_log = get_logger(__name__)

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
        container_name: Deterministic per-session container name (``vivarium-worker-<sid>``).
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

    def exit_diagnosis(self) -> str:
        """Classify why the worker exited: ``"oom"`` / ``"other"`` / ``"unknown"`` (ADR-023/037).

        Server-side container-engine METADATA query only (``inspect`` of ``State.OOMKilled`` and
        ``State.ExitCode``) — it parses no binary and loads no JVM (ADR-001). Used by the adapter to
        distinguish a memory-cap OOM (→ ``resource-exhausted``) from a generic crash/closed socket
        (→ ``worker-unavailable``). Fails closed to ``"unknown"`` on any engine error or
        unparseable output (never mis-report an OOM the engine didn't confirm).

        A worker OOMs two ways with DIFFERENT exit signatures (ADR-037):

        - **Native / off-heap overrun** → the cgroup OOM-killer SIGKILLs the container →
          ``OOMKilled=true`` / ``ExitCode=137`` (128 + SIGKILL).
        - **JVM heap exhaustion** → the worker JVM (``-XX:MaxRAMPercentage=75``) hits its heap
          ceiling *below* the cgroup wall and self-exits via ``-XX:+ExitOnOutOfMemoryError``, which
          is HotSpot ``os::exit(3)`` → ``ExitCode=3`` / ``OOMKilled=false``. This is the **common**
          large-binary case (the v1.5 #5 spike observed it mis-tagged ``worker-unavailable``). Exit
          ``3`` is collision-free here: the worker's own deliberate codes are ``{0}`` (clean) and
          ``{2}`` (missing-session-id, pre-JVM); a Python error exits 1, a JVM hard crash 134 — only
          ``ExitOnOutOfMemoryError`` uses 3.

        Returns:
            ``"oom"`` when the engine reports OOMKilled, the cgroup OOM-kill exit ``137``, or the
            JVM ``ExitOnOutOfMemoryError`` exit ``3``; ``"other"`` for any other confirmed exit;
            ``"unknown"`` when the engine query fails or its output cannot be parsed.
        """
        r = self.runner(
            [
                self.engine,
                "inspect",
                "-f",
                "{{.State.OOMKilled}} {{.State.ExitCode}}",
                self.container_name,
            ]
        )
        if r.returncode != 0:
            return "unknown"
        parts = r.stdout.split()
        if len(parts) != 2:
            return "unknown"
        oom_killed, exit_code = parts
        if oom_killed == "true" or exit_code in ("137", "3"):
            return "oom"
        return "other"


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
        run_as_uid / run_as_gid: Worker process uid/gid (default the hardened ``65532``). Must
            match the uid owning the bind-mounted socket dir under ``--userns keep-id`` (see the
            note at the ``--user`` flag); overridable so a host-run server can align the worker.
        mem_mib / cpus / pids / tmpfs_scratch_mib / tmpfs_project_mib: Resource bounds (F7/ADR-023
            DoS caps), as resolved + clamped integers (whole MiB / whole CPUs / pid count). They are
            rendered to the engine's spelling at argv build (``f"{mib}m"`` / ``str(cpus)``).
            ``--memory-swap`` is pinned EQUAL to ``--memory`` (no swap — ADR-004 invariant).
        analysis_timeout_s: Passed to the worker as defense-in-depth (it enforces its own too).
        seccomp: Seccomp policy. ``"RuntimeDefault"`` (default) applies the engine's built-in
            profile by OMITTING the flag (passing the literal value would be read as a file path
            and fail to launch); any other value is passed as ``seccomp=<value>`` (a custom profile
            path, or ``unconfined`` to disable — never the default).
        runner: Injected subprocess runner (default real ``subprocess``).
    """

    worker_image: str
    import_root: str
    runtime: str = "runsc"
    engine: str = "podman"
    run_as_uid: int = 65532
    run_as_gid: int = 65532
    # Resource bounds as resolved, clamped integers (ADR-023 / F1). Defaults mirror the historical
    # hardcoded values (4g mem, 2 cpus, 512 pids, 2g scratch tmpfs, 4g project tmpfs).
    mem_mib: int = 4096
    cpus: int = 2
    pids: int = 512
    tmpfs_scratch_mib: int = 2048
    tmpfs_project_mib: int = 4096
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
        name = f"vivarium-worker-{session_id}"

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
            # Non-root (image USER is 65532); rootless maps to an unprivileged host uid. With
            # --userns keep-id the worker uid must match the uid that owns the bind-mounted socket
            # dir (the server's): in production the server also runs containerized as 65532
            # (deploy/server-run.sh + socket-dir.md), so both map to the same host subuid. It is
            # configurable so a host-run server (e.g. the gated ground-truth e2e) can align the
            # worker to its own uid — the default stays the hardened 65532 (ADR-004).
            "--user",
            f"{self.run_as_uid}:{self.run_as_gid}",
            "--userns",
            "keep-id",
            # Drop ALL capabilities; a headless analyzer needs none.
            "--cap-drop",
            "ALL",
            # No setuid privilege escalation. (Seccomp is appended below — see the note: the
            # engine's default profile is applied by OMITTING the flag, not by a magic value.)
            "--security-opt",
            "no-new-privileges",
            # Immutable rootfs; writable scratch + per-session project store ONLY via tmpfs
            # (noexec,nosuid,nodev; mode=1777 so the non-root worker can write under ro-rootfs).
            "--read-only",
            "--tmpfs",
            # In-container mount spec, NOT a host temp path — the worker's scratch tmpfs (ADR-004).
            # Size rendered from the resolved MiB integer to the engine's ``Nm`` spelling.
            f"/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size={self.tmpfs_scratch_mib}m",  # noqa: S108  # nosec B108
            "--tmpfs",
            f"/work/project:rw,noexec,nosuid,nodev,mode=1777,size={self.tmpfs_project_mib}m",
            # Resource bounds (F7/ADR-023): OOM/pids/cpu caps; OOM-kill → server evicts. Rendered
            # from resolved integers; --memory-swap is pinned EQUAL to --memory (no swap — ADR-004).
            "--memory",
            f"{self.mem_mib}m",
            "--memory-swap",
            f"{self.mem_mib}m",
            "--cpus",
            str(self.cpus),
            "--pids-limit",
            str(self.pids),
            "--oom-kill-disable=false",
            # The ONLY writable shared surface: this session's private UDS dir (rpc-protocol §2).
            "--volume",
            f"{sess_dir}:/run/vivarium:rw,Z",
            # The hostile input(s): confined import root, READ-ONLY, at the SAME path so the
            # server-passed source_ref (a host path under the root) resolves inside the container.
            "--volume",
            f"{self.import_root}:{self.import_root}:ro,Z",
            # Minimal, explicit env (no host env leakage).
            "--env",
            f"VIVARIUM_SESSION_ID={session_id}",
            "--env",
            "VIVARIUM_RPC_SOCKET_DIR=/run/vivarium",
            "--env",
            f"VIVARIUM_ANALYSIS_TIMEOUT_SECONDS={self.analysis_timeout_s}",
            "--env-host=false",
        ]
        # Seccomp: ``"RuntimeDefault"`` is the OCI/K8s sentinel for "use the engine's built-in
        # default profile". podman/docker apply that profile when NO seccomp option is passed, and
        # interpret ``seccomp=<value>`` as a PROFILE FILE PATH — so passing the literal string
        # "RuntimeDefault" makes the engine try to open a file by that name and fail to launch.
        # Therefore: omit the flag for the default (the default profile still blocks the dangerous
        # syscalls — hardening preserved, ADR-004) and pass ``seccomp=<path>`` only for a custom
        # profile (or ``unconfined`` to disable, which is never the default).
        if self.seccomp != "RuntimeDefault":
            argv += ["--security-opt", f"seccomp={self.seccomp}"]
        argv.append(self.worker_image)
        result = self.runner(argv)
        if result.returncode != 0:
            # Full engine detail stays SERVER-SIDE (CI/ops diagnosability — e.g. an absent OCI
            # runtime or rootless cgroup-delegation refusal); the engine's own stderr carries no
            # binary content or secrets. The raised error is boundary-safe (rc only, no host
            # detail) so nothing leaks to the MCP client (topic-logging-observability, master §5).
            _log.error(
                "worker.launch_failed",
                extra={
                    "rc": result.returncode,
                    "runtime": self.runtime,
                    "engine_stderr": (result.stderr or "")[:2000],
                },
            )
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
        try:
            candidate = Path(source_ref).resolve()
        except ValueError as exc:
            # A malformed path (e.g. an embedded NUL byte makes ``Path.resolve()`` raise
            # ``ValueError``) — fail closed as a reason-tagged ``SourceRefError`` (an ``OSError``
            # subclass) so the adapter maps it to a specific ``VALIDATION`` detail (F4), not a leaky
            # ``internal-error`` (CWE-20; G11 finding).
            raise SourceRefError("malformed", "source_ref is not a valid path") from exc
        if not candidate.is_relative_to(root):
            raise SourceRefError("escapes-root", "source_ref escapes the import root")
        try:
            return candidate.stat().st_size
        except FileNotFoundError as exc:
            # Resolved under the root but no such file — distinct, actionable reason (F4).
            raise SourceRefError("not-found", "source_ref not found under the import root") from exc

    return resolve
