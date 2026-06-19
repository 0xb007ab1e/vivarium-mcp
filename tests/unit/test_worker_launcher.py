"""Unit tests for the concrete container worker launcher (ADR-009; hermetic, no real engine).

Asserts the spawned ``podman run`` argv carries the ADR-004 hardening (no network, read-only
rootfs, all caps dropped, no-new-privileges, non-root, tmpfs scratch, resource bounds, the
per-session socket mount + the read-only import-root mount), that the lifecycle handle kills /
inspects correctly, that a launch failure fails closed, and that the confined source resolver
enforces CWE-22 path confinement. The subprocess runner is injected, so no container engine runs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vivarium.ghidra.launcher import (
    ContainerWorkerLauncher,
    ContainerWorkerProcess,
    WorkerLaunchError,
    make_confined_resolver,
)


class _Recorder:
    """A fake subprocess runner that records argv and returns a canned result."""

    def __init__(self, returncode: int = 0, stdout: str = "") -> None:
        self.calls: list[list[str]] = []
        self._rc = returncode
        self._stdout = stdout

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self._rc, self._stdout, "")


def _launcher(tmp_path: Path, runner: _Recorder, **kw: object) -> ContainerWorkerLauncher:
    return ContainerWorkerLauncher(
        worker_image="ghcr.io/o/vivarium-worker@sha256:" + "a" * 64,
        import_root=str(tmp_path / "imports"),
        runner=runner,
        **kw,  # type: ignore[arg-type]
    )


def test_launch_builds_hardened_podman_argv(tmp_path: Path) -> None:
    """The launch argv carries every ADR-004 control + the two expected mounts + the env."""
    runner = _Recorder()
    launcher = _launcher(tmp_path, runner)
    sock = tmp_path / "sockets" / "sid1" / "sid1.sock"

    proc = launcher("sid1", str(sock))

    assert isinstance(proc, ContainerWorkerProcess)
    assert proc.container_name == "vivarium-worker-sid1"
    # The per-session socket dir was created, private (0700).
    sess_dir = sock.parent
    assert sess_dir.is_dir()
    assert (sess_dir.stat().st_mode & 0o777) == 0o700

    (argv,) = runner.calls
    joined = " ".join(argv)
    assert argv[0] == "podman"
    assert argv[1] == "run"
    # Critical isolation flags (ADR-004).
    for flag in ("--network", "none", "--read-only", "--cap-drop", "ALL", "--detach"):
        assert flag in argv, flag
    assert "--security-opt" in argv and "no-new-privileges" in argv
    assert "65532:65532" in argv  # non-root
    assert "--pids-limit" in argv and "--memory" in argv  # DoS bounds
    # Mounts: per-session socket dir read-write; import root read-only at the same path.
    assert f"{sess_dir}:/run/vivarium:rw,Z" in argv
    assert f"{tmp_path / 'imports'}:{tmp_path / 'imports'}:ro,Z" in argv
    # Env: session identity + socket dir; no host env leakage.
    assert "VIVARIUM_SESSION_ID=sid1" in argv
    assert "--env-host=false" in argv
    # The image is the final argument.
    assert argv[-1] == "ghcr.io/o/vivarium-worker@sha256:" + "a" * 64
    # Default seccomp ("RuntimeDefault") = the engine's built-in profile, applied by OMITTING the
    # flag (passing the literal value would be read as a profile path and fail to launch). So no
    # explicit seccomp option is present for the default; only no-new-privileges.
    assert "seccomp=RuntimeDefault" not in joined
    assert "seccomp=" not in joined


def test_runtime_is_configurable(tmp_path: Path) -> None:
    """The OCI runtime flag reflects the configured runtime (gVisor by default)."""
    runner = _Recorder()
    _launcher(tmp_path, runner, runtime="runc")("s", str(tmp_path / "s" / "s.sock"))
    (argv,) = runner.calls
    i = argv.index("--runtime")
    assert argv[i + 1] == "runc"


def test_default_runs_as_hardened_uid(tmp_path: Path) -> None:
    """The default worker uid/gid is the hardened non-root 65532:65532 (ADR-004)."""
    runner = _Recorder()
    _launcher(tmp_path, runner)("s", str(tmp_path / "s" / "s.sock"))
    (argv,) = runner.calls
    i = argv.index("--user")
    assert argv[i + 1] == "65532:65532"


def test_run_as_uid_gid_is_configurable(tmp_path: Path) -> None:
    """A host-run server can align the worker uid/gid to its own (socket-dir mapping — ADR-009)."""
    runner = _Recorder()
    _launcher(tmp_path, runner, run_as_uid=1000, run_as_gid=1000)(
        "s", str(tmp_path / "s" / "s.sock")
    )
    (argv,) = runner.calls
    i = argv.index("--user")
    assert argv[i + 1] == "1000:1000"


def test_custom_seccomp_profile_is_passed(tmp_path: Path) -> None:
    """A non-default seccomp value is passed as an explicit ``seccomp=<profile>`` option."""
    runner = _Recorder()
    _launcher(tmp_path, runner, seccomp="/etc/ghidra-seccomp.json")(
        "s", str(tmp_path / "s" / "s.sock")
    )
    (argv,) = runner.calls
    assert "--security-opt" in argv
    assert "seccomp=/etc/ghidra-seccomp.json" in argv


def test_launch_failure_fails_closed(tmp_path: Path) -> None:
    """A non-zero engine exit raises ``WorkerLaunchError`` (server then evicts — fail closed)."""
    runner = _Recorder(returncode=125, stdout="")
    launcher = _launcher(tmp_path, runner)
    with pytest.raises(WorkerLaunchError):
        launcher("s", str(tmp_path / "s" / "s.sock"))


def test_worker_process_kill_is_idempotent_rm(tmp_path: Path) -> None:
    """``kill`` issues ``rm -f`` against the container name (idempotent)."""
    runner = _Recorder()
    proc = ContainerWorkerProcess(container_name="w", engine="podman", runner=runner)
    proc.kill()
    assert runner.calls[-1] == ["podman", "rm", "-f", "w"]


@pytest.mark.parametrize(
    ("rc", "stdout", "expected"),
    [(0, "true", True), (0, "false", False), (1, "true", False), (0, "", False)],
)
def test_worker_process_is_alive(rc: int, stdout: str, expected: bool) -> None:
    """``is_alive`` is True only when inspect succeeds AND reports Running=true."""
    proc = ContainerWorkerProcess(
        container_name="w", engine="podman", runner=_Recorder(returncode=rc, stdout=stdout)
    )
    assert proc.is_alive() is expected


# ----------------------------------------------------------------------------------------------
# Resource-bound rendering (ADR-023 / F1): resolved ints → engine spelling at argv build.
# ----------------------------------------------------------------------------------------------
def test_default_resource_bounds_render_to_historical_values(tmp_path: Path) -> None:
    """Default resolved ints render to the historical engine spelling (4096m mem, 2 cpus, ...)."""
    runner = _Recorder()
    _launcher(tmp_path, runner)("s", str(tmp_path / "s" / "s.sock"))
    (argv,) = runner.calls
    assert argv[argv.index("--memory") + 1] == "4096m"
    assert argv[argv.index("--cpus") + 1] == "2"
    assert argv[argv.index("--pids-limit") + 1] == "512"
    joined = " ".join(argv)
    assert "/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size=2048m" in joined  # noqa: S108
    assert "/work/project:rw,noexec,nosuid,nodev,mode=1777,size=4096m" in joined


def test_configured_resource_bounds_render_correctly(tmp_path: Path) -> None:
    """Tuned resolved ints render to the corresponding engine spelling."""
    runner = _Recorder()
    _launcher(
        tmp_path,
        runner,
        mem_mib=8192,
        cpus=4,
        pids=1024,
        tmpfs_scratch_mib=512,
        tmpfs_project_mib=1024,
    )("s", str(tmp_path / "s" / "s.sock"))
    (argv,) = runner.calls
    assert argv[argv.index("--memory") + 1] == "8192m"
    assert argv[argv.index("--cpus") + 1] == "4"
    assert argv[argv.index("--pids-limit") + 1] == "1024"
    joined = " ".join(argv)
    assert "size=512m" in joined and "size=1024m" in joined


def test_memory_swap_pinned_equal_to_memory(tmp_path: Path) -> None:
    """``--memory-swap`` is pinned EQUAL to ``--memory`` (no swap — ADR-004 invariant)."""
    runner = _Recorder()
    _launcher(tmp_path, runner, mem_mib=8192)("s", str(tmp_path / "s" / "s.sock"))
    (argv,) = runner.calls
    mem = argv[argv.index("--memory") + 1]
    swap = argv[argv.index("--memory-swap") + 1]
    assert mem == swap == "8192m"


def test_adr004_hardening_flags_unchanged_with_tuned_resources(tmp_path: Path) -> None:
    """Tuning resource bounds leaves every other ADR-004 hardening flag intact (byte-for-byte)."""
    runner = _Recorder()
    _launcher(tmp_path, runner, mem_mib=1024, cpus=1)("s", str(tmp_path / "s" / "s.sock"))
    (argv,) = runner.calls
    for flag in ("--network", "none", "--read-only", "--cap-drop", "ALL", "--detach"):
        assert flag in argv, flag
    assert "--security-opt" in argv and "no-new-privileges" in argv
    assert "65532:65532" in argv
    assert "--oom-kill-disable=false" in argv
    assert "--env-host=false" in argv


# ----------------------------------------------------------------------------------------------
# exit_diagnosis (ADR-023 / F1 + ADR-037): OOM vs other vs unknown via fake engine runner.
# ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("rc", "stdout", "expected"),
    [
        (0, "true 137", "oom"),  # engine reports OOMKilled
        (0, "false 137", "oom"),  # cgroup SIGKILL exit signature (128+9) even without the flag
        (0, "false 3", "oom"),  # JVM ExitOnOutOfMemoryError heap-OOM self-exit (ADR-037 §D1)
        (0, "true 3", "oom"),  # OOMKilled flag still wins regardless of exit code
        (0, "false 2", "other"),  # worker missing-session-id exit — NOT an OOM (collision guard)
        (0, "false 1", "other"),  # uncaught Python error — confirmed non-OOM exit
        (0, "false 0", "other"),  # clean exit
        (1, "true 137", "unknown"),  # engine query failed → fail closed (never spurious oom)
        (0, "true", "unknown"),  # unparseable output (one field) → unknown
        (0, "", "unknown"),  # empty output → unknown
        (0, "a b c", "unknown"),  # too many fields → unknown
    ],
)
def test_exit_diagnosis_classification(rc: int, stdout: str, expected: str) -> None:
    """``exit_diagnosis`` classifies via OOMKilled flag / exit 137 / JVM exit 3 (ADR-037),
    failing closed to unknown; worker's own codes {0,2} stay ``other``."""
    proc = ContainerWorkerProcess(
        container_name="w", engine="podman", runner=_Recorder(returncode=rc, stdout=stdout)
    )
    assert proc.exit_diagnosis() == expected


def test_exit_diagnosis_queries_engine_metadata_only(tmp_path: Path) -> None:
    """``exit_diagnosis`` issues an inspect of OOMKilled+ExitCode (engine metadata; no binary)."""
    runner = _Recorder(returncode=0, stdout="false 1")
    proc = ContainerWorkerProcess(container_name="w", engine="podman", runner=runner)
    proc.exit_diagnosis()
    argv = runner.calls[-1]
    assert argv[0:3] == ["podman", "inspect", "-f"]
    assert argv[3] == "{{.State.OOMKilled}} {{.State.ExitCode}}"
    assert argv[4] == "w"


def test_confined_resolver_accepts_in_root_and_returns_size(tmp_path: Path) -> None:
    """A real file under the import root resolves to its byte size."""
    root = tmp_path / "imports"
    root.mkdir()
    f = root / "a.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)
    resolve = make_confined_resolver(str(root))
    assert resolve(str(f)) == 64


def test_confined_resolver_rejects_outside_root(tmp_path: Path) -> None:
    """A ref outside the import root (incl. traversal) raises ``OSError`` → VALIDATION."""
    root = tmp_path / "imports"
    root.mkdir()
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"x")
    resolve = make_confined_resolver(str(root))
    with pytest.raises(OSError, match="import root"):
        resolve(str(outside))
    with pytest.raises(OSError, match="import root"):
        resolve(str(root / ".." / "secret.bin"))
