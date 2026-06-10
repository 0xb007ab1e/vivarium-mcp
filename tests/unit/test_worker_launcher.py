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

from ghidra_mcp.ghidra.launcher import (
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
        worker_image="ghcr.io/o/ghidra-mcp-worker@sha256:" + "a" * 64,
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
    assert proc.container_name == "ghidra-mcp-worker-sid1"
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
    assert f"{sess_dir}:/run/ghidra-mcp:rw,Z" in argv
    assert f"{tmp_path / 'imports'}:{tmp_path / 'imports'}:ro,Z" in argv
    # Env: session identity + socket dir; no host env leakage.
    assert "GHIDRA_MCP_SESSION_ID=sid1" in argv
    assert "--env-host=false" in argv
    # The image is the final argument.
    assert argv[-1] == "ghcr.io/o/ghidra-mcp-worker@sha256:" + "a" * 64
    assert "seccomp=RuntimeDefault" in joined


def test_runtime_is_configurable(tmp_path: Path) -> None:
    """The OCI runtime flag reflects the configured runtime (gVisor by default)."""
    runner = _Recorder()
    _launcher(tmp_path, runner, runtime="runc")("s", str(tmp_path / "s" / "s.sock"))
    (argv,) = runner.calls
    i = argv.index("--runtime")
    assert argv[i + 1] == "runc"


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
