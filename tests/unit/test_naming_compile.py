"""Unit tests for the sandboxed naming-eval compile runner (ADR-010 §Security / TB5).

Hermetic: a fake subprocess runner captures the argv (so the ADR-004 hardening is asserted with no
real engine) and simulates compiler outcomes. The real-engine path is exercised by the gated
naming-eval e2e.
"""

from __future__ import annotations

import subprocess

from ghidra_mcp.naming.compile import ContainerCompileRunner

_IMG = "ghcr.io/o/cc@sha256:" + "a" * 64


class _Recorder:
    """A fake runner recording the argv and returning a canned completed process."""

    def __init__(self, *, rc: int = 0, stdout: str = "", stderr: str = "") -> None:
        self._rc, self._stdout, self._stderr = rc, stdout, stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self._rc, self._stdout, self._stderr)


def test_argv_is_hardened_and_compiles_read_only_source() -> None:
    runner = _Recorder(rc=0)
    ContainerCompileRunner(compiler_image=_IMG, runner=runner)("int main(void){return 0;}")
    (argv,) = runner.calls
    assert argv[0] == "podman" and argv[1] == "run" and "--rm" in argv
    for flag in ("--network", "none", "--read-only", "--cap-drop", "ALL", "no-new-privileges"):
        assert flag in argv, flag
    assert "65532:65532" in argv  # non-root
    assert "--timeout" in argv  # hard wall-clock kill
    assert "--memory" in argv and "--pids-limit" in argv  # DoS bounds
    joined = " ".join(argv)
    assert ":/work:ro,Z" in joined  # untrusted source mounted READ-ONLY
    # Compile-only (no link/run); object discarded to /dev/null; image precedes the cc invocation.
    assert argv[-6:] == ["-c", "-O0", "-w", "-o", "/dev/null", "/work/src.c"]
    assert _IMG in argv and argv.index(_IMG) < argv.index("/work/src.c")


def test_zero_exit_means_compiles() -> None:
    runner = _Recorder(rc=0)
    result = ContainerCompileRunner(compiler_image=_IMG, runner=runner)("int x;")
    assert result.ok is True


def test_nonzero_exit_reports_diagnostics() -> None:
    runner = _Recorder(rc=1, stderr="src.c:1:1: error: unknown type name 'undefined4'")
    result = ContainerCompileRunner(compiler_image=_IMG, runner=runner)("undefined4 f(void){}")
    assert result.ok is False
    assert "unknown type name" in result.diagnostics


def test_default_seccomp_is_omitted_custom_is_passed() -> None:
    default = _Recorder()
    ContainerCompileRunner(compiler_image=_IMG, runner=default)("int x;")
    assert "seccomp=" not in " ".join(default.calls[0])  # RuntimeDefault → flag omitted
    custom = _Recorder()
    ContainerCompileRunner(compiler_image=_IMG, seccomp="/etc/p.json", runner=custom)("int x;")
    assert "seccomp=/etc/p.json" in custom.calls[0]


def test_runtime_is_configurable() -> None:
    runner = _Recorder()
    ContainerCompileRunner(compiler_image=_IMG, runtime="crun", runner=runner)("int x;")
    argv = runner.calls[0]
    assert argv[argv.index("--runtime") + 1] == "crun"


def test_engine_failure_fails_closed() -> None:
    def boom(_argv: list[str]) -> subprocess.CompletedProcess[str]:
        raise OSError("podman: not found")

    result = ContainerCompileRunner(compiler_image=_IMG, runner=boom)("int x;")
    assert result.ok is False  # never report a non-compiling source as compiling
    assert "unavailable" in result.diagnostics


def test_diagnostics_are_truncated() -> None:
    runner = _Recorder(rc=1, stderr="e" * 10_000)
    result = ContainerCompileRunner(compiler_image=_IMG, runner=runner)("int x;")
    assert len(result.diagnostics) == 4_000
