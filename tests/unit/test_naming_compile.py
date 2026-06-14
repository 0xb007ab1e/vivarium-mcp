"""Unit tests for the sandboxed naming-eval compile + differential-run runners (TB5; ADR-010/016).

Hermetic: a fake subprocess runner captures the argv (so the ADR-004 hardening is asserted with no
real engine) and simulates compiler/program outcomes. The real-engine path is exercised by the
gated naming-eval / differential e2e.
"""

from __future__ import annotations

import subprocess

from ghidra_mcp.naming.compile import ContainerCompileRunner, ContainerExecRunner
from ghidra_mcp.naming.metrics import RunResult

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


# --- ContainerExecRunner (ADR-016 differential build+run+capture; TB5 extension) -----------------


class _BytesRecorder:
    """A fake bytes runner recording (argv, stdin) and returning a canned bytes completed proc."""

    def __init__(self, *results: tuple[int, bytes]) -> None:
        # Each call pops the next canned (returncode, stdout); reuses the last if exhausted.
        self._results = list(results) or [(0, b"")]
        self.calls: list[tuple[list[str], bytes]] = []

    def __call__(self, argv: list[str], stdin: bytes) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((argv, stdin))
        rc, stdout = self._results[min(len(self.calls) - 1, len(self._results) - 1)]
        return subprocess.CompletedProcess(argv, rc, stdout, b"")


def test_exec_argv_is_hardened_like_the_compile_runner() -> None:
    rec = _BytesRecorder((0, b"hi\n"))
    ContainerExecRunner(compiler_image=_IMG, runner=rec)("int main(void){return 0;}", [b""])
    (argv, _stdin) = rec.calls[0]
    assert argv[0] == "podman" and argv[1] == "run" and "--rm" in argv
    for flag in ("--network", "none", "--read-only", "--cap-drop", "ALL", "no-new-privileges"):
        assert flag in argv, flag
    assert "65532:65532" in argv  # non-root
    assert "--interactive" in argv  # stdin for the input vector
    assert "--timeout" in argv  # hard wall-clock kill (hang/loop containment)
    assert "--memory" in argv and "--pids-limit" in argv  # DoS bounds (fork-bomb/over-alloc)
    joined = " ".join(argv)
    assert ":/work:ro,Z" in joined  # untrusted source mounted READ-ONLY
    # Two tmpfs: noexec scratch + an exec-allowed run surface for ONLY the freshly built artifact.
    assert "/tmp:rw,noexec" in joined  # noqa: S108  # asserting the noexec scratch flag, not a path
    assert "/run/x:rw,exec" in joined
    # The build+run is a CONSTANT in-container script; the source is the mounted file, never argv.
    assert argv[-3:] == ["sh", "-c", "cc -O0 -w -o /run/x/a.out /work/src.c && exec /run/x/a.out"]
    assert _IMG in argv and argv.index(_IMG) < argv.index("sh")


def test_exec_runs_once_per_input_vector_and_feeds_stdin() -> None:
    rec = _BytesRecorder((0, b"a"), (0, b"b"), (0, b"c"))
    runs = ContainerExecRunner(compiler_image=_IMG, runner=rec)(
        "int main(void){return 0;}", [b"in1", b"in2", b"in3"]
    )
    assert [r.stdout for r in runs] == [b"a", b"b", b"c"]
    assert all(r.ok and r.exit_code == 0 for r in runs)
    # Each vector was passed on stdin (not argv) to its own contained build+run.
    assert [stdin for _argv, stdin in rec.calls] == [b"in1", b"in2", b"in3"]


def test_exec_empty_inputs_yields_no_runs() -> None:
    rec = _BytesRecorder((0, b"x"))
    runs = ContainerExecRunner(compiler_image=_IMG, runner=rec)("int main(void){return 0;}", [])
    assert runs == []
    assert rec.calls == []  # no container started when there is nothing to run


def test_exec_captures_nonzero_exit_and_stdout() -> None:
    rec = _BytesRecorder((3, b"partial output"))
    (run,) = ContainerExecRunner(compiler_image=_IMG, runner=rec)(
        "int main(void){return 3;}", [b""]
    )
    # A non-zero exit (program OR build failure) is the OBSERVED outcome — recorded, not raised.
    assert run.ok is True and run.exit_code == 3 and run.stdout == b"partial output"


def test_exec_output_is_size_capped_against_flood() -> None:
    # A candidate that floods stdout is truncated to the cap (anti output-flood DoS — D3/TB5).
    rec = _BytesRecorder((0, b"A" * 10_000))
    (run,) = ContainerExecRunner(compiler_image=_IMG, runner=rec, max_stdout_bytes=128)(
        "int main(void){for(;;)putchar('A');}", [b""]
    )
    assert len(run.stdout) == 128
    assert run.stdout == b"A" * 128


def test_exec_engine_failure_fails_closed() -> None:
    def boom(_argv: list[str], _stdin: bytes) -> subprocess.CompletedProcess[bytes]:
        raise OSError("podman: not found")

    (run,) = ContainerExecRunner(compiler_image=_IMG, runner=boom)("int main(void){}", [b""])
    # No fabricated match: a spawn failure is ok=False (a non-match for every comparison).
    assert run.ok is False and run.exit_code is None and run.stdout == b""


def test_exec_default_seccomp_omitted_custom_passed() -> None:
    default = _BytesRecorder()
    ContainerExecRunner(compiler_image=_IMG, runner=default)("int main(void){}", [b""])
    assert "seccomp=" not in " ".join(default.calls[0][0])  # RuntimeDefault → flag omitted
    custom = _BytesRecorder()
    ContainerExecRunner(compiler_image=_IMG, seccomp="/etc/p.json", runner=custom)(
        "int main(void){}", [b""]
    )
    assert "seccomp=/etc/p.json" in custom.calls[0][0]


def test_exec_runtime_is_configurable() -> None:
    rec = _BytesRecorder()
    ContainerExecRunner(compiler_image=_IMG, runtime="crun", runner=rec)("int main(void){}", [b""])
    argv = rec.calls[0][0]
    assert argv[argv.index("--runtime") + 1] == "crun"


def test_exec_runner_satisfies_runresult_contract() -> None:
    # Each element is a RunResult (the pure metric's input type) — structural conformance.
    rec = _BytesRecorder((0, b"ok"))
    runs = ContainerExecRunner(compiler_image=_IMG, runner=rec)("int main(void){}", [b""])
    assert all(isinstance(r, RunResult) for r in runs)
