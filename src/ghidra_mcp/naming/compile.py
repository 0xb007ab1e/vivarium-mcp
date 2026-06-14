"""Sandboxed compile (and ADR-016 differential run) runner for the naming eval (TB5).

The naming eval measures whether the renamed translation unit *compiles*. That source is
**attacker-derived** — it came, via the namer, from a hostile binary's decompilation — so compiling
it is running untrusted-influenced input through a real compiler. :class:`ContainerCompileRunner`
does it in **worker-style isolation** (ADR-004): a rootless container with ``--network none``, a
read-only rootfs, all caps dropped, ``no-new-privileges`` + seccomp, CPU/memory/pids caps, an
ephemeral tmpfs for output, killed on timeout, as a non-root user. The untrusted source is mounted
**read-only**; only the compiler's exit status + (truncated) diagnostics leave the sandbox.

It satisfies the ``CompileRunner`` port (``c_source -> CompileResult``) from
:mod:`ghidra_mcp.naming.metrics`, so the pure eval scorer stays runtime-agnostic. The subprocess
``runner`` is injected, so the argv construction + result mapping are unit-tested with no real
engine (the real-engine path is exercised only by the gated naming-eval e2e). NEVER links or RUNS
the output: it compiles (``-c``) and discards the object to ``/dev/null`` — measuring
well-formedness, not producing an executable.

:class:`ContainerExecRunner` (ADR-016 §Architecture / TB5) **extends** that boundary to
compile→run→capture: it builds a TU to an executable in the ephemeral tmpfs and runs it once per
**synthetic** input vector (author-controlled stdin bytes — NOT attacker-controlled), capturing the
bounded ``(exit_code, stdout)`` into a :class:`~ghidra_mcp.naming.metrics.RunResult`. It satisfies
the ``ExecRunner`` port and is used by the **gated** differential e2e to compute
``behavioral_equivalence`` over BOTH builds (A: trusted reference source; B: candidate recompiled
C) uniformly — the hostile binary itself is **never** executed (ADR-001 / D1). Output is
size-capped (anti output-flood DoS); the build+run is killed on timeout; the in-container
build+run is a single ``sh -c`` over a **constant** script (the untrusted source is a mounted file,
never interpolated into any command), so the host never runs a shell.
"""

from __future__ import annotations

import contextlib
import subprocess  # nosec B404 - argv lists only, never shell=True (see _default_runner)
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from ghidra_mcp.logging import get_logger
from ghidra_mcp.naming.metrics import CompileResult, RunResult

_log = get_logger(__name__)

#: Cap on captured compiler diagnostics (chars). Bounds log/return size; the text is the compiler's
#: own output (may quote the untrusted source) — truncated, and the sandbox has no secrets to leak.
_MAX_DIAGNOSTICS = 4_000

#: Default cap on captured stdout per run (bytes). Bounds the differential oracle's memory/return
#: size — a malicious candidate that floods stdout is truncated, not allowed to exhaust the host
#: (ADR-016 D3 / TB5 anti output-flood). The byte-exact compare is over the (capped) prefix.
_DEFAULT_MAX_STDOUT_BYTES = 64 * 1024

#: A subprocess runner: takes an argv list, returns the completed process (injected so tests assert
#: the exact command + simulate outcomes with no real engine).
Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

#: A subprocess runner for the exec path: takes an argv list + stdin bytes, returns the completed
#: process with BYTES streams (byte-exact stdout for the differential oracle). Injected for tests.
BytesRunner = Callable[[list[str], bytes, int], "subprocess.CompletedProcess[bytes]"]


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:  # pragma: no cover
    """Run ``argv`` capturing output, never raising on non-zero (the caller inspects rc).

    Real-subprocess default; tests inject a fake, so this thin shim is excluded from coverage
    (exercised only by the gated naming-eval e2e). ``argv`` is a fixed list — no shell.
    """
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603  # nosec B603


def _read_capped(stream: IO[bytes], limit: int) -> bytes:
    """Read at most ``limit`` bytes from ``stream`` — bounded by construction.

    Unlike ``capture_output``/``communicate`` (which buffer the WHOLE stream), a single bounded
    ``read(limit)`` means a flooding child cannot force the host to buffer more than ``limit`` bytes
    during capture (ADR-016 F1 — CWE-400). Pure over an injected stream, so it is unit-tested.
    """
    return stream.read(limit) or b""


def _default_bytes_runner(  # pragma: no cover - real subprocess; tests inject a fake
    argv: list[str], stdin: bytes, max_stdout_bytes: int
) -> subprocess.CompletedProcess[bytes]:
    """Run ``argv`` feeding ``stdin``, capturing stdout with a BOUNDED read (peak host mem <= cap).

    Streams at most ``max_stdout_bytes`` from the child's stdout via :func:`_read_capped`, then
    kills it — so a candidate that floods stdout cannot blow up host memory DURING capture (ADR-016
    F1; ``capture_output`` would buffer the whole stream first). The engine-level ``--timeout`` is
    the hard wall-clock backstop. ``argv`` is a fixed list — no host shell. stdin vectors are small
    + synthetic; written best-effort then closed (a flooding child is bounded by the timeout).
    """
    proc = subprocess.Popen(  # noqa: S603  # nosec B603
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        if proc.stdin is not None:
            with contextlib.suppress(OSError):
                proc.stdin.write(stdin)
                proc.stdin.close()
        out = _read_capped(proc.stdout, max_stdout_bytes) if proc.stdout is not None else b""
    finally:
        proc.kill()  # stop any further output (flood) / runaway; no-op if already exited
        proc.wait()  # reap — no leaked process/pipe (topic-resource-management)
    return subprocess.CompletedProcess(argv, proc.returncode, stdout=out, stderr=b"")


@dataclass(frozen=True, slots=True)
class ContainerCompileRunner:
    """A :data:`~ghidra_mcp.naming.metrics.CompileRunner` that compiles untrusted C in isolation.

    Attributes:
        compiler_image: Pinned-by-digest image carrying the C compiler (supply-chain: pin + verify
            before the gated e2e trusts it — std-supplychain).
        runtime: OCI runtime (``runsc``/gVisor in prod — ADR-004; ``crun`` where gVisor is absent).
        engine: Container CLI (``podman``).
        cc: Compiler entry point inside the image.
        mem / cpus / pids / scratch_size: Resource bounds (DoS — a compiler bomb must be contained).
        timeout_s: Hard wall-clock cap; the engine kills the container on expiry.
        seccomp: Seccomp policy — ``"RuntimeDefault"`` (engine default, applied by OMITTING it;
            passing the literal value is read as a profile path and fails) or a profile path.
        runner: Injected subprocess runner (default real ``subprocess``).
    """

    compiler_image: str
    runtime: str = "runsc"
    engine: str = "podman"
    cc: str = "cc"
    mem: str = "1g"
    cpus: str = "1"
    pids: int = 256
    scratch_size: str = "256m"
    timeout_s: int = 60
    seccomp: str = "RuntimeDefault"
    runner: Runner = field(default=_default_runner)

    def __call__(self, c_source: str) -> CompileResult:
        """Compile ``c_source`` in the sandbox and report whether it built.

        Args:
            c_source: The (untrusted) translation unit to compile.

        Returns:
            A :class:`CompileResult` — ``ok`` on a zero exit, with truncated diagnostics otherwise.
            Any sandbox/engine failure also maps to ``ok=False`` (fail closed — never report a
            non-compiling source as compiling).
        """
        with tempfile.TemporaryDirectory(prefix="gmcp-compile-") as workdir:
            # mkdtemp is 0700; the non-root container user (a rootless subuid != the host owner)
            # must traverse the dir + read the file on the ro mount. Make both world-readable —
            # the dir holds only the about-to-be-compiled untrusted source, no secrets.
            Path(workdir).chmod(0o755)
            src = Path(workdir) / "src.c"
            src.write_text(c_source)
            src.chmod(0o644)
            argv = [
                self.engine,
                "run",
                "--rm",
                # gVisor user-space kernel around the compiler on hostile input (ADR-004).
                "--runtime",
                self.runtime,
                # No network / no egress — a malicious #include or pragma cannot exfiltrate.
                "--network",
                "none",
                # Non-root; drop ALL caps; no setuid escalation.
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                # Immutable rootfs; the ONLY writable surface is an ephemeral tmpfs (the compiler's
                # own scratch — the object output itself is discarded to /dev/null below).
                "--read-only",
                "--tmpfs",
                # mode=1777 so the non-root compiler can write its intermediates under ro-rootfs.
                f"/tmp:rw,noexec,nosuid,nodev,mode=1777,size={self.scratch_size}",  # noqa: S108  # nosec B108
                # Resource bounds (F7 DoS): a compiler bomb is OOM/CPU/time-capped, not unbounded.
                "--memory",
                self.mem,
                "--memory-swap",
                self.mem,
                "--cpus",
                self.cpus,
                "--pids-limit",
                str(self.pids),
                "--oom-kill-disable=false",
                # Hard wall-clock kill (engine-enforced) — a hung/looping compile is reclaimed.
                "--timeout",
                str(self.timeout_s),
                # The untrusted source, READ-ONLY.
                "--volume",
                f"{workdir}:/work:ro,Z",
                "--env-host=false",
            ]
            if self.seccomp != "RuntimeDefault":
                argv += ["--security-opt", f"seccomp={self.seccomp}"]
            argv += [
                self.compiler_image,
                # Compile-only (no link, no run); discard the object to /dev/null — we measure
                # well-formedness, not artifacts (and avoid writing any output path).
                self.cc,
                "-c",
                "-O0",
                "-w",
                "-o",
                "/dev/null",
                "/work/src.c",
            ]
            try:
                result = self.runner(argv)
            except OSError as exc:
                # Engine/spawn failure → fail closed (cannot claim it compiled). Detail server-side.
                _log.warning(
                    "naming.compile_runner_failed",
                    extra={"exc": type(exc).__name__, "detail": str(exc)[:300]},
                )
                return CompileResult(ok=False, diagnostics="compile sandbox unavailable")

        diagnostics = (result.stderr or result.stdout or "")[:_MAX_DIAGNOSTICS]
        return CompileResult(ok=result.returncode == 0, diagnostics=diagnostics)


#: In-container build+run script (ADR-016). A CONSTANT — the untrusted source is the mounted file
#: ``/work/src.c`` (never interpolated), the input vector arrives on stdin. Build to the tmpfs, then
#: exec the artifact passing our stdin through. A build failure exits non-zero BEFORE any run, which
#: the host maps to ``RunResult(ok=False)`` (a stub/non-recompiling TU scores as a non-match — D2).
#: ``noexec`` would block running the built binary, so the run uses a dedicated ``exec``-allowed
#: tmpfs (``/run/x``) distinct from the ``noexec`` scratch ``/tmp``; the rootfs stays read-only.
#: INVARIANT: ``cc``/``engine``/``runtime``/``compiler_image`` are TRUSTED operator config — NEVER
#: bind them to request/binary-derived values (the only substitution below is the trusted ``cc``).
_BUILD_RUN_SCRIPT = "{cc} -O0 -w -o /run/x/a.out /work/src.c && exec /run/x/a.out"


@dataclass(frozen=True, slots=True)
class ContainerExecRunner:
    """An :data:`~ghidra_mcp.naming.metrics.ExecRunner`: build + run untrusted C in isolation.

    The ADR-016 differential-run adapter (TB5 extension). For each synthetic input vector it builds
    the (untrusted-derived) translation unit to an executable in an ephemeral, ``exec``-allowed
    tmpfs and runs it with the vector on **stdin**, capturing the bounded ``(exit_code, stdout)``.
    The same isolation as :class:`ContainerCompileRunner` (rootless, ``--network none``, read-only
    rootfs, all caps dropped, ``no-new-privileges`` + seccomp, CPU/memory/pids caps, killed on
    timeout, non-root) — plus an output-size cap (anti output-flood DoS). The hostile binary is
    never run (D1); BOTH builds (trusted reference A and candidate B) go through this one contained
    path uniformly. The injected ``runner`` lets the argv + stdin + result mapping be unit-tested
    with no real engine (the real-engine path runs only in the gated differential e2e).

    Attributes:
        compiler_image: Pinned-by-digest image carrying the C compiler + a libc to run against
            (supply-chain: pin + verify — std-supplychain).
        runtime: OCI runtime (``runsc``/gVisor in prod — ADR-004; ``crun`` where gVisor is absent).
        engine: Container CLI (``podman``).
        cc: Compiler entry point inside the image.
        mem / cpus / pids / scratch_size: Resource bounds (DoS — a hang/fork-bomb/over-alloc must be
            contained).
        run_size: Size of the ``exec``-allowed run tmpfs holding the built artifact.
        timeout_s: Hard wall-clock cap; the engine kills the container on expiry (a hung/looping
            build OR run is reclaimed).
        max_stdout_bytes: Cap on captured stdout per run (anti output-flood — D3).
        seccomp: Seccomp policy — ``"RuntimeDefault"`` (engine default, applied by OMITTING it) or a
            profile path.
        runner: Injected bytes subprocess runner (default real ``subprocess``).
    """

    compiler_image: str
    runtime: str = "runsc"
    engine: str = "podman"
    cc: str = "cc"
    mem: str = "1g"
    cpus: str = "1"
    pids: int = 256
    scratch_size: str = "256m"
    run_size: str = "64m"
    timeout_s: int = 60
    max_stdout_bytes: int = _DEFAULT_MAX_STDOUT_BYTES
    seccomp: str = "RuntimeDefault"
    runner: BytesRunner = field(default=_default_bytes_runner)

    def __call__(self, c_source: str, inputs: list[bytes]) -> list[RunResult]:
        """Build ``c_source`` once per input vector and capture each run's bounded outcome.

        Args:
            c_source: The (untrusted-derived) translation unit to build + run.
            inputs: The synthetic input vectors (author-controlled stdin bytes), one per run. An
                empty list yields an empty result (no vectors → nothing to compare; the pure metric
                then reports ``None``).

        Returns:
            One :class:`RunResult` per input vector, in order. Each carries ``ok`` (the TU built and
            ran), the ``exit_code``, and the size-capped ``stdout``. A build/spawn failure or
            timeout maps to ``RunResult(ok=False)`` (fail closed — never fabricate a match).
        """
        return [self._run_one(c_source, vector) for vector in inputs]

    def _run_one(self, c_source: str, stdin: bytes) -> RunResult:
        """Build + run ``c_source`` once on a single stdin vector inside the sandbox."""
        with tempfile.TemporaryDirectory(prefix="gmcp-exec-") as workdir:
            # 0755 dir + 0644 file so the rootless non-root container user can read the ro mount
            # (same rationale as ContainerCompileRunner); holds only the untrusted source.
            Path(workdir).chmod(0o755)
            src = Path(workdir) / "src.c"
            src.write_text(c_source)
            src.chmod(0o644)
            argv = self._build_argv(workdir)
            try:
                result = self.runner(argv, stdin, self.max_stdout_bytes)
            except OSError as exc:
                # Engine/spawn failure → fail closed (no run, no fabricated match). Detail
                # server-side only (no untrusted content in the log — topic-logging-observability).
                _log.warning(
                    "naming.exec_runner_failed",
                    extra={"exc": type(exc).__name__, "detail": str(exc)[:300]},
                )
                return RunResult(ok=False)

        # A non-zero exit can mean either a build failure (before any run) or the program's own
        # non-zero exit. Either way it is the OBSERVED outcome for this vector — recorded, then
        # compared byte-exactly against the other build (a build failure on one side is simply a
        # non-match). stdout is capped + carried as inert data (compared, never executed — D2/D3).
        stdout = (result.stdout or b"")[: self.max_stdout_bytes]
        return RunResult(ok=True, exit_code=result.returncode, stdout=stdout)

    def _build_argv(self, workdir: str) -> list[str]:
        """Construct the hardened ``engine run`` argv for one build+run (TB5 isolation, ADR-016).

        Mirrors :class:`ContainerCompileRunner`'s isolation flags exactly, plus ``--interactive``
        (stdin), an ``exec``-allowed run tmpfs for the built artifact, and the constant in-container
        build+run command. ``workdir`` (the per-call host temp dir holding the untrusted source) is
        mounted READ-ONLY at ``/work``.
        """
        argv = [
            self.engine,
            "run",
            "--rm",
            # Read the input vector from our stdin into the contained program.
            "--interactive",
            # gVisor user-space kernel around the build+run on untrusted-derived input (ADR-004).
            "--runtime",
            self.runtime,
            # No network / no egress — a malicious program/#include cannot exfiltrate or phone home.
            "--network",
            "none",
            # Non-root; drop ALL caps; no setuid escalation.
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            # Immutable rootfs. Two writable tmpfs surfaces: a NOEXEC scratch for compiler
            # intermediates, and a small EXEC-allowed tmpfs holding ONLY the freshly built artifact.
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,mode=1777,size={self.scratch_size}",  # noqa: S108  # nosec B108
            "--tmpfs",
            f"/run/x:rw,exec,nosuid,nodev,mode=1777,size={self.run_size}",  # nosec B108
            # Resource bounds (F7 DoS): a hang/fork-bomb/over-alloc is OOM/CPU/pids/time-capped.
            "--memory",
            self.mem,
            "--memory-swap",
            self.mem,
            "--cpus",
            self.cpus,
            "--pids-limit",
            str(self.pids),
            "--oom-kill-disable=false",
            # Hard wall-clock kill (engine-enforced) — a hung/looping build OR run is reclaimed.
            "--timeout",
            str(self.timeout_s),
            # The untrusted source, READ-ONLY.
            "--volume",
            f"{workdir}:/work:ro,Z",
            "--env-host=false",
        ]
        if self.seccomp != "RuntimeDefault":
            argv += ["--security-opt", f"seccomp={self.seccomp}"]
        # Build+run via a CONSTANT in-container script: the untrusted source is the mounted file
        # (never interpolated into the command), the vector arrives on stdin. The host never runs a
        # shell (this `sh -c` executes INSIDE the contained, network-less, non-root sandbox).
        argv += [
            self.compiler_image,
            "sh",
            "-c",
            _BUILD_RUN_SCRIPT.format(cc=self.cc),
        ]
        return argv
