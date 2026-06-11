"""Sandboxed compile runner for the naming eval (ADR-010 §Security — trust boundary TB5).

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
engine (the real-engine path is exercised
only by the gated naming-eval e2e). NEVER links or RUNS the output: it compiles (``-c``) and
discards the object to ``/dev/null`` — measuring well-formedness, not producing an executable.
"""

from __future__ import annotations

import subprocess  # nosec B404 - argv lists only, never shell=True (see _default_runner)
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ghidra_mcp.logging import get_logger
from ghidra_mcp.naming.metrics import CompileResult

_log = get_logger(__name__)

#: Cap on captured compiler diagnostics (chars). Bounds log/return size; the text is the compiler's
#: own output (may quote the untrusted source) — truncated, and the sandbox has no secrets to leak.
_MAX_DIAGNOSTICS = 4_000

#: A subprocess runner: takes an argv list, returns the completed process (injected so tests assert
#: the exact command + simulate outcomes with no real engine).
Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:  # pragma: no cover
    """Run ``argv`` capturing output, never raising on non-zero (the caller inspects rc).

    Real-subprocess default; tests inject a fake, so this thin shim is excluded from coverage
    (exercised only by the gated naming-eval e2e). ``argv`` is a fixed list — no shell.
    """
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603  # nosec B603


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
