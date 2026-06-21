"""Real-worker NON-EMPTY FID match validation (ADR-042 Phase 1 inner loop + Phase 2 SPIKE-1).

Companion to ``test_identify_functions_fid.py`` (which proves the FID service path runs and returns
a well-formed EMPTY result on an ELF vs the MSVC-only shipped DBs). That test cannot reach the
non-empty inner match loop without a matching database — and a real MSVC PE / a shipped ELF DB is
not hermetically buildable here (no MSVC toolchain; copyleft licensing for ELF DBs). This test
closes that gap WITHOUT either: it drives the in-worker script ``fid_selfmatch_inworker.py``, which
builds a throwaway FID DB from a benign micro-binary's OWN named functions, activates it headlessly,
and confirms the program self-matches — exercising the exact getters ``_gh_identify_functions`` uses
(``FidSearchResult.function``/``.matches`` → ``FidMatch.getFunctionRecord().getName()`` /
``.getLibraryRecord().get*`` / ``.getOverallScore()``) on a NON-EMPTY result.

It also validates **Phase-2 SPIKE-1**: the headless custom-``.fidb`` create → ingest → re-attach →
activate → query chain (the technical precondition for ELF FID coverage). No copyleft/licensing
concern — the DB is derived from the test's own benign micro-binary (master §5).

Hard gate: the worker run exits 0 and prints ``SELF-MATCH PASS n=<count>`` with count > 0.

Posture mirrors ``test_analyze_profiles.py``: benign, locally-built micro-binary (no real malware),
hardened worker (no-net, non-root, read-only rootfs, caps dropped) under crun (the CI floor) / runsc
(prod). Gated by ``conftest.py`` (``integration``-marked → SKIPPED in the default hermetic run;
runs only when ``VIVARIUM_INTEGRATION`` is truthy with a real worker image + container engine + a C
compiler). Honored env matches the other integration tests.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_INWORKER_SCRIPT = Path(__file__).parent / "fid_selfmatch_inworker.py"


def _big_function_c() -> str:
    """A benign C source with one LARGE function (clears FID's minimum-hash length) + small ones.

    FID does not hash functions below a minimum code-unit length, so a trivial micro-binary yields
    no self-matches. ``big_compute`` is a long, distinct instruction sequence that comfortably
    clears that floor (observed FID score ~1200 self-matching).
    """
    lines = [
        "#include <stdlib.h>",
        "int big_compute(int *a, int n){",
        "  int s = n * 2654435761u;",
    ]
    lines += [f"  s = s * 31 + a[{i % 16}] - (s >> 3) + ({i * 7 + 13});" for i in range(80)]
    lines += [
        "  for (int i=0;i<n;i++){ s += (a[i&15]^i)*(i+3); s -= (s>>2)+a[(i+1)&15]; }",
        "  return s;",
        "}",
        "int helper(int x){return x*3+1;}",
        "int run(int n){int a[16];for(int i=0;i<16;i++)a[i]=helper(i);return big_compute(a,n);}",
        "int main(int argc,char**argv){(void)argv;return run(argc)&0xff;}",
    ]
    return "\n".join(lines) + "\n"


def _compiler() -> str | None:
    """Return a C compiler binary on ``PATH`` (``cc`` preferred, then ``gcc``), or ``None``."""
    for candidate in ("cc", "gcc"):
        if shutil.which(candidate):
            return candidate
    return None


def _engine() -> str:
    """Return the configured container engine (default ``podman``)."""
    return os.environ.get("VIVARIUM_CONTAINER_ENGINE", "podman").strip() or "podman"


def _build_micro_binary(out_dir: Path) -> Path:
    """Compile the benign big-function micro-binary into ``out_dir`` (non-PIE; fail closed)."""
    compiler = _compiler()
    assert compiler is not None, "no C compiler on PATH"
    src = out_dir / "micro.c"
    src.write_text(_big_function_c(), encoding="utf-8")
    binary = out_dir / "micro"
    proc = subprocess.run(  # noqa: S603 — argv list (no shell); compiler resolved from PATH.
        [compiler, "-O0", "-no-pie", "-fno-pie", "-o", str(binary), str(src)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"micro-binary compile failed:\n{proc.stderr[-2000:]}"
    return binary


def test_identify_functions_selfmatch_on_real_worker(tmp_path: Path) -> None:
    """A self-built FID DB makes the program self-match — non-empty FID inner loop + SPIKE-1.

    Builds a benign big-function micro-binary, then runs the in-worker self-match script in the
    hardened worker container and asserts it exits 0 with ``SELF-MATCH PASS n=<count>``, count > 0.

    Args:
        tmp_path: pytest temp dir used as the (host) build + mount root.
    """
    engine = _engine()
    if shutil.which(engine) is None:
        pytest.skip(f"container engine {engine!r} not found on PATH")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) on PATH to build the benign micro-binary")

    image = os.environ.get("VIVARIUM_WORKER_IMAGE", "").strip() or "localhost/vivarium-worker:dev"
    runtime = os.environ.get("VIVARIUM_WORKER_RUNTIME", "crun").strip() or "crun"
    uid = os.environ.get("VIVARIUM_WORKER_UID", "65532").strip() or "65532"
    gid = os.environ.get("VIVARIUM_WORKER_GID", "65532").strip() or "65532"
    timeout_s = int(os.environ.get("VIVARIUM_E2E_TIMEOUT", "600"))

    binary = _build_micro_binary(tmp_path)

    # The same hardened ADR-004 floor the server applies (no-net, non-root, ro-rootfs, caps dropped,
    # tmpfs scratch + project store); entrypoint overridden to run the in-worker validation script.
    cmd = [
        engine,
        "run",
        "--rm",
        "--runtime",
        runtime,
        "--network",
        "none",
        "--user",
        f"{uid}:{gid}",
        "--userns",
        "keep-id",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size=2g",  # noqa: S108 — in-container tmpfs
        "--tmpfs",
        "/work/project:rw,noexec,nosuid,nodev,mode=1777,size=2g",
        "--memory",
        "4g",
        "--memory-swap",
        "4g",
        "--cpus",
        "2",
        "--pids-limit",
        "512",
        "--volume",
        f"{_INWORKER_SCRIPT}:/inworker.py:ro",
        "--volume",
        f"{binary}:/work/input.bin:ro",
        "--env",
        "HOME=/tmp/ghidra",
        "--env-host=false",
        "--entrypoint",
        "python",
        image,
        "/inworker.py",
    ]
    proc = subprocess.run(  # noqa: S603 — argv list (no shell); engine resolved from PATH.
        cmd, capture_output=True, text=True, check=False, timeout=timeout_s
    )
    out = proc.stdout + proc.stderr
    print(out)
    assert proc.returncode == 0, f"in-worker self-match exited {proc.returncode}:\n{out[-3000:]}"
    assert "SELF-MATCH PASS" in out, f"no SELF-MATCH PASS in output:\n{out[-3000:]}"
    # Parse the count and assert it is genuinely non-empty (the whole point — the inner loop ran).
    match_line = next((ln for ln in out.splitlines() if ln.startswith("SELF-MATCH PASS")), "")
    count = int(match_line.split("n=", 1)[1]) if "n=" in match_line else 0
    assert count > 0, f"SELF-MATCH PASS but count == 0:\n{out[-2000:]}"
    print(f"[live-regression] identify_functions self-match matches={count}")
