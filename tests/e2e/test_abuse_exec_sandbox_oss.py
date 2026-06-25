"""Live TB5 exec-sandbox abuse cases (G4 Tier C; threat-model §10 cases 59/60; GATED).

Unlike the other ``test_abuse_*_oss.py`` suites these do NOT drive the MCP server over stdio — they
drive the **compile+run sandbox** :class:`~vivarium.naming.compile.ContainerExecRunner` directly
(ADR-010/ADR-016/TB5): the contained path that builds and RUNS an untrusted-derived candidate
translation unit in worker-style isolation (rootless, ``--network none``, read-only rootfs, all caps
dropped, ``no-new-privileges`` + seccomp, CPU/memory/pids caps, killed on timeout, non-root user).

- **Case 59** — a candidate TU that infinite-loops / fork-bombs / over-allocates is RECLAIMED by the
  engine ``--timeout`` / ``--pids-limit`` / ``--memory`` cap: it does NOT run to a clean ``exit 0``
  and the harness returns (it is not stuck) — containment, not escape.
- **Case 60** — a candidate cannot egress (``--network none``) or write the host rootfs
  (``--read-only``): probe TUs self-report that ``connect()`` and a host-path ``fopen("w")`` are
  blocked.

The argv-hardening half (the caps/flags are PRESENT in the engine argv) is asserted hermetically in
``tests/unit/test_naming_compile.py``; these are the LIVE behavioral counterparts.

GATING: skip unless ``VIVARIUM_INTEGRATION`` is truthy, ``VIVARIUM_COMPILER_IMAGE`` is set (the
pinned-by-digest compiler image — std-supplychain), and a container engine is on PATH. No Ghidra
worker / fixtures are needed (this is the TB5 sandbox, not the worker). In CI this runs under
**crun** (stock runners have no gVisor); ``--network none`` / ``--read-only`` / ``--cap-drop ALL``
still apply under crun, so the controls hold — the gVisor-tier kernel isolation (ADR-004) is
validated separately at deploy (overlaps G12).

NO REAL MALWARE: the candidate TUs are synthetic, benign resource-exhaustion / egress PROBES
(master §5) — never a real sample; the hostile binary itself is never run (ADR-016 D1).
"""

from __future__ import annotations

import os
import shutil
import textwrap

import pytest

from vivarium.naming.compile import ContainerExecRunner

_ENV_INTEGRATION = "VIVARIUM_INTEGRATION"
_ENV_ENGINE = "VIVARIUM_CONTAINER_ENGINE"
_ENV_COMPILER_IMAGE = "VIVARIUM_COMPILER_IMAGE"


def _truthy(v: str | None) -> bool:
    """Return whether an env flag is set to a truthy token."""
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


def _skip_reason() -> str | None:
    """Return a human reason to skip, or None if the exec-sandbox prerequisites are met."""
    if not _truthy(os.environ.get(_ENV_INTEGRATION)):
        return f"{_ENV_INTEGRATION} not set (gated exec-sandbox e2e)"
    if not os.environ.get(_ENV_COMPILER_IMAGE, "").strip():
        return f"{_ENV_COMPILER_IMAGE} not set (pinned compiler image for the TB5 sandbox)"
    engine = os.environ.get(_ENV_ENGINE, "podman")
    if shutil.which(engine) is None:
        return f"container engine {engine!r} not found on PATH"
    return None


_SKIP = _skip_reason()
pytestmark = [
    pytest.mark.integration,
    pytest.mark.abuse,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]


def _runner() -> ContainerExecRunner:
    """A ``ContainerExecRunner`` wired to the gated compiler image + CI runtime.

    SMALL caps (short timeout, low pids/memory) so a bomb is reclaimed fast + deterministically.
    """
    return ContainerExecRunner(
        compiler_image=os.environ[_ENV_COMPILER_IMAGE],
        runtime=os.environ.get("VIVARIUM_WORKER_RUNTIME", "runsc"),
        engine=os.environ.get(_ENV_ENGINE, "podman"),
        timeout_s=int(os.environ.get("VIVARIUM_EXEC_ABUSE_TIMEOUT", "15")),
        mem="256m",
        pids=64,
    )


# --- Case 59 — resource-exhaustion candidates are reclaimed by the engine caps -----------------
_INFINITE_LOOP = "int main(void) { for (;;) {} return 0; }"
_FORK_BOMB = "#include <unistd.h>\nint main(void) { for (;;) { fork(); } return 0; }"
_OVER_ALLOC = (
    "#include <stdlib.h>\n#include <string.h>\n"
    "int main(void) {\n"
    "  for (;;) { void *p = malloc(64UL << 20); if (!p) return 1; memset(p, 1, 64UL << 20); }\n"
    "  return 0;\n"
    "}"
)


def test_exec_hang_forkbomb_overalloc_contained() -> None:
    """Case 59: a hang/fork-bomb/over-alloc candidate is reclaimed by the caps, not an escape."""
    runner = _runner()
    for label, src in (
        ("infinite-loop", _INFINITE_LOOP),
        ("fork-bomb", _FORK_BOMB),
        ("over-alloc", _OVER_ALLOC),
    ):
        (result,) = runner(src, [b""])  # one input vector → one RunResult
        # Reaching here at all means the runner RETURNED — the harness was not stuck (bounded by the
        # engine --timeout). Containment: the candidate did NOT run to a clean success — it was
        # reclaimed by --timeout/--pids-limit/--memory (ok=True + non-zero exit) or failed to spawn
        # (ok=False). Either way it must NOT be a clean exit-0 completion.
        assert not (result.ok and result.exit_code == 0), (
            f"{label} candidate must be reclaimed by the sandbox caps, got {result!r}"
        )


# --- Case 60 — a candidate cannot egress or write the host (isolation parity) -------------------
_EGRESS_PROBE = textwrap.dedent(
    """\
    #include <stdio.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    int main(void) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) { printf("EGRESS-BLOCKED\\n"); return 0; }
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons(80);
        inet_pton(AF_INET, "1.1.1.1", &a.sin_addr);
        if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) { printf("EGRESS-OK\\n"); return 3; }
        printf("EGRESS-BLOCKED\\n"); return 0;
    }
    """
)
_HOST_WRITE_PROBE = textwrap.dedent(
    """\
    #include <stdio.h>
    int main(void) {
        FILE *f = fopen("/etc/vivarium_escape_60", "w");
        if (f == NULL) { printf("ROOTFS-RO\\n"); return 0; }
        fputs("x", f); fclose(f); printf("ROOTFS-WRITABLE\\n"); return 4;
    }
    """
)


def test_exec_sandbox_isolation_parity() -> None:
    """Case 60: a candidate cannot egress (--network none) nor write the host rootfs."""
    runner = _runner()

    # Egress: under --network none, connect() to a public IP must fail — the candidate cannot
    # exfiltrate. The security invariant is "no successful egress"; the probe also self-reports.
    (egress,) = runner(_EGRESS_PROBE, [b""])
    assert egress.ok, f"egress probe must build + run, got {egress!r}"
    assert b"EGRESS-OK" not in egress.stdout, (
        f"candidate must NOT reach the network, got {egress!r}"
    )
    assert b"EGRESS-BLOCKED" in egress.stdout, f"egress must be blocked + reported, got {egress!r}"

    # Host write: under a read-only rootfs, opening a host path for write must fail — the candidate
    # cannot tamper with the host / escalate.
    (host_write,) = runner(_HOST_WRITE_PROBE, [b""])
    assert host_write.ok, f"host-write probe must build + run, got {host_write!r}"
    assert b"ROOTFS-WRITABLE" not in host_write.stdout, (
        f"candidate must NOT write the host rootfs, got {host_write!r}"
    )
    assert b"ROOTFS-RO" in host_write.stdout, (
        f"rootfs must be read-only + reported, got {host_write!r}"
    )
