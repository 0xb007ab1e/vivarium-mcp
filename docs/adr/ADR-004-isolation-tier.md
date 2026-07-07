# ADR-004: Worker isolation tier — rootless OCI baseline + gVisor

> **Naming note (post-ADR-038):** environment variables in this record predate the rename to Vivarium
> and appear under their original `GHIDRA_MCP_*` names — they are now `VIVARIUM_*` (e.g.
> `GHIDRA_MCP_WORKER_RUNTIME` → `VIVARIUM_WORKER_RUNTIME`). The authoritative config reference is
> [`docs/getting-started.md`](../getting-started.md) and `src/vivarium/config.py`.

- **Status:** Accepted (locked by PLAN.md v2 / red-team F8); concrete runtime args owned by WS3
- **Date:** 2026-06-03
- **Deciders:** Human + red-team + PM; recorded by Software Architect (WS0)

## Context

The worker parses hostile binaries (trust boundary 3). Even contained out-of-process (ADR-001), a
worker compromise must not reach the host, the network, or other sessions. The strength of the
sandbox is the load-bearing control.

## Decision

The worker runs under a **defense-in-depth isolation stack**:

**Baseline (mandatory) — rootless OCI (podman/equivalent):**
- non-root user; **read-only root filesystem**; **all Linux capabilities dropped**;
- `no-new-privileges`; **seccomp `RuntimeDefault`** (verified to load, not assumed);
- **no network / no egress** (the worker never needs the network — analysis is local);
- **CPU / memory / pids limits**; **tmpfs** scratch only; minimal pinned base image (ADR-003).

**Strong tier — gVisor (`runsc`) for the worker:** strongly preferred and the default
(`GHIDRA_MCP_WORKER_RUNTIME=runsc`). gVisor's main rootless caveat (its own network stack) is
**neutralized because the worker has no network**, so we get a user-space kernel boundary around
the hostile JVM at low cost.

WS3 owns the concrete runtime flags / Containerfile / deploy manifests and **verifies** each
control actually applies at runtime (e.g. seccomp loaded, caps dropped, no network namespace
reachability) as acceptance criteria.

## Consequences

- **Positive:** a worker escape must defeat multiple independent layers; no-network removes the
  exfiltration path and de-risks gVisor; resource limits bound DoS (F7).
- **Negative:** gVisor adds syscall-emulation overhead and some Java/JVM syscalls may need tuning;
  rootless + read-only rootfs requires careful scratch/tmpfs layout.
- **Fallback:** if a specific environment cannot run gVisor, the rootless OCI baseline (above) is
  the **minimum** acceptable tier — never run the worker with fewer controls.
- **Rejected:** running the worker privileged / with host networking / writable rootfs — forbidden.
