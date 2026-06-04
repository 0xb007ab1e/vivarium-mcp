# Runbook: Scaling / Resource Tuning

> Rules: `@rules/topic-reliability.md`, `@rules/topic-performance.md`. SCAFFOLD — finalized in WS3.

## When to use
- Backpressure (`limit-exceeded` from the session cap) under legitimate load, or tuning per-worker
  resource limits / the concurrency cap (`GHIDRA_MCP_MAX_SESSIONS`).

## Prerequisites & access
- Access to config/orchestrator + dashboards. Know the real bottleneck (CPU/mem/pids per worker,
  disk for project stores).

## Steps
1. Confirm the constraint from metrics — **scale the actual bottleneck**. Each session = one worker
   (ADR-002); total load ≈ `max_sessions` × per-worker CPU/mem.
2. Tune deliberately: raise `GHIDRA_MCP_MAX_SESSIONS` only if host CPU/mem/disk headroom exists
   (clamped to `HARD_MAX_SESSIONS`); adjust per-worker CPU/mem/pids limits in `deploy/`.
3. If the host is saturated, **shed load** via backpressure (the cap returning `limit-exceeded`) and
   add hosts horizontally rather than oversubscribing one host (oversubscription weakens DoS
   bounds).
4. Re-verify isolation still applies after any runtime/limit change (ADR-004 acceptance checks):
   non-root, ro-rootfs, caps dropped, seccomp loaded, **no network**, gVisor active.

## Verification
- Backpressure relieved; no worker OOM/timeout regressions; isolation checks still pass.

## Scaling down
- Lower `max_sessions` gradually; live sessions finish/evict normally (TTL/idle). Don't drop below
  the level that keeps p95 healthy.

## Escalation
- If tuning can't relieve it (hard host limit) → `on-call.md` / open an incident.

## Related
- `on-call.md`, `deploy.md`; ADR-002/004; threat model TB1-D/TB3-D.

---
_Last validated: <date>. Owner: <team>._
