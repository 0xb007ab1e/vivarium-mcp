# Runbook: Scaling / Resource Tuning

> Rules: `@rules/topic-reliability.md`, `@rules/topic-performance.md`. SCAFFOLD — finalized in WS3.

## When to use
- Backpressure (`limit-exceeded` from the session cap) under legitimate load, or tuning per-worker
  resource limits / the concurrency cap (`VIVARIUM_MAX_SESSIONS`). On the HTTP transport, a
  sustained or flapping `/readyz` `503` (the pool-full backpressure signal — see
  [`observability.md`](../observability.md)) is the readiness-level symptom of the same condition.

## Prerequisites & access
- Access to config/orchestrator + dashboards. Know the real bottleneck (CPU/mem/pids per worker,
  disk for project stores).

## Steps
1. Confirm the constraint from metrics — **scale the actual bottleneck**. Read the latest
   `metrics.snapshot` (`sessions_active` vs `max_sessions`, `limit-exceeded`/`timeout` share of
   `tool_calls`; see [`observability.md`](../observability.md)) and `/readyz`. Each session = one
   worker (ADR-002); total load ≈ `max_sessions` × per-worker CPU/mem.
2. Tune deliberately: raise `VIVARIUM_MAX_SESSIONS` only if host CPU/mem/disk headroom exists
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
- [`../observability.md`](../observability.md) (readiness + capacity signals); `on-call.md`,
  `deploy.md`; ADR-002/004; threat model TB1-D/TB3-D.

---
_Status: scaffold (pre-1.0) — deploy/promote commands pending WS3 tooling; not yet drill-validated. Owner: repo maintainer (solo — no formal on-call rotation pre-1.0)._
