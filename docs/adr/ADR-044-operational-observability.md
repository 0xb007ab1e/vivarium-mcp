# ADR-044: Operational observability — in-process metrics SLIs + unauthenticated health probes

- **Status:** **Accepted** (ratified 2026-06-30; v1.x). Implemented by gap-remediation **N3** (#208)
  and **N5** (#197); recorded retroactively to capture the decisions that shipped in code.
- **Date:** 2026-06-30
- **Deciders:** Human operator (decided the two open design points below via direct Q&A on
  2026-06-29/30); recorded by the assistant during round-3 gap remediation.
- **Context source:** Round-2/round-3 gap analysis found the server had structured logs but **no
  aggregated SLIs and no liveness/readiness** (`topic-logging-observability` / `topic-reliability`),
  and the abandoned-session worker/store was reclaimed only lazily (no scheduled reaper). The
  observability surface shipped before this ADR; this record closes the `topic-documentation`
  (ADR-for-significant-decisions) + `workflow-threat-model` (new boundary) gap.

## Context

Two operational gaps, both with a genuine design choice:

1. **Metrics / SLIs.** The server emits redacting structured logs but no Rate/Errors/Duration (RED)
   or lifecycle/auth aggregates — an operator had no rate/error/latency trend, occupancy, or
   auth-decision visibility. The choice: *how* to expose metrics on a single-process, security-
   focused server that already treats all binary-derived data as hostile (master §5).
2. **Liveness/readiness.** No `/healthz`·`/readyz` for orchestrators/the tailnet to probe. The
   choice: *whether the probes are authenticated*, on a server whose HTTP surface (TB6) is otherwise
   default-deny.
3. **(Related) Abandoned-session reclamation.** `SessionManager.reap_expired()` existed (ADR-025)
   but nothing called it on a schedule, so an abandoned session's hardened worker + per-session store
   lingered until process shutdown — a resource-leak + confidentiality window.

## Decision

- **D1 — Metrics are in-house counters emitted as a periodic structured-log snapshot. No new
  dependency, no `/metrics` scrape endpoint.** A tiny thread-safe in-process `Metrics` registry
  (`vivarium/metrics.py`) accumulates RED (per-tool count by `(tool, outcome)` + duration sum/count),
  lifecycle (sessions created/evicted-by-reason + an `active_count` gauge), and auth-decision
  (allow/deny by mode) counters. A `PeriodicMetricsLogger` daemon emits one `metrics.snapshot`
  structured-log line every `VIVARIUM_METRICS_SNAPSHOT_INTERVAL_SECONDS` (default 60s) and one final
  snapshot on shutdown. **Operator decision (2026-06-29):** in-house-counters-via-logs over
  prometheus-client or OpenTelemetry — minimizes dependency/attack-surface for a pre-1.0
  single-principal server; the existing redacting logger is the transport.
  - **Redaction invariant:** every label is **closed-vocabulary** (allow-listed Tier-1 tool name,
    `OUTCOME_OK`/`ErrorType` slug, eviction reason, auth mode/decision). No binary-derived content,
    session id, principal id, or token is ever recorded → bounded cardinality + safe to log
    (master §5). Distinct from `vivarium.core.metrics` (the code-analysis metric cores, ADR-008).
  - Instrumented at single chokepoints so both transports are covered: RED at the tool
    error-boundary, lifecycle at the session manager, auth at the HTTP authentication middleware.

- **D2 — `/healthz` + `/readyz` are UNAUTHENTICATED and DETAIL-FREE.** `HealthMiddleware` is the
  **outermost** ASGI layer (probes answered before auth + rate-limit, so orchestrators/the tailnet
  can reach them without credentials). `/healthz` = liveness (bare `200` while the process is up);
  `/readyz` = readiness (bare `200`/`503` from `SessionManager.has_capacity()` — pool-capacity
  backpressure). **Both responses are status-only (empty body)** — no JSON, no internal/worker
  state. Only `GET`/`HEAD` on exactly those two paths short-circuit; everything else passes through.
  **Operator decision (2026-06-30):** unauthenticated **but** detail-free, over authenticated probes
  — orchestrator/LB probing without credentials is the common need, and the detail-free bodies bound
  the residual disclosure to a coarse liveness/occupancy signal (see the residual risk in the
  threat-model TB6 delta).

- **D3 — A periodic session reaper closes the abandoned-session window.** A `PeriodicReaper` daemon
  calls `reap_expired()` every `VIVARIUM_SESSION_REAP_INTERVAL_SECONDS` (default 60s), so an expired
  session's worker is killed + its store verified-wiped (ADR-002/ADR-025) on a schedule, not only on
  a client's next call. The reaper owns no new policy — it just invokes the existing lock-safe,
  in-flight-exempt eviction.

## Consequences

- **Positive:** RED/lifecycle/auth SLIs + liveness/readiness with zero new dependency and no new
  authenticated surface to secure; the reaper bounds the abandoned-session leak/confidentiality
  window to `idle/ttl + interval`. Both daemons mirror one proven pattern (`daemon=True` +
  interruptible `Event` stop + bounded join + swallow-and-log).
- **Negative / residual risk:** `/readyz` is a coarse, unauthenticated **capacity oracle** and is
  **not rate-limited** (it sits outside the limiter) — a documented residual risk (threat-model TB6
  delta); the `/readyz` answer is now cached (gap P3) so it is at most `VIVARIUM_READINESS_CACHE_TTL_SECONDS`
  stale and cannot drive session-lock contention; deployment expectation is that probes are reachable
  from the orchestrator/tailnet, not the open internet. The metrics are **log-only** — there is no
  scrape endpoint and **no external alerting engine is bundled** (a deliberate pre-1.0 decision).
  Consuming the SLIs is an operator responsibility: the snapshot schema, the SLIs/SLOs, and the exact
  log-based alert queries are now specified in [`docs/observability.md`](../observability.md) (gap
  round-3 P4 — the previously-deferred item is now a documented decision, not a gap). The reaper
  detaches an expired session in-memory under the session lock, then performs the worker-kill +
  store-wipe **outside** the lock (`_run_eviction_io`, #217/round-3 P10) — so a slow kill/wipe on the
  timer cannot stall request threads waiting on the lock — noted in the reliability/threat-model notes.

## Related

- [`docs/observability.md`](../observability.md) — the operator-facing signal reference (schema, SLOs, alerts).
- ADR-002 (verified store wipe), ADR-025 (session lifecycle / `reap_expired`), ADR-011/ADR-017 (TB6
  HTTP transport + multi-principal authZ), master §5 (redaction), `topic-logging-observability`,
  `topic-reliability`. Threat-model: the **TB6 delta — v1.x operational observability** note.
