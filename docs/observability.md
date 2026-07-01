# Observability — metrics, SLOs, and alerts

> How to read Vivarium's operational signals and what to alert on. Companion to
> [ADR-044](adr/ADR-044-operational-observability.md) (the design decision), the
> [on-call runbook](runbooks/on-call.md), and [`topic-logging-observability`]. Closes round-3 gap
> **P4** (the RED counters existed but had no documented schema / SLO / alert guidance).

Vivarium emits **structured logs only** — there is no `/metrics` scrape endpoint and no metrics
dependency (ADR-044 D1). Aggregated SLIs are published as a single periodic `metrics.snapshot` log
line; readiness/liveness are exposed as unauthenticated HTTP probes. Everything below is consumed
by pointing your existing log pipeline (the platform ships stdout/stderr — 12-Factor) at these
lines; alerting is expressed as log queries, not PromQL.

## The `metrics.snapshot` line

A `PeriodicMetricsLogger` daemon emits one `metrics.snapshot` record every
`VIVARIUM_METRICS_SNAPSHOT_INTERVAL_SECONDS` (default 60s) **and one final snapshot on shutdown**.
The counters are cumulative since process start (RED — Rate, Errors, Duration). Every label is
**closed-vocabulary** — a Tier-1 tool name, an outcome slug, a session-evict reason, or an auth
mode/decision — so the line is redaction-safe: no binary-derived content, session id, or principal
id ever appears (master §5).

The record carries a `metrics` field with this shape:

```json
{
  "tool_calls":            { "<tool>/<outcome>": <count> },
  "tool_duration_seconds": { "<tool>": { "sum": <float>, "count": <int> } },
  "sessions_created":      <int>,
  "sessions_evicted":      { "<reason>": <count> },
  "auth_decisions":        { "<mode>/<decision>": <count> },
  "sessions_active":       <int>
}
```

| Field | Meaning | Vocabulary |
|---|---|---|
| `tool_calls` | Per-tool call count keyed by outcome | `<tool>` = a Tier-1 tool name; `<outcome>` = `ok` or an `ErrorType` slug (`validation-error`, `session-invalid`, `timeout`, `worker-unavailable`, `limit-exceeded`, `internal-error`, …) |
| `tool_duration_seconds` | Per-tool wall-clock `sum` + `count` (derive mean = `sum/count`) | `<tool>` |
| `sessions_created` | Sessions created since start | — |
| `sessions_evicted` | Evictions by reason | `<reason>` = `ttl`, `idle`, `close`, `capacity`, `poisoned`, … |
| `auth_decisions` | Auth allow/deny by mode (HTTP chokepoint) | `<mode>` = `none`/`bearer`/`mtls`/`oauth`/`mtls-proxy`; `<decision>` = `allow`/`deny` |
| `sessions_active` | Live-session gauge at emit time | — |

Counters are **cumulative**; compute a rate by differencing two consecutive snapshots (or let your
log backend do it). The snapshot is emitted even when idle (all-zero), so its **absence** is itself
a signal (see "process liveness" below).

## Env knobs

| Variable | What it does | Default |
|---|---|---|
| `VIVARIUM_METRICS_SNAPSHOT_INTERVAL_SECONDS` | Interval between `metrics.snapshot` lines (and the cadence you can diff for rates) | `60` |
| `VIVARIUM_SESSION_REAP_INTERVAL_SECONDS` | Background reaper sweep interval for expired sessions | `60` |
| `VIVARIUM_READINESS_CACHE_TTL_SECONDS` | TTL for the cached `/readyz` capacity answer (gap P3) — the max staleness of a readiness result | `1` |

All are positive integers; an invalid value fails the server closed at startup.

## Health probes (HTTP transport)

Both are answered at the outermost middleware layer — **unauthenticated and not rate-limited** (N3b,
ADR-044 D2) — and return a bare status with no body (no internals leak):

- **`GET /healthz` — liveness.** Always `200` while the process is up. Wire it to the
  orchestrator's liveness probe; a non-`200`/no-answer means restart the process.
- **`GET /readyz` — readiness.** `200` when the session pool has capacity, `503` when full
  (backpressure — pauses *new* traffic while in-flight sessions keep being served). The answer is
  cached for `VIVARIUM_READINESS_CACHE_TTL_SECONDS` (gap P3), so it is at most that stale and a probe
  flood cannot contend on the session lock. `/readyz` is **advisory** — the `create` path is the
  real capacity gate; a load balancer should poll it on an interval, not treat it as a reservation.

> Deploy expectation: expose the probes only to the orchestrator / tailnet, not the public internet
> (they are unauthenticated by design — see the TB6 residual-risk note in
> [`security/threat-model.md`](security/threat-model.md)).

> Path-matching caveat (gap round-3 P16, accepted): the health middleware matches the probe paths
> **exactly** (`/healthz`, `/readyz`). The server is not mounted under a sub-path today, so this is
> correct; if a future deployment mounts it behind a `root_path` prefix, the probe matching would need
> prefix-awareness. Noted here so the assumption is explicit, not silently load-bearing.

## SLIs → SLOs (minimal, pre-1.0)

These are **starting targets**, not contractual — tune to your deployment and revisit as real
traffic data arrives. Derive each from the snapshot fields above.

| SLI | Derivation | Suggested SLO (pre-1.0) |
|---|---|---|
| **Availability** | fraction of `tool_calls` whose outcome is **not** `internal-error`/`worker-unavailable` | ≥ 99% over a rolling window |
| **Correctness of intent** | `validation-error` / `limit-exceeded` are *client* faults, not server faults — track but don't burn budget on them | trend only |
| **Latency** | `tool_duration_seconds[tool].sum / .count` per tool (esp. `session_analyze`, `decompile_function`) | mean within the tool's expected band; watch the ratio, not an absolute |
| **Readiness** | `503`/`200` ratio on `/readyz` | `503` should be rare + brief; sustained `503` = under-capacity → [scaling](runbooks/scaling.md) |
| **Confidentiality invariant** | any `store_wiped:false` in worker-eviction logs | **zero** — a single occurrence is an incident |

An **error budget** is out of scope pre-1.0; the availability SLI drives the alerts below instead.

## Log-based alerts

Express these as saved queries/alerts in your log backend. Each names the signal, the field, and the
response runbook.

| Alert | Fires when | Why / response |
|---|---|---|
| **Auth-deny burst** | `auth_decisions["<mode>/deny"]` rises sharply over a few snapshots | Credential-stuffing / probing at the HTTP edge → [http-exposure](runbooks/http-exposure.md); confirm rate-limit + auth mode |
| **Internal-error rate** | `tool_calls` `internal-error` share exceeds a small threshold (e.g. >1% of calls) | Server-side fault (not client input) → [on-call](runbooks/on-call.md), consider [rollback](runbooks/rollback.md) |
| **Store-wipe failure** | log field `store_wiped:false` on a worker eviction (not in the snapshot — a per-event log) | **Confidentiality breach of a hostile-binary store** → **declare an incident** ([incident-response](runbooks/incident-response.md)) |
| **Readiness flapping** | `/readyz` oscillates `200`↔`503`, or is `503` for a sustained window | Chronic under-capacity or a stuck session → [scaling](runbooks/scaling.md) / [evict-poisoned-worker](runbooks/evict-poisoned-worker.md) |
| **Backpressure / timeouts** | `limit-exceeded`, `timeout`, or `worker-unavailable` outcomes spike in `tool_calls` | Overload or a bad worker → [scaling](runbooks/scaling.md) / [evict-poisoned-worker](runbooks/evict-poisoned-worker.md) |
| **Process liveness** | **no** `metrics.snapshot` line for ≫ the snapshot interval | The emitter/process is wedged — a *missing* signal is itself alertable (fail loud) |

## Consuming the snapshot (example)

Filter the log stream for the metric line and pull a field (structured JSON logs):

```
# most recent snapshot's active-session gauge and internal-error count
… | jq 'select(.event=="metrics.snapshot") | {active: .metrics.sessions_active,
        internal_errors: [.metrics.tool_calls | to_entries[] | select(.key|endswith("/internal-error")) | .value] | add}'
```

## Related

- [ADR-044 — operational observability](adr/ADR-044-operational-observability.md) (the design decision)
- [Runbook: on-call](runbooks/on-call.md) · [scaling](runbooks/scaling.md) · [incident-response](runbooks/incident-response.md)
- [`security/threat-model.md`](security/threat-model.md) (TB6 — the unauthenticated probe surface)
