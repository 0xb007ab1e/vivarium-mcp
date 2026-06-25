# Runbook: On-Call

> Rules: `@rules/topic-reliability.md`. SCAFFOLD — alert routes/contacts finalized in WS3.

## When to use
- You received an alert, or you're starting/ending an on-call shift.

## Prerequisites & access
- Paging, dashboards, server + worker logs, the runbooks, and the ability to deploy/rollback.

## Responding to an alert
1. **Acknowledge** within a reasonable time (best-effort, pre-1.0).
2. Open the linked dashboard/runbook; assess user impact + severity. Key signals:
   `timeout`/`worker-unavailable` spikes, sessions stuck `analyzing`, `limit-exceeded` (backpressure),
   `internal-error` rate, worker resource alerts, **`store_wiped:false`** (confidentiality — treat
   as an incident).
3. **Mitigate first:** for a single bad worker → `evict-poisoned-worker.md`; for backpressure →
   `scaling.md`; for a bad release → `rollback.md`.
4. If security (suspected escape) or major outage → **declare** and follow `incident-response.md`.
5. Keep a timeline; communicate on GitHub (issues / Security Advisory) at a cadence.

## Verification
- Alert cleared; metrics normal; user impact resolved. Silence only with a follow-up task.

## Escalation
- Out of depth / unresolved within a reasonable window → the maintainer (solo; no secondary/eng-lead pre-1.0). Escalate early.

## Shift handoff
- Document open issues, ongoing mitigations, flapping alerts, follow-ups.

## Related
- `incident-response.md`, `evict-poisoned-worker.md`, `scaling.md`, `rollback.md`.

---
_Status: scaffold (pre-1.0) — deploy/promote commands pending WS3 tooling; not yet drill-validated. Owner: repo maintainer (solo — no formal on-call rotation pre-1.0)._
