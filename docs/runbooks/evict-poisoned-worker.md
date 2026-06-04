# Runbook: Evict / Rotate a Poisoned or Hung Worker

> Service-specific (PLAN/ADR-002). Rules: `@rules/workflow-incident-response.md`,
> `@rules/topic-resource-management.md`. SCAFFOLD — commands `<...>` finalized in WS2/WS3.

## When to use
- A worker is **hung** (a tool/analysis exceeded its timeout and the auto-kill did not reclaim it),
  is **OOM/CPU-pegged**, is suspected **poisoned** (returning anomalous/garbage results), or is
  suspected **compromised** (a sandbox-escape attempt). Symptoms: `worker-unavailable`/`timeout`
  error spikes, a session stuck `analyzing`, resource alerts on a worker container.

## Severity / impact
- Routine eviction of one hung worker: low (one session affected). **Suspected escape/compromise →
  SEV1/2** — STOP and follow [`incident-response.md`](incident-response.md); preserve evidence
  before killing.

## Prerequisites & access
- Access to the container runtime + the server's session admin/log view; least privilege.
- Know the affected `session_id` (from logs/alerts).

## Steps
1. Confirm the symptom and identify the worker for the session: `<list workers / map session→worker>`
   → note the worker container id and the session id.
2. **If compromise is suspected:** capture evidence first (worker logs, `<container inspect/diff>`),
   then escalate per `incident-response.md`. Do NOT skip evidence on a suspected escape.
3. Evict the session — this **kills the worker and verified-wipes the store** (ADR-002):
   `<server admin evict --session <id> --reason poison>` → expect `store_wiped: true`.
4. If the orchestrator-level kill is needed (server couldn't reach it): `<runtime kill <container>>`,
   then re-run the evict to ensure the store is wiped.
5. Verify the per-session socket and project store are gone: `<ls socket dir>` / `<stat store path>`
   → both absent.

## Verification
- The session is no longer listed; `store_wiped: true` was logged; no orphan worker container
  remains; `worker-unavailable`/`timeout` rates return to baseline. A **wipe failure** (`store_wiped:
  false`) is a **confidentiality incident** → escalate.

## Rollback / abort
- None — eviction is one-way and idempotent. The client simply opens a new session and re-imports.

## Escalation
- Suspected escape/compromise → page security + `incident-response.md`; repeated unexplained
  poisoning may indicate a Ghidra/JDK CVE → `dependency-patch.md`.

## Related
- `incident-response.md`, `dependency-patch.md`; ADR-002, ADR-004; threat model TB3.

---
_Last validated: <date> (drill). Owner: <team>._
