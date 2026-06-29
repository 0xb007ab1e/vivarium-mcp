# Runbook: Evict / Rotate a Poisoned or Hung Worker

> Service-specific (PLAN/ADR-002). Rules: `@rules/workflow-incident-response.md`,
> `@rules/topic-resource-management.md`. Commands assume rootless **podman** (the default
> `VIVARIUM_CONTAINER_ENGINE`); substitute the configured engine. `<session_id>` is the only
> operator-supplied value (from logs/alerts).

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
- Access to the container runtime (podman) on the server host + the server's structured log stream;
  least privilege. Each worker container is named `vivarium-worker-<session_id>` — the name suffix
  IS the session id, so the runtime and the logs cross-reference directly.
- Know the affected `session_id` (from the `worker-unavailable`/`timeout` log events or alerts).

## Steps
1. Confirm the symptom and identify the worker for the session — list the live workers (the
   `vivarium-worker-<sid>` name carries the session id):

   ```sh
   podman ps --filter "name=vivarium-worker-" --format '{{.Names}}\t{{.Status}}\t{{.RunningFor}}'
   ```

2. **If compromise is suspected (suspected sandbox escape): capture evidence FIRST**, then escalate
   per `incident-response.md` — do NOT skip this on a suspected escape:

   ```sh
   SID=<session_id>
   podman logs    "vivarium-worker-${SID}" > "evict-${SID}.log"   2>&1   # worker stderr (no PII/bytes — redacted by design)
   podman inspect "vivarium-worker-${SID}" > "evict-${SID}.inspect.json"
   podman diff    "vivarium-worker-${SID}" > "evict-${SID}.diff"          # rootfs is read-only → any diff is notable
   ```

3. Evict the session — this **kills the worker and verified-wipes the per-session store** (ADR-002).
   There is **no admin CLI**; eviction has two real paths:
   - **Graceful (session reachable + trusted):** the owning client calls the **`session_close`**
     tool — owner-checked at the chokepoint, kills the worker, and returns `store_wiped: true`.
   - **Poison / unreachable / untrusted (the usual case here):** kill the container directly at the
     orchestrator (next step) — the server observes `worker-unavailable` and auto-evicts + wipes.

4. Orchestrator-level kill (the poison lever — does not depend on trusting the session):

   ```sh
   podman kill  "vivarium-worker-${SID}" 2>/dev/null || true
   podman rm -f "vivarium-worker-${SID}" 2>/dev/null || true   # --rm usually reaps it; force-remove any lingering
   ```

   The server then logs `session_evicted` with `store_wiped: true` for that session.
5. Verify the per-session state is gone:
   - **Socket dir** (server-owned, on the host) is removed:
     `ls -la "${VIVARIUM_RPC_SOCKET_DIR:-/run/vivarium}/${SID}"` → **No such file or directory**.
   - **Project store** needs no host check — it is a worker-internal **tmpfs** (`/work/project`,
     never written to disk, ADR-002), so it is destroyed with the container by construction.
   - No `vivarium-worker-${SID}` container remains: re-run the step-1 `podman ps` filter → absent.

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
_Last validated: not yet drilled (commands verified against the ADR-002/ADR-004 worker spec —
`deploy/worker-run.sh`, `sessions/manager.py` eviction). Owner: repo maintainer (no formal on-call
rotation pre-1.0)._
