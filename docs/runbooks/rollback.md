# Runbook: Rollback

> Rules: `@rules/workflow-release.md`. SCAFFOLD — commands finalized in WS3 + release prep.

## When to use
- A release caused elevated errors (`internal-error`/`worker-unavailable` spikes), a regression, or
  a security defect and forward-fix isn't fast enough.

## Severity / impact
- Usually SEV2+; bias to rollback when in doubt during an active regression. v1 has **no
  database/migrations** and **ephemeral sessions**, so rollback is a straightforward image revert.

## Prerequisites & access
- Previous known-good **server + worker image digests** (in git history / `deploy/`); deploy role.

## Steps
1. Stop further promotion: `<cmd>`.
2. Redeploy the previous server + worker digests (both immutable, available by digest): `<cmd>`.
3. In-flight sessions are ephemeral — they are evicted on the old process exit (workers killed +
   stores wiped). Clients re-open sessions against the rolled-back version.

## Verification
- Health green; error rates back to baseline; the original symptom is gone; a smoke session passes.

## Rollback / abort
- If rollback itself fails → `incident-response.md`.

## Escalation
- Page `<on-call>` / incident commander; notify `<stakeholders>`.

## Related
- `deploy.md`, `incident-response.md`, `dependency-patch.md`.

---
_Last validated: <date>. Owner: <team>._
