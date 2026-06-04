# Runbook: Backup & Restore

> Rules: `@rules/workflow-data-lifecycle.md`, `@rules/topic-reliability.md`. SCAFFOLD.

## When to use
- Restoring **configuration / deployment state** after host loss or misconfiguration.

## Scope note (important for this service)
- **Sessions are intentionally ephemeral and confidential** (hostile-origin artifacts). Per-session
  project stores are **NOT backed up** — they are wiped on eviction by design (ADR-002, master §5).
  There is **no analyzed-artifact backup**; clients re-import binaries to recreate a session.
- What IS recoverable: the pinned image **digests**, `deploy/`/`infra/` IaC, and non-secret config —
  all of which live in **version control** (git is the source of truth), not a data backup.

## Prerequisites & access
- Access to the repo + registry (images are immutable, available by digest); deploy role.

## Steps
1. Recover config/IaC from git at the desired release tag: `<git checkout <tag>>`.
2. Redeploy the pinned server + worker digests (`deploy.md`).
3. No data restore step — sessions are recreated on demand by clients.

## Verification
- Server boots with validated config; a smoke session import→analyze→decompile succeeds.

## Escalation
- If host/registry is unrecoverable → `incident-response.md`.

## Related
- `deploy.md`, `dependency-patch.md`; ADR-002/003; master §5.

---
_Last validated: <date>. Owner: <team>._
