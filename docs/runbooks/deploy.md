# Runbook: Deploy / Release

> Rules: `@rules/workflow-release.md`. SCAFFOLD — commands finalized in WS3 + release prep.

## When to use
- Promoting a tagged, gate-passing build (server image + **digest-pinned** worker image) to an env.

## Prerequisites & access
- Green CI on the release commit (all gates — `workflow-cicd`); SBOM + signed artifacts exist;
  worker image pinned **by digest** and the digest approved (gated — ADR-003). Deploy role (OIDC).

## Steps
1. Confirm the release tag + **server and worker image digests** match the intended commit: `<cmd>`.
2. Deploy the **promoted** artifacts (build once, promote — no rebuild per env): `<deploy cmd>`.
3. Verify the worker runs under the hardened runtime (gVisor/rootless, no-network) — see
   `scaling.md`/ADR-004 acceptance checks: `<verify isolation cmd>`.
4. Roll out progressively where applicable; watch error rates / worker health for a few min.

## Verification
- Server starts (config validated, fail-closed); a smoke session (import→analyze→decompile on a
  synthetic binary) succeeds; `timeout`/`worker-unavailable` rates at baseline.

## Rollback / abort
- Follow `rollback.md` (revert to previous server + worker digests).

## Escalation
- Page the maintainer; notify affected users (via the repo) on GitHub (issues / Security Advisory).

## Related
- `rollback.md`, `dependency-patch.md`, `scaling.md`; ADR-003/004.

---
_Status: scaffold (pre-1.0) — deploy/promote commands pending WS3 tooling; not yet drill-validated. Owner: repo maintainer (solo — no formal on-call rotation pre-1.0)._
