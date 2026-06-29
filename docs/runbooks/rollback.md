# Runbook: Rollback

> Rules: `@rules/workflow-release.md`. v1 has no orchestrated deploy — rollback is reverting the
> pinned worker digest + restarting the server at the prior commit (see `deploy.md`).

## When to use
- A release caused elevated errors (`internal-error`/`worker-unavailable` spikes), a regression, or
  a security defect and forward-fix isn't fast enough.

## Severity / impact
- Usually SEV2+; bias to rollback when in doubt during an active regression. v1 has **no
  database/migrations** and **ephemeral sessions**, so rollback is a straightforward image revert.

## Prerequisites & access
- Previous known-good **server + worker image digests** (in git history / `deploy/`); deploy role.

## Steps
1. Halt the in-progress promotion: stop merging/tagging the bad release; cancel any running release
   workflow (`gh run cancel <run-id>`). The worker pin only advances via a merged PR, so an
   unmerged bump needs no action.
2. Revert the worker to the previous **digest** and the server to the previous **commit**:
   - Worker: restore the prior `sha256:` in `.github/worker-image.pin` (find it in history —
     `git log -p -- .github/worker-image.pin` — e.g. the pre-#190 `sha256:34d4a96e…`). The image is
     immutable + still in GHCR by digest; the server pulls the restored digest on next worker spawn.
   - Server: `git checkout <previous-release-tag>` and relaunch `python -m vivarium` (the prior
     known-good process — see `deploy.md`).
3. In-flight sessions are ephemeral — they are evicted on the old process exit (workers killed +
   stores wiped). Clients re-open sessions against the rolled-back version.

## Verification
- Health green; error rates back to baseline; the original symptom is gone; a smoke session passes.

## Rollback / abort
- If rollback itself fails → `incident-response.md`.

## Escalation
- Page the maintainer / incident commander; notify affected users (via the repo).

## Related
- `deploy.md`, `incident-response.md`, `dependency-patch.md`.

---
_Last validated: not yet drilled (the worker-pin revert lever is the inverse of the #190 bump).
A managed-rollout/auto-rollback pipeline is pending WS3 tooling. Owner: repo maintainer (solo — no
formal on-call rotation pre-1.0)._
