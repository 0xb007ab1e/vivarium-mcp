# Runbook: Deploy / Release

> Rules: `@rules/workflow-release.md`. v1 has **no orchestrated deploy** — it is a local **stdio**
> MCP server process (workers are spawned per-session from the digest-pinned image, not deployed);
> the steps below reflect that. A managed-rollout pipeline is pending WS3 tooling.

## When to use
- Promoting a tagged, gate-passing build (server image + **digest-pinned** worker image) to an env.

## Prerequisites & access
- Green CI on the release commit (all gates — `workflow-cicd`); SBOM + signed artifacts exist;
  worker image pinned **by digest** and the digest approved (gated — ADR-003). Deploy role (OIDC).

## Steps
1. Confirm the pinned worker digest matches the intended, **cosign-signed** release build:
   `cat .github/worker-image.pin`, then
   `cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com
   --certificate-identity-regexp '^https://github.com/<owner>/vivarium-mcp/.github/workflows/worker-image.yml@'
   ghcr.io/<owner>/vivarium-worker@<digest>`.
2. "Promote" the worker by **digest** (build once, promote — no per-env rebuild): the worker image
   is **pinned**, not redeployed — advancing `.github/worker-image.pin` IS the promotion (the server
   pulls that digest when it spawns a worker). Launch/restart the **server** process with the
   release config: stdio — `python -m vivarium`; HTTP transport — `VIVARIUM_TRANSPORT=http`
   `VIVARIUM_HTTP_BIND=…` `VIVARIUM_HTTP_AUTH=…` `python -m vivarium` (see `http-exposure.md`).
3. Verify the worker runs under the hardened runtime (gVisor/rootless, no-network, caps-dropped) —
   run the ADR-004 drill against the pinned image: `deploy/verify-isolation.sh` (or dispatch the
   `gvisor-isolation.yml` workflow). All six controls must pass.
4. Roll out progressively where applicable; watch `timeout`/`worker-unavailable` rates + worker
   health for a few min.

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
_Last validated: not yet drilled. The v1 reality (promote-by-digest-pin + server launch +
`deploy/verify-isolation.sh`) is filled; a managed progressive-rollout pipeline is pending WS3
tooling. Owner: repo maintainer (solo — no formal on-call rotation pre-1.0)._
