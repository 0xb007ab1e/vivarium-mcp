# Runbook: Patch a Ghidra / JDK / Dependency CVE via Digest Bump

> Service-specific (ADR-003, `std-supplychain`). Rules: `@rules/workflow-cve-management.md`,
> `@rules/workflow-vuln-mgmt.md`. SCAFFOLD — commands `<...>` finalized in WS3.

## When to use
- SCA (pip-audit) flags a vulnerable Python dep, OR an advisory / **CISA KEV** entry matches the
  pinned **Ghidra**, **JDK**, or **base image** in the worker (tracked via the SBOM).

## Severity / impact
- Score with CVSS + EPSS + KEV and assess **reachability** in our context (is the vulnerable code
  path / loader actually used? is it reachable given no-network + isolation?). Record a **VEX**
  status. SLAs: Critical/KEV **24–72h**, High 7d, Medium 30d.

## Prerequisites & access
- The SBOM to locate every affected artifact; repo write + CI access. For the worker image: access
  to build + the registry. **Image pulls/builds are a GATED supply-chain action** — surface the new
  digest for approval.

## Steps
### A. Python dependency
1. Confirm exposure + VEX (`affected` / `not affected` + reason).
2. Determine the fixed version (OSV/GHSA/NVD); update `pyproject.toml` floor + regenerate the
   **hash-pinned lockfile**: `<uv lock>` / `<pip-compile --generate-hashes>`.
3. Run the full gates (`<make ci>`); check for breaking changes.

### B. Ghidra / JDK / base image (the worker)
1. Identify the fixed Ghidra/JDK version or patched base image.
2. Rebuild the worker image; obtain the **new `@sha256:` digest**: `<build + inspect digest>`.
3. **Vet the digest** (provenance/signature where available) and **surface it for human approval**
   (gated). Update the pinned digest in `deploy/` and `.env.example`'s `GHIDRA_MCP_WORKER_IMAGE`.
4. Regenerate the worker **SBOM**; re-run the image/IaC scan (Trivy) → no high/critical remaining.

## Verification
- Re-run SCA + image scan: the finding is gone for **all** affected artifacts. Add/confirm a
  regression test where applicable. Close the tracked finding with resolution + evidence + VEX.
- Smoke test a session import→analyze→decompile against a synthetic binary with the new image.

## Rollback / abort
- Revert to the previous pinned digest (still in git history / `deploy/`) and redeploy; the old
  image is immutable and available by its digest. Follow `rollback.md`.

## Escalation
- Actively-exploited (KEV) / evidence of exploitation → `incident-response.md` and rotate any
  potentially exposed secrets (none in v1).

## Related
- `deploy.md`, `rollback.md`, `incident-response.md`; ADR-003; threat model §4 (supply chain).

---
_Last validated: <date>. Owner: <team>._
