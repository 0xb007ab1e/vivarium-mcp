# Runbook: Patch a Ghidra / JDK / Dependency CVE via Digest Bump

> Service-specific (ADR-003, `std-supplychain`). Rules: `@rules/workflow-cve-management.md`,
> `@rules/workflow-vuln-mgmt.md`.

## When to use
- SCA (pip-audit) flags a vulnerable Python dep, OR an advisory / **CISA KEV** entry matches the
  pinned **Ghidra**, **JDK**, or **base image** in the worker (tracked via the SBOM).
- **A scheduled rescan fails:** `.github/workflows/scheduled-rescan.yml` runs daily against `main`
  (pip-audit on the lockfiles + Trivy on the rebuilt images) and **fails closed** on a new
  HIGH/CRITICAL in an *unchanged* dep or pinned base — the failed run is the alert. For a base-image
  CVE (e.g. openssl), the fix is a **base-digest bump** to a patched Chainguard/Wolfi rebuild
  (resolve via `podman pull <ref> && podman image inspect --format '{{index .RepoDigests 0}}'`),
  landed via the normal PR + release flow.

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
2. Determine the fixed version (OSV/GHSA/NVD); update the `pyproject.toml` floor + regenerate the
   **hash-pinned lockfile** (the project pins with `pip-compile --generate-hashes`, NOT uv — one
   lock per `.in`):
   `pip-compile --generate-hashes -o requirements.lock pyproject.toml` (and `requirements-dev.lock`,
   `requirements-*.lock` similarly). Resolution needs network → run it via `cot` (the sandbox has
   no egress). **The lock-gen Python must match the consuming job's Python** (cot is 3.13; e.g.
   `mutation.yml` runs on 3.13 for this reason).
3. Run the gates locally (there is no `make` target — these mirror `ci.yml`):
   `ruff check . && ruff format --check . && mypy && pytest` (the merge-blocking SAST/SCA —
   bandit/semgrep/pip-audit/gitleaks — run in CI). Check for breaking changes.

### B. Ghidra / JDK / base image (the worker)
1. Identify the fixed Ghidra/JDK version or patched base image (bump the relevant `ARG …_SHA256` /
   base digest in `Containerfile.worker`).
2. Rebuild the worker image via the **`worker-image.yml`** workflow (GATED — it builds, Trivy-scans,
   SBOMs, and **cosign-signs** the image, then records the signed digest as the `worker-image-digest`
   artifact): `gh workflow run worker-image.yml --ref <branch>`, then
   `gh run download <run-id> -n worker-image-digest` → the new `sha256:` token. (For a quick local
   check only: `podman build -f Containerfile.worker -t vivarium-worker:<tag> .` then
   `podman image inspect --format '{{index .RepoDigests 0}}' …` — but the signed CI digest is what
   ships.)
3. **Vet the digest** (cosign verify — identity `worker-image.yml@<repo>`) and **surface it for
   human approval** (gated). Advance the authoritative trust pin **`.github/worker-image.pin`** (the
   single `sha256:` token the live-regression / e2e workflows cosign-verify + pull); also update
   `.env.example`'s `VIVARIUM_WORKER_IMAGE`.
4. Worker **SBOM** + the image/IaC scan (Trivy) are produced by the same `worker-image.yml` run →
   confirm no high/critical remaining.

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
_Last validated: not yet drilled (the worker-image rebuild + `.github/worker-image.pin` bump path
was exercised live in #190). Owner: repo maintainer (no formal on-call rotation pre-1.0)._
