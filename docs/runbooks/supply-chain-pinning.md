# Runbook: Supply-Chain Pinning & Lockfile (GATED)

> Rules: `@rules/std-supplychain.md`, `@rules/workflow-cicd.md`, `@rules/workflow-gated-actions.md`,
> PLAN §6 / §9, ADR-003. **This is the first GATED action of the build.** A maintainer (human) runs
> it; Claude prepared the sequence but does **not** execute it (network/install/pull are gated).

## When to use
- Resolving the WS0/WS1–WS5 placeholders so dependencies, base images, the Ghidra release, and CI
  actions are pinned **by digest/hash** before any install/build — the prerequisite for running the
  CI gates and for the first commit. Re-run (in part) on any dependency or base-image bump
  (`docs/runbooks/dependency-patch.md`).

## Severity / impact
- **Blast radius:** pulls third-party code + container images into the build and writes pinned
  references + a lockfile into the tree. No remote/prod is touched. **Rollback:** every pin is
  immutable and git-reverts to its prior value; delete the lockfile to undo.

## Prerequisites & access
- Network access (this is the gated step). Tools: `podman` (rootless — PLAN §3; `docker` works too),
  `uv` (preferred) **or** `pip-tools`, `git`, `sha256sum`, `curl`, and `jq`. Optional: `cosign`,
  `trivy` for the verify phase.
- Run from the repo root: `/home/b007ab1e/_src/_dev/ghidra`. Set the engine once:
  ```bash
  export ENGINE=podman      # or: export ENGINE=docker
  ```
- **Confirm the exact Ghidra 11.x patch with the SME first** (PLAN §9 open item) — do not guess a
  version. The official releases live at `https://github.com/NationalSecurityAgency/ghidra/releases`.

> **Runnable companion:** `infra/pin-supply-chain.sh` automates Phases 1–4 (idempotent, fail-closed,
> pinning-only — it does NOT install/build/commit). Run **that script**, not this `.md` (this file is
> prose + reference). Each command below is also copy-pasteable into a shell or, in the Claude Code
> prompt, prefixed with `!`. Steps are ordered; do not skip the verify phase.
>
> ```bash
> # base images + CI-action SHAs + lockfile now; add the GHIDRA_* env vars once the SME confirms 11.x:
> ENGINE=podman ./infra/pin-supply-chain.sh
> ```

---

## Phase 1 — Pin the 4 base images by digest (5 occurrences)

Pull each base, capture its repo digest, and rewrite the `@REPLACE_WITH_DIGEST_FOR_*` placeholder.
Mirrors the `BASES` map in `infra/pin-supply-chain.sh` (which automates this):
- **Worker** (`Containerfile.worker`): `eclipse-temurin:21-jdk`, `eclipse-temurin:21-jre`,
  `python:3.12-slim` (pybuilder + runtime — 2 occurrences).
- **Server** (`Containerfile.server`): `cgr.dev/chainguard/python:latest-dev` (builder) +
  `cgr.dev/chainguard/python:latest` (runtime) — the Wolfi distroless migration (PLAN §9). Chainguard
  publishes `:latest` only, so the *tag* is mutable but the pinned *digest* is immutable; re-pin on
  each rebuild.

```bash
# 1a. eclipse-temurin:21-jdk  (Containerfile.worker builder)
$ENGINE pull eclipse-temurin:21-jdk
JDK_DIGEST=$($ENGINE inspect --format '{{index .RepoDigests 0}}' eclipse-temurin:21-jdk | sed 's/.*@//')
echo "21-jdk -> $JDK_DIGEST"

# 1b. eclipse-temurin:21-jre  (Containerfile.worker runtime)
$ENGINE pull eclipse-temurin:21-jre
JRE_DIGEST=$($ENGINE inspect --format '{{index .RepoDigests 0}}' eclipse-temurin:21-jre | sed 's/.*@//')
echo "21-jre -> $JRE_DIGEST"

# 1c. python:3.12-slim  (Containerfile.worker pybuilder + runtime — 2 occurrences; WORKER ONLY)
$ENGINE pull python:3.12-slim
PY_DIGEST=$($ENGINE inspect --format '{{index .RepoDigests 0}}' python:3.12-slim | sed 's/.*@//')
echo "python:3.12-slim -> $PY_DIGEST"

# 1d. cgr.dev/chainguard/python  (Containerfile.server: -dev builder + latest runtime; distroless)
$ENGINE pull cgr.dev/chainguard/python:latest-dev
CG_DEV_DIGEST=$($ENGINE inspect --format '{{index .RepoDigests 0}}' cgr.dev/chainguard/python:latest-dev | sed 's/.*@//')
$ENGINE pull cgr.dev/chainguard/python:latest
CG_RUN_DIGEST=$($ENGINE inspect --format '{{index .RepoDigests 0}}' cgr.dev/chainguard/python:latest | sed 's/.*@//')
echo "chainguard -dev -> $CG_DEV_DIGEST ; latest -> $CG_RUN_DIGEST"

# 1e. Rewrite the placeholders (exact-match sed; @<placeholder> -> @<sha256:...>):
sed -i "s|eclipse-temurin:21-jdk@REPLACE_WITH_DIGEST_FOR_eclipse-temurin:21-jdk|eclipse-temurin:21-jdk@${JDK_DIGEST}|" Containerfile.worker
sed -i "s|eclipse-temurin:21-jre@REPLACE_WITH_DIGEST_FOR_eclipse-temurin:21-jre|eclipse-temurin:21-jre@${JRE_DIGEST}|" Containerfile.worker
sed -i "s|python:3.12-slim@REPLACE_WITH_DIGEST_FOR_python:3.12-slim|python:3.12-slim@${PY_DIGEST}|g" Containerfile.worker
sed -i "s|cgr.dev/chainguard/python:latest-dev@REPLACE_WITH_DIGEST_FOR_cgr.dev/chainguard/python:latest-dev|cgr.dev/chainguard/python:latest-dev@${CG_DEV_DIGEST}|" Containerfile.server
sed -i "s|cgr.dev/chainguard/python:latest@REPLACE_WITH_DIGEST_FOR_cgr.dev/chainguard/python:latest|cgr.dev/chainguard/python:latest@${CG_RUN_DIGEST}|" Containerfile.server

# 1f. Confirm no base-image placeholder remains:
grep -n "REPLACE_WITH_DIGEST_FOR_eclipse\|REPLACE_WITH_DIGEST_FOR_python\|REPLACE_WITH_DIGEST_FOR_cgr" Containerfile.* || echo "base images pinned ✓"
```

## Phase 2 — Pin the Ghidra release (4 ARGs) with verified integrity (ADR-003)

Confirm the version with the SME, then capture the release zip URL + **publisher SHA-256** and
verify the downloaded artifact before trusting it (fail-closed — supply-chain integrity).

```bash
# 2a. Set the SME-confirmed values (EXAMPLE shape — replace with the confirmed 11.x release):
GHIDRA_VERSION="11.x.y"                                   # e.g. 11.3.2  (SME-confirmed)
GHIDRA_RELEASE_TAG="Ghidra_${GHIDRA_VERSION}_build"       # exact tag on the releases page
GHIDRA_ZIP_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_RELEASE_TAG}/ghidra_${GHIDRA_VERSION}_PUBLIC_<DATE>.zip"

# 2b. Download + compute the SHA-256, then CROSS-CHECK against the checksum the release page lists:
curl -fsSL -o /tmp/ghidra.zip "$GHIDRA_ZIP_URL"
GHIDRA_ZIP_SHA256=$(sha256sum /tmp/ghidra.zip | awk '{print $1}')
echo "computed sha256 = $GHIDRA_ZIP_SHA256"
echo ">>> Compare this against the SHA-256 published on the Ghidra release page. They MUST match."
# (Do NOT proceed if they differ — that is a supply-chain integrity failure → stop, investigate.)

# 2c. Write the 4 ARGs into Containerfile.worker and infra/Makefile:
sed -i "s|ARG GHIDRA_VERSION=REPLACE_WITH_GHIDRA_11x_PATCH_VERSION|ARG GHIDRA_VERSION=${GHIDRA_VERSION}|" Containerfile.worker
sed -i "s|ARG GHIDRA_RELEASE_TAG=REPLACE_WITH_GHIDRA_RELEASE_TAG|ARG GHIDRA_RELEASE_TAG=${GHIDRA_RELEASE_TAG}|" Containerfile.worker
sed -i "s|ARG GHIDRA_ZIP_SHA256=REPLACE_WITH_GHIDRA_RELEASE_ZIP_SHA256|ARG GHIDRA_ZIP_SHA256=${GHIDRA_ZIP_SHA256}|" Containerfile.worker
sed -i "s|ARG GHIDRA_ZIP_URL=REPLACE_WITH_GHIDRA_RELEASE_ZIP_URL|ARG GHIDRA_ZIP_URL=${GHIDRA_ZIP_URL}|" Containerfile.worker
sed -i "s|REPLACE_WITH_GHIDRA_11x_PATCH_VERSION|${GHIDRA_VERSION}|;s|REPLACE_WITH_GHIDRA_RELEASE_ZIP_URL|${GHIDRA_ZIP_URL}|;s|REPLACE_WITH_GHIDRA_RELEASE_ZIP_SHA256|${GHIDRA_ZIP_SHA256}|" infra/Makefile

grep -n "REPLACE_WITH_GHIDRA" Containerfile.worker infra/Makefile || echo "Ghidra release pinned ✓"
```

## Phase 3 — Pin the 10 CI-action SHAs (both workflows)

Resolve each moving major tag to the commit SHA it currently points to, then rewrite the
`@REPLACE_WITH_DIGEST_FOR_<tag>` placeholders. (`ci.yml` + `worker-image.yml`.)

```bash
# 3a. action -> tag map (the 10 distinct actions in the two workflows):
declare -A ACTIONS=(
  [actions/checkout]=v4
  [actions/setup-python]=v5
  [actions/upload-artifact]=v4
  [aquasecurity/trivy-action]=v0          # confirm the current major/tag you want, then pin its SHA
  [docker/build-push-action]=v6
  [docker/login-action]=v3
  [docker/setup-buildx-action]=v3
  [gitleaks/gitleaks-action]=v2
  [hadolint/hadolint-action]=v3
  [sigstore/cosign-installer]=v3
)

# 3b. Resolve each to a commit SHA (dereference annotated tags with ^{}; fall back to the tag ref):
for repo in "${!ACTIONS[@]}"; do
  tag="${ACTIONS[$repo]}"
  sha=$(git ls-remote "https://github.com/${repo}" "refs/tags/${tag}^{}" | awk '{print $1}')
  [ -z "$sha" ] && sha=$(git ls-remote "https://github.com/${repo}" "refs/tags/${tag}" | awk '{print $1}')
  echo "${repo}@${tag} -> ${sha}"
  # rewrite "<repo>@REPLACE_WITH_DIGEST_FOR_<tag>" -> "<repo>@<sha>" across both workflows:
  sed -i "s|${repo}@REPLACE_WITH_DIGEST_FOR_${tag}|${repo}@${sha}|g" .github/workflows/ci.yml .github/workflows/worker-image.yml
done

# 3c. Confirm no action placeholder remains (the comment trailing each `uses:` keeps the readable tag):
grep -rn "REPLACE_WITH_DIGEST_FOR_v" .github/workflows/ || echo "CI action SHAs pinned ✓"
```

> Note: `trivy-action` uses `v0` as a placeholder in the tree — confirm the major/tag you intend
> (e.g. the current `0.x`) before pinning its SHA. All others map 1:1 to the tags above.

## Phase 4 — Generate the hash-pinned lockfile

`pyproject.toml` declares floors only; the lockfile is the hashed source of truth (gated per the
lockfile-intent note). **Preferred (uv):**

```bash
uv lock                                  # writes uv.lock (resolved + hashed)
git add uv.lock
```

**Alternative (pip-tools), producing the `requirements*.lock` the CI comment references:**

```bash
pip install pip-tools
pip-compile --generate-hashes --output-file=requirements.lock pyproject.toml
pip-compile --generate-hashes --extra=dev --output-file=requirements-dev.lock pyproject.toml
git add requirements.lock requirements-dev.lock
# Then enable the `--require-hashes` install line in .github/workflows/ci.yml (it's commented out).
```

## Phase 5 — Vet before trusting (fail-closed)

```bash
# 5a. Install from the lock into an isolated env (uv shown; pip --require-hashes equivalent works):
uv sync --extra dev            # or: pip install --require-hashes -r requirements-dev.lock

# 5b. CVE scan the resolved deps (block on high/critical):
uv run pip-audit --strict --desc        # or: pip-audit --strict --desc

# 5c. License check (deny AGPL/GPL for this Apache-2.0 project unless legal-approved — topic-license-compliance):
uv run pip-licenses --format=markdown --with-urls   # review output; no copyleft surprises

# 5d. (Optional, needs trivy) scan the pinned base images for known CVEs:
trivy image --config infra/trivy.yaml "eclipse-temurin:21-jre@${JRE_DIGEST}"
trivy image --config infra/trivy.yaml "python:3.12-slim@${PY_DIGEST}"
```

## Verification — run the full gate suite locally (must be green)

```bash
uv run ruff check . && uv run ruff format --check .          # gate 2 (incl. D docstrings)
uv run mypy                                                  # gate 3 (strict)
uv run pytest -m "not integration"                           # gate 4 (>=90% line+branch baseline)
uv run pytest -m "not integration" \
  --cov=ghidra_mcp.core.validation --cov=ghidra_mcp.core.envelope \
  --cov=ghidra_mcp.core.errors --cov=ghidra_mcp.sessions.manager \
  --cov=ghidra_mcp.security.limits --cov-fail-under=100       # 100% critical paths
uv run bandit -r src -c pyproject.toml                       # gate 5 SAST
```

- **Expected reality at this point:** lint/type/SAST should pass; the **coverage gates will surface
  the remaining work** — the Build-cycle-2 follow-ups (PM task #9: adapter `wrap` chokepoint +
  reconciliations) and WS5 Wave-2 (task #10: drive critical paths to 100%, mutation tests) close
  them. Integration/e2e stay skipped until the worker image is built (Phase below). **Report gate
  output back to the PM — do not hand-wave a pass.**

## Next gated steps (separate approvals — NOT part of pinning)

1. **Build + scan + SBOM the images** (gated container build/pull):
   ```bash
   make -f infra/Makefile build GHIDRA_VERSION="$GHIDRA_VERSION" GHIDRA_ZIP_URL="$GHIDRA_ZIP_URL" GHIDRA_ZIP_SHA256="$GHIDRA_ZIP_SHA256"
   make -f infra/Makefile scan-images scan-config sbom
   # then pin the BUILT image digests into deploy/*.sh + .env.example (REPLACE_WITH_PINNED_DIGEST):
   #   ghcr.io/OWNER/ghidra-mcp-worker@sha256:...   ghcr.io/OWNER/ghidra-mcp-server@sha256:...
   ```
2. **ADR-004 isolation acceptance** on a gVisor-capable host: `deploy/verify-isolation.sh`.
3. **First commit** of the integrated tree (separate gate — `@rules/workflow-git.md`, noreply email).

## Rollback / abort
- Any phase: `git checkout -- Containerfile.* infra/Makefile .github/workflows/*.yml .env.example deploy/*.sh`
  restores the placeholders; `rm -f uv.lock requirements*.lock` undoes the lock. Pins are immutable —
  reverting the file reverts the pin. If a SHA-256 cross-check fails in Phase 2, **stop** (integrity
  failure) and do not build.

## Escalation
- SHA-256 mismatch, an unexpected high/critical CVE with no fix, or a copyleft license surprise →
  stop and surface to the PM; treat a confirmed integrity failure as `docs/runbooks/incident-response.md`.

## Related
- `docs/runbooks/dependency-patch.md`, `docs/runbooks/deploy.md`, `docs/ci-cd.md`, `pyproject.toml`
  (lockfile-intent note), ADR-003, ADR-004, PLAN §6/§9.

---
_Last validated: not yet run (prepared 2026-06-03 by the SDLC PM for the gated supply-chain step). Owner: maintainer._
