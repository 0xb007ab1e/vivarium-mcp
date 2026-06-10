#!/usr/bin/env bash
# Pin supply-chain placeholders by digest/hash + generate the lockfile (GATED — run by a human).
#
# This is the EXECUTABLE companion to docs/runbooks/supply-chain-pinning.md. It is PINNING-ONLY:
# it resolves digests/SHAs and rewrites the REPLACE_WITH_* placeholders in-tree and generates the
# hash-pinned lockfile. It deliberately does NOT install deps, build/pull deploy images, run the
# gates, or commit — those are separate gated steps (see the runbook's "Next gated steps").
#
# Idempotent: each rewrite only fires if its placeholder is still present. Fail-closed: a Ghidra
# SHA-256 mismatch aborts. Safe to re-run.
#
# Usage:
#   # base images + CI-action SHAs + lockfile (no Ghidra yet):
#   ENGINE=podman ./infra/pin-supply-chain.sh
#
#   # also pin the Ghidra release (after the SME confirms the exact 11.x version):
#   GHIDRA_VERSION=11.x.y \
#   GHIDRA_RELEASE_TAG=Ghidra_11.x.y_build \
#   GHIDRA_ZIP_URL='https://github.com/NationalSecurityAgency/ghidra/releases/download/.../ghidra_11.x.y_PUBLIC_YYYYMMDD.zip' \
#   GHIDRA_ZIP_EXPECTED_SHA256=<sha256-from-the-release-page> \
#   ENGINE=podman ./infra/pin-supply-chain.sh
set -euo pipefail
IFS=$'\n\t'

ENGINE="${ENGINE:-podman}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

note() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; }

# Replace LHS->RHS in a file ONLY if LHS is still present (idempotent). $1=lhs $2=rhs $3..=files
pin() {
  local lhs="$1" rhs="$2"; shift 2
  local f hit=0
  for f in "$@"; do
    if grep -qF -- "$lhs" "$f" 2>/dev/null; then
      # use a non-/ delimiter; lhs/rhs contain slashes and colons but no '|'
      sed -i "s|$(printf '%s' "$lhs" | sed 's/[&|]/\\&/g')|$(printf '%s' "$rhs" | sed 's/[&|]/\\&/g')|g" "$f"
      hit=1
    fi
  done
  [ "$hit" = 1 ] && ok "pinned: $lhs -> $rhs" || warn "already pinned / not found: $lhs"
}

UNRESOLVED=()

# ---------------------------------------------------------------------------
note "Phase 1 — base images by digest"
if command -v "$ENGINE" >/dev/null 2>&1; then
  declare -A BASES=(
    [eclipse-temurin:21-jdk]=Containerfile.worker
    [eclipse-temurin:21-jre]=Containerfile.worker
    # python:3.12-slim is now the WORKER base only (the server moved to Chainguard/Wolfi — PLAN §9).
    [python:3.12-slim]=Containerfile.worker
    # Server (distroless migration): Chainguard publishes :latest only, so we pin its digest.
    [cgr.dev/chainguard/python:latest-dev]=Containerfile.server
    [cgr.dev/chainguard/python:latest]=Containerfile.server
  )
  for img in "${!BASES[@]}"; do
    "$ENGINE" pull "$img" >/dev/null
    digest="$("$ENGINE" inspect --format '{{index .RepoDigests 0}}' "$img" | sed 's/.*@//')"
    if [ -z "$digest" ]; then err "no digest for $img"; UNRESOLVED+=("base:$img"); continue; fi
    pin "${img}@REPLACE_WITH_DIGEST_FOR_${img}" "${img}@${digest}" "${BASES[$img]}"
  done
else
  warn "engine '$ENGINE' not found — skipping base-image pinning (set ENGINE=docker|podman). Bases left as placeholders."
  UNRESOLVED+=("base-images(no-engine)")
fi

# ---------------------------------------------------------------------------
note "Phase 2 — Ghidra release (verified SHA-256)"
if [ -n "${GHIDRA_VERSION:-}" ] && [ -n "${GHIDRA_ZIP_URL:-}" ] && [ -n "${GHIDRA_ZIP_EXPECTED_SHA256:-}" ]; then
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  curl -fsSL -o "$tmp" "$GHIDRA_ZIP_URL"
  got="$(sha256sum "$tmp" | awk '{print $1}')"
  if [ "$got" != "$GHIDRA_ZIP_EXPECTED_SHA256" ]; then
    err "Ghidra SHA-256 MISMATCH — integrity failure, aborting."
    err "  expected: $GHIDRA_ZIP_EXPECTED_SHA256"
    err "  got:      $got"
    exit 1
  fi
  ok "Ghidra zip integrity verified ($got)"
  pin "ARG GHIDRA_VERSION=REPLACE_WITH_GHIDRA_11x_PATCH_VERSION" "ARG GHIDRA_VERSION=${GHIDRA_VERSION}" Containerfile.worker
  pin "ARG GHIDRA_RELEASE_TAG=REPLACE_WITH_GHIDRA_RELEASE_TAG" "ARG GHIDRA_RELEASE_TAG=${GHIDRA_RELEASE_TAG:-Ghidra_${GHIDRA_VERSION}_build}" Containerfile.worker
  pin "ARG GHIDRA_ZIP_SHA256=REPLACE_WITH_GHIDRA_RELEASE_ZIP_SHA256" "ARG GHIDRA_ZIP_SHA256=${GHIDRA_ZIP_EXPECTED_SHA256}" Containerfile.worker
  pin "ARG GHIDRA_ZIP_URL=REPLACE_WITH_GHIDRA_RELEASE_ZIP_URL" "ARG GHIDRA_ZIP_URL=${GHIDRA_ZIP_URL}" Containerfile.worker
  pin "REPLACE_WITH_GHIDRA_11x_PATCH_VERSION" "${GHIDRA_VERSION}" infra/Makefile
  pin "REPLACE_WITH_GHIDRA_RELEASE_ZIP_URL" "${GHIDRA_ZIP_URL}" infra/Makefile
  pin "REPLACE_WITH_GHIDRA_RELEASE_ZIP_SHA256" "${GHIDRA_ZIP_EXPECTED_SHA256}" infra/Makefile
else
  warn "GHIDRA_VERSION / GHIDRA_ZIP_URL / GHIDRA_ZIP_EXPECTED_SHA256 not all set — skipping Ghidra pinning (confirm 11.x with the SME, PLAN §9)."
  UNRESOLVED+=("ghidra-release(inputs-unset)")
fi

# ---------------------------------------------------------------------------
note "Phase 3 — CI action SHAs (both workflows)"
declare -A ACTIONS=(
  [actions/checkout]=v4
  [actions/setup-python]=v5
  [actions/upload-artifact]=v4
  [aquasecurity/trivy-action]=v0
  [docker/build-push-action]=v6
  [docker/login-action]=v3
  [docker/setup-buildx-action]=v3
  [gitleaks/gitleaks-action]=v2
  [hadolint/hadolint-action]=v3
  [sigstore/cosign-installer]=v3
)
WF=(.github/workflows/ci.yml .github/workflows/worker-image.yml)
for repo in "${!ACTIONS[@]}"; do
  tag="${ACTIONS[$repo]}"
  sha="$(git ls-remote "https://github.com/${repo}" "refs/tags/${tag}^{}" 2>/dev/null | awk '{print $1}')"
  [ -z "$sha" ] && sha="$(git ls-remote "https://github.com/${repo}" "refs/tags/${tag}" 2>/dev/null | awk '{print $1}')"
  if [ -z "$sha" ]; then
    warn "could not resolve ${repo}@${tag} (e.g. trivy-action uses 0.x, not v0) — leaving placeholder; pin manually."
    UNRESOLVED+=("action:${repo}@${tag}")
    continue
  fi
  pin "${repo}@REPLACE_WITH_DIGEST_FOR_${tag}" "${repo}@${sha}" "${WF[@]}"
done

# ---------------------------------------------------------------------------
note "Phase 4 — hash-pinned lockfile"
if command -v uv >/dev/null 2>&1; then
  uv lock && ok "uv.lock written"
elif command -v pip-compile >/dev/null 2>&1; then
  pip-compile --generate-hashes --output-file=requirements.lock pyproject.toml
  pip-compile --generate-hashes --extra=dev --output-file=requirements-dev.lock pyproject.toml
  ok "requirements.lock + requirements-dev.lock written (enable --require-hashes in ci.yml)"
else
  warn "neither 'uv' nor 'pip-compile' found — install one, then re-run (lockfile is GATED-but-required)."
  UNRESOLVED+=("lockfile(no-tool)")
fi

# ---------------------------------------------------------------------------
note "Summary"
remaining="$(grep -rn 'REPLACE_WITH' --include='*.yml' --include='Containerfile*' --include='*.sh' --include='*.env*' --include='Makefile' . 2>/dev/null | grep -v __pycache__ | grep -v '.claude/worktrees' | grep -v 'docs/runbooks/supply-chain-pinning.md' | grep -v 'infra/pin-supply-chain.sh' | grep -vc 'REPLACE_WITH_PINNED_DIGEST')"
ok "non-built-image placeholders remaining: ${remaining} (REPLACE_WITH_PINNED_DIGEST for the built worker/server images is pinned AFTER 'make build', per the runbook)"
if [ "${#UNRESOLVED[@]}" -gt 0 ]; then
  warn "unresolved this run (re-run with inputs/tools, or pin manually):"
  printf '      - %s\n' "${UNRESOLVED[@]}"
fi
cat <<'EOF'

  Next (separate gates — NOT run here):
    1. Vet:        pip-audit --strict --desc ; pip-licenses   (deny AGPL/GPL)
    2. Gates:      ruff check . && mypy && pytest -m "not integration"  (+ 100%-critical cov)
    3. Build:      make -f infra/Makefile build scan-images sbom   (set IMAGE_OWNER; pin built digests)
    4. Isolation:  deploy/verify-isolation.sh    (gVisor host)
    5. First commit of the integrated tree (gated — workflow-git).
  Report gate output back to the PM. See docs/runbooks/supply-chain-pinning.md.
EOF
