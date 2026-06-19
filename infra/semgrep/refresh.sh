#!/usr/bin/env bash
# Refresh the vendored Semgrep rulesets (infra/semgrep/p-*.yml) from the registry.
#
# The CI SAST gate (.github/workflows/ci.yml) runs Semgrep against these VENDORED files with
# --metrics=off and no network config, so the gate is fully OFFLINE and REPRODUCIBLE — it never
# fetches `p/...` packs from semgrep.dev at scan time (egress + silent rule drift). The trade-off
# is that new upstream rules don't appear automatically; refresh DELIBERATELY with this script,
# review the diff (new/removed/changed rules), re-run the gate locally, and commit via PR.
#
# Usage:  infra/semgrep/refresh.sh           # re-fetch both packs, rewrite the vendored files
# Then:   semgrep --config infra/semgrep/ --error --metrics=off src   # confirm the gate still passes
set -euo pipefail
cd "$(dirname "$0")"
DATE="$(date -u +%Y-%m-%d)"
tmp=""
trap 'rm -f "${tmp:-}"' EXIT   # clean up the temp file on any exit path (incl. set -e mid-loop)
for p in python security-audit; do
  tmp="$(mktemp)"
  # NOTE: the rule pack is fetched over TLS with NO pinned checksum/signature — semgrep.dev serves
  # the canonical pack and has no published per-pack digest. The compensating control is the
  # vendor-and-review workflow: this script only stages the new rules; a human reviews the YAML diff
  # in the PR before it lands (the diff IS the integrity check). Refresh deliberately, never blindly.
  curl -fsSL "https://semgrep.dev/c/p/${p}" -o "$tmp"
  {
    echo "# Vendored Semgrep ruleset: p/${p} (registry pack), frozen for an OFFLINE, reproducible SAST gate."
    echo "# Source: https://semgrep.dev/c/p/${p}  — fetched ${DATE}."
    echo "# DO NOT hand-edit. Refresh deliberately: re-run infra/semgrep/refresh.sh, review the diff, re-run the gate."
    echo "# Rationale: the CI SAST gate must not fetch rules from the network at scan time (egress + non-reproducible)."
    cat "$tmp"
  } > "p-${p}.yml"
  rm -f "$tmp"
  echo "refreshed p/${p}: $(grep -c '^- id:' "p-${p}.yml") rules"
done
