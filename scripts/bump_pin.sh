#!/usr/bin/env bash
# Rewrite the worker-image trust pin: emit the current pin content with its `sha256:<digest>` line
# replaced by DIGEST, preserving every comment/blank line (the header) in order.
#
# Extracted from `.github/workflows/worker-image.yml` (round-6 V2) so the trust-anchor transform is
# a TESTED, reviewable unit instead of untested inline CI shell — a regression in the rewrite would
# silently produce a malformed pin (what `live-regression` cosign-verifies). See tests/unit/
# test_bump_pin.py. Pure stdin -> stdout (no file / network / gh side effects): the caller feeds the
# current pin text and substitutes the output. Fails closed on a malformed digest (exit 2).
#
# Usage:  printf '%s' "$current_pin_text" | scripts/bump_pin.sh "sha256:<64 hex>"
set -euo pipefail

digest="${1:-}"

# Validate the digest shape BEFORE touching content (fail closed — a bad digest must never reach the
# pin file). Exactly `sha256:` + 64 lowercase hex, WHOLE-string. Bash `[[ =~ ]]` anchors against the
# entire value (not line-by-line like `grep`), so an embedded newline whose first line looks valid
# is still rejected — the pin's frozen format is a single token.
if [[ ! "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "bump_pin: invalid digest (expected sha256:<64 lowercase hex>): '${digest}'" >&2
  exit 2
fi

current="$(cat)"

# Preserve every non-digest line (header comments + blanks) in order, then append the single new
# digest line with one trailing newline. `|| true`: `grep -v` exits 1 when it selects NO lines (a
# pin file that is only a digest line, no header) — that is not an error here, just an empty header.
{
  printf '%s' "${current}" | grep -vE '^sha256:' || true
  printf '%s\n' "${digest}"
}
