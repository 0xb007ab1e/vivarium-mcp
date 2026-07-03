#!/usr/bin/env bash
# Read arbitrary text on stdin, emit the first `sha256:<64 lowercase hex>` token, or fail closed.
#
# Extracted from `.github/workflows/worker-image.yml` (round-8 X3) so the digest-extraction that
# decides WHAT gets cosign-verified, compared against the current pin, and written into the trust
# pin is a TESTED unit, not untested inline shell. Used at three sites in `propose-pin-bump`: the
# freshly-built digest artifact (twice) and the current pin file (the "already at pin?" compare).
# See tests/unit/test_extract_digest.py.
#
# Strict LOWERCASE hex (OCI/cosign digests are lowercase); a non-matching input emits nothing and
# exits 1 (fail closed) — the caller must treat that as "no digest". Pairs with scripts/bump_pin.sh,
# whose whole-string validator likewise rejects uppercase/malformed digests.
#
# Usage:  ./scripts/extract_digest.sh < worker-image.digest      # or:  printf '%s' "$text" | ...
set -euo pipefail

digest="$(grep -oE 'sha256:[0-9a-f]{64}' | head -n1 || true)"
if [ -z "${digest}" ]; then
  echo "extract_digest: no sha256:<64 lowercase hex> token found on stdin" >&2
  exit 1
fi
printf '%s\n' "${digest}"
