#!/usr/bin/env bash
#
# Reproducibly build the OpenSSL blind-analysis fixture binary.
#
# This script downloads the pinned OpenSSL source, builds a fully static,
# stripped `openssl` command-line binary, and verifies its SHA-256 against the
# value recorded in expected-analysis.json. The binary itself is deliberately
# NOT committed to the repository (it is 7.9 MiB; repo policy keeps real binary
# samples out of git history and CI). Run this script to regenerate it on demand.
#
# Usage:
#   ./build-openssl-fixture.sh [output_path]
# Default output_path: ./openssl.blind (next to this script).
#
# Requirements: a C toolchain (gcc, make), perl, curl, and static libc
# (glibc-static or equivalent). Network access to github.com to fetch the source.

set -euo pipefail

# --- Pinned inputs (keep in sync with expected-analysis.json) ---
OPENSSL_VERSION="4.0.1"
SRC_TARBALL_SHA256="2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09"
EXPECTED_BIN_SHA256="fba4556e7bba19522230cd0aab531d9cb380e6e6ebc0dc3a79defefadcb83060"

OUT="${1:-$(cd "$(dirname "$0")" && pwd)/openssl.blind}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> building OpenSSL ${OPENSSL_VERSION} fixture in ${WORK}"
cd "$WORK"

URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
echo "==> downloading ${URL}"
curl -fsSL -o src.tar.gz "$URL"

echo "==> verifying source tarball sha256"
echo "${SRC_TARBALL_SHA256}  src.tar.gz" | sha256sum -c -

tar xzf src.tar.gz
cd "openssl-${OPENSSL_VERSION}"

echo "==> configure (fully static, no shared libs, no docs, no tests)"
./Configure no-shared no-docs no-tests -static linux-x86_64 >/dev/null

echo "==> build (this takes a few minutes)"
make -j"$(nproc)" build_programs >/dev/null

echo "==> strip"
strip --strip-all apps/openssl

echo "==> verify binary sha256"
GOT="$(sha256sum apps/openssl | cut -d' ' -f1)"
if [ "$GOT" != "$EXPECTED_BIN_SHA256" ]; then
  echo "ERROR: built binary sha256 mismatch"
  echo "  expected: $EXPECTED_BIN_SHA256"
  echo "  got:      $GOT"
  echo "Note: exact reproducibility depends on the toolchain (gcc/binutils/libc)."
  echo "If the toolchain differs, the byte layout may shift; re-record the hash"
  echo "in expected-analysis.json only after confirming the analysis still holds."
  exit 1
fi

cp apps/openssl "$OUT"
echo "==> OK: $OUT"
echo "    sha256: $GOT"
echo "    size:   $(stat -c%s "$OUT") bytes"
