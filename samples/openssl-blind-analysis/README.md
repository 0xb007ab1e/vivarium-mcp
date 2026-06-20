# OpenSSL blind-analysis sample

A worked blind reverse-engineering validation: a stripped, statically linked
OpenSSL 4.0.1 command-line binary analyzed with the Vivarium tools, with every
conclusion verified against the original source.

## Contents

- `REPORT.md` — the full report: process, methodology, scoring, metrics,
  the fifteen identifications with source comparison, false-positive analysis,
  reproducibility, and the fixture-promotion assessment.
- `REPORT.pdf` — the same report exported to PDF (8 pages).
- `expected-analysis.json` — the golden, machine-readable results: subject
  hashes, program-level metrics, the fifteen identifications with confidence and
  verification outcome, and the fixture acceptance evaluation.
- `openssl.blind` — the exact 7.9 MiB subject binary, committed via **Git LFS**
  (repo-root `.gitattributes`: `*.blind`). The OpenSSL static build is not
  byte-reproducible across toolchains, so the recorded bytes are pinned rather than
  rebuilt; the golden test loads this directly.
- `build-openssl-fixture.sh` — provenance: how the subject was built from pinned
  source (kept for documentation/local comparison; the LFS bytes are authoritative).

## Headline result

Fifteen high-signal functions and constants identified blind; 15 of 15 confirmed
against source. Identification accuracy 100 percent, mean confidence 92.3, no
high-confidence refutations. No indicators of malicious behavior.

## Fixture-promotion status

PROMOTED. The golden integration test is
`tests/integration/test_golden_fixture_openssl_blind.py` (gated `@pytest.mark.integration`,
runs as an advisory step in `.github/workflows/live-regression.yml`). It loads the
LFS-committed `openssl.blind`, re-runs the real analysis, and asserts it reproduces the
golden facts in `expected-analysis.json`.

## Provenance / regenerate

`build-openssl-fixture.sh` documents how the subject was built (OpenSSL 4.0.1, static,
stripped). Note the byte layout is toolchain-dependent, so a rebuild will not match the
LFS-pinned SHA-256; the committed bytes are authoritative.

```
git lfs pull --include="samples/openssl-blind-analysis/openssl.blind"   # fetch the subject
```
