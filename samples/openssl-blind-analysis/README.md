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
- `build-openssl-fixture.sh` — deterministically rebuilds the subject binary from
  pinned source and verifies its SHA-256.
- `.gitignore` — keeps the 7.9 MiB binary out of git (rebuild it on demand).

## Headline result

Fifteen high-signal functions and constants identified blind; 15 of 15 confirmed
against source. Identification accuracy 100 percent, mean confidence 92.3, no
high-confidence refutations. No indicators of malicious behavior.

## Fixture-promotion status

The subject meets the acceptance criteria defined in `REPORT.md` section 9 and is
recommended for promotion to a test fixture. Promotion is a gated action requiring
human approval. The binary itself is never committed (repo policy); a promoted
fixture is the golden file plus the build script. If promotion is rejected,
discard this directory.

## Regenerate

```
./build-openssl-fixture.sh            # rebuild openssl.blind and check its hash
```
