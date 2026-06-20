# OpenSSL full first-party decompilation

A complete Ghidra decompilation of every first-party function in OpenSSL 4.0.1
(libcrypto + libssl + apps), the whole-binary counterpart to the targeted blind
validation in `../openssl-blind-analysis/`.

## Headline

- 15,423 first-party functions decompiled, 15,412 cleanly (99.93%), 11 hard
  crypto/SIMD primitives recorded as failed.
- 788,037 lines / 22.3 MiB of C (artifact compresses to 3.3 MiB).
- The 22 MiB listing and the tarball are not committed (repo policy); they are
  rebuildable via `reproduce.md` and verifiable against `manifest.json` hashes.

## Notable outcome

Completing this required finding and fixing a real memory leak in the extraction
path (Ghidra's native decompiler growing unbounded without periodic disposal, plus
pathological functions ballooning it), compounded by the execution framework having
no per-job memory isolation so a runaway job OOM-killed the whole daemon
(filed as claude-tools#11). With the fix, the full run completes in about two minutes
with bounded memory. See REPORT.md section 3.

## Contents

- `REPORT.md` / `REPORT.pdf` - full report (method, results, leak analysis,
  reproducibility).
- `manifest.json` - hashes, counts, failed list, module breakdown, guards used.
- `index.csv` - per-function index (name, address, size, lines, status).
- `scripts/` - the export script and the first-party allow-list.
- `reproduce.md` - exact rebuild steps.
