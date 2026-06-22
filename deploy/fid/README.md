# Bundled ELF FunctionID databases (ADR-043 Phase 2)

This directory is the source of the worker image's bundled ELF FunctionID databases. At runtime it
lands at **`/opt/vivarium/fid`** inside the worker image (the default `VIVARIUM_FID_DB_DIR`), and the
worker **startup-attaches** every `*.fidbf` it finds here so `identify_functions` matches Linux
library code.

## How activation works (the PROVEN mechanism — ADR-043 D3)

A data-dir drop-in into `Ghidra/Features/FunctionID/data/` is **silently ignored** (Ghidra registers
DBs via an install step, not a directory glob). The worker therefore attaches at startup
(`vivarium.ghidra._jvm_bridge._attach_bundled_fid_dbs`, orchestrated by the hermetically-tested
`vivarium.ghidra._fid_attach`):

1. scan `VIVARIUM_FID_DB_DIR` for `*.fidbf` (this dir);
2. copy each DB to the **writable** tmpfs scratch (`/tmp/ghidra`) — `addUserFidFile` needs a
   writable, valid packed path (it returns `None` otherwise; the rootfs is read-only);
3. `FidFileManager.getInstance().addUserFidFile(File(writableCopy))` → `FidFile.setActive(True)`.

It is **fail-soft**: a missing/empty dir is a clean no-op (identical to the pre-Phase-2 baseline); a
bad/corrupt DB is logged (`fid_db_skipped`) and skipped — it never crashes the worker.

## What lands here

- `sources.toml` — the CI-gated source set + SPDX licenses (the license allow-list gate,
  `vivarium.fid_licenses`, runs over this). Non-`.fidbf` files here are ignored by the worker scan.
- `README.md` — this file.
- `*.fidbf` — **the bundled packed databases. These are NOT committed to the repo.** They are
  generated during the PM's gated validation by the in-worker generator
  (`scripts/fid/generate_fidb.py`) from a pinned-by-digest library build (e.g. zlib-static), then
  dropped here (or produced in a dedicated build stage) so `Containerfile.worker`'s
  `COPY deploy/fid/ /opt/vivarium/fid/` bakes them in. Each `.fidbf` ships with a sibling
  `*.fidbf.provenance.json` manifest (source version + digest, compiler/flags, Ghidra + generator
  version, `.fidbf` digest, SPDX license — `std-supplychain`).

## Licensing (ADR-043 D1/D5; SPIKE-2)

Only **permissively-licensed** sources may be bundled (allow-list:
`Zlib`/`MIT`/`Apache-2.0`/`BSL-1.0`/`BSD-2-Clause`/`BSD-3-Clause`). Copyleft sources
(`LGPL-*`/`GPL-*`/`AGPL-*`, OpenSSL pre-3.0) are **blocked** by the merge-blocking
`fid-license-gate` CI job and require counsel sign-off + a reviewed waiver before they may enter the
build. A `.fidbf` contains only non-reversible hashes + symbol names + metadata — **no library code**
(see `docs/security/fid-database-licensing.md`).
