# Reproducing the full first-party decompilation

Requirements: a C toolchain, perl, curl, Ghidra (with `support/analyzeHeadless`),
and a JDK Ghidra supports. Memory note: with the guards below, peak memory is about
1.5 GB; without them the run will OOM (see REPORT.md section 3).

## 1. Build the subject (keep the unstripped binary)

Use `../openssl-blind-analysis/build-openssl-fixture.sh`, but keep the unstripped
`apps/openssl` (it has symbols, which makes the first-party filter and names exact).
The build configures OpenSSL 4.0.1 with `no-shared no-docs no-tests -static`.

## 2. Build the first-party allow-list

From the build tree, collect defined text symbols from OpenSSL's own archives:

```
{ nm libcrypto.a; nm libssl.a; nm apps/libapps.a; for o in apps/*.o; do nm "$o"; done; } \
  | awk '$2 ~ /^[tT]$/ {print $3}' | sed '/^$/d' | sort -u > first-party-allowlist.txt
```

## 3. Analyze once and save the project

```
analyzeHeadless <projdir> proj_ossl -import <build>/apps/openssl
```

This imports, auto-analyzes, and saves the analyzed program. Do this as its own
step so a later decompile crash never costs the analysis.

## 4. Decompile in bounded, resumable chunks

Run `scripts/ExportChunk.py` against the saved project, repeatedly, until it reports
`CHUNK_DONE new=0`. The script skips functions already in the index and appends new
ones, so it is resume-safe.

```
export ALLOWLIST=first-party-allowlist.txt
export OUT_C=openssl_firstparty_decompiled.c
export OUT_IDX=index.csv
export MAX_PER_RUN=2500 DISPOSE_EVERY=50 MAX_PAYLOAD_MB=30 DECOMP_TIMEOUT=30 MAX_FN_BYTES=40000

while :; do
  analyzeHeadless <projdir> proj_ossl -process openssl -noanalysis -readOnly \
    -scriptPath scripts -postScript ExportChunk.py
  grep -q 'CHUNK_DONE new=0' <last log> && break
done
```

The guards (`DISPOSE_EVERY`, `MAX_PAYLOAD_MB`, `DECOMP_TIMEOUT`, `MAX_FN_BYTES`) are
what keep memory bounded and make pathological functions abort gracefully instead of
OOMing. See REPORT.md section 3.

## 5. Verify

Compare `openssl_firstparty_decompiled.c` and `index.csv` SHA-256 against the values
in `manifest.json`. Exact byte-for-byte reproduction depends on the Ghidra version
(this run used 10.3.2); the function set and identifications are stable across
versions even if formatting shifts.
