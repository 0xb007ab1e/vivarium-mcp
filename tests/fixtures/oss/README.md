# OSS ground-truth e2e fixtures (WS5)

A **known-answer sanity check**: run real, source-available Linux tools through the full
vivarium pipeline (MCP stdio → real Ghidra worker) and compare Ghidra's *recovered* structure
against a **ground truth** derived from the tools' own source/symbols. It answers, end to end:
*can the server ingest a binary, decompile/analyze it, produce a leaf-first reverse call-graph
order, and return results — and is what it returns actually correct?*

## The three tools (`manifest.toml`)

| Tool | Analyzed binary | Why |
|------|-----------------|-----|
| **cJSON** 1.7.18 | a tiny driver linked with `cJSON.c` | single-file MIT parser; rich self-contained `parse_*`/`print_*` call graph |
| **zlib** 1.3.1 | `minigzip` | the bundled gzip-ish tool → deflate/inflate/crc call graph; robust hand-written `./configure --static` (no autotools) |
| **lua** 5.4.7 | `lua` interpreter | rich VM + stdlib call graph; plain Makefile (`make posix`), no autotools |

(coreutils/util-linux were evaluated but dropped: GNU autotools + gnulib makes them CI-build-fragile on a moving glibc/toolchain — wrong dependency for a *sanity check*.)

## How the ground truth is made (`build_fixtures.py` → `extract_ground_truth.py`)

1. **Fetch** each pinned source tarball and **verify its SHA-256** (`manifest.toml`; fail closed).
2. **Build** with `-g -O0 -fno-inline -no-pie`:
   - `-g` → DWARF, so we know the tool's **own** functions (name + address), excluding
     statically-linked libc (no DWARF) and system headers (filtered by compilation-unit path).
   - `-no-pie` → `ET_EXEC` absolute addresses, so a ground-truth address **equals** the address
     Ghidra reports for the stripped copy (no rebasing).
   - `-O0 -fno-inline` → the call graph is preserved (calls aren't inlined away).
3. **Extract** the truth (`extract_ground_truth.py`): functions from DWARF `DW_TAG_subprogram`
   DIEs; direct `caller -> callee` edges by disassembling each body (capstone) and resolving
   direct `call`/tail-`jmp` immediates that land in another known function. The truth is a
   deliberate **subset oracle** — everything in it is real, but it does not claim completeness.
4. **Strip** a copy — that stripped binary is what Ghidra analyzes (so it must invent `FUN_<addr>`).

Output per tool: `<name>.stripped`, `<name>.groundtruth.json`, `<name>.meta.json`, plus `index.json`.

## How the comparison works (`../../e2e/_groundtruth.py`)

`compare()` (pure, unit-tested in `tests/unit/test_groundtruth_compare.py`) scores Ghidra's
recovery with **tolerances**, not exact equality (Ghidra output drifts by version):

- **function recall** — fraction of truth functions whose entry address Ghidra also recovered.
- **edge recall** — fraction of truth edges present in Ghidra's `call_graph`, over the *fair*
  denominator of edges whose **both** endpoints were recovered.
- **leaf-first consistency** — every recovered truth edge `caller -> callee` must place the callee
  at-or-before the caller in `analysis_order`'s SCC components (same component = a cycle, allowed).

Per-tool thresholds live in `test_groundtruth_oss.py`.

## Hermeticity & gating

- The **build** (network + toolchain) is **GATED** — it runs only in `.github/workflows/e2e-groundtruth.yml`
  (manual dispatch), never in the fast PR/unit job. The committed repo contains **no binaries**
  (`.gitignore` excludes `samples/`); only source, the driver, and these scripts are committed.
- The **e2e** (`tests/e2e/test_groundtruth_oss.py`) is hermetic at run time (consumes the artifact,
  no network) and **self-skips** unless `VIVARIUM_INTEGRATION` + `VIVARIUM_FIXTURES` +
  `VIVARIUM_WORKER_IMAGE` + a container engine are all present.
- The **pure scorer + extractor methodology** are validated offline in the normal CI run.

## Supply-chain pins

- `manifest.toml` `sha256` values are **pinned** to the upstream releases (cJSON 1.7.18,
  zlib 1.3.1, lua 5.4.7); `build_fixtures.py` verifies each and fails closed on a
  mismatch. Re-pin when bumping a version.
- `e2e-groundtruth.yml` actions are pinned **by digest**; the worker image is pulled **by digest**
  from `vars.WORKER_IMAGE_DIGEST` (the signed digest of the most recent `worker-image.yml` run) and
  `cosign verify`d (scoped to this repo's `worker-image.yml` OIDC identity) before it is run.

## Run it

```bash
# 1) GATED build (toolchain host with gcc/make/python3.11+, pyelftools, capstone, network):
python tests/fixtures/oss/build_fixtures.py --out /tmp/fix          # all 3
python tests/fixtures/oss/build_fixtures.py --out /tmp/fix --only cjson

# 2) Gated e2e against a built+signed worker image:
export VIVARIUM_INTEGRATION=1 VIVARIUM_FIXTURES=/tmp/fix
export VIVARIUM_WORKER_IMAGE=ghcr.io/0xb007ab1e/vivarium-worker@sha256:...
pytest tests/e2e/test_groundtruth_oss.py -m integration -v --no-cov
```
