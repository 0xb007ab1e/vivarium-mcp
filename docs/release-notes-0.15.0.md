# Vivarium 0.15.0 — release notes (2026-11-05)

> Android/firmware **loader + unwrap** coverage, Apple **dyld shared-cache** analysis, the
> **deobfuscation** family, and the dashboard interactive backend's **§21 pre-exposure security
> controls** — released together as **0.15.0**. No breaking changes; every addition is read-only or an
> opt-in/consent-gated capability, and the containment model (ADR-001/002/005) is unchanged.

**Highlights:** import + analyze an **Apple dyld shared-cache** component; a structured **Android
ramdisk** file tree with **lz4** (standard + legacy frame) support; the **`deobfuscate_strings`**
family grows to cover multi-stage, interprocedural, stateful/stream-cipher, and self-modifying-unpacker
decoders; and the status dashboard's interactive command surface gains **per-principal auth, an
app-layer rate limiter, and redacted per-command audit**. The Tier-1 tool catalog grows **74 → 81**.

---

## What's new

### Apple dyld shared-cache analysis

- **`loader="dyld"` + `dyld_component`** — mount a dyld shared cache, extract the named component
  dylib (through the cache's own `DyldCacheFileSystem` / `DyldCacheExtractLoader`), and import it as
  Mach-O; omit `dyld_component` for a bounded component listing. (ADR-086, #369)
- **`list_cache_components`** — a read-only tool to discover a cache's component dylibs without a
  failed import. (ADR-089, #418)

### Android boot-image + ramdisk

- **`container_region="ramdisk"`** surfaces the decompressed cpio ramdisk for string/byte triage —
  gzip / xz / uncompressed-cpio, and now **lz4 standard + legacy frame** (the common Android format,
  via a pure fuzzed `core.lz4legacy` + `lz4.block`). (ADR-085 #380, ADR-088 #414)
- **`ramdisk_list`** parses that ramdisk into a structured cpio **file tree** (path / size / mode /
  kind / address); per-file extract composes with `read_bytes`. (ADR-087, #415)

### String deobfuscation (`deobfuscate_strings`)

Recovers local string decoders by bounded p-code emulation, extended across this release to:
**multi-stage / chained** (ADR-081), **ADD-const** (#401), **interprocedural** (ADR-082),
**stateful / stream-cipher** (`stream_decode`, ADR-083), and **self-modifying unpackers**
(`unpack`, ADR-084). Function-scoped; gated/whole-program paths stay fail-closed.

### Dashboard interactive backend — §21 pre-exposure security controls

The interactive command surface (`POST /api/command`, **default-OFF**) gains the three hard
prerequisites before any compute executor or wider exposure, **reusing the server** (ADR-017/019):
**per-principal auth** (a `{token: principal}` map; interactive-without-auth fails closed at
startup), an **app-layer rate limiter** scoped to the command path (GET navigation never throttled),
and a **redacted per-command audit log** (principal / op / decision / status — never params or binary
content). The compute `WorkerExecutor` and production enablement remain **gated**. (ADR-076 §21, #368)

### Cross-binary + detection

- **Cross-binary corpus links + export-on-close** for the memory-graph exporter (ADR-080, #367).
- **`secret_scan` byte-magic sub-pass** — detect binary-only container/bootloader magic (ADR-072).

---

## Security & supply chain

- An independent **security/quality review** of the dyld/ramdisk/lz4 increments and the §21 dashboard
  auth returned **approve**; its findings (parser-hardening, recursion/parity, parse-before-auth, audit
  redaction) were remediated in-release. Hostile-byte parsers (`core.cpio`, `core.lz4legacy`) are
  fuzzed + fail-closed; the dashboard auth path is covered 100%.
- One new vetted, hash-pinned dependency: **`lz4`** (BSD-3-Clause), imported only inside the worker.
- The worker image is rebuilt, Trivy-scanned, cosign-**signed**, and SBOM'd per increment; the
  live-regression trust pin advances only to a verified signed digest.

## Compatibility

No breaking changes. New tools are read-only or consent-gated; `session_import` is byte-for-byte
unchanged with no hint set. The out-of-process worker + untrusted-data envelope containment model is
unchanged (ADR-001/002/005).
