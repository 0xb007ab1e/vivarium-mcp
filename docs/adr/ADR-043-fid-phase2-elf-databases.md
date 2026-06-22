# ADR-043: FID Phase 2 — bundled ELF FunctionID databases (permissive-source, build-time)

- **Status:** **Accepted** (ratified 2026-06-21; v1.x). Implements Phase 2 of
  **[ADR-042](./ADR-042-function-id-signature-identification.md)**. Builds on **SPIKE-1** (the
  headless custom-`.fidb` build chain, proven end-to-end in #150) and **SPIKE-2**
  ([`docs/security/fid-database-licensing.md`](../security/fid-database-licensing.md), the
  permissive-only licensing path). **O1 spike run** (below) — both activation mechanisms
  characterized; implementation may proceed.
- **Date:** 2026-06-21
- **Deciders:** Human (ratifies) + PM; recorded by the Software Architect.
- **Context source:** ADR-042 shipped `identify_functions` (Phase 1), but Ghidra bundles FID
  databases for **MSVC/Windows only** — so on ELF (Vivarium's primary target) the tool returns ~0
  matches. Phase 2 adds **ELF** FID databases so the tool identifies Linux library code.

## Context

Phase 1's value is Windows-skewed: the `identify_functions` machinery is shipped + CI-gated, but
without ELF databases it cannot label libc/crypto/compression functions in Linux binaries. The two
gates ADR-042 deferred Phase 2 behind are now cleared:

- **SPIKE-1 (technical) — proven (#150).** A `.fidb` can be built, attached, and **activated**
  headlessly: `createNewFidDatabase` → `addUserFidFile` → `getFidDB(true)` →
  `createNewLibraryFromPrograms([DomainFile], …)` → `saveDatabase` → `close` → **remove + re-add the
  FidFile** (a file attached while empty caches `canProcessLanguage()==False`) → `setActive(true)` →
  `openFidQueryService` → `processProgram` → matches. (Self-match is a live-regression hard gate.)
- **SPIKE-2 (licensing) — analyzed.** A `.fidb` (non-reversible hashes + uncopyrightable symbol
  names + metadata, **no code**) is almost certainly not a derivative work, and a **permissive-only**
  source set is shippable under our Apache-2.0 image **without a hard legal ruling**. Copyleft
  (glibc/Qt LGPL, GPL/AGPL) stays deferred to counsel.

## Decisions

- **D1 — Permissive-only v1 source set (per SPIKE-2).** Generate ELF FID databases from, and only
  from: **musl libc (MIT)** — the static-libc identification workhorse and the glibc-role substitute;
  **OpenSSL 3.0+ (Apache-2.0)**; **zlib (Zlib)**; **Boost (BSL-1.0)**. (BSD libs may follow.)
  **Excluded** from v1: glibc + Qt (LGPL — CAUTION), readline/GPL, AGPL, OpenSSL pre-3.0 (AVOID) —
  each requires counsel sign-off before it may enter the build (SPIKE-2 §5).

- **D2 — Build-time generation via Ghidra's FID build tooling, never at runtime.** A dedicated, gated
  build stage compiles each library from **pinned-by-digest source** (unstripped, with symbols) and
  produces a **packed `.fidbf`** using **Ghidra's FunctionID database build tooling** (the
  `analyzeHeadless` FunctionID prescript / packed-DB creator that the shipped MSVC DBs are made
  with), one per *(library, version, processor)*. **O1 finding:** the simple `createNewFidDatabase`
  service API (the SPIKE-1 chain) yields an **unpacked** DB that Ghidra's data-dir scan does **not**
  discover — so generation must use the real packed-DB tooling, not the raw service API. The worker
  **never** ingests or mutates a DB at runtime (ADR-001 isolation + read-only-rootfs). Reproducible;
  each `.fidbf` is pinned by digest.

- **D3 — Activation by "installed" placement (primary); startup-attach (proven fallback).** Bake the
  packed `.fidbf` into Ghidra's FunctionID **data directory** (`Ghidra/Features/FunctionID/data/`)
  **next to the shipped MSVC DBs**, so they are *installed* and **active by default** — SPIKE-0
  confirmed shipped DBs there report `active=True` headless, so `identify_functions` (which queries
  active DBs) matches ELF with **zero tool code change**. This requires the **packed** format (D2);
  **O1 confirmed an *unpacked* DB dropped in `data/` is silently ignored.** **Fallback (proven,
  SPIKE-1):** a one-time worker-startup `addUserFidFile` + `setActive` of the bundled DBs — but O1
  found `addUserFidFile` returns `None` on a read-only/wrong-format path, so the fallback needs the
  DB presented in a writable, accepted form (copy into the tmpfs at startup). Either way: no
  per-request work. **Decision: pursue data-dir-packed (D2 tooling) as primary; keep startup-attach
  as the validated fallback.**

- **D4 — Supply chain (each DB is a pinned, attested artifact).** Generation source tarballs are
  verified by digest; each `.fidb` is digest-pinned and baked into the **worker image** → the image
  digest changes, flowing through the existing `propose-pin-bump` automation (#129/#149). Ship per
  SPIKE-2: a **provenance manifest** per DB (source + exact version + source digest + compiler/flags
  + Ghidra + generator version + `.fidb` digest), an **SBOM entry** with the source's SPDX license
  ID, **NOTICE** attribution aggregation, and a **"hashes + names, no code" disclaimer**.

- **D5 — License-allow-list CI gate (wire `topic-license-compliance`).** A merge-blocking gate over
  the DB **source set**: allow `Zlib`/`MIT`/`Apache-2.0`/`BSL-1.0`/`BSD-2-Clause`/`BSD-3-Clause`;
  **block** `LGPL-*`/`GPL-*`/`AGPL-*`/`OpenSSL` (pre-3.0). A copyleft source cannot enter the build
  without an explicit, reviewed, time-boxed waiver + counsel sign-off (SPIKE-2).

- **D6 — No tool-contract change; additive behavior.** `identify_functions` is unchanged (catalog
  stays **56**; same `In`/`Out`, same untrusted-envelope + bounds). The only observable change is
  that it now returns **non-empty** matches on ELF — purely additive. Expected bump: **minor**
  (capability delivered via bundled data + a worker-image change); **no frozen-contract delta**, so
  no WS0 contract churn.

- **D7 — v1 scope = x86-64 first.** Databases are processor-specific; ship **x86-64** ELF DBs in v1
  (the dominant target). Other arches (aarch64, …) are a follow-on once the pipeline is proven.

## Open items (resolve during implementation)

- **O1 — auto-activation of generated DBs in the data dir — ✅ RESOLVED (spike, 2026-06-21).**
  Finding: Ghidra's data-dir scan only discovers **genuinely packed `.fidbf`** (a raw
  `createNewFidDatabase`/`saveDatabase` DB, even renamed `.fidbf`, is silently ignored); the shipped
  MSVC DBs are packed + `active=True` by default. So **D2 must use Ghidra's packed-DB build tooling**,
  and D3 data-dir placement works only with that packed output. Startup-attach is the proven fallback
  but `addUserFidFile` needs a writable/accepted path (returns `None` otherwise). Remaining sub-task
  (implementation): wire the packed-DB build step (the `analyzeHeadless` FunctionID flow).
- **O2 — generation mechanism + arch matrix** — `FunctionIDHeadlessPrescript` vs a PyGhidra generator;
  confirm per-arch coverage; settle the exact build flags for stable, reproducible hashes.
- **O3 — exact source versions** — musl (static), OpenSSL 3.x, zlib, Boost subset; pin each.
- **O4 — image size / DB-set bound** — cap the bundled set; measure image growth + `processProgram`
  cost on large programs (output is already bounded by the Phase-1 `limit`).

## Testing

- **New live-regression hard gate:** a benign, statically-linked ELF built at test time from a
  **bundled** library (e.g. a tiny musl- or zlib-static program) must yield **≥1 real FID match via
  `identify_functions` through the MCP stack** — extends the proven self-match approach
  (`test_identify_functions_selfmatch.py`) to the *shipped* DBs (not a self-built one).
- Keep the existing empty-match (ELF-vs-MSVC) and self-match gates.
- License-gate negative test: a copyleft source in the DB build list fails the gate (SPIKE-2 §4).

## Consequences

- **Positive:** real library identification on ELF — closes Phase 1's Windows skew; the highest-value
  remaining FID work, delivered with no tool-contract change and **no legal ruling required** (D1).
- **Negative / costs:** worker-image size grows with the DB set; build-time generation + ongoing
  **DB maintenance** as libraries update (re-generate, re-pin); glibc/Qt (the most common Linux libc
  + GUI toolkit) stay **out** until counsel clears them (musl mitigates the libc gap, not Qt).

## Alternatives considered

- **Ship third-party prebuilt DBs (threatrack, MIT).** *Rejected* — we pin + build from source for
  provenance/auditability (`std-supplychain`); a prebuilt binary DB is unverifiable input.
- **Runtime ingest / user-supplied DBs.** *Rejected* — breaks the read-only worker posture (ADR-001)
  and needs unstripped reference libs the user won't have.
- **glibc-first.** *Rejected* — LGPL (counsel-gated, SPIKE-2); musl covers the static-libc role.

## References

- ADR-042 (Phase 1 + SPIKE-0/1 record); `docs/security/fid-database-licensing.md` (SPIKE-2);
  `tests/integration/fid_selfmatch_inworker.py` (the proven generation chain); `std-supplychain`
  (pin/SBOM/provenance), `topic-license-compliance` (the license gate), ADR-001/002 (worker isolation).

---
_Awaiting ratification. On ratification: resolve O1–O4 in a short implementation spike, then build
the pipeline + the x86-64 permissive DB set + the new live-regression gate; copyleft DBs remain
counsel-gated._
