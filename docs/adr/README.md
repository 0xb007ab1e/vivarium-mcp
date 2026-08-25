# Architecture Decision Records (ADR) index

This directory holds the numbered, append-only decision records for Vivarium (ADR-001 … ADR-075).
Each ADR captures one significant decision: its context, the decision, alternatives, and consequences.
Records are **point-in-time** — a `Status:` of *Proposed* reflects the record when it was written; what
actually shipped in each release is tracked in [`../../CHANGELOG.md`](../../CHANGELOG.md) and the
delivery plan [`../../PLAN.md`](../../PLAN.md). Environment-variable names in the older ADRs predate the
rename to Vivarium (ADR-038); the authoritative, current config reference is
[`../getting-started.md`](../getting-started.md) and `src/vivarium/config.py`.

## Suggested reading order (newcomers)

Start with the load-bearing decisions that define the security model, then read by area:

1. **ADR-001** — the server never loads the JVM / a hostile binary (the core containment rule).
2. **ADR-002** — one disposable worker per session; verified store wipe.
3. **ADR-005** — the untrusted-data envelope on every binary-derived output.
4. **ADR-004** — the worker isolation tier (rootless OCI + gVisor).
5. **ADR-006** — stdio-first transport; HTTP is a gated increment.

The frozen wire/tool contracts these build on live in [`../contracts/`](../contracts/README.md); the
system-level view is in [`../architecture.md`](../architecture.md) and the STRIDE analysis in
[`../security/threat-model.md`](../security/threat-model.md).

## By theme

### Execution model & isolation (the trust core)
- **ADR-001** — Out-of-process Ghidra worker is mandatory (server never loads the JVM).
- **ADR-002** — One worker per session, killed on eviction; verified store wipe.
- **ADR-003** — Container-only worker; Ghidra 12.1.2 + JDK 21 pinned by digest.
- **ADR-004** — Worker isolation tier: rootless OCI baseline + gVisor.
- **ADR-009** — Concrete worker launcher, import-root mount, per-session socket subdir.
- **ADR-023** — Configurable worker resources + distinct OOM/exit error.
- **ADR-025** — Session liveness during a long in-flight call (no idle-eviction mid-call).
- **ADR-029** — Large-binary analysis: analyzer-profile selector + pre-flight reject mode.
- **ADR-035** — Analyzer-option existence guard (fail closed on an unknown preset option).
- **ADR-037** — Classify the JVM heap-OOM self-exit as `resource-exhausted`.

### Contracts & data handling
- **ADR-005** — Untrusted-data envelope for all binary-derived output.
- **ADR-006** — stdio-first transport; HTTP is a gated v1.1 increment.
- **ADR-036** — Dedicated `forbidden` (403) authorization-denied error type.
- **ADR-039** — Run status reporting to the end user.

### Import & loaders (v1.8)
- **ADR-045** — `session_import` loader hints: raw/headerless binary import (`loader="binary"`).
- **ADR-046** — Loader selection: Intel-HEX / Motorola-SREC firmware images.
- **ADR-047** — Self-describing loaders: DEX / Mach-O / APK (force the loader).
- **ADR-048** — Loader options: fat/universal Mach-O slice selection (DYLD-component deferred).
- **ADR-061** — PDB companion symbols: apply a Microsoft PDB at import (`session_import` `pdb_ref`).
- **ADR-063** — DYLD shared-cache support — **DEFERRED** (fixture-blocked; capability ready).

### v1.9 capability-gap batch (post-v1.8 survey)
- **ADR-064** — Data-flow slicing (`data_flow_slice`; read-only def-use/taint) — **MERGED** (#294).
- **ADR-065** — Multi-region / scatter-load raw import (same-arch regions into one session) — **Accepted**.
- **ADR-066** — Emulation ergonomics: call-with-args + library-call stubs on `emulate` — **Accepted**.
- **ADR-067** — Function-granularity binary-diff report (patch-diffing) — **Accepted**.
- **ADR-068** — String / constant deobfuscation (stack-strings, XOR-decoded) — **Accepted**.
- **ADR-069** — Automatic struct/type recovery from access patterns (proposes; existing write applies) — **Accepted**.
- **ADR-070** — Extended firmware container unwrap + loaders (OTA/uImage/decompress, fuzz-gated) — **Accepted**.
- **ADR-071** — Debug-info import beyond PDB (DWARF / `.map` / `.sym`) — **Accepted**.
- **ADR-072** — Firmware-aware secret/credential/key-material scan (redacted) — **Accepted**.

### Validation-driven detection batch (blind-triage benchmark remediation)
- **ADR-073** — Program-level fingerprint (`program_fingerprint`) + offline family-match corpus (`family_match`) — **Accepted** (`program_fingerprint` MVP implemented; `family_match`/corpus + VT-hashes fast-follow).
- **ADR-074** — Capability detection + MITRE ATT&CK tagging (`capability_scan`, capa-style) — **Proposed**.
- **ADR-075** — Crypto detection by API/import/instruction (`crypto_detect`; complements `crypto_constant_scan`) — **Accepted** (import + api_name sources implemented; instruction/code_pattern fast-follow).

### Read/analysis tools
- **ADR-007** — Semantic-naming support tools (call graph, leaf-first ordering, function context).
- **ADR-008** — Tier-2 reporting & metrics tools (read-only analysis layer).
- **ADR-010** — Semantic-naming reference client + naming-quality eval.
- **ADR-042** — Library-function identification via Ghidra FunctionID (FID).
- **ADR-043** — FID Phase 2: bundled permissive-source ELF FunctionID databases.
- **ADR-049** — Bounded p-code `emulate` tool (interpreter; no native exec/syscalls/IO).
- **ADR-050** — C++ symbol demangling (`demangle`; read-only, program-independent).
- **ADR-052** — P-code (IR) listing (`get_pcode`; read-only).
- **ADR-053** — High (SSA) p-code listing (`get_high_pcode`; read-only).
- **ADR-054** — Recovered stack-frame layout (`stack_frame`; read-only).
- **ADR-055** — Control-flow graph / basic blocks (`basic_blocks`; read-only).
- **ADR-056** — Data-type enumeration (`list_data_types`; read-only).
- **ADR-057** — Function match-hashes (`function_hash`; read-only).
- **ADR-058** — BSim fuzzy similarity between two functions (`bsim_similarity`; read-only).
- **ADR-059** — Whole-program BSim clone/variant search (`find_similar_functions`; read-only).
- **ADR-060** — Version Tracking: two-program function matching (`version_track`; read-only w.r.t. the session).
- **ADR-062** — Cross-binary BSim search over an ephemeral corpus (`bsim_search_corpus`; read-only w.r.t. the session).

### Write / mutation tools (all consent-gated)
- **ADR-012** — Mutation (write) tools — first gated increment.
- **ADR-013** — Structural mutation tools — Phase A (local/parameter rename).
- **ADR-014** — Structural mutation — Phase B (signature + data-type apply).
- **ADR-015** — Composite-type creation — Phase C (`define_struct`/`define_union`).
- **ADR-021** — Multi-type composite batch (`define_types`) with cycle detection.
- **ADR-031** — Gated deletion of session-authored composite types.
- **ADR-026** — Rename name-collision handling.
- **ADR-051** — Bundled type-archive application (`apply_type_archive`; structural write).

### Annotation persistence
- **ADR-018** — Cross-session annotation persistence (export + import).
- **ADR-024** — Fix `export_annotations` on real programs + worker-error observability.
- **ADR-027** — Export only user-authored annotations.
- **ADR-032** — `define_types` annotation round-trip (interdependent composite graphs).

### Streaming & progress
- **ADR-030** — Progress signal during a long `analyze`.
- **ADR-040** — Streaming partial results (pull-based job + cursor).
- **ADR-041** — Mid-stream cancellation of a decompile stream.

### HTTP transport, identity & authorization
- **ADR-011** — HTTP transport: secure-by-default, auth-pluggable.
- **ADR-017** — Multi-principal authorization (per-principal session ownership).
- **ADR-019** — mTLS + OAuth identity sources (pluggable principals).
- **ADR-020** — mTLS peer-cert bridge (custom uvicorn HTTP protocol).
- **ADR-033** — OAuth scopes → fine-grained per-tool authorization.
- **ADR-034** — Reverse-proxy-terminated mTLS (opt-in, shared-secret-anchored).

### Quality, evaluation & operations
- **ADR-016** — Behavioral-equivalence differential-run harness.
- **ADR-022** — Deeper behavioral-equivalence eval (output normalization + fuzz inputs).
- **ADR-028** — Recurring live-regression harness (blind-acceptance run promoted into CI).
- **ADR-044** — Operational observability: in-process metrics SLIs + unauthenticated health probes.

### Project
- **ADR-038** — Rename the project `ghidra-mcp` → `Vivarium`.
