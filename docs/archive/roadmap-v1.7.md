# Roadmap — v1.7 backlog (candidate)

> Source of truth for delivery: [`PLAN.md`](../PLAN.md). Decisions are ADRs in [`docs/adr/`](adr/);
> the threat model is [`docs/security/threat-model.md`](security/threat-model.md); frozen contracts are
> in [`docs/contracts/`](contracts/); release history is [`CHANGELOG.md`](../CHANGELOG.md). Prior
> backlogs: [`roadmap-v1.4.md`](roadmap-v1.4.md), [`roadmap-v1.5.md`](roadmap-v1.5.md),
> [`roadmap-v1.6.md`](roadmap-v1.6.md).

## Status

**Committed headline: ADR-042 Function ID (Phase 1).** Since v1.6 (v0.8.0) two increments shipped
out-of-band: **v0.9.0** (the `ghidra-mcp → Vivarium` rename, ADR-038) and **v0.10.0** (streaming
partial results + mid-stream cancellation, ADR-040/041, catalog 51 → 55, acceptance-green). With the
streaming work done, the v0.10.0 functional-gap review picked the next headline: **library-function
identification via Ghidra FunctionID** (ADR-042) — the highest-leverage *new* capability for the core
naming workflow: auto-label known library code so the LLM focuses on the actual program.

**Scope is phased on an SME finding (see ADR-042).** Ghidra ships FID databases for **MSVC/Windows
only**; ELF coverage (libc/OpenSSL/zlib) means **generating our own `.fidb`** at build time, which
carries two unverified blockers (headless custom-DB activation API; licensing of a copyleft-derived
DB). So v1.7 commits **Phase 1 only** — a read-only `identify_functions` tool surfacing the matches
Ghidra's already-running analyzer produces from the bundled MSVC DBs (zero custom DBs, zero licensing
exposure, additive contract 55 → 56). **Phase 2** (ELF DBs) stays **deferred behind SPIKE-1 + SPIKE-2**
with its own ADR/ratification.

**The rest of the backlog remains genuinely thin.** A blind-binary acceptance run against **v0.8.0**
(below) was clean end-to-end; the big findings from earlier runs were already driven into v1.3–v1.6.
What remains beyond the FID headline is **deferred-pending-a-real-need** (incremental analysis, import
progress), **infra-gated** (self-hosted gVisor runner), or **minor polish** (folded into v1.7). This
roadmap records that honestly rather than manufacturing scope.

> Promotion path unchanged: **design ADR → human ratification → implement (isolated worktree) →
> `sdlc-reviewer` security pass → CI green → gated merge.** Pre-1.0: items are additive/opt-in unless
> noted; a frozen-contract change carries a version bump + threat-model review.

### v0.8.0 blind-acceptance run — result (2026-06-19)

Ran `scripts/acceptance_run.py` against the released code on a benign binary (`/bin/bzip2`, 134
functions) via the real hardened worker (crun):

| Phase | Result |
|---|---|
| Mode A: import → analyze → list → select top-20 → per-function decompile+context dump | **20/20 dumped, 0 failures**; import 8.1s, analyze 3.7s, dump 10.9s; `session_close store_wiped=true` |
| Mode B: `session_enable_writes` consent → 20 gated `rename_function` → `session_export_annotations` | **20/20 applied; export emitted exactly the 20 renames** (the ADR-027 change-log path), each wrapped in the ADR-005 untrusted envelope |

**Conclusion:** v0.8.0 is solid end-to-end; no new high-severity findings. Two minor items (§3 below).

## Priorities (suggested)

| # | Item | Area | Contract / TB impact | Expected bump | Source |
|---|------|------|----------------------|---------------|--------|
| 1 | **FID Phase 1 — `identify_functions`** (read-only; bundled MSVC DBs) | Capability (headline) | additive (catalog 55 → 56; new untrusted output path) | minor | **ADR-042** |
| 2 | **Export `binary.name` / `binary.size` population** in the annotation document | Persistence / polish | additive (doc fields) | patch | v0.8.0 acceptance run |
| 3 | **Echo effective analysis profile** (`light`/`deep`) in `SessionInfo` | Observability / polish | additive (doc field) | patch | v0.10.0 gap review (ADR-029 §Negative) |
| 4 | **Minor polish / maintenance** (origin-tagging doc note; pyelftools `eval` extra; ADR-022 deeper eval) | Docs / maint | none | patch | v0.8.0 run + v1.6 carry-forward |
| 5 | **Self-hosted gVisor runner** for per-PR isolation acceptance (ADR-004 / `verify-isolation.sh`) | Infra / CI | none | minor | carry-forward (ADR-028 §D3); the one real CI gap — still deferred |
| 6 | Carry-forward **deferred** (gates restated): incremental analysis · `session_import` progress · **FID Phase 2 (ELF DBs)** behind SPIKE-1/2 | — | — | — | v1.5/v1.6 deferrals + ADR-042 |

---

## 1. FID Phase 1 — `identify_functions` (the v1.7 headline)

**What.** A new **read-only** Tier-1 tool, `identify_functions(session)`, that surfaces the
library-function matches Ghidra's **Function ID** analyzer already produces — initially from the
**MSVC runtime DBs Ghidra bundles** (Windows/PE targets). Each match returns the function address, the
matched **library name/version** and **function name** (both in the **ADR-005 untrusted envelope**),
and **match-quality metadata** (full- vs. specific-hash, relation-corroborated, multiplicity), bounded
with a `truncated` flag. It is a **hint surface** — no rename, no auto-action (LLM09 overreliance).

**Why.** Auto-identifying known library code collapses the bulk of unknown-symbol noise so the client
LLM spends inference on the functions that are the actual program — the single highest-leverage gap
from the v0.10.0 review. Catalog **55 → 56**; additive contract (minor bump + threat-model note for
the new untrusted-output path and the FID-DB-as-trusted-input supply-chain edge).

**Scope boundary (see [ADR-042](adr/ADR-042-function-id-signature-identification.md)).** Phase 1 ships
**only** the MSVC-DB read path (zero custom DBs, zero licensing exposure). **Run SPIKE-0** first
(confirm the analyzer + bundled DBs are active/readable headlessly on the 12.1.2 worker — likely a
no-op, verify via the ADR-028 harness). The **`apply_signatures` write tool is deferred** (D2). **ELF
DB generation (Phase 2) is deferred** behind **SPIKE-1** (headless custom-`.fidb` activation API) +
**SPIKE-2** (licensing of a glibc/OpenSSL-derived DB — needs counsel), with its own ADR.

## 5. Self-hosted gVisor runner for isolation acceptance (the one real CI gap — still deferred)

**What.** ADR-004's runtime isolation acceptance (`deploy/verify-isolation.sh`: `--runtime runsc`,
no-net, caps-dropped, read-only rootfs) currently **cannot run in CI** — GitHub-hosted runners have no
gVisor, so `worker-image.yml` only ships an `isolation-verify-note` placeholder and the live-regression
harness runs under `crun` (the CI floor), not the production `runsc`. The actual isolation posture is
verified only manually on a gVisor-capable host. A self-hosted gVisor runner would close that gap and
let the per-PR `live-regression` label exercise the *production* isolation tier.

**Why deferred so far (ADR-028 §D3 gate).** Every JVM-edge / isolation regression to date has been
caught at *implement-time* by pre-merge live-verify, not by the nightly — so the cadence has been
sufficient. The cost is real: ongoing ops for a self-hosted runner **plus** the security surface of
running untrusted-binary analysis on a persistent runner. **Promote when:** isolation/JVM-edge drift
starts slipping past pre-merge verification, or a compliance need requires CI-proven `runsc` isolation.
Design-first (ADR): runner hardening, ephemerality, network egress controls, and the untrusted-code
threat model are the hard part, not the wiring.

## 2. Populate `binary.name` / `binary.size` in the export document

**What.** The v0.8.0 acceptance export (`session_export_annotations`) emitted
`"binary": {"name": null, "sha256": "<set>", "size": null}` — only the authoritative `sha256` is
overlaid server-side; `name` and `size` are left null.

**Why.** Low-value but easy: a consumer of the annotation document gets the integrity hash but no
human-facing size/name for provenance/triage. Populating them (server-side, from the import metadata
the server already holds — no binary parse) makes the document more self-describing. Additive doc
fields; confirm against the frozen annotation-document contract (likely a no-op additive change, but
check). Pairs with a quick test that export carries them.

## 3. Echo the effective analysis profile in `SessionInfo`

**What.** The analysis profile (`light`/`deep`, ADR-029) is applied but **not echoed** in results, so
the operator can't see which one ran. Surface the effective profile in `SessionInfo` (additive doc
field) for honesty/observability.

**Why.** Cheap, additive, and removes a small "which profile did I get?" ambiguity flagged in the
v0.10.0 gap review (ADR-029 §Negative). Pairs with a test asserting the field round-trips.

## 4. Minor polish / maintenance

- **Untrusted-origin doc note (Info).** The exported user-supplied `new_name` is tagged
  `origin: "binary-derived"`. This is *defensible* — on export the name is read back from the hostile
  Ghidra program, so treating it as untrusted (ADR-005) is the conservative, correct posture — but it
  reads as surprising ("I supplied that name"). Add a one-line note to the annotation-document /
  ADR-005 docs explaining why read-back values are untrusted regardless of who wrote them.
- **`pyelftools` `eval` extra (Info, v1.6 carry-forward).** `scripts/naming_eval.py` imports pyelftools
  lazily; add a hash-pinned `[project.optional-dependencies] eval = [...]` **only if naming-eval
  becomes routine** (not yet — speculative otherwise).
- **ADR-022 deeper behavioral-equivalence eval (deferred).** Memory-state equivalence and
  coverage-guided equivalence remain out of scope; revisit if the advisory naming/equivalence eval
  becomes a gating signal.

## 6. Carry-forward deferrals (gates restated)

- **FID Phase 2 — ELF FID DBs (ADR-042, deferred).** Build-time generation + bundling of libc/OpenSSL/
  zlib `.fidb` for Linux targets. Gated on **SPIKE-1** (headless custom-`.fidb` activation API,
  `FidFileManager`/`FidService` — Ghidra normally requires GUI attach+activate) and **SPIKE-2**
  (licensing of a copyleft/OpenSSL-derived DB — counsel sign-off). Generate from **permissively-licensed
  pinned sources only** until cleared; provenance per DB + SBOM; own ADR/ratification before build.
- **Incremental / lazy analysis (ADR-029 §D5).** Still deferred. The v1.5 #5 measurement spike
  confirmed the large-binary blocker is **peak memory**, which is **configurable** (ADR-023
  `VIVARIUM_WORKER_MEM_MIB`) — raising the cap converted a fast OOM into a stable analysis. Incremental
  analysis lowers *peak* memory, so it is justified **only** for **memory-capped hosts that cannot add
  RAM** *and* must analyze very large binaries. First levers stay: raise the cap, use `profile=light`.
- **`session_import` progress (ADR-030 deferred).** Still deferred: `pyghidra.open_program` exposes no
  monitor hook and import is ~0.4% of analyze time (the v0.8.0 run measured import 8.1s vs analyze
  3.7s — import is bounded and fast on a normal binary). Revisit only on a real large-import complaint
  + a confirmed hook.

---

## Permanently out of scope (not backlog)
- **`runScript` / arbitrary script execution** — the read-only/least-agency posture forbids it (PLAN §2; ADR-012).
- **Diffing the real hostile binary** in the eval harness — breaches ADR-001 (ADR-016 constraint).

## Maintenance (not features)
- **CVE / dependency hygiene** — keep the three locks (`requirements.lock` + `-dev` + `-sast`) current
  and regenerated together; the daily `scheduled-rescan.yml` rescans both the lockfiles and rebuilt
  images. A release build can fail-closed anytime a new base CVE lands — remediate via base re-pin
  (server) / apk floor (worker), as in v0.7.1.
- **Recurring acceptance run** — keep running the blind-acceptance harness on each release; it is the
  proven way new JVM-edge / observability findings surface (it found nothing new on v0.8.0, which is
  the goal). Refresh the vendored Semgrep rules (`infra/semgrep/refresh.sh`) on the same cadence.
- **Post-release doc/contract drift sweeps** — sync README banner + tool count + ADR range.
