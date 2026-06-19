# Roadmap — v1.7 backlog (candidate)

> Source of truth for delivery: [`PLAN.md`](../PLAN.md). Decisions are ADRs in [`docs/adr/`](adr/);
> the threat model is [`docs/security/threat-model.md`](security/threat-model.md); frozen contracts are
> in [`docs/contracts/`](contracts/); release history is [`CHANGELOG.md`](../CHANGELOG.md). Prior
> backlogs: [`roadmap-v1.4.md`](roadmap-v1.4.md), [`roadmap-v1.5.md`](roadmap-v1.5.md),
> [`roadmap-v1.6.md`](roadmap-v1.6.md).

## Status

**Candidate backlog, not committed scope.** v1.6 shipped (released as **v0.8.0**, 2026-06-19): the
ADR-037 JVM heap-OOM → `resource-exhausted` reclassification + memory-sizing hint, the fully-offline
vendored-Semgrep SAST gate, and the tool-catalog prose fix.

**The substantive backlog is genuinely thin, and that is the headline.** A blind-binary acceptance run
against the released **v0.8.0** (below) was **clean end-to-end** — the read chain, the gated write
path, annotation export, and the store-wipe all work on the real worker with no regressions. The big
findings from earlier runs were already driven into v1.3–v1.6. What remains is **deferred-pending-a-real-need**
(incremental analysis, import progress), **infra-gated** (self-hosted gVisor runner), or **minor
polish** (the two items the v0.8.0 run surfaced). This roadmap records that honestly rather than
manufacturing scope.

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
| 1 | **Self-hosted gVisor runner** for per-PR isolation acceptance (ADR-004 / `verify-isolation.sh`) | Infra / CI | none | minor | carry-forward (ADR-028 §D3); the one real CI gap |
| 2 | **Export `binary.name` / `binary.size` population** in the annotation document | Persistence / polish | additive (doc fields) | patch | v0.8.0 acceptance run |
| 3 | **Minor polish / maintenance** (origin-tagging doc note; pyelftools `eval` extra; ADR-022 deeper eval) | Docs / maint | none | patch | v0.8.0 run + v1.6 carry-forward |
| 4 | Carry-forward **deferred** (gates restated): incremental analysis · `session_import` progress | — | — | — | v1.5/v1.6 deferrals |

---

## 1. Self-hosted gVisor runner for isolation acceptance (the one real CI gap)

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

## 3. Minor polish / maintenance

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

## 4. Carry-forward deferrals (gates restated)

- **Incremental / lazy analysis (ADR-029 §D5).** Still deferred. The v1.5 #5 measurement spike
  confirmed the large-binary blocker is **peak memory**, which is **configurable** (ADR-023
  `GHIDRA_MCP_WORKER_MEM_MIB`) — raising the cap converted a fast OOM into a stable analysis. Incremental
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
