# Roadmap — v1.4 backlog (candidate)

> Source of truth for delivery: [`PLAN.md`](../PLAN.md). Decisions are recorded as ADRs in
> [`docs/adr/`](adr/); the threat model is [`docs/security/threat-model.md`](security/threat-model.md);
> frozen contracts are in [`docs/contracts/`](contracts/); release history is
> [`CHANGELOG.md`](../CHANGELOG.md). Prior backlogs: [`roadmap-v1.2.md`](roadmap-v1.2.md),
> v1.3 findings [`roadmap-v1.3-findings.md`](roadmap-v1.3-findings.md).

## Status

**Candidate backlog, not committed scope.** v1.3 shipped F1–F7 (configurable worker resources, worker
OOM/error observability, export crash-fix + user-authored-only export, session liveness during long
calls, rename-collision docs) — see the v1.3 PRs and `roadmap-v1.3-findings.md`. The items below are
drawn from **deferred ADR items**, the **blind real-world acceptance run**, and maturity gaps. Nothing
here is started; each item is promoted only through the established rhythm:

> **design ADR → human ratification → implement (isolated worktree) → `sdlc-reviewer` security pass → CI green → gated merge.**

**Pre-1.0 note.** Items are additive/backward-compatible unless noted; each lands as a **minor** bump
under SemVer + the frozen-contract posture. Items opening a new trust boundary must be STRIDE
threat-modeled before coding.

## Priorities (suggested)

| # | Item | Area | New trust boundary? | Expected bump | Source |
|---|------|------|---------------------|---------------|--------|
| 1 | Blind-acceptance run as a recurring **live regression** (naming accuracy + export-count + behavioral-equiv) | Quality/CI | no | minor | v1.3 acceptance run; the JVM-edge lesson |
| 2 | **Large-binary** analysis: progress streaming, analyzer-profile selector, RAM-vs-size pre-flight | Perf/reliability | no | minor | F1 follow-on; 184 MiB OOM/slow |
| 3 | **Type deletion / redefine** (gated) | Write/types | no (extends TB7) | minor | ADR-015 §6 deferred |
| 4 | **`define_types` persistence round-trip** (mutually-recursive pointer composites) | Write/lifecycle | no | minor | ADR-021 §b tracked |
| 5 | **OAuth scopes → fine-grained per-tool authZ** | Auth | hardens TB6 | minor | ADR-019 deferred |
| 6 | **Reverse-proxy-terminated mTLS** (verified-DN header, opt-in) | Auth | hardens TB6 | minor | ADR-019 deferred |
| 7 | Behavioral-equivalence: **bounded-streaming stdout read** | Eval | no (TB5) | patch/minor | tracked follow-up |
| 8 | **F1 pre-flight reject mode** (opt-in, beyond warn-only) | Reliability | no | minor | ADR-023 D3 |

---

## 1. Blind-acceptance run as a recurring live regression — **highest leverage**

**What.** Promote `scripts/acceptance_run.py` + the F2/F7 live-verification scenarios into a
**gated/scheduled integration job** that, against a rebuilt worker image, asserts: (a) the export of a
known set of writes returns *exactly* those entries (the F7 regression), (b) export succeeds on a real
program (the F2 regression), and (c) naming accuracy / behavioral-equivalence on a small trusted-source
fixture stays within a band.

**Why.** The v1.3 acceptance run caught **two** bugs (`isProgramArchive` crash, auto-content
over-export) that `# pragma: no cover` JVM-edge unit tests **structurally cannot**. The lesson: the
`_gh_*` helpers are only validated by a real-worker run. Make that validation continuous, not ad-hoc.

**Notes.** Synthetic/benign fixtures only (no malware in CI). Gate it on a label / nightly to bound
cost (image rebuild + Ghidra analysis are minutes). Track naming accuracy as a metric over time.

## 2. Large-binary analysis — progress, profiles, pre-flight

**What.** (a) **Progress streaming** during `analyze` (the 184 MiB run gave no signal for ~26 min;
ties to F4 liveness); (b) an **analyzer-profile selector** (lighter analysis passes) so a huge binary
fits less heap / finishes faster; (c) the **reject-mode pre-flight** (F1 D3) + documented RAM-vs-size
guidance; (d) revisit incremental/lazy analysis.

**Why.** The original blind target (184 MiB aarch64) OOM-killed the worker and exceeded practical
analysis time even with more RAM (F1). Large binaries are a real usability ceiling.

## 3. Type deletion / redefine (gated) — ADR-015 §6

A gated tool to delete/redefine a composite (today a name collision is fail-closed REJECT). Extends
TB7; deletion of an in-use type re-renders dependents — treat the redefine-in-use/data-poisoning
vector deliberately. One transaction + rollback; audit; behind `allow_structural`.

## 4. `define_types` persistence round-trip — ADR-021 §b

Mutually-recursive **pointer** composites can't round-trip as independent export entries (importing A
fails `not-found` on B's pointer target). Add a `define_types` export-grouping/Entry variant so an
interdependent type graph round-trips as a batch. (Pairs with the F7 change-log model.)

## 5. OAuth scopes → fine-grained per-tool authZ — ADR-019 deferred

Today OAuth maps `sub` → principal (identity only). Add scope/claim → per-tool/per-capability
authorization (e.g. a read-only token can't drive write tools). Centralize in the existing authZ path.

## 6. Reverse-proxy-terminated mTLS — ADR-019 deferred

An opt-in mode trusting a strictly-enforced proxy-supplied verified-DN header (common in prod behind a
terminating proxy). Rejected as the v1.2 default (header-spoofing footgun); revisit as opt-in with
clear deployment constraints.

## 7. Behavioral-equivalence: bounded-streaming stdout read

The differential harness reads worker/sandbox stdout; make the read bounded-streaming (avoid buffering
a large output whole). Tracked follow-up from the behavioral-equivalence increment.

## 8. F1 pre-flight reject mode — ADR-023 D3

v1.3 shipped warn-only. Add the opt-in `GHIDRA_MCP_WORKER_PREFLIGHT=reject` mode that fails fast with
`resource-exhausted` when an input is implausible for the configured worker memory.

---

## Permanently out of scope (not backlog)
- **`runScript` / arbitrary script execution** — the read-only/least-agency posture forbids it (PLAN §2; ADR-012).
- **Diffing the real hostile binary** in the eval harness — breaches ADR-001 (ADR-016 constraint).

## Maintenance (not features)
- **CVE/dependency hygiene** — keep the runtime lock current (e.g. the starlette ≥1.3.1 SCA bump that
  preceded the v1.3 merges); the scheduled rescan surfaces new CVEs against `main`.
- **Naming-accuracy ground-truth tooling** — the debuginfod-based scorer used in the v1.3 acceptance
  run could become a reusable eval harness.
