# Roadmap — v1.5 backlog (candidate)

> Source of truth for delivery: [`PLAN.md`](../PLAN.md). Decisions are recorded as ADRs in
> [`docs/adr/`](adr/); the threat model is [`docs/security/threat-model.md`](security/threat-model.md);
> frozen contracts are in [`docs/contracts/`](contracts/); release history is
> [`CHANGELOG.md`](../CHANGELOG.md). Prior backlogs: [`roadmap-v1.2.md`](roadmap-v1.2.md),
> [`roadmap-v1.4.md`](roadmap-v1.4.md), v1.3 findings [`roadmap-v1.3-findings.md`](roadmap-v1.3-findings.md).

## Status

**Candidate backlog, not committed scope.** v1.4 shipped (released as **v0.6.0**, 2026-06-17): the
recurring live-regression harness (ADR-028) + its analyzer-profile dimension, large-binary analyzer
profiles + pre-flight reject (ADR-029 B/C), streamed `analyze` progress (ADR-030), gated `delete_type`
(ADR-031), `define_types` round-trip (ADR-032), OAuth scope → per-tool authZ (ADR-033), and opt-in
reverse-proxy mTLS (ADR-034). That closed v1.4 backlog items #1–#6 + #8; #7 (bounded-streaming stdout
read) closed separately.

The items below are drawn from **deferred ADR items** (the explicit "out of scope here / defer to a
later increment" calls in ADR-028…034), the **v1.3 blind acceptance run**, and **maturity gaps**.
Nothing here is started; each item is promoted only through the established rhythm:

> **design ADR → human ratification → implement (isolated worktree) → `sdlc-reviewer` security pass → CI green → gated merge.**

**Pre-1.0 note.** Items are additive/backward-compatible unless noted; each lands as a **minor** bump
under SemVer + the frozen-contract posture. An item that changes a **frozen contract** (e.g. a new
error-envelope type) carries an explicit contract-version bump and threat-model review; an item that
opens a new trust boundary must be STRIDE threat-modeled before coding.

## Priorities (suggested)

| # | Item | Area | Contract / trust-boundary impact | Expected bump | Source |
|---|------|------|----------------------------------|---------------|--------|
| 1 | **Enable hash-pinned dev-dep installs in CI** (`--require-hashes -r requirements-dev.lock`) | Supply chain / CI | none | patch | workflow TODO, now unblocked (lock exists) |
| 2 | **Analyzer-option existence guard** (worker fail-closed on an unknown preset option) | Reliability / correctness | extends the ADR-029 JVM edge; no new TB | minor | ADR-029 / ADR-034 deferred; v1.4 profile-gate follow-up |
| 3 | **Dedicated authZ-denied error type** (FORBIDDEN/403) | Auth / error contract | **error-envelope contract change** (version bump) | minor | ADR-033 deferred |
| 4 | **`session_import` progress** (extend ADR-030 `$/progress` to import) | Perf / UX | additive TB2 frame (same opt-in pattern) | minor | ADR-030 deferred (analyze-only) |
| 5 | **Incremental / lazy analysis** (analyze-on-demand) | Perf / large-binary | deep analysis-model change; TBD | minor–major | ADR-029 §D5 deferred |
| 6 | **Self-hosted gVisor runner** for per-PR live gating | CI / ops | none (CI infra) | n/a | ADR-028 §D3 deferred |
| 7 | **Reusable naming-accuracy ground-truth eval harness** | Eval / quality | no (TB5) | minor | v1.3 acceptance; v1.4 maintenance note |

---

## 1. Enable hash-pinned dev-dependency installs in CI — supply-chain (do-first)

**What.** `requirements-dev.lock` now exists (hash-pinned, committed alongside the runtime
`requirements.lock`). Flip on the already-staged `pip install --require-hashes -r requirements-dev.lock`
installs in `ci.yml` (two jobs) and `live-regression.yml` — they currently float via `pip install -e
".[dev]"` with a stale `# <- enable once the lock exists` comment. `scheduled-rescan.yml` already
consumes the dev lock, so this reconciles the workflows.

**Why.** `std-supplychain` / `workflow-cicd`: pin every dependency by hash; a floating dev-extras
resolve in CI is an unpinned supply-chain surface. The blocker (no lock) is gone — this is a small,
concrete hardening that closes a known TODO.

**Notes.** Verify the lock resolves on both Python lanes (3.12 + the 3.14 quality lane); add a
maintenance note to regenerate both locks together. No code change; CI-only.

## 2. Analyzer-option existence guard — ADR-029 / ADR-034 deferred

**What.** Make the worker validate that each preset analyzer-option name (`light`/`deep` overlays)
actually **exists** in the program's analysis options before `setBoolean`, and **fail closed**
(distinct error) on an unknown name — rather than letting Ghidra silently create/ignore it.

**Why.** The v1.4 profile gate (ADR-028 follow-up) catches a *binding crash* on the
`getOptions(ANALYSIS_PROPERTIES)` / `setBoolean` edge, but **not** a silently-misspelled or
**version-renamed** option (Ghidra's `Options.setBoolean` tolerates unknown names). A Ghidra version
bump that renames an analyzer option would make a preset a silent no-op. This was explicitly
considered and deferred during the v1.4 profile follow-up as "its own feature, not a harness change."

**Notes.** Worker `_jvm_bridge._gh_analyze` change → REQUIRES-LIVE-VERIFICATION (build a branch worker
image, run on the real worker). Pure decision (name ∈ available-options) is unit-testable; the JVM
enumeration is not. Add an abuse test (a bogus preset name → fail-closed). Pairs with the standing
ADR-028 profile gate, which would then also catch a rename (not just a crash).

## 3. Dedicated authZ-denied error type (FORBIDDEN/403) — ADR-033 deferred

**What.** Add a dedicated authorization-denied error type to the frozen error envelope (a `FORBIDDEN`
type / `403` status), replacing the current mapping of a scope→tool denial onto the generic
`VALIDATION` / `400`.

**Why.** ADR-033 deliberately kept the frozen envelope stable for the v1.4 increment (scope-denial
rides the existing `VALIDATION`/400 shape) and recorded a dedicated 403 type as "a future
error-contract change, out of scope." A distinct type lets clients distinguish "you may not" from
"your request was malformed" — better authZ semantics (`std-owasp-api`).

**Notes.** This **changes a frozen contract** (`docs/contracts/error-envelope.md`) → contract-version
bump + threat-model touch + update every authZ-denial site (scope-authZ + write-consent). Backward
-compatibility: confirm clients tolerate the new type (additive); decide whether write-consent denial
also moves to 403 or stays 400 (consistency call to ratify).

## 4. `session_import` progress — ADR-030 deferred (analyze-only)

**What.** Extend the ADR-030 additive `$/progress` notification to `session_import` (today progress is
**`analyze` only**). Import of a large binary is also slow and silent.

**Why.** ADR-030 scoped progress to `analyze` to de-risk the TaskMonitor binding first; import was
explicitly deferred. The framing, redaction (percent + closed phase enum only), opt-in
(`params.progress:true`), and deadline-not-extended rules are already designed and proven — this
reuses them for the import path.

**Notes.** Confirm Ghidra's import path exposes a monitor with usable progress (REQUIRES-LIVE
-VERIFICATION); same flood/redaction bounds; same token-gated client relay.

## 5. Incremental / lazy analysis — ADR-029 §D5 deferred

**What.** Analyze-on-demand (per function / region) instead of full auto-analysis up front, so very
large binaries become usable without a full multi-minute (or OOM) pass.

**Why.** The v1.3 blind run's 184 MiB target OOM-killed the worker and exceeded practical analysis
time even with more RAM. ADR-029 shipped profiles (B) as the low-risk relief and deferred incremental
analysis as a "deep Ghidra analysis-model change… revisit only if (B) proves insufficient on real
large targets." **Gate this on evidence** — measure whether `light`/`deep` + configurable resources
actually fall short on real large binaries (via the acceptance harness) before committing to the cost.

**Notes.** Very large; **start with a feasibility ADR** (does Ghidra's model support partial analysis
cleanly? interaction with the read tools that assume a fully-analyzed program?). Likely multi-increment.

## 6. Self-hosted gVisor runner for per-PR live gating — ADR-028 §D3 deferred

**What.** A self-hosted, gVisor(runsc)-capable CI runner so the live-regression gate can run **per-PR**
(at prod isolation) instead of nightly/label-gated under crun.

**Why.** ADR-028 relaxed CI isolation to crun (stock runners lack gVisor) and gated the live run to
nightly/label to bound cost, accepting that a JVM-edge regression is caught async (not at PR time).
A self-hosted gVisor runner is the path to per-PR gating at prod isolation. ADR-028 says revisit
"**only if drift proves frequent**" — so this is **conditional**: track how often the nightly catches
something the unit suite didn't; promote only if the rate justifies the ops cost.

**Notes.** Ops/infra (runner provisioning, hardening, maintenance) — weigh against the nightly's
adequacy. Not a code change.

## 7. Reusable naming-accuracy ground-truth eval harness

**What.** Promote the debuginfod-based naming-accuracy scorer used in the v1.3 acceptance run into a
maintained, reusable eval harness (a tracked trend, not a gate — naming quality is a non-deterministic
LLM signal).

**Why.** v1.4 made the *deterministic* checks (F2/F7 + profiles) recurring gates and kept naming
accuracy **advisory**. A reusable scorer turns the one-off v1.3 scoring (33/39 functionally correct vs
debuginfod ground truth) into a watchable trend across Ghidra/model changes (the v1.4 "maintenance"
note).

**Notes.** Benign/OSS fixtures with trusted debuginfod ground truth only (master §5; never the real
hostile binary — ADR-001/ADR-016). Stays advisory; pairs with `e2e-groundtruth.yml`.

---

## Permanently out of scope (not backlog)
- **`runScript` / arbitrary script execution** — the read-only/least-agency posture forbids it (PLAN §2; ADR-012).
- **Diffing the real hostile binary** in the eval harness — breaches ADR-001 (ADR-016 constraint).

## Maintenance (not features)
- **CVE / dependency hygiene** — keep **both** locks (`requirements.lock` + `requirements-dev.lock`)
  current and regenerated together; the scheduled rescan surfaces new CVEs against `main` (and, once
  item 1 lands, enforces hash-pinned dev installs everywhere).
- **Doc/contract drift sweeps** — after each release, sync the README banner + tool count + ADR range
  (the v0.6.0 cut needed this) and re-check `docs/contracts/` against the catalog assertion in tests.
