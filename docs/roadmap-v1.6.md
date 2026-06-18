# Roadmap — v1.6 backlog (candidate)

> Source of truth for delivery: [`PLAN.md`](../PLAN.md). Decisions are recorded as ADRs in
> [`docs/adr/`](adr/); the threat model is [`docs/security/threat-model.md`](security/threat-model.md);
> frozen contracts are in [`docs/contracts/`](contracts/); release history is
> [`CHANGELOG.md`](../CHANGELOG.md). Prior backlogs: [`roadmap-v1.4.md`](roadmap-v1.4.md),
> [`roadmap-v1.5.md`](roadmap-v1.5.md).

## Status

**Candidate backlog, not committed scope.** v1.5 shipped (released as **v0.7.1**, 2026-06-18 — v0.7.0's
image build fail-closed on a base-layer CVE, remediated in v0.7.1): analyzer-option existence guard
(ADR-035), dedicated `forbidden`/403 authZ type (ADR-036), on-demand naming-accuracy scorer (ADR-010),
hash-pinned dev + scanner CI installs, and a profile dimension in the live-regression harness. v1.5
items #4/#5/#6 were deferred condition-gated.

The items below are drawn from **the v1.5 #5 measurement spike** (below), the **v0.7.0→v0.7.1
supply-chain incident**, `sdlc-reviewer` follow-ups, and the v1.5 deferrals. Nothing here is started;
each item is promoted only through the established rhythm:

> **design ADR → human ratification → implement (isolated worktree) → `sdlc-reviewer` security pass → CI green → gated merge.**

**Pre-1.0 note.** Items are additive/backward-compatible unless noted; a frozen-contract change carries
a contract-version bump + threat-model review; a new trust boundary is STRIDE-modeled before coding.

### v1.5 #5 measurement spike — result (informs items 4 + 5 below)

Ran the real worker on a benign **192 MB** ELF (`/usr/lib/caido/caido` ≈ the v1.3 184 MiB OOM target):

| Run | Outcome |
|---|---|
| `light` @ 4 GiB | **worker-unavailable @ ~6 min** — hit the ~3 GB JVM heap ceiling (`MaxRAMPercentage=75%` of 4 GiB) |
| `default` @ 4 GiB | did not complete in ~15 min (consistent with the v1.3 OOM/intractable-at-4 GiB result) |
| `light` @ 6 GiB | **past 3 GB, plateaued ~3.2 GB, analyzed healthily ~17 min with no OOM** (limiter became *time*, not memory) |

**Finding:** the binding constraint on large-binary analysis is **peak memory**, which is **already
configurable** (ADR-023 `GHIDRA_MCP_WORKER_MEM_MIB`) — raising 4→6 GiB converted a fast OOM into a
stable analysis. `light` reduces passes but the memory *ceiling* (not the profile) was decisive. This
**confirms the ADR-029 §D5 deferral of incremental analysis** for memory-provisioned deployments
(add RAM first), and **refines its gate** (item 5).

## Priorities (suggested)

| # | Item | Area | Contract / TB impact | Expected bump | Source |
|---|------|------|----------------------|---------------|--------|
| 1 | **OOM classified as `resource-exhausted` on the JVM self-exit path** | Reliability / observability | none (existing slug) | minor | v1.5 #5 spike (mis-classified as `worker-unavailable`) |
| 2 | **Proactive base-image CVE rescan** in `scheduled-rescan` | Supply chain / CI | none | minor | v0.7.0→v0.7.1 incident |
| 3 | **Pin `buildkit-syft-scanner`** (floating `stable-1` → digest) | Supply chain / CI | none | patch | release-build review |
| 4 | **Operator memory-sizing hint** for large binaries | Reliability / UX | none | minor | v1.5 #5 spike |
| 5 | **`tool-catalog.md` prose drift** fix (math reads 50; headline 51) | Docs | none | patch | release-prep flag (×2) |
| 6 | Carry-forward: **#4 import progress** / **#5 incremental analysis** / **#6 self-hosted gVisor runner** | — | — | — | v1.5 deferrals (gates below) |
| 7 | **semgrep ruleset egress** hardening; **pyelftools `eval` extra** | Supply chain / maint | none | patch | reviewer notes |

---

## 1. OOM classified as `resource-exhausted` on the JVM self-exit path

**What.** When a worker dies from memory pressure, classify it as `resource-exhausted` (ADR-023) even
when the JVM exits via `-XX:+ExitOnOutOfMemoryError` (a clean process exit) rather than a cgroup
OOM-kill (exit 137 / `OOMKilled`).

**Why.** The v1.5 #5 spike showed `light @ 4 GiB` OOM surfacing as **`worker-unavailable`**, not
`resource-exhausted`. ADR-023's classification keys on the container engine's OOM/exit-137 signal, but
the JVM's `ExitOnOutOfMemoryError` exits cleanly *before* the cgroup kills it, so the OOM is
mis-reported as a generic transport drop. The operator loses the precise, actionable
"increase worker memory / reduce input" signal exactly when it matters most (large binaries).

**Notes.** Likely detectable from the JVM's exit signature / a worker-side last-gasp marker; map to the
existing `resource-exhausted` slug (no contract change). Server-side classification; REQUIRES-LIVE
-VERIFICATION on a real OOM (the spike's caido@4 GiB reproduces it deterministically).

## 2. Proactive base-image CVE rescan in `scheduled-rescan`

**What.** Have `scheduled-rescan.yml` rebuild the server + worker images from the pinned Containerfiles
and **Trivy-scan the images** (not just `pip-audit` the three lockfiles), so a new base-layer CVE
surfaces against `main` on a schedule.

**Why.** v0.7.0's release build fail-closed on **CVE-2026-44432** (`py3-pip-wheel`, a base-layer
package) that was published *after* the prior build — caught only at release time, forcing the v0.7.1
remediation. A scheduled image rescan would surface such base CVEs proactively (between releases), as
`workflow-cve-management` intends, instead of blocking the next release.

**Notes.** Reuse the digest-pinned Containerfiles + the same Trivy config/ignore as `worker-image.yml`;
alert on a failed scheduled run (mirrors the existing rescan cadence). CI-only.

## 3. Pin `buildkit-syft-scanner` by digest

**What.** `worker-image.yml`'s SBOM generation pulls `docker.io/docker/buildkit-syft-scanner:stable-1`
— a **floating tag**. Pin it by digest (`std-supplychain`: pin every build input).

**Why.** The release build's SBOM attestation depends on a floating image; a silent roll could change
the SBOM/attestation format or break the build. Small, closes an unpinned supply-chain input.

## 4. Operator memory-sizing hint for large binaries

**What.** Surface a clearer "this input likely needs ~N GiB of worker memory" signal — extend the
ADR-023 size-vs-memory pre-flight (currently `warn`/`reject` on a coarse heuristic) with an estimated
memory figure, and/or document a sizing table (binary size → suggested `GHIDRA_MCP_WORKER_MEM_MIB`).

**Why.** The #5 spike showed the lever for large binaries is *memory*, and it's configurable — but an
operator hitting an OOM has no guidance on *how much* to set. A concrete hint turns a frustrating
trial-and-error OOM loop into a one-shot fix.

**Notes.** Pairs with item 1 (a `resource-exhausted` error could carry the suggested figure in its safe
`detail`). Heuristic only (no binary parsing server-side — ADR-001).

## 5. `tool-catalog.md` prose drift fix

The catalog's **headline count is correct (51, asserted in tests)**, but the prose breakdown still
enumerates the v1.1/v1.2 tiers and omits `delete_type` (the v0.6.0 50→51 tool) — the descriptive math
reads 50. Doc-only sync. Flagged during both the v0.6.0 and v0.7.0 release preps.

## 6. Carry-forward v1.5 deferrals (gates restated)

- **#4 `session_import` progress (ADR-030 deferred)** — still deferred: `pyghidra.open_program` exposes
  no monitor hook and import is ~0.4% of analyze time. Revisit only on a real large-import complaint +
  a confirmed hook.
- **#5 Incremental / lazy analysis (ADR-029 §D5)** — **gate refined by the #5 spike:** the large-binary
  blocker is peak memory, and memory is configurable (raising the cap fixed the 192 MB case in the
  spike). Incremental analysis lowers *peak* memory, so it is justified **only** for **memory-capped
  hosts that cannot add RAM** *and* must analyze very large binaries. First levers stay: raise
  `GHIDRA_MCP_WORKER_MEM_MIB`, use `profile=light`. Deferred until such a constrained, real need appears.
- **#6 Self-hosted gVisor runner (ADR-028 §D3)** — still deferred: JVM-edge drift is caught at
  implement-time by pre-merge live-verify, not by the nightly; ops + untrusted-code-on-runner cost.
  Interim remains the opt-in `live-regression` PR label.

## 7. Maintenance / low-priority hardening

- **semgrep ruleset egress** — `semgrep --config p/python --config p/security-audit` fetches rule packs
  from the registry at scan time (network egress not lock-covered). Vendor/pin the rulesets for a fully
  offline, reproducible SAST gate. *(Low.)*
- **`pyelftools` `eval` extra** — `scripts/naming_eval.py` imports pyelftools lazily; it's an
  operator-run tool outside the runtime/CI dep graph. If naming-eval becomes routine, add a hash-pinned
  `[project.optional-dependencies] eval = [...]`. *(Info.)*

---

## Permanently out of scope (not backlog)
- **`runScript` / arbitrary script execution** — the read-only/least-agency posture forbids it (PLAN §2; ADR-012).
- **Diffing the real hostile binary** in the eval harness — breaches ADR-001 (ADR-016 constraint).

## Maintenance (not features)
- **CVE / dependency hygiene** — keep the three locks (`requirements.lock` + `requirements-dev.lock` +
  `requirements-sast.lock`) current and regenerated together; rescan all three + (item 2) the images.
  **A release build can fail-closed anytime a new base CVE lands** — remediate via base re-pin (server)
  / apk floor (worker), as in v0.7.1.
- **Post-release doc/contract drift sweeps** — sync README banner + tool count + ADR range; re-check
  `docs/contracts/` against the catalog assertion (item 5).
