# ADR-028: Recurring live-regression harness (promote the blind-acceptance run into CI)

- **Status:** Accepted (v1.4; human-ratified 2026-06-17). Ratified: **F2 (export-succeeds) + F7 (exact user-authored count) are HARD gates; naming/behavioral-equivalence is ADVISORY** (logged trend, non-deterministic LLM, not invoked in CI). Cadence: **nightly cron + workflow_dispatch + opt-in `live-regression` PR label** (NOT per-PR; failed scheduled run alerts; F2/F7 SKIPPED = fail-loud). Worker image: **pull the cosign-signed released image + verify** (build-in-CI as the dispatch fallback). CI isolation: **crun fallback accepted** (all other ADR-004 floors kept; benign synthetic fixtures only; prod keeps runsc). Addresses v1.4 backlog item #1.
  §"Decisions needing human ratification"). **Design only** — no code lands until ratified and built
  via reviewed, gated PRs. Every Ghidra-binding assumption is flagged **REQUIRES LIVE VERIFICATION**
  (the F2 lesson).
- **Date:** 2026-06-17
- **Deciders:** Human (ratifies D1–D6) + PM; recorded by the Software Architect.
- **Addresses:** v1.4 roadmap item 1 (`docs/roadmap-v1.4.md` §1) — "Blind-acceptance run as a
  recurring live regression."
- **Relates to / constrained by:** ADR-001 (server never parses a binary; enumeration is
  worker-only), ADR-002 (one ephemeral worker per session; evict-wipe), ADR-003 (container-only
  Ghidra/JDK, pinned by digest), ADR-004 (worker isolation tier — rootless OCI baseline + gVisor),
  ADR-024 (F2 export crash fix + the `_is_address_keyable` guard), ADR-027 (F7 user-authored-only
  export via the session change-log). Builds on the existing `scripts/acceptance_run.py` harness,
  the `tests/fixtures/oss/build_fixtures.py` ground-truth pipeline, the gated integration/e2e
  suites, and the `scheduled-rescan.yml` cadence pattern. **Touches no trust boundary** — this is
  test/CI infrastructure that exercises the existing surface; it adds no new runtime capability.

## Context

### Why this is the #1 v1.4 item

v1.3 surfaced **two** correctness bugs that the unit suite is **structurally incapable** of
catching, because the offending code is the JVM/PyGhidra binding edge marked
`# pragma: no cover - JVM edge` (TB3, ADR-001 — excluded from server unit coverage by design):

| Finding | Bug | What caught it |
|---|---|---|
| **F2** (ADR-024) | `session_export_annotations` stringified `symbol.getAddress()` for address-less `USER_DEFINED` symbols → `AttributeError`/null-deref crashed export on **every** real renamed program. (Roadmap names `isProgramArchive`; the live crash root cause per ADR-024 is the address-less symbol deref — same lesson either way.) | An **ad-hoc real-worker run** (the blind acceptance run). |
| **F7** (ADR-027) | A 39-rename session exported **1190** entries: 39 renames + **13 Ghidra auto-structs** + **1138 Ghidra auto-comments**. ADR-018 promised `USER_DEFINED`-only. | The **same** blind run, by counting the exported document. |

The lesson is explicit in ADR-027 §"Live-verification obligations": *"F2 was a speculative `_gh_*`
API call that only a live run caught."* The `_gh_*` helpers in `src/ghidra_mcp/ghidra/_jvm_bridge.py`
are validated **only** by running the real Ghidra worker end-to-end. We already extract the pure
*decision* into hermetically-testable predicates (e.g. `_is_address_keyable`, unit-tested in
`tests/unit/test_export_address_guard.py`) — but the JVM *enumeration loop that calls it* is
unit-invisible. The next `_gh_*` binding regression (a renamed Ghidra API, a new auto-content
category, a changed `getSource()` semantic across a Ghidra version bump) will land silently unless a
real worker runs it.

**Goal:** make the verification that *found* F2 and F7 **continuous and automatic**, not ad-hoc and
lucky.

### What exists today (the substrate to promote)

We are **not** building a harness from scratch — we are wiring the existing one into a recurring job:

- **`scripts/acceptance_run.py`** (1097 lines, fully documented) — drives the **real** stdio chain
  (`python -m ghidra_mcp` → `RpcGhidraAdapter` → hardened worker) as an MCP client. Two modes:
  - **analyze** (L375–526): import → analyze → `list_functions` → `analysis_order` + `call_graph` →
    select top-N by xref → per-function `decompile_function`/`function_context`/strings → manifest +
    `names.template.json`.
  - **apply** (L621–729): re-import the same binary → `session_enable_writes` (ADR-012 gate) →
    replay `rename_function` from a filled names map → `session_export_annotations` →
    `annotations.json`; with `--measure` (L716–793) runs the ADR-016 differential and writes
    `metrics.json` (name-coverage always; behavioral-equivalence only with a trusted reference).
  - It already **inherits `GHIDRA_MCP_WORKER_RUNTIME`** (L781) and the pinned image / engine from
    the environment, fails closed in `_preflight` (L155–186) if the gated chain is unavailable, and
    redacts binary-derived content from the progress log (master §5).
- **`tests/fixtures/oss/build_fixtures.py`** — the **GATED** fixtures pipeline: fetches pinned OSS
  source (cJSON/zlib/lua), verifies SHA-256 (fail closed), builds **with DWARF, `-no-pie -O0
  -fno-inline`** (so symbol addresses equal Ghidra's view of the stripped copy), extracts
  call-graph + function-name ground truth, and emits `<tool>.stripped` + `<tool>.groundtruth.json` +
  `<tool>.meta.json`. **This is our naming ground-truth source** — benign, source-available, no
  malware (master §5).
- **Gated integration/e2e tests already model both gate and signal:**
  - `tests/integration/test_export_annotations_after_rename.py` — the **F2 regression**: in-container
    import → analyze → rename → export, asserts the export does not crash and carries the rename
    entry. `integration`-marked; runs only under `GHIDRA_MCP_INTEGRATION=1` + a real worker image.
  - `tests/e2e/test_groundtruth_oss.py` / `test_naming_eval_oss.py` — drive the real stdio chain on
    the OSS fixtures, score recovery + naming-accuracy plumbing against DWARF truth with **per-tool
    tolerance bands** (`_THRESHOLDS`, L55–60) — the exact "band" model item (c) needs.
  - `tests/e2e/test_acceptance_run.py` — a smoke test that imports `acceptance_run.py` by path and
    asserts it produces artifacts on cJSON. The harness **already runs under test**.
- **`tests/integration/conftest.py` + `tests/e2e/conftest.py`** — the centralized skip gate:
  `integration`-marked items are *skipped* (green, hermetic) unless `GHIDRA_MCP_INTEGRATION` is
  truthy and the worker prerequisites exist; e2e additionally needs `GHIDRA_MCP_FIXTURES`.
- **CI:** `ci.yml` (`pytest -m "not integration"` — never runs the real worker on PRs),
  `worker-image.yml` (build + Trivy + SBOM + cosign on `v*`/dispatch; notes GH runners **cannot run
  gVisor/runsc** → `isolation-verify-note` documents it as a gVisor-capable-host step),
  `scheduled-rescan.yml` (the daily-cron + `workflow_dispatch` model for a recurring job that
  **builds the worker image locally and fails closed as the alert**).

> Note: the brief mentions a `verify_f7.py` scenario (rename + comment + struct → exactly 3
> entries). No such script is committed; it was the ad-hoc verification described in ADR-027
> §"Validation path." **This ADR promotes that scenario into a committed fixture + test** (D5).

### The structural blind spot, precisely

`pytest -m "not integration"` (the merge-blocking gate) **never touches a JVM**. The `_gh_*` loop
that calls `_is_address_keyable`, enumerates `SourceType.USER_DEFINED` symbols, reads
`Listing.getComment(type, addr)`, and now (post-ADR-027) reads the change-log targets is invisible
to it. **A unit test cannot regress F2 or F7.** Only a real worker can.

## Decision (proposed — requires human ratification)

Add a **recurring, scheduled live-regression workflow** (`.github/workflows/live-regression.yml`)
that brings up the real hardened worker on **benign synthetic/OSS fixtures** and runs a small set of
**gated `pytest.mark.integration` tests** asserting the JVM-edge regressions, plus an **advisory
metrics job** that trends naming accuracy without gating. It reuses the existing harness, fixtures
pipeline, conftest skip-gate, and the `scheduled-rescan.yml` shape.

### D1 — What it asserts: deterministic hard gates + one advisory metric

| # | Assertion | Determinism | Verdict | Realized by |
|---|---|---|---|---|
| **(a)** | Export **succeeds** on a real analyzed program after writes (the F2 regression). | Deterministic (pass/fail; a crash is a crash). | **HARD GATE** | The **existing** `tests/integration/test_export_annotations_after_rename.py` — already written; this ADR makes it *run on a schedule* rather than only on a gated manual rebuild. |
| **(b)** | A **known-count** scenario: N renames + M comments + K structs → export contains **exactly N+M+K** user-authored entries, **zero** auto-content (the F7 regression). | Deterministic (exact integer counts; no LLM). | **HARD GATE** | A **new** committed `pytest.mark.integration` test driving the in-container backend on a benign fixture with a fixed write set (D5). This is the ADR-027 "Validation path" scenario, promoted. |
| **(c)** | **Naming-accuracy band** on a small trusted-source fixture (cJSON DWARF truth): exact-match rate + token-F1 stay within a band. | **Non-deterministic** — naming is the **client LLM's** job (ADR-007 decision #1); it is not even invoked in CI without a model client. | **ADVISORY METRIC (recommended), not a gate** | The existing naming-accuracy plumbing (`tests/e2e/test_naming_eval_oss.py`, `naming/metrics.py`) run with a recorded/deterministic namer, **logged as a trend**, never failing the build. |

**Why (a) and (b) are hard gates and (c) is advisory.**

- (a) and (b) are **deterministic JVM-edge facts**: a crash, or an exact entry count, on a fixed
  benign input through a fixed worker image. They are hermetic *modulo the worker image* — same
  input → same output. They satisfy `topic-testing`'s deterministic/hermetic mandate (the only
  non-hermetic input is the pinned worker image itself, which is the whole point of a *live*
  regression). **A regression here is a real bug — block.**
- (c) is **inherently non-deterministic**: real naming quality depends on an LLM client that is (i)
  not run in CI (no model calls in the build — cost, flakiness, master §4 hermeticity), and (ii)
  varies run to run even with a fixed model (`topic-testing`: "no reliance on network… or shared
  mutable state"; an LLM over the network is exactly that). The existing e2e already treats stub
  naming accuracy as **tracked, not gated** (`test_naming_eval_oss.py` L202–209: *"we do NOT gate on
  stub quality"*). Gating on it would be **coverage theater that flakes**. **Track it as a logged
  metric/trend; alert a human if it drifts, but never fail the build on it.** This honors
  `topic-testing` ("inherently non-deterministic → advisory") and `std-owasp-llm` LLM09
  (overreliance — don't trust the model for a pass/fail).

> **Behavioral-equivalence (ADR-016) is also advisory here**, for the same reason and an additional
> one: a *blind* binary has no trusted reference build (the harness already records this as a skip,
> `_maybe_measure` L759–771). On the **OSS fixtures** a reference source *does* exist, so
> behavioral-equivalence is computable — but it depends on the sandboxed compiler image and the
> client namer's generated C, so it belongs in the **advisory metrics job**, not a hard gate.

### D2 — Cadence + trigger: scheduled nightly + manual dispatch + opt-in PR label (NOT every PR)

Bound the cost. The dominant costs are the **worker image** (Ghidra fetch + build is large/slow —
`Containerfile.worker`; the rescan build is the ~5 min reference) and **Ghidra auto-analysis** on
each fixture (minutes). Running this on every PR would balloon CI time and burn the Actions budget
(we have already hit the Actions-minutes ceiling once — the mTLS PR was blocked on it). So:

```yaml
on:
  schedule:
    - cron: "23 4 * * *"      # nightly 04:23 UTC (off the top-of-hour + off scheduled-rescan's 06:17)
  workflow_dispatch: {}        # manual run on demand (e.g. before a release, after a worker-image bump)
  pull_request:
    types: [labeled]           # opt-in: runs ONLY when the `live-regression` label is applied
```

The `pull_request: [labeled]` trigger is **guarded** so the body runs only for the explicit
`live-regression` label (a job-level `if: github.event.label.name == 'live-regression'`), giving a
maintainer an on-demand way to run the live regression against a PR that touches `_gh_*`/export/RPC
**without** making it a default per-PR gate. Mirror `scheduled-rescan.yml`'s `concurrency` +
least-privilege `permissions: contents: read`.

**Merge-blocking posture:** the deterministic gates (a)/(b) are **not** added to branch-protection
required checks per-PR (they don't run per-PR by default). Instead, a **failed scheduled run is the
alert** — exactly the `scheduled-rescan.yml` model (GitHub notifies the repo owner of scheduled
default-branch failures). A maintainer triages, files the finding (next v1.x findings doc), and
fixes via the normal `design → ratify → implement → review → gated merge` rhythm. For a PR *known*
to touch the JVM edge, the maintainer applies the `live-regression` label to gate that PR
explicitly. **Recommendation:** start here; promote (a)/(b) to required-on-label, and consider a
self-hosted gVisor runner for true per-PR gating, only if drift proves frequent.

### D3 — How the hardened worker runs in CI (the runtime relaxation)

GitHub-hosted runners **cannot run gVisor/runsc** (documented in `worker-image.yml`
`isolation-verify-note` and `deploy/README.md`). The hardened spec (`deploy/worker-run.sh`, ADR-004)
defaults to `--runtime runsc`. The established **local fallback** (and the memory note's
real-worker recipe) is **crun + host-uid override + a writable socket dir**. So the CI job:

1. **Provisions the worker image** (D4 decides build-vs-pull).
2. **Runs the chain** with the documented fallback environment, **keeping every ADR-004 baseline
   control** and relaxing **only** the gVisor tier to the rootless-OCI baseline (which ADR-004
   §Consequences explicitly sanctions as the floor: *"if a specific environment cannot run gVisor,
   the rootless OCI baseline is the minimum acceptable tier"*):

   | ADR-004 control | CI posture | Note |
   |---|---|---|
   | `--network none` (no egress) | **KEPT** | The worker never needs the network; non-negotiable. |
   | `--cap-drop ALL`, `no-new-privileges` | **KEPT** | Baseline. |
   | `--read-only` rootfs + tmpfs scratch | **KEPT** | Baseline. |
   | seccomp `RuntimeDefault` | **KEPT** | Baseline. |
   | mem/cpu/pids limits | **KEPT** | DoS bounds (F7); also bound CI cost. |
   | **gVisor `--runtime runsc`** | **RELAXED → crun** (`GHIDRA_MCP_WORKER_RUNTIME=crun`) | GH runners lack runsc; rootless-OCI baseline is the sanctioned floor. |
   | uid mapping (`--user 65532 --userns keep-id`) | **uid override** | The local recipe overrides the worker uid to the runner's host uid so the tmpfs/socket dir is writable rootless; documented in the memory recipe. |
   | per-session UDS dir | **writable socket dir** | A runner-owned, private socket dir the worker can bind. |

   The harness already plumbs all of this: it inherits `GHIDRA_MCP_WORKER_RUNTIME`,
   `GHIDRA_MCP_CONTAINER_ENGINE`, `GHIDRA_MCP_WORKER_IMAGE`, and `GHIDRA_MCP_IMPORT_ROOT`. The CI job
   sets `GHIDRA_MCP_INTEGRATION=1`, `GHIDRA_MCP_WORKER_RUNTIME=crun`, the uid override, the socket
   dir, and the import root, then runs the gated tests.

**Why relaxing gVisor (only) is acceptable here:** the threat gVisor defends against is a **hostile
binary** escaping the worker (TB3). The CI regression runs **only benign, source-available
fixtures** (master §5 — no malware), so the residual risk of dropping the user-space kernel boundary
in CI is low, *and the rootless-OCI baseline (no-net, caps-dropped, ro-rootfs, seccomp) is still
fully in force*. **Production keeps gVisor** (ADR-004 default); CI is a benign-input regression, not
a prod deployment. **Document this explicitly** in the workflow header and `deploy/README.md`. (A
self-hosted gVisor-capable runner would let CI keep runsc and is the path to per-PR gating — noted
as a future option, D2/D6.)

### D4 — Provision the worker image: **pull the signed, SBOM'd released image** (recommended), with build-in-CI as the dispatch fallback

Two options:

- **(i) Build the worker image in the job** (like `scheduled-rescan.yml` does for its CVE rescan).
  Self-contained; always matches the working tree. **Cost:** the Ghidra fetch + build is the slow
  part (~5 min+), paid **every nightly run**, and the built tag is **not** the signed/SBOM'd release
  artifact (it tests an *equivalent*, not the shipped image).
- **(ii) Pull the released, digest-pinned, cosign-**signed** image** that `worker-image.yml`
  produced (`ghcr.io/<owner>/ghidra-mcp-worker@sha256:…`), **verify its cosign signature** before
  running (std-supplychain: *"verify signatures before deploy"*). **Cost:** a ~1.3 GB pull (the
  `worker-image.yml` skopeo note documents the HTTP/2 pull hazard and the skopeo/HTTP-1.1
  workaround). **Benefit:** the regression runs the **exact shipped artifact** — "test what you
  ship" — and is faster than a rebuild after the first cache.

**Recommendation: (ii) pull-the-signed-released-image as the default scheduled path, with (i)
build-in-CI available via `workflow_dispatch` input** (`build_image: true`) for validating a
worker-image change *before* it is released. Rationale: the whole point is to catch `_gh_*`
regressions in **the image users run**; testing an in-CI rebuild instead tests a parallel artifact.
Pulling the signed image also exercises the supply-chain verify path (cosign verify → run), which is
itself worth continuously asserting. The dispatch-time build covers the bootstrap case (no released
image yet) and pre-release validation of an image bump.

> **REQUIRES LIVE VERIFICATION:** confirm the ~1.3 GB worker pull completes reliably on a GH-hosted
> runner using the `skopeo` HTTP/1.1 path (the `worker-image.yml` review found `docker pull` died on
> HTTP/2 PROTOCOL_ERROR). Reuse that exact skopeo recipe. If the pull is too flaky/slow on hosted
> runners, fall back to (i) build-in-CI and revisit a self-hosted runner.

### D5 — Promote the harness properly: which becomes a gated test vs. stays an operator script

| Artifact | Disposition | Rationale |
|---|---|---|
| **`scripts/acceptance_run.py`** | **Stays an operator/dogfooding script** (unchanged). | It is glue + artifact I/O for a *blind, possibly-hostile* binary investigation (`acceptance_run.py` docstring) — an operator tool, not a CI assertion. Its existing smoke test (`tests/e2e/test_acceptance_run.py`) already keeps it from bit-rotting. The nightly job **may** additionally run it on the OSS fixture as an advisory smoke (D1c metrics job), but it is not a gate. |
| **F2 regression** | **Already a gated `pytest.mark.integration` test** (`test_export_annotations_after_rename.py`) — the workflow *runs* it on schedule. **No new test.** | It exists and is correct; this ADR only schedules it. |
| **F7 known-count regression** (the ad-hoc `verify_f7.py` scenario) | **New committed `pytest.mark.integration` test** (`tests/integration/test_export_known_count_after_writes.py`). Drives the in-container backend with a **fixed write set** (N renames + M comments + K structs on a benign fixture) and asserts the export document carries **exactly** those N+M+K entries, of the right kinds, with **zero** auto-content. | This is the deterministic F7 gate (b). It is the ADR-027 "Validation path" scenario, made a permanent regression test (`topic-testing`: failing test first, then fix — the test *encodes* the fix's contract). It depends on the ADR-027 change-log being implemented. |
| **Naming-accuracy / behavioral-equivalence** | **Advisory metrics job** reusing `test_naming_eval_oss.py` + `naming/metrics.py`; emits `metrics.json` as a workflow artifact and logs the trend. **Never gates.** | (c) per D1 — non-deterministic; tracked, not blocking. |

**Net:** one **new** deterministic test (F7 known-count), one **existing** deterministic test
scheduled (F2), one advisory metrics job, and the operator script stays an operator script.

### D6 — Fixtures + ground truth (master §5 — NO real malware)

All inputs are **benign and synthetic/source-available**. Three fixture tiers, simplest-reliable
first:

1. **F2 gate (a)** — needs **no ground truth**: it analyzes an **in-image benign OS utility**
   (`/bin/true` by default, `GHIDRA_MCP_INTEGRATION_TARGET`), renames the first function, exports,
   and asserts no crash. Already wired. **Nothing committed.**
2. **F7 gate (b)** — needs **no ground truth** (it is an **exact-count** assertion, not a
   correctness-of-content assertion). Recommended fixture: a **tiny purpose-built C program compiled
   in-CI** (a handful of named functions) so the test controls exactly which addresses it renames /
   comments / structs. The source is a few lines committed under `tests/fixtures/known_count/`; the
   binary is **built in the job** (never committed — master §5, repo hygiene). Alternatively reuse
   the cJSON OSS fixture and pick K known addresses; the purpose-built micro-binary is simpler and
   fully deterministic. **Recommendation: the tiny purpose-built C program** — smallest, fastest to
   analyze, and gives total control over the write set.
3. **Naming band (c), advisory** — needs **trusted-source ground truth**. Reuse the **existing OSS
   fixture pipeline** (`build_fixtures.py` → cJSON with DWARF `-no-pie` truth). cJSON is the
   simplest reliable choice (small, self-contained; already the default in the e2e tolerance table).
   Built in the (gated) job, **never committed** (the pipeline is already gated and emits to a
   tmp/artifact dir). The naming accuracy is computed against `cjson.groundtruth.json` and reported.

**Nothing real-malware, nothing large committed.** Synthetic micro-source (a few KB of C) is the
only new committed fixture; everything binary is built/pulled in the job and lives in tmp/artifacts.

## Architecture & invariants

- **ADR-001 preserved:** the harness/tests run **server-side code only** as an MCP client; the
  worker container is the sole thing that parses a binary. The new F7 in-container test drives
  `PyGhidraBackend` *inside* the worker image (the same pattern as the F2 test), which is correct —
  that code is *meant* to run in the worker.
- **ADR-002 preserved:** every test/harness run uses ephemeral sessions; `session_close` wipes the
  store (the e2e already asserts `store_wiped is True`). No durable state.
- **ADR-004 honored with a documented, sanctioned relaxation:** CI keeps the full rootless-OCI
  baseline and relaxes **only** gVisor → crun (the ADR-004 floor), justified by benign-only inputs;
  prod is unchanged.
- **master §5 (data classification):** benign synthetic/OSS fixtures only; binary-derived content is
  redacted from logs (the harness already does this) and written only to tmp/artifact dirs.
- **`topic-testing` honored:** deterministic gates (a)/(b) are hermetic modulo the pinned worker
  image (the intended live input); the non-deterministic naming/LLM signal is **explicitly
  advisory**, not a flaky gate — and we *prove the gate fails on a known-bad* (the F7 test must go
  red if export over-includes; verify by temporarily reverting the ADR-027 filter in a scratch run,
  per `topic-testing` "verify the gate actually fails").
- **`workflow-cicd` honored:** the recurring job fails closed (a missing image / unavailable chain
  is a failure, not a skip-to-green **in the scheduled context** — note the nuance below), and the
  failed scheduled run is the alert (the `scheduled-rescan.yml` model).

> **Skip-vs-fail nuance (important):** the conftest skip-gate makes integration tests *skip* when
> the worker is unavailable — correct for the **unit/PR** job (keeps it green + hermetic). But in the
> **scheduled live-regression** job, a worker that *should* be present but isn't must be a **failure,
> not a silent skip** (else the regression silently stops running — a monitoring gap). The workflow
> therefore (a) sets all prerequisites so tests *do* run, and (b) adds a **guard step that asserts at
> least the F2 + F7 tests were collected-and-run, not skipped** (e.g. fail if `pytest` reports them
> skipped). Fail-loud on "the regression didn't actually run" (`batch-job` template: *"alert on
> silent non-execution"*).

## Contracts

- **No frozen-contract change.** This ADR adds CI/test infrastructure only — no RPC, tool-schema,
  envelope, or document-schema change. (The F7 *test* depends on ADR-027's already-ratified RPC
  `targets` change, but introduces none of its own.)
- **No new tool**, no new trust boundary.

## Live-verification obligations (the F2 lesson, applied to the harness itself)

1. **The crun + uid-override + writable-socket-dir recipe runs the chain on a GH-hosted runner** —
   the JVM boots, Ghidra analyzes, and `session_close` wipes the store, all under the rootless-OCI
   baseline without runsc. (The memory recipe established this locally; confirm on a hosted runner.)
2. **The ~1.3 GB signed image pulls reliably** via the documented skopeo HTTP/1.1 path on a hosted
   runner (D4); else fall back to build-in-CI.
3. **The F7 known-count test goes RED on the pre-ADR-027 behavior** and GREEN on the fix — prove the
   gate catches the regression, not just that it passes (`topic-testing`).
4. **Worker-analysis wall-time fits the runner budget** for the chosen fixtures (cJSON is small;
   `/bin/true` and the micro-binary are tiny) — bound with the harness/worker timeouts already in
   place; set the job timeout generously but finite.

## Consequences

- **Positive:** the verification that *found* F2 and F7 becomes **continuous** — the next `_gh_*`
  binding regression (Ghidra version bump, renamed API, new auto-content class) is caught by a
  nightly red build, not by luck on the next blind run. Naming quality gets a **logged trend** to
  watch for drift without flaky gating. The supply-chain verify-then-run path (pull signed image →
  cosign verify → run) is exercised continuously. Reuses existing harness/fixtures/conftest — small
  net-new surface (one workflow + one test + a few KB of micro-source).
- **Negative / trade-offs:** (a) the nightly job costs a worker-image pull (or build) + Ghidra
  analysis (minutes) — bounded by cadence (not per-PR) and concurrency; (b) CI relaxes gVisor → crun
  (sanctioned by ADR-004 for benign inputs; prod unchanged) — a documented, deliberate posture; (c)
  a *failed nightly* is async (the regression isn't caught *at PR time* unless the `live-regression`
  label is applied) — the accepted cost of not gating every PR; (d) one more workflow to maintain
  and one more place the worker-image/runtime recipe must stay in sync (mitigated by reusing the
  documented `deploy/` recipe + env vars rather than re-deriving flags).
- **Deferred / out of scope:** per-PR live gating on a **self-hosted gVisor runner** (revisit if
  drift is frequent — D2/D6); diffing/analyzing a **real hostile binary** in CI (forbidden — master
  §5, ADR-001; roadmap "permanently out of scope"); making naming accuracy a **hard gate** (rejected
  — non-deterministic LLM signal, D1c); a durable metrics store / dashboard for the naming trend
  (start with workflow artifacts + the run log; a dashboard is a later nicety).

## Follow-ups (landed)

- **Analyzer-profile dimension (2026-06-17, post-v0.6.0).** Folded the ADR-029 B follow-up into this
  harness: `tests/integration/test_analyze_profiles.py` parametrizes `session_analyze` over
  `{default, light, deep}` as **deterministic HARD gates** — each profile must analyze without an
  error envelope and populate a function surface (`>= 1`) on the real worker. This is the sole
  recurring exercise of the ADR-029 option-overlay JVM edge (`getOptions(ANALYSIS_PROPERTIES)` +
  `setBoolean`), which the `default` (empty-overlay) path skips — a renamed `ANALYSIS_PROPERTIES`
  constant or a changed `setBoolean` signature across a Ghidra version bump now reds the nightly
  instead of failing silently in production. The per-profile recovered-function count is recorded
  into the JUnit XML as an **advisory trend** (NOT asserted to differ — micro-binary pass effects are
  not deterministic enough to gate). The fail-loud-on-skip assertion's threshold rose `>=2 → >=5`
  (F2 + F7 + 3 profile params). Harness-only — no `src/` change (ratified scope; an option-existence
  hardening in the worker was considered and deferred as a separate feature, not a harness follow-up).

## Alternatives considered

- **Run the live regression on every PR (default gate).** **Rejected** — worker build/pull + Ghidra
  analysis on every PR balloons CI time and Actions spend (we have hit the minutes ceiling before);
  the JVM-edge regressions are slow-moving (they track Ghidra/`_gh_*` changes), so nightly +
  on-label catches them with far less cost. (Promote to per-PR-on-label, then per-PR on a self-hosted
  gVisor runner, only if needed.)
- **Make naming accuracy a hard gate.** **Rejected** — naming is the client LLM's job
  (non-deterministic, not even invoked in CI); gating on it is flaky coverage theater and
  overreliance on the model (`std-owasp-llm` LLM09, `topic-testing`). Advisory trend instead.
- **Build the worker image in CI every run (only).** **Rejected as the default** — tests a parallel
  artifact, not the signed/SBOM'd image users run, and pays the slow Ghidra build nightly. Kept as
  the `workflow_dispatch` fallback for pre-release/bootstrap validation (D4).
- **Heuristic auto-content detection in the F7 test (pattern-match auto-comments).** **Rejected** —
  the same Silent-Corruption fragility ADR-027 rejected; the known-count test uses an **exact
  integer count** on a controlled write set, which needs no provenance heuristic.
- **Commit a prebuilt fixture binary to avoid the build.** **Rejected** — repo-hygiene / no large
  binary blobs (`workflow-git`); master §5 prefers synthetic-built-in-CI. The micro-source is a few
  KB; OSS fixtures are built by the existing gated pipeline.
- **Skip-to-green when the worker is unavailable in the scheduled job.** **Rejected for the
  scheduled context** — that turns a broken regression harness into a silent no-op (a monitoring
  gap). Fail loud on non-execution; the conftest skip stays correct for the PR/unit job only.

## Decisions needing human ratification

1. **D1 — the (a)/(b)/(c) hard-gate-vs-advisory split.** *Recommended:* (a) F2 export-succeeds and
   (b) F7 exact-count are **hard gates**; (c) naming-accuracy band (and ADR-016
   behavioral-equivalence on OSS fixtures) is an **advisory tracked metric**, never a gate. This is
   the load-bearing call.
2. **D2 — cadence + trigger.** *Recommended:* scheduled **nightly** + `workflow_dispatch` + **opt-in
   `live-regression` PR label**; **not** every PR; failed scheduled run = the alert (not a
   branch-protection required check by default).
3. **D4 — provision the worker image: pull the signed released image vs. build-in-CI.**
   *Recommended:* **pull the cosign-signed, digest-pinned released image and verify before running**
   (test what you ship), with **build-in-CI via `workflow_dispatch` input** as the
   bootstrap/pre-release fallback. Pending live verification that the ~1.3 GB pull is reliable on
   hosted runners (skopeo path).
4. **D6 — the ground-truth fixture choice.** *Recommended:* F2 uses an in-image OS utility (no
   truth); F7 uses a **tiny purpose-built C micro-binary built in CI** (exact-count, no truth);
   the advisory naming band uses the **existing cJSON OSS DWARF fixture**. Confirm the micro-binary
   approach vs. reusing cJSON for the F7 count.
5. **The CI isolation relaxation (gVisor → crun for benign inputs only).** Ratify that running the
   regression under the rootless-OCI baseline (no gVisor) on **benign fixtures only** is acceptable
   for CI (ADR-004 sanctions the baseline as the floor), with prod unchanged — and whether a
   self-hosted gVisor runner is worth provisioning now or later.
6. **Skip-vs-fail in the scheduled context.** Ratify that the scheduled live-regression job
   **fails loud** if the F2/F7 tests are skipped (worker unavailable when it should be present),
   rather than skipping to green — so a broken harness is an alert, not a silent no-op.

---
_Design only. No implementation, no gated actions taken. Once ratified: implement in an isolated
worktree (new `live-regression.yml` workflow + the F7 known-count test + micro-source fixture +
`deploy/README.md` CI-relaxation note), `sdlc-reviewer` security pass, CI green, gated merge._
