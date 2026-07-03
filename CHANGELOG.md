# Changelog

All notable changes to **Vivarium** (formerly `ghidra-mcp`) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Continued **security-hardening / gap-remediation** (round-6 → round-8 findings, #258–#276) — **no
new tools, no contract changes** (Tier-1 catalog stays **56**, observable behavior unchanged). A
streaming cancel-availability fix and a concurrency guard, a hostile-worker output clamp, a daemon
restart-race fix, the worker-image auto-repin trust-anchor flow made signed + CI-triggering +
verified with the cosign trust identity tightened to tag builds, plus CI-drift tripwires and
CI/docs/threat-model currency.

### Fixed
- **Cancelling a stream frees the session at once (#260, gap V1).** `cancel_job` now drains the
  cancelled producer so the adapter's in-flight flag is cleared and the socket left clean —
  previously a cancelled stream left the session rejecting every plain call with "session busy"
  until eviction (up to the TTL).
- **Starting a stream while one is already active is refused (#269, gap W1).** The stream-start path
  now fails closed with a retryable "session busy" (symmetric with plain calls) — closing a
  concurrent cancel+start window (exposed by #260) that could desync two read loops on one session's
  socket and kill the worker.
- **Reaper + metrics daemons use a per-run stop signal (#267, gap V8).** Each start mints its own
  `Event`, removing a latent start/stop restart race in the periodic session-reaper and
  metrics-logger.

### Security
- **Untrusted worker-reported stream `total` is clamped (#268, gap V9).** The terminal `total`
  (which feeds only the server-side ETA) is bounded to `[produced, max-stream-chunks]` with a
  safe fallback on a non-numeric value — defense-in-depth against a hostile worker (LLM02).
- **cosign worker-image trust identity tightened to tag builds (#271, gap W5).** The
  `--certificate-identity-regexp` at all four verify sites (worker-image/live-regression/
  e2e-groundtruth/gvisor-isolation) is tail-anchored to `worker-image.yml@refs/tags/`, so only a
  signature minted by a release-tag build verifies — the pinned image is always tag-built.

### Internal / CI / supply-chain / docs
- **Worker-image auto-repin PR is signed, CI-triggering, and pre-verified (#258, #259, #261, #265).**
  The per-release trust-pin bump PR is now opened via a GitHub App (GitHub-signed commit + real
  `pull_request` checks so it can actually merge), gated on both `REPIN_APP_*` secrets (fail-safe
  skip), cosign-verifies the digest before proposing, and reads the pin blob sha from the freshly
  created bump branch (409-race fix).
- **Trust-pin rewrite extracted + unit-tested (#264, gap V2).** `scripts/bump_pin.sh` (fail-closed
  digest validation) replaces the untested inline rewrite.
- **`image-scan-gate` poll budget de-magicked (#266, gap V10).** Named constants; deadline kept below
  the job `timeout-minutes` so the gate fails via its own message.
- **CI/threat-model/docs currency (#262, #263, #266, #270).** `docs/ci-cd.md` lists all ten required
  checks + seven critical modules with a `test_coverage_markers` doc-drift tripwire; threat-model §4
  delta + secret-rotation entry for the `REPIN_APP_*` App key; branch-protection enforcement-
  verification record; CHANGELOG backfill + supply-chain-pinning runbook updated to Ghidra 12.1.2.
- **Both round-5-promoted required gates empirically proven to red-block (#273, #275).** Recorded in
  the `docs/ci-cd.md` red-block observation log: `mtls-auth-gate` (PR #272) and `image-scan-gate`
  (PR #274) each observed reporting FAILURE + blocking a merge via a throwaway deliberately-failing PR.
- **CI-drift tripwires added (#276, gaps X7/X8).** `test_coverage_markers` now asserts the cosign
  identity stays tail-anchored at all four verify sites, and that every required status check maps to
  a real workflow job (a renamed job → fail-closed hang would otherwise pass silently).

## [0.13.0] — 2026-07-02

A **security-hardening / gap-remediation** release: it closes the round-2 → round-5 gap-analysis
findings (#196–#253) with **no new tools and no contract changes** — the Tier-1 catalog stays **56**
and the observable behavior is unchanged. The work spans a streaming cross-session availability fix,
an OAuth JWKS-URI SSRF guard, owner-scoped session in-flight tracking, fail-closed auth-fault
handling, the mTLS auth binding now gated in CI, the server image on the hash-pinned supply-chain
install, plus operational observability, a background session reaper, and extensive test/CI/docs
hardening. Grouped below by change type.

### Added
- **Operational observability layer (#208, gap N3).** RED (per-tool request/error/duration),
  session-lifecycle (created/evicted), and auth-decision (allow/deny) counters accumulate in an
  in-process registry and are emitted as a periodic, redaction-safe `metrics.snapshot` structured-log
  line (interval `VIVARIUM_METRICS_SNAPSHOT_INTERVAL_SECONDS`, default 60s) — no new dependency, no
  scrape endpoint. Adds **unauthenticated, detail-free** `/healthz` (liveness) and `/readyz`
  (readiness, backed by session-pool capacity) HTTP probes.
- **Background session reaper (#197, gap N5).** A periodic daemon sweeps expired sessions (interval
  `VIVARIUM_SESSION_REAP_INTERVAL_SECONDS`, default 60s), reclaiming an abandoned session's worker +
  per-session store without waiting for its next call — closing a resource-leak + confidentiality
  window.

### Changed
- **Streaming resume is now at-least-once within a bounded replay window (#207, gap N4 / ADR-040 §D7).**
  A `fetch_job_results` re-fetch from an earlier cursor now **replays** already-delivered chunks from
  a bounded (count + bytes) window (clients dedupe by `seq`); previously drained chunks were gone
  (effectively at-most-once). A cursor older than the window fails closed with a typed validation
  error. New cap `VIVARIUM_MAX_STREAM_REPLAY_CHUNKS`.
- **Session-reaper eviction I/O runs off the session lock (#217, gap round-3 P10).** The periodic
  reaper now detaches an expired session in-memory under the lock, then performs the worker-kill +
  verified store-wipe **outside** it — so a slow kill/wipe on the timer can no longer stall request
  threads (or `/readyz`) waiting on the lock. Kill-before-wipe ordering and the synchronous `evict()`
  contract are unchanged.
- **Streaming eviction hook wired via a call-once seam (#236, round-4 Q11).** `build_app` binds the
  session→streaming-job discard hook through a documented, call-once `set_evict_callback()` instead
  of poking a private attribute (encapsulation; runtime wiring + behavior unchanged).

### Fixed
- **Structural writes are now atomic (#182, CWE-460/ADR-021 §D2).** A failed `define_struct` /
  `define_union` / `define_types` no longer leaves a partial/orphan composite committed: members
  are resolved and the size cap is enforced read-only **before** the transaction (validate-before-
  mutate — a committed `DataTypeManager` change cannot be rolled back in-program). As a result the
  error slugs now match the documented contract: an oversized composite → `limit-exceeded` and an
  unresolvable member ref → `not-found` (previously masked as `analysis-failed`). Worker image
  rebuilt + re-pinned to ship the fix.
- **RPC frame reads bounded by an absolute deadline (#201, gap N11, CWE-400).** A length-prefixed
  frame is read under one monotonic deadline instead of a per-`recv` timeout, closing a slow-loris
  dribble from a hostile/slow worker.
- **Per-session adapter locking under concurrent HTTP (#196, gap N1).** Per-session socket/stream
  state is guarded (RLock for short sections + a stream-exclusion flag, lock-free kill/cancel,
  bounded acquire), removing a race/TOCTOU that assumed a single-threaded request path.
- **Metrics final-snapshot race on a timed-out join (#211, gap round-3 P6).** `PeriodicMetricsLogger.stop()`
  now emits the shutdown snapshot only after the daemon thread has actually exited, so it can no
  longer race a second concurrent emit with an in-flight one.
- **Streaming producer pumps off the manager lock (#240, round-5 R1).** The blocking worker-socket
  read now runs under a per-job lock instead of the shared streaming-manager lock, so one
  slow/hung/dribbling worker can no longer head-of-line-stall every other session's stream
  operations (cross-session availability/DoS).
- **Streaming reuse GCs the prior terminal job (#228, round-4 Q2, CWE-400).** Starting a new stream on
  a session now drops the old terminal job + its replay window, bounding `_jobs` to the live jobs.
- **RPC connect-retry charged to one absolute per-call deadline (#229, round-4 Q4, CWE-400).** A single
  call's lock/connect/send/read now share one deadline, so a stuck connect can no longer exceed it.
- **`import_binary` fails closed on a rejected source ref (#235, round-4 Q12).** A confined resolver
  raising `ValueError` (e.g. a path outside its allow-list) now maps to a fail-closed, content-free
  `VALIDATION` error instead of an unclassified one; unexpected exception types still propagate.
- **OAuth JWKS client lazy-init is thread-safe (#237, round-4 INFO-1).** A cold-start race could build
  a redundant JWKS client; the build is now lock-guarded.
- **Reaper/metrics daemon lifecycle serialized + restart-safe (#238 round-4 INFO-2, #242 round-5 R3).**
  `start()`/`stop()` are lock-guarded (no double-spawn/double-join) and `start()` clears the stop
  signal so a start-after-stop resumes instead of silently no-op'ing.
- **`$/cancel` send no longer races a concurrent worker-kill (#249, round-5 R11).** `_send_cancel`
  snapshots `sess.sock` once instead of re-reading it after the `None` guard, closing a TOCTOU
  (`AttributeError` on a concurrent lock-free `kill_worker` nulling the socket); the send stays
  best-effort.

### Security
- **Signed-commit + admin enforcement on `main` (gap N7).** Branch protection now requires
  verified-signed commits and applies to admins (`enforce_admins`), alongside the 8 required checks +
  linear history.
- **Per-PR container-image CVE scan + SBOM (#202, gap N8).** A Containerfile change triggers a Trivy
  image scan (fail-closed on HIGH/CRITICAL) + a CycloneDX SBOM, closing the window between the
  IaC-only PR scan and the daily rescan.
- **Broadened real-worker regression coverage (#198/#209, gap N2).** `live-regression` auto-runs on
  core-runtime-path PRs (not just FID); the required `fid-elf-match-gate` was decoupled so non-FID PRs
  no longer wait on the real-worker run.
- **`/readyz` pre-auth DoS + occupancy-oracle hardening (#214, gap round-3 P3).** The readiness
  probe's capacity check is now cached (single-flight, lock-free fast path), so the unauthenticated,
  pre-rate-limit `/readyz` can no longer drive session-lock contention (CWE-400) and its 200/503
  answer is coarsened (blunting the pool-occupancy oracle, CWE-200). New knob
  `VIVARIUM_READINESS_CACHE_TTL_SECONDS` (default 1s).
- **Direct-mTLS cert principal-id bounded + sanitized (#216, gap round-3 P9).** The cert CN/SAN mapped
  to a principal now goes through the same length-bound + control-char rejection as the reverse-proxy
  path (`_valid_principal_id`), so a hostile-but-CA-issued cert cannot inject an over-long or
  log-poisoning session-owner id.
- **FID real-worker gate fails fast if its sibling never runs (#220, gap round-3 P13).** The
  `fid-elf-match-gate` poll now fails loudly within a bounded grace if the `live-regression` job it
  depends on is renamed / never scheduled, instead of silently hanging to the 65-min timeout.
- **Worker error text no longer reaches the client error envelope (#232, round-4 Q8).** A worker
  method error maps to a fixed per-type safe detail; the worker's free-form message is logged
  server-side only, so no binary-derived/hostile content is disclosed to the client (CWE-209).
- **Session in-flight tracking is owner-scoped (#234, round-4 Q10, BOLA).** `begin_call`/`end_call`
  no-op on an owner mismatch, so a foreign caller holding a valid but non-owned session id cannot
  defer another principal's idle-eviction (complete mediation — `std-owasp-api` API1).
- **Reverse-proxy rate-limit residual documented (#233, round-4 Q9).** The per-client limiter keys on
  the TCP peer IP; behind a proxy it degrades to per-proxy — recorded as an accepted deployment
  constraint (the proxy must rate-limit per client) in ADR-034 + the HTTP-exposure runbook + TB6.
- **Authenticator faults fail closed at the auth chokepoint (#244, round-5 R5).** A raising
  authenticator now yields a generic `500` with no internals (error type logged server-side only) and
  never reaches the app, instead of relying on the ASGI server's default exception handling.
- **mTLS peer-cert→principal auth is gated in CI (#241, round-5 R2).** The mTLS bridge test (incl.
  ADR-019 untrusted-CA rejection at the handshake) now runs on every PR — previously it ran in no
  workflow, so an mTLS auth regression could pass every gate.
- **OAuth JWKS URI scheme constrained (#248, round-5 R9, CWE-918).** `_load_http_config` now requires
  an `https` JWKS URI (allowing `http` only to a loopback dev/test IdP) and refuses to boot on
  `file://`/`ftp://`/internal-`http://`/schemeless — closing an SSRF / local-file-read surface via
  `PyJWKClient`'s urllib fetch.
- **Rate-limiter bucket update is lock-guarded (#247, round-5 R8, API4).** `RateLimitMiddleware._allow`'s
  compound `OrderedDict` read-modify-write now runs under a lock, so a threaded server can't corrupt
  the LRU or drop the wrong bucket (a limit bypass / victim over-limit) — the control no longer rests
  on an undocumented single-thread assumption.
- **Server image installs deps from the hash-pinned lock (#252, round-5 R12, SLSA).** `Containerfile.server`
  now installs runtime deps with `--require-hashes -r requirements.lock` (rejecting any un-hashed /
  tampered resolve at build time), matching the worker image — no floating build-time dependency
  resolution.

### Internal / tooling
- Renovate config for gated dependency-bump PRs (#199, N9 — inert until the GitHub App is enabled);
  cyclomatic-complexity lint `C901` at max 10 (#200, N13); IOC/crypto property/fuzz tests (#203, N14);
  stdio BOLA + boundary-validation e2e + worker-coverage gate (#204/#195, N15/N6); CI-comment + registry
  branch-coverage hygiene (#205, N16); a read-only dry-run rollback / evict-poisoned-worker drill
  harness (#206, N10).
- **Round-3 test-quality + docs + hygiene:** `jobs/streaming.py` enforced at 100% coverage + mutation
  (#212, P5); property/fuzz tests for `parse_address`/`validate_name` + an autouse metrics-reset
  fixture (#218, P14/P16); retired 3 coverage-theater RPC round-trip skip-stubs (#219, P8); the
  operational-observability reference `docs/observability.md` — snapshot schema, SLIs/SLOs, log-based
  alerts (#215, P4); the Renovate manual-bump decision + a health-probe `root_path` caveat (#221,
  P12/P16); corrected stale GitHub-Action version tag-comments (#213, P11); the mutation gate turned
  into a regression floor (`MUTATION_SCORE_MIN=65`, baseline 69.5%) + killed the error-envelope status
  survivors (#222, P7).
- **Round-4/5 gap-remediation test + CI + docs:** the live abuse/containment e2e now runs on a
  nightly schedule (#223, Q1); the critical-module 100%-coverage tripwire extended 5→7 with an
  assertion that the ci.yml / pyproject / test lists stay in sync (#224, Q3); hostile-worker
  notification decoders (#230, Q5) and the structural-DoS validators (#231, Q7) property-fuzzed; the
  streaming chunk-flood cap (#243, round-5 R4) covered; two never-wired integration skip-stubs
  removed (#227, Q14); two stale round-3 security docs corrected (#226, Q13); a `setup-python` pin
  tag-comment aligned (#239, INFO-3); threat-model TB4/TB6 deltas recorded for the #232/#234 authZ
  fixes (#246, R7); the HTTP auth-fault fail-closed + resolver-raise paths covered (#250, R14); the
  ADR-034/runbook proxy-header replace-not-append (first-value-wins, CWE-290) constraint documented
  (#251, R10); and the streaming chunk-seq invariant extended to backward + duplicate vectors
  (#253, R13).

## [0.12.0] — 2026-06-24

ELF library identification lands. `identify_functions` — Windows/MSVC-only in v0.11.0 — now returns
real matches on Linux binaries: this release bundles **permissive-source FunctionID databases** (zlib,
musl static libc, OpenSSL 3.x, Boost) into the worker image, so the tool labels libc / crypto /
compression / C++ library code on ELF (Vivarium's primary target). Additive — no tool or contract
change (catalog stays **56**); the only observable difference is non-empty matches on ELF.

### Added
- **Bundled ELF FunctionID databases (ADR-042/043 Phase 2; x86-64).** zlib (Zlib), musl static libc
  (MIT), OpenSSL 3.x libcrypto/libssl (Apache-2.0), and Boost compiled libraries (BSL-1.0) — generated
  build-time from digest-pinned source, baked into the worker image at `/opt/vivarium/fid/*.fidbf`, and
  attached at worker startup. `identify_functions` now identifies Linux library code (previously ~0
  matches on ELF). (#152–#157, #167)
- **`--minimal-analysis` FID generator mode (ADR-043 Inc E).** Builds a FID database from a very large
  C++ object (Boost) without overflowing Ghidra's analysis DB buffer cache; match-validated end-to-end
  (215 Boost matches, zero false positives). (#167)

### Changed
- **FID generator modernized** off the deprecated `pyghidra.open_program` onto the supported
  `open_project` + `program_loader` API — regression-free across the bundled databases. (#158)

### Security / CI
- **`fid-elf-match-gate` is now a required branch-protection check** — a deadlock-proof always-run gate
  that requires the real-worker `live-regression` suite to pass on any FID-path PR; verified end-to-end.
  Adds a deterministic same-toolchain ELF-match hard gate, per-PR auto-trigger on FID paths, and
  fork-PR hardening (auto-run restricted to same-repo PRs). (#159–#162, #164, #166)
- **FID source-license gate** (merge-blocking) restricts bundled databases to permissive licenses
  (blocks copyleft / AGPL / pre-3.0 OpenSSL). (#151–#153)
- hadolint hygiene on `Containerfile.worker` (justified DL4006 annotations). (#168)

## [0.11.0] — 2026-06-21

Library-function identification: the new read-only `identify_functions` tool surfaces Ghidra
**FunctionID (FID)** matches as untrusted, bounded **hints** — auto-labeling known library code so an
LLM client can focus on the program's own logic. Plus session/export provenance polish. Additive —
every existing tool and contract is unchanged; the catalog grows **55 → 56**.

### Added
- **`identify_functions` — library-function identification (ADR-042 Phase 1).** A read-only tool that
  runs Ghidra's FunctionID service over the analyzed program and returns, per matched function, the
  library function name + `"<family> <version> <variant>"` + FID score. Each binary-derived field is
  wrapped in the ADR-005 untrusted-data envelope (a match is a best-effort, possibly-multiple **hint**,
  never an authoritative identity), and the result is bounded with a `truncated` flag. **Phase 1 covers
  the bundled MSVC FID databases** (Windows/PE targets); ELF database coverage is deferred (ADR-042
  Phase 2, behind a headless-activation + licensing spike). Catalog **55 → 56**. Validated end-to-end
  against the real worker (a `live-regression` hard gate).
- **`SessionInfo.analysis_profile` (ADR-029).** `session_status` now echoes the effective analyzer
  profile that ran (`default` / `light` / `deep`, or `null` before analysis).
- **`SessionInfo.binary_size`, and export-document `binary.name` / `binary.size` provenance.**
  Populated server-side from import metadata — no binary parse (ADR-001); `name`/`size` remain advisory
  (the `sha256` binding stays authoritative).

### Changed
- Tool catalog **55 → 56** (the `identify_functions` tool).

## [0.10.0] — 2026-06-21

Streaming reverse-engineering: the worker now emits decompiled functions **as it produces them**, so an
LLM client can begin reasoning over early results while extraction continues, and can stop a long run
mid-stream. Additive — every existing tool and contract is unchanged; the catalog grows **51 → 55**.

### Added
- **Streaming partial results (ADR-040) + mid-stream cancellation (ADR-041).** A bulk decompile is run
  as a pull-based job: the worker streams one `$/chunk` partial result per decompiled function, the
  server buffers them with pause-backpressure (never silent drop), and the client pulls batches by a
  monotonic cursor (seq-ordered, resumable, each chunk wrapped in the ADR-005 untrusted-data envelope).
  First-chunk latency is far below full-run time, so inference overlaps extraction. Four new Tier-1 tools
  (**catalog 51 → 55**): `start_decompile_stream`, `fetch_job_results`, `job_status`, and `cancel_job`
  (stops the worker promptly mid-stream via a `$/cancel` control notification). Each job is bound to its
  session/principal (BOLA) and lives within the ADR-002 worker lifetime; one active streaming job per
  session. Live-validated against the real Ghidra worker (extraction overlap + prompt cancel).
- **CI run-status reporting (ADR-039).** `live-regression` now reports start/finish status via GitHub
  annotations, a job summary, and an optional ntfy push.
- **Worker-image trust-pin automation.** A release tag now opens a reviewed PR bumping the committed
  `.github/worker-image.pin`; the `live-regression` and `e2e-groundtruth` workflows resolve the pinned,
  cosign-verified digest from that file instead of a stale repo variable.

### Changed
- Tool catalog **51 → 55** (the four streaming tools above).
- New clamp-only limit **`VIVARIUM_MAX_STREAM_BUFFER_CHUNKS`** caps the server-side per-job chunk buffer.

### Security
- Bump `pydantic-settings` 2.14.1 → 2.14.2 (GHSA-4xgf-cpjx-pc3j).

## [0.9.0] — 2026-06-19

**Project renamed `ghidra-mcp` → `Vivarium`** (ADR-038). Vivarium = a sealed enclosure to safely keep and
observe a live, dangerous specimen — the per-session isolated, hostile-binary worker (contain) you then
inspect (reveal). No capability change; the catalog stays **51 tools**. The project remains a secure MCP
server exposing **Ghidra** — "Ghidra" still names the engine throughout.

### Changed (BREAKING — operator + integrator action required)
- **Import package `ghidra_mcp` → `vivarium`**; module entry point `python -m ghidra_mcp` → `python -m
  vivarium`; **distribution name → `vivarium-mcp`** (matches the GitHub repo); console script
  `ghidra-mcp` → `vivarium`.
- **Environment-variable prefix `GHIDRA_MCP_*` → `VIVARIUM_*` (clean break, no fallback — ADR-038 D2).**
  Every config var is renamed (e.g. `GHIDRA_MCP_WORKER_MEM_MIB` → `VIVARIUM_WORKER_MEM_MIB`); the server
  reads **only** `VIVARIUM_*`. Update all deployment/launch env and local recipes before upgrading.
- **MCP server display name `ghidra-mcp` → `vivarium`** (the handshake name MCP clients see).
- **Container images `ghidra-mcp-{worker,server}` → `vivarium-{worker,server}`** (`ghcr.io/0xb007ab1e/…`);
  the new images publish on this release tag. Prior `ghidra-mcp-*` images remain as historical artifacts.

### Notes
- **History preserved (ADR-038 D8):** historical ADRs (001–037), prior CHANGELOG entries, and the roadmaps
  keep the `ghidra-mcp` name as it was at the time — they are an immutable record and were not rewritten.
- The GitHub repository is renamed `ghidra-mcp` → `vivarium-mcp`; GitHub auto-redirects old links, clones, and
  the prior release URLs.

## [0.8.0] — 2026-06-19

The **v1.6** increment — a reliability/observability + supply-chain hardening pass. No new tools (the
catalog stays **51**), no RPC or error-envelope **contract** change; the one client-observable change
is the worker heap-OOM reclassification below.

### Changed
- **Worker JVM heap-OOM is now classified `resource-exhausted` (503, not retryable), not
  `worker-unavailable` (ADR-037).** The worker JVM runs `-XX:MaxRAMPercentage=75` +
  `-XX:+ExitOnOutOfMemoryError`, so a heap OOM self-exits the JVM via `os::exit(3)` (container
  `ExitCode=3`, `OOMKilled=false`) *below* the cgroup wall — which `exit_diagnosis()` previously
  mis-tagged as the generic, **retryable** `worker-unavailable`. It now also recognizes exit `3`
  (collision-free: the worker's own deliberate exit codes are `{0,2}`) alongside the existing cgroup
  OOM-kill path (`OOMKilled` / exit `137`). **Client impact:** a heap-OOM on the same input + cap is
  now correctly reported as non-retryable (it would OOM again). Pure server-side container-engine
  metadata query — ADR-001 intact (no binary parsed, no JVM in the server). Live-verified on the real
  worker image.
- **`resource-exhausted` errors now name the configured memory cap + the knob to raise** (ADR-037 §3):
  `"worker exhausted its memory limit (N MiB); increase GHIDRA_MCP_WORKER_MEM_MIB (currently N) or
  reduce input size"`. Server-computed integer + fixed knob name only — no host path or
  binary-derived content (error-envelope disclosure rules unchanged; `detail` is the non-frozen
  per-occurrence field, so this is not a contract change).

### Security
- **SAST gate is now fully offline + reproducible (v1.6 #5).** Semgrep previously ran
  `--config p/python --config p/security-audit`, fetching rule packs from semgrep.dev at scan time
  (network egress, not lock-covered, silently mutable). The packs are now **vendored** under
  `infra/semgrep/p-*.yml` (151 + 225 rules, with provenance headers) and the gate runs
  `--config infra/semgrep/ --metrics=off --disable-version-check --exclude infra/semgrep .` — no
  scan-time network calls, whole-repo coverage preserved (`worker/` + `scripts/` included; bandit
  only covers `src/`), refreshed deliberately via `infra/semgrep/refresh.sh`.

### Docs
- Corrected the frozen tool-catalog tier-count prose (the breakdown summed to 49; the structural-write
  tier is **8** — the ADR-013/014/015 set plus `define_types` (ADR-021) and `delete_type` (ADR-031);
  the headline **51** was always correct and test-asserted) and synced the error-envelope
  `resource-exhausted` note with ADR-037. Added ADR-037 and the v1.6 roadmap (reconciled against the
  actual workflow/contract files: dropped an already-implemented "proactive image rescan" item and
  demoted a "pin buildkit-syft-scanner" item to a maintenance note).

## [0.7.1] — 2026-06-18

A **supply-chain patch** completing the v1.5 release. The `v0.7.0` tag's image build **fail-closed**
on a newly-published base-layer CVE (the supply-chain gate working as designed), so no signed v0.7.0
artifacts were published; **v0.7.1 is the first complete, signed v1.5 release** (same application code
as `[0.7.0]` below — no tool / RPC / envelope change).

### Security
- **CVE-2026-44432 (HIGH, `py3-pip-wheel`) remediated — upgrade-first, no waiver.** Trivy fail-closed
  the v0.7.0 release-image build on `py3-pip-wheel 26.1.2-r0` (fixed in `-r1`); `pip` is a
  build-bootstrap package, **not executed in the distroless runtime**, but it was patched rather than
  waived (preferred remediation order). **Server:** bumped the Chainguard/Wolfi `python` base image
  pins (`-dev` builder + runtime) to current digests that ship `py3-pip-wheel 26.1.2-r1`. **Worker:**
  floored `apk add … "py3-pip-wheel>=26.1.2-r1"` (it rides in as a transitive dep of `python-3.12`;
  the explicit constraint also busts the stale build-layer cache so a fresh resolve gets the fix).
  Both images re-verified locally: **Trivy HIGH/CRITICAL = 0**.

## [0.7.0] — 2026-06-18

The **v1.5** increment — a correctness/supply-chain hardening pass: a worker analyzer-option
**existence guard** (fail closed on a version-renamed preset option), an on-demand
**naming-accuracy scorer** (advisory eval tooling), hash-pinned CI installs for the dev and scanner
tool surfaces (run-from-`src/`), the analyzer-`profile` dimension folded into the live-regression
harness, and a dedicated **`forbidden` / 403** authorization-denied error type. Backward-compatible:
every change is additive or opt-in — no tool / RPC contract was broken. The one client-visible
contract change is **additive** (a new error-envelope slug; see Security + the compatibility note).
The tool catalog stays **51** (no new tool); ADRs now span **001–036**.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before 1.0.

### Added
- **Analyzer-option existence guard (ADR-035)** — `session_analyze` now **fails closed** with an
  `internal-error` if a `light`/`deep` profile preset names an analyzer option the running Ghidra
  build doesn't expose. The v1.4 profile gate (ADR-028 follow-up) caught a *binding crash* on the
  `getOptions(ANALYSIS_PROPERTIES)` / `setBoolean` edge, but **not** a silently renamed option —
  `Ghidra Options.setBoolean` tolerates unknown names, so a version bump that renamed a preset option
  would have made the profile a silent no-op. The guard enumerates the program's available analysis
  options and rejects any preset name not present (the pure name ∈ available-options decision is
  unit-tested; the JVM enumeration is live-verified on a real branch worker). An abuse test asserts a
  bogus preset name fails closed. Worker-side only; no new trust boundary (extends the ADR-029 JVM
  edge); no client-facing contract change.
- **On-demand naming-accuracy scorer (ADR-010 — `scripts/naming_eval.py`)** — promotes the v1.3
  blind-acceptance run's one-off debuginfod scoring into a committed, reusable, **advisory** tool
  (NOT a CI gate; it runs no LLM). Given a set of **proposed** names and an address→name
  **ground-truth** source it scores strict exact-match rate + token-set F1 by delegating to the
  project's own unit-tested scoring, now extracted as the public `naming.metrics.score_name_map`.
  Three ground-truth sources: **`debuginfod`** (the v1.3 path — build-id → debuginfod → DWARF),
  **`elf`** (a local unstripped build), and **`json`**. It reads only DWARF/build-id metadata via
  pyelftools — **never executes the binary and never parses it through Ghidra** (ADR-001 / ADR-016;
  benign/source-available ground truth only — master §5). Live-verified end-to-end on the `elf`
  path and against the live debuginfod federation (106 real function names for `/usr/bin/gzip`).
  Naming quality stays a non-deterministic, advisory LLM signal — never a gate.

### Changed
- **CI: hash-pinned dev-dependency installs, run-from-`src/` (#101)** — the dev tool surface now
  installs via `pip install --require-hashes -r requirements-dev.lock` (replacing the floating
  `pip install -e ".[dev]"`), and the quality jobs run the package from `src/`. Closes the staged
  `# <- enable once the lock exists` TODO now that `requirements-dev.lock` is committed; reconciles
  `ci.yml` / `live-regression.yml` with `scheduled-rescan.yml` (which already consumed the dev lock).
  Pins every dependency by hash (`std-supplychain` / `workflow-cicd`). CI-only; no code change.
- **CI: hash-pinned scanner-tool installs (#104)** — bandit / semgrep / pip-audit now install from a
  dedicated hash-pinned `requirements-sast.lock` (`--require-hashes`), so the whole scanner surface
  is pinned, not just the runtime/dev surfaces. The scheduled rescan audits all **three** locks
  (runtime + dev + sast), surfacing a new CVE in any surface — including the scanner tooling —
  against `main` between releases. CI-only; no code change.
- **Live-regression harness gains the analyzer-`profile` dimension (ADR-028 follow-up, #98)** — the
  recurring live run now exercises `default` / `light` / `deep` as a **hard-gated** dimension, so a
  Ghidra change that breaks a profile (or, with ADR-035, renames one of its options) is caught by
  the nightly/label gate, not just at implement-time. No runtime capability or contract change.

### Security
- **Dedicated `forbidden` / 403 authorization-denied error type (ADR-036 — frozen-contract change,
  additive)** — authorization denials now return a distinct `forbidden` (HTTP `403`) error slug
  instead of riding the generic `validation-error` / `400`. This covers a missing OAuth capability
  (ADR-033 scope→tool authZ) and an absent write / structural-write consent (ADR-012), letting a
  client mechanically distinguish "you may not" from "your request was malformed." It is an
  **additive** slug — no existing slug is repurposed — so the frozen `docs/contracts/error-envelope.md`
  takes an additive contract bump, not a break. **BOLA invariant preserved (`std-owasp-api` API1):**
  an ownership / cross-caller denial is **never** `forbidden` — it stays `session-invalid` / `404`,
  so a 403 can never become an existence oracle; `forbidden` only fires *after* the owner check has
  passed. `detail` is a fixed, value-free string (never the token, the scope contents, or which
  capability). Server-only; hardens TB6; not retryable.

  > **Compatibility note (client-visible):** a client that previously branched on
  > `validation-error` / `400` for a **consent or capability denial** now receives `forbidden` /
  > `403`. Ownership / cross-caller denials still return `session-invalid` / `404` (BOLA-safe,
  > unchanged), and malformed arguments still return `validation-error` / `400` (unchanged). The slug
  > is additive; clients that don't special-case it degrade gracefully (an unknown error type is
  > still a typed failure). This is the only client-facing compatibility note in v0.7.0.

### Notes
- **Backward-compatible / no operator action required on upgrade.** Every change is additive or
  opt-in: the analyzer-option guard only fires on a genuinely-broken preset, the naming scorer is
  on-demand tooling, the CI changes are pipeline-only, and the `forbidden` type is an additive slug.
  The only awareness item is the `forbidden` / 403 reclassification above.
- **Annotation documents:** the v0.6.0 schema note still applies — new exports are `schema_version 2`
  and a v2 importer reads both v1 and v2; a pre-0.6.0 / v1-only importer rejects a v2 document.
- **No DB / persistence / schema migration** — sessions remain ephemeral (ADR-002); nothing is
  persisted server-side. Rollback is a redeploy of the prior signed image digest.
- **Tracked follow-ups (deferred, not regressions):** `session_import` progress (ADR-030 §D8 —
  deferred: import is fast + no clean `open_program` monitor hook); incremental/lazy analysis
  (ADR-029 §D5 — deferred, evidence-gate unmet); a self-hosted gVisor runner for per-PR live gating
  (ADR-028 §D3 — deferred, drift-gate unmet). See `docs/roadmap-v1.5.md`.

## [0.6.0] — 2026-06-17

The **v1.4** increment — large-binary usability (analyzer profiles, pre-flight reject, live
`analyze` progress), a deletion/round-trip completion of the type-write surface, fine-grained
OAuth authorization, and a reverse-proxy mTLS mode. Backward-compatible: every change is additive
or opt-in — no client-facing tool / RPC / envelope contract was broken. The tool catalog grows
**50 → 51** (`delete_type`). The TB2 worker RPC framing gains an **additive, opt-in** progress
notification (non-progress calls are byte-for-byte unchanged), and the annotation document schema
bumps **1 → 2** with import accepting both `{1, 2}`. A correctness-of-release fix also syncs the
stale in-package `__version__` (was `0.1.0`) to the real version.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before 1.0.

### Added
- **Analyzer-profile selector (ADR-029 B)** — `session_analyze` gains an additive, optional
  `profile: "default" | "light" | "deep"` (default = byte-for-byte current behavior). `light` skips
  the expensive Ghidra passes (decompiler parameter-ID, switch analysis, aggressive finders) so a
  large binary finishes in less heap/time while still populating the function/symbol surface the
  read tools depend on; `deep` adds the thorough passes. The closed `Literal` vocabulary is the
  validation (no free-form analyzer strings from the client — least-agency). Server→worker additive
  RPC param; live-verified on a real worker (default 8.2 s / light 6.7 s / deep 13.8 s on gzip 1.13).
- **Worker analyze progress signal (ADR-030, Phase 1 + Phase 2)** — a long `analyze` is no longer
  silent. The worker's Ghidra `TaskMonitor` emits **additive, opt-in `$/progress` JSON-RPC
  notifications** (TB2 framing revision; only when the call sets `params.progress: true`) carrying
  **percent + a closed phase enum only** — never free-form / binary-derived `TaskMonitor` strings
  (ADR-005 redaction). **Phase 1** relays them to the server log (correlation-id scoped, bounded).
  **Phase 2** streams them to the MCP client via `Context.report_progress`, **token-gated** on a
  client-supplied `progressToken`: with a token, `session_analyze` runs async (offloaded via
  `anyio.to_thread`) so the event loop stays free to flush notifications; with no token it runs
  inline exactly as before. Live-verified end-to-end through the real FastMCP runtime.
- **`define_types` annotation round-trip (ADR-032)** — session-authored composites now export as a
  **single `define_types` batch entry** and re-import through the existing gated handler, so
  **mutually-recursive pointer composites** (and any acyclic-but-misordered interdependency)
  round-trip losslessly (the pre-registration in the batch resolves the cycle; no per-entry ordering
  problem). The annotation document `schema_version` bumps **1 → 2**; import accepts **both `{1, 2}`**
  so existing v1 exports still import. A session authoring **> 64** composites fails closed
  `limit-exceeded` on export (no partial/lossy round-trip; the live writes succeeded).
- **Recurring live-worker regression harness (ADR-028)** — promotes the v1.3 blind-acceptance run
  into a scheduled CI workflow (`live-regression.yml`): nightly cron + `workflow_dispatch` + opt-in
  `live-regression` PR label (not per-PR — bounds Actions cost). It brings up the real hardened
  worker on **benign synthetic/OSS fixtures only** and asserts the two deterministic JVM-edge
  regressions unit tests structurally cannot catch — **F2** (export succeeds on a real program) and
  **F7** (exact user-authored entry count, zero auto-content) — as **hard gates**; naming-accuracy /
  behavioral-equivalence is an **advisory tracked metric**, never a gate (non-deterministic LLM
  signal). CI relaxes only gVisor → crun (the ADR-004 sanctioned floor for benign inputs); prod
  isolation is unchanged. A failed scheduled run is the alert. No runtime capability or contract
  change.

### Changed
- **Tool catalog 50 → 51** — adds the gated `delete_type` (below); all prior tools unchanged. The
  exact count stays asserted in tests.
- **Pre-flight reject mode (ADR-029 C)** — the v1.3 warn-only size-vs-memory pre-flight is now
  selectable via `GHIDRA_MCP_WORKER_PREFLIGHT ∈ {warn, reject, off}`, **default `warn`** (v1.3
  behavior preserved). `reject` fails fast at import time with the existing non-retryable
  `resource-exhausted` (503) instead of burning ~26 min on a doomed OOM run; `off` silences the
  heuristic (the hard size cap + memory cgroup remain). Opt-in; no behavior change unless configured.
- **In-package `__version__` synced** — `src/ghidra_mcp/__init__.py` advertised a stale
  `__version__ = "0.1.0"`; it is now `0.6.0`, kept in sync with `[project].version` in
  `pyproject.toml` (the build-time source of truth). No runtime path read the stale value (it is not
  wired into the MCP handshake), so this is a metadata-correctness fix, not a behavior change.

### Security
- **Gated `delete_type` for session-authored composites (ADR-031 — tools 50 → 51, GATED)** — the
  inverse of `define_struct`/`define_union`/`define_types`. Deletion is bounded to types **this
  session created** (the ADR-027 change-log `composite_targets`, server-side authority) — a Ghidra
  auto-analysis struct, a built-in, or another session's type is **never** deletable, so the
  injection "delete type `FILE`" fails closed (a data-poisoning defense by construction, not by
  in-use detection). Gated by **write consent + `allow_structural`**, untrusted name validated at
  the boundary, one worker transaction with rollback, audited (name length only — never contents),
  and the change-log entry removed so a later export never references a deleted type. An in-use type
  may be deleted and the result reports `dependents_reverted` (the caller's own applications). No new
  trust boundary (extends TB7). Live-verified on a real worker.
- **OAuth scopes → per-tool read/write authorization (ADR-033)** — closes the ADR-019 §E gap
  (`std-owasp-api` API5). A `Principal` now carries `capabilities ⊆ {read, write}`; the 15 mutation
  tools require `write`, everything else requires `read`, enforced at the registry dispatch chokepoint
  (complete mediation, server-side, every request). **Config-gated opt-in, default off**: with
  `GHIDRA_MCP_HTTP_OAUTH_WRITE_SCOPE` unset, OAuth tokens get full capability (byte-for-byte prior
  behavior); set it and a token gets `write` **iff** its `scope`/`scp` claim contains the configured
  value — a read-only token is mechanically barred from every write tool. Non-OAuth principals
  (stdio / bearer / mTLS) stay full-capability. Structural granularity remains the orthogonal
  `allow_structural` runtime consent (defense in depth). Denial maps to the existing `VALIDATION`
  envelope (no error-contract change). Server-only; hardens TB6.
- **Reverse-proxy-terminated mTLS, opt-in (ADR-034)** — a new `auth_mode=mtls-proxy` lets a
  TLS-terminating reverse proxy (nginx/Envoy/HAProxy) forward a verified client identity, made safe
  by a **required pre-shared secret** that anchors trust: the proxy must send a correct secret header
  (`x-proxy-auth`, constant-time compared against `proxy_shared_secret`) or the forwarded identity
  header (`x-client-cert-subject`) is never consulted — generic reject, no oracle, fail closed. The
  mode **cannot start without the secret** (config validation), and a mandatory network-isolation
  deployment constraint is documented. The forwarded subject is validated (non-empty, length-bounded,
  no control chars) → owner-scoped `Principal` (ADR-017). The secret is never logged / excluded from
  `repr`. Purely additive (bearer / mTLS / OAuth / none paths unchanged); server-only; hardens TB6.

### Notes
- **Backward-compatible / no operator action required on upgrade.** Every new capability is additive
  or opt-in and default-safe: `profile` defaults to `default`, `GHIDRA_MCP_WORKER_PREFLIGHT` defaults
  to `warn`, progress is inert without a client `progressToken`, OAuth scope-authZ is off until
  `GHIDRA_MCP_HTTP_OAUTH_WRITE_SCOPE` is set, and `auth_mode=mtls-proxy` is a new opt-in mode.
- **Annotation documents:** new exports are `schema_version 2`; a v2 importer reads both v1 and v2,
  so existing v1 exports keep importing unchanged. (A pre-0.6.0 / v1-only importer will reject a v2
  document as an unsupported version rather than mis-parse it — export v1 documents if a downstream
  consumer is still on an older build.)
- **No DB / persistence / schema migration** — sessions remain ephemeral (ADR-002); nothing is
  persisted server-side.
- **Tracked follow-ups (deferred, not regressions):** real `analyze` progress for `import_binary`
  (ADR-030 §D8 — import is fast; trivial future extension); incremental/lazy analysis (ADR-029 §D5);
  atomic type *redefine* and deletion of built-in/recovered types (ADR-031 — each its own re-render
  threat model). The README "latest release" banner still cites an older version (docs-only drift,
  not shipped behavior) — refresh separately.

## [0.5.0] — 2026-06-17

The **v1.3** increment — hardening and correctness driven by a **blind real-world acceptance run**
(a stripped binary analyzed end-to-end on the real worker; 33/39 blind function names verified
functionally-correct against debuginfod ground truth). Backward-compatible: no client-facing tool /
RPC / envelope contract changed; the tool catalog stays **50**. Two never-run JVM-edge bugs that unit
tests structurally cannot catch (F2, F7) were found and fixed via the live run, then re-verified live.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before 1.0.

### Added
- **Configurable worker resources (ADR-023, F1)** — worker memory / cpus / pids / tmpfs are now set
  via `GHIDRA_MCP_WORKER_*` env (integer MiB / whole CPUs), each with a safe default + hard ceiling,
  so large binaries can run on bigger hosts without a rebuild. All ADR-004 hardening (non-root,
  ro-rootfs, dropped caps, no-network, **no-swap**, seccomp) is unchanged.
- **`resource-exhausted` error (ADR-023, F1)** — a worker OOM / abnormal exit is now a distinct,
  non-retryable `503` (classified from the container engine's OOM/exit signal) instead of masquerading
  as a generic retryable `worker-unavailable`. Plus a warn-only pre-flight when an input is implausibly
  large for the configured memory.
- **Worker-error observability (ADR-024, F2/F3)** — the worker now attaches a **redacted** `data.detail`
  (exception class + fixed template, never raw text) to its JSON-RPC errors; the server log renders
  `exc_info` tracebacks (frames-only, value-echoing `ValidationError` lines stripped); a reserved
  `LogRecord`-key guard stops `extra={"msg": …}`-style collisions from crashing a handler.
- **Blind acceptance harness + v1.4 backlog (tooling/docs)** — `scripts/acceptance_run.py` (Mode A
  analyze→select→dump, Mode B apply→export→measure, with progress) + `docs/roadmap-v1.3-findings.md`
  and `docs/roadmap-v1.4.md`.

### Changed
- **Export only user-authored annotations (ADR-027, F7)** — `session_export_annotations` previously
  leaked Ghidra **auto-generated** content (a 39-rename session exported 39 renames **+ 13 auto structs
  + 1138 auto comments**). Comments carry no source-type and auto structs are program-local, so a
  **session-scoped, in-memory, evict-wiped change-log** (identity keys only — ADR-002-compatible) now
  gates comments + composites; symbols/signatures stay `USER_DEFINED`-enumerated. The `export_annotations`
  worker RPC gains an **additive, server-supplied `targets`** field (server→worker only; client tool +
  envelope unchanged). Live-verified: a 1-rename/1-comment/1-struct session exports exactly 3 entries.
- **Session liveness during long calls (ADR-025, F4)** — a long `analyze` no longer idle-evicts its
  own session: in-flight calls are exempt from the idle timeout (the per-call timeout-kill remains the
  in-flight DoS bound); the absolute TTL is re-applied at the next call boundary. Adds a fail-closed
  startup invariant `session_idle_s ≥ analysis_timeout_s`. Defaults unchanged.

### Fixed
- **`session_export_annotations` crashed on every real program (ADR-024, F2)** — step 1 called a
  non-existent `ArchiveType.isProgramArchive()` (an `AttributeError` that collapsed the whole export);
  fixed to compare against `ArchiveType.PROGRAM`. Also guards address-less `USER_DEFINED` symbols in
  the symbol-rename enumeration.

### Security
- **Dependency CVE bumps** — `starlette` ≥ 1.3.1 (CVE-2026-54282 / CVE-2026-54283) and `cryptography`
  ≥ 48.0.1 (GHSA-537c-gmf6-5ccf); the hashed lock resolves to starlette 1.3.1 + cryptography 49.0.0.
  `pip-audit` on the lock: no known vulnerabilities.

### Docs
- **Rename name-collision behavior documented (ADR-026, F5)** — duplicate function names apply
  (Ghidra keys functions by address); duplicate same-namespace symbol names already fail closed;
  client-side de-duplication is the recommended practice. No server change.

## [0.4.0] — 2026-06-15

Composite-batch type creation + a deeper naming-eval. The tool catalog grows **49 → 50**.
Backward-compatible: the new tool is additive (no existing tool / RPC / envelope contract changed)
and gated; the eval refinement is client-side and additive.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before 1.0.

### Added

**`define_types` — multi-type composite batch (ADR-021 — tools 49 → 50, GATED)**
- Create a **batch of interdependent new composites** (structs/unions) in **one transaction** — a
  field may reference **another new composite in the same batch** (beyond ADR-015's single-composite
  `define_struct`/`define_union`, which remain). Gated by per-session write-consent + `allow_structural`.
- **By-value cycle detector:** an iterative 3-colour DFS over by-value member edges (`pointer_levels
  == 0`, array-of-B included) **rejects** any by-value cycle (self / array-of-self / A↔B / longer) →
  infinite-size types are impossible; **pointer members create no edge**, so **mutually-recursive
  pointer structs are allowed**.
- Assembly **pre-registers all empties** in the batch, resolves + adds each, enforces a batch-total
  size cap, and **rolls back the whole batch** on any failure (no partial/orphan type). Structured
  `TypeRef` only (no C parsed); name-collision (existing or intra-batch dup) fail-closed REJECT.

**Deeper behavioral-equivalence eval (ADR-022 — client-side)**
- `behavioral_equivalence_normalized` — a second naming-eval score reported **alongside** the
  unchanged strict byte-exact `behavioral_equivalence`. A conservative `normalize_output` masks
  volatile tokens (pointers `0x…`, ISO/clock timestamps, labelled PIDs, trailing whitespace) so two
  builds that differ **only** in volatile output are no longer scored as divergent. Invariant
  `normalized >= strict`; over-normalization risks false positives, so **strict stays the primary
  signal** (measured, not guaranteed).
- Seeded, deterministic `generate_fuzz_vectors` broadens behavioral coverage beyond the fixed
  vectors. Still **never runs the analyzed (hostile) binary** — A = trusted-source build vs B =
  recompiled renamed-C, both sandboxed (TB5).

### Changed
- Tool catalog **49 → 50** (`define_types`); all prior tools unchanged.

### Security
- **TB7** extended (ADR-021): the by-value cycle detector + one-transaction rollback-all bound the
  composite-batch write surface; structural consent + owner-scoping unchanged.
- **TB5** extended (ADR-022): normalization is a pure transform on inert captured bytes; fuzz inputs
  are seeded/bounded synthetic; the eval never executes the hostile original.

### Notes
- **Backward-compatible** (additive gated tool + additive client-side metric).
- **Tracked follow-ups:** `define_types` persistence round-trip of mutually-recursive pointer
  composites (ADR-021 §b); memory-state / coverage-guided equivalence (ADR-022 deferred).

## [0.3.1] — 2026-06-15

Patch release: the **mTLS peer-cert bridge** — `auth_mode=mtls` is now end-to-end functional (ADR-020), resolving the v0.3.0 known limitation. No new dependency; no other auth/transport path changed.

### Added
- **mTLS peer-cert bridge — `auth_mode=mtls` now functional (ADR-020).** A custom uvicorn HTTP
  protocol (`MtlsAwareProtocol`, used **only** for `auth_mode=mtls`) injects the **verified** client
  certificate into the ASGI scope, so it reaches the in-app `MtlsAuthenticator` and resolves to its
  cert-derived principal. Completes the ADR-019 increment-A seam: the `[0.3.0]` "Known limitation"
  (the cert never reaching the authenticator → all requests rejected) is resolved. Fail-closed
  preserved (an empty/absent peer cert injects nothing → generic `401`); the cert is read **only**
  from the verified TLS object, never a header (no spoofing). No new dependency; every other
  transport/auth path is unchanged.

### Security
- mTLS is now end-to-end verified by a **real-TLS integration test** (synthetic CA + server/client
  certs; no real secrets): a CA-signed client cert authenticates as its CN principal, and a client
  with no/untrusted cert is rejected at the handshake (ADR-019 abuse case 70 promoted from skip).
- Removed the `auth.mtls_bridge_pending` startup warning (the bridge is now wired).

## [0.3.0] — 2026-06-15

Cross-session **annotation persistence** plus two new pluggable **authentication identity sources**
(mTLS, OAuth) for the HTTP transport. The tool catalog grows **47 → 49**. Backward-compatible: all
new tools are additive (no existing tool / RPC / envelope contract changed), and the new auth modes
are opt-in. Ghidra still runs **isolated, headless, out-of-process** (ADR-001); the analyzed binary
remains hostile input.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before 1.0.

### Added

**Cross-session annotation persistence (ADR-018 — tools 47 → 49)**
- **`session_export_annotations`** — exports a session's `USER_DEFINED` annotations
  (renames / comments / signatures / applied + defined types) as a **versioned, binary-hash-bound,
  structured document**; read-only, owner-scoped, binary-derived strings wrapped `Untrusted`
  (ADR-005), bounded.
- **`session_import_annotations`** — replays such a document into a fresh same-binary session:
  schema-validated → **binary-hash verified** (mismatch fails closed) → write-consent gated
  (+ `allow_structural`) → **every entry re-validated through the live validators and replayed via
  the existing gated write tools** (one transaction each). **Import adds no new write primitive.**
- **Stateless / client-owned:** the server persists nothing (ADR-002 preserved) — export returns the
  document, import takes it; the client owns the artifact + its confidentiality. New trust boundary
  **TB8** (threat-model §12).

**Pluggable authentication identity sources for HTTP (ADR-019)**
- **OAuth (`GHIDRA_MCP_HTTP_AUTH=oauth`) — functional.** JWT access tokens validated locally via
  **JWKS**: a **pinned asymmetric algorithm allow-list** (`alg:none` and HS/RS confusion impossible —
  the token's `alg` is never trusted), `iss` / `aud` / `exp` / `nbf` enforced, `sub` (configurable)
  → principal. JWKS is fetched + cached (no per-request round-trip); failures fail closed, no oracle,
  the token is never logged. Config: `…_OAUTH_ISSUER` / `…_AUDIENCE` / `…_JWKS_URI` /
  `…_PRINCIPAL_CLAIM` / `…_ALGORITHMS` / `…_LEEWAY_SECONDS`.
- **mTLS (`GHIDRA_MCP_HTTP_AUTH=mtls`) — seam shipped (made functional in [Unreleased] / ADR-020).**
  Server-terminated client-cert verification (uvicorn `CERT_REQUIRED` + a configured client-CA
  bundle); the verified cert's configured field (CN / SAN / DN) maps to the principal. Config:
  `…_TLS_CLIENT_CA`, `…_MTLS_PRINCIPAL_FIELD`. (In 0.3.0 the verified cert did not yet reach the
  authenticator — wired by the ADR-020 peer-cert bridge in [Unreleased].)
- Both produce distinct **`Principal`s** that feed the existing per-principal session-ownership
  mechanism (ADR-017) unchanged. Hardens trust boundary **TB6** (threat-model §13).

### Changed
- Tool catalog **47 → 49** (the two persistence tools; all prior tools unchanged).

### Security
- **TB8** (annotation-import) and **TB6** (mTLS/OAuth identity) threat-modeled (STRIDE); 25 new
  abuse-case tests (annotation-import 68–77; mTLS 67–71; OAuth 72–82, renumbered in §13).
- Network principals are now **cryptographically proven** (client cert / JWKS-verified JWT), not just
  shared bearer secrets; all auth modes are fail-closed with no credential oracle and no token/cert
  logging.

### Dependencies
- Promoted **`pyjwt[crypto]`** (MIT) + **`cryptography`** (Apache-2.0 / BSD) to direct dependencies
  for OAuth (already present transitively via `mcp`); pinned + hashed in the lockfile
  (`pyjwt 2.13.0`, `cryptography 48.0.0`); `pip-audit` reports no known vulnerabilities.

### Known limitations
- **`auth_mode=mtls` is not yet end-to-end functional.** *(RESOLVED in [Unreleased] by the ADR-020
  peer-cert bridge — `auth_mode=mtls` is now functional.)* In 0.3.0, uvicorn did not surface the
  verified peer certificate into the request scope, so the transport→scope peer-cert bridge was a
  tracked follow-up; until it landed, an `mtls` endpoint was **fail-closed** (the TLS handshake still
  required a CA-signed client cert, and the authenticator rejected when no cert reached it) and
  startup logged `auth.mtls_bridge_pending`. mTLS startup requires server TLS (refuses a plaintext
  mtls listener).

## [0.2.1] — 2026-06-13

Patch release: a defense-in-depth hardening of the (gated, client-side) naming-eval differential
runner. No tool/RPC/envelope contract change; no behavior change for normal use.

### Security
- **Bounded-streaming stdout capture in the differential-run sandbox (ADR-016 F1 / CWE-400).** The
  exec runner previously buffered a candidate's entire stdout (`subprocess.run(capture_output=True)`)
  before truncating to `max_stdout_bytes`, so the cap bounded only the *retained* output — a candidate
  flooding stdout could force the host to buffer far more during capture. It now performs a single
  bounded `read(cap)` at the subprocess boundary (`_read_capped`) then kills + reaps the child, so
  **peak host memory during capture is bounded by the cap**; the engine `--timeout` remains the
  wall-clock backstop. Confined to the gated TB5 eval path; the threat-model TB5 mitigation wording is
  corrected to match.

## [0.2.0] — 2026-06-13

The **first write surface.** v0.1.0 was strictly read-only; this release adds an allow-listed,
default-deny **mutation/write** tier (annotation + structural), a behavioral-equivalence naming
metric, and **multi-principal authorization** for the HTTP transport. The tool catalog grows
**35 → 47**. Ghidra still runs **isolated, headless, and out-of-process** (ADR-001 unchanged);
the analyzed binary remains hostile input; the server never loads the JVM or mutates — every
write executes only inside the hardened worker, in one transaction with rollback.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts may still evolve before
> 1.0. **This release is backward-compatible:** all new tools are **additive** (no existing
> tool / RPC method / envelope shape changed), the new write tier and per-owner session cap are
> **opt-in and default-off**, and existing stdio / single-principal users are unaffected (the
> session `owner` defaults to the implicit `local` principal). See `docs/contracts/`.

### Added

**Mutation / write tools — the headline (first write/agency boundary — threat-model TB7)**
- **Default-deny write consent (ADR-012):** a session is read-only until the operator calls the
  explicit, auditable, revocable, per-session, non-transferable **`session_enable_writes`**
  human-in-the-loop gate (OWASP LLM08 least-agency). `session_disable_writes` reverts to
  read-only; **`session_undo`** reverts the last committed mutation transaction. Every write runs
  `authorize → require_write_consent → validate → worker-RPC → audit`; the server **never
  mutates** (ADR-001) — the write executes only in the worker inside **one Ghidra transaction**
  (commit on success, `endTransaction(commit=False)` rollback on any failure — fail closed).
- **Annotation writes (ADR-012):** `rename_function`, `rename_symbol`, `set_comment`.
  Attacker-influenced `new_name` / comment `text` are validated **on the way in** (the
  `validate_write_name` identifier allow-list / bounded `validate_comment_text` normalization —
  stored-injection / data-poisoning defense), and the read path still wraps `Untrusted[...]` +
  normalizes **on the way out** (two-sided defense, ADR-005).
- **Structural writes — Phase A (ADR-013):** `rename_local_variable`, `rename_parameter` via the
  HighFunction path (name-only; the `updateDBVariable` data type is `null` — **no C parser
  surface**). HighSymbol resolution (decompile) happens **before** the transaction opens, so a
  resolution failure is a clean `not-found` with no transaction.
- **Structural writes — Phase B (ADR-014):** `set_function_signature`, `apply_data_type` over a
  **structured / constrained `TypeRef`** (resolved base/named types, bounded pointer-levels and
  array-length, closed-vocabulary calling convention) — **resolved against the program's
  `DataTypeManager`, never parsed from a C string**, so the C-parser injection surface is
  eliminated by construction (LLM07).
- **Structural writes — Phase C (ADR-015):** `define_struct`, `define_union` — composite
  *creation*. The empty composite is pre-registered so self-`named` pointers resolve (true
  self-referential types); a **by-value self-embed (incl. array-of-self) is rejected**, name
  collisions are fail-closed REJECTED, and a 1 MiB size cap + transactional rollback bound the
  rest.
- **Two-level consent for structural writes:** the six structural tools (Phase A/B/C) require, in
  addition to write consent, the **separate `allow_structural` opt-in**
  (`session_enable_writes{allow_structural: true}` → `require_write_consent(structural=True)`).
- **Per-write audit** (intent + outcome: tool, opaque session id, target address, value sizes,
  applied/denied — **never** binary-derived content or the new value verbatim; redacted) on an
  append-only stream; write-consent grant/revoke is itself audited. Mutations are
  **session-scoped + ephemeral** (lost on evict — ADR-002; no persistence).

**Behavioral-equivalence naming metric (ADR-016)**
- Completes ADR-010's deferred **`behavioral_equivalence`** metric with a client-side
  **differential harness** for semantic-naming quality (alongside the existing `naming_accuracy`
  + compile-rate). Evaluation extends the TB5 sandbox (rootless, no-egress, read-only rootfs,
  caps dropped, resource-capped, kill-on-timeout); it **never executes the hostile binary** —
  best-effort C remains a measured metric, not a guarantee.

**Multi-principal authorization for HTTP (ADR-017 — threat-model TB6)**
- **Multi-token bearer:** the single shared bearer token is replaced by a **token → principal-id
  map**, so distinct tokens authenticate distinct principals (constant-time compare, **no
  which-token timing oracle**, generic `401`, tokens never logged; mTLS/OAuth remain pluggable
  port stubs).
- **Enforced per-principal session ownership:** a session is owned by its creating principal; the
  `owner` is server-derived and immutable. Every session-scoped entry point (read / write /
  close) goes through the shared owner check (complete mediation).
- **Operator-configurable per-owner session cap** (`GHIDRA_MCP_MAX_SESSIONS_PER_OWNER`; **default
  off** — the global `max_sessions` backstops) bounds the noisy-neighbor / pool-monopolization
  case in a multi-principal deployment.

**Supply chain & operations**
- **Daily scheduled CVE rescan of `main` (`scheduled-rescan.yml`):** SCA (pip-audit on the
  hash-pinned runtime + dev lockfiles) **and** a digest-pinned image rebuild + Trivy scan, on a
  daily cron, **scan-only** (never builds-to-push / signs / publishes), **fail-closed** on a new
  HIGH/CRITICAL — the failed run is the alert. Surfaces a new CVE in an **unchanged** dependency
  or pinned base between releases (the gap that let CVE-2026-45447 / openssl reach the v0.1.0 tag).

### Changed
- **Tool catalog: 35 → 47** — 22 Tier-1 read-only + 5 semantic-naming + 8 Tier-2 reporting
  (all read-only, unchanged) **+ 12 new write tools** (6 annotation/lifecycle ADR-012, 6
  structural ADR-013/014/015). The exact count is asserted in tests.
- **HTTP BOLA (TB6-I) is now ENFORCED, no longer deferred (ADR-017):** v0.1.0 closed BOLA "by
  construction" for a single principal (256-bit CSPRNG session-id capability); v0.2.0 adds an
  **enforced per-principal owner check** on top — a cross-principal session reference returns the
  **same `SESSION_INVALID`** as unknown/expired/evicted (no oracle). Transparent to existing
  single-principal / stdio users (owner defaults to `local`).

### Security
- **TB7 — write/agency boundary (ADR-012/013/014/015):** mutation raises OWASP LLM08 agency (the
  read-only "no destructive action exists" bound no longer holds inside a write-enabled session).
  Bounded — not prevented — by default-deny consent (human gate), the second `allow_structural`
  gate, allow-list / structured-input validation (no free-form C parsed), one-transaction
  rollback, per-write audit, `session_undo`, and ADR-002 session ephemerality. Worst case is a
  mis-annotated / mis-restructured **disposable** session — never host or durable-data compromise.
- **TB5 — eval boundary extended (ADR-016):** the behavioral-equivalence harness compiles
  attacker-derived C in the existing no-egress / read-only / resource-capped / kill-on-timeout
  sandbox; compile-only, never links or runs the binary.
- **TB6 — enforced ownership + multi-token authn (ADR-017):** closes the deferred BOLA gap;
  forging another principal requires their secret token; identity is server-derived only.

### Notes
- **Pre-1.0 contract posture:** contracts remain frozen per release but may evolve before 1.0;
  this release is additive and backward-compatible (see the version header above).
- **New environment variables (opt-in):**
  - **Multi-token bearer map** — operator supplies a token → principal-id mapping (secret-managed
    credentials, never in source/logs); see `docs/runbooks/http-exposure.md`. HTTP off-loopback
    still requires **TLS + an authenticator** or the server fails closed at startup (unchanged).
  - **`GHIDRA_MCP_MAX_SESSIONS_PER_OWNER`** — per-owner session cap; **default off** (global
    `max_sessions` backstops).
- **Upgrade is transparent for read-only / stdio / single-principal users.** To use writes an
  operator must explicitly call `session_enable_writes` (and `{allow_structural: true}` for the
  6 structural tools). No DB schema or migration (sessions are ephemeral; no persistence).

## [0.1.0] — 2026-06-12

First tagged release. A secure [MCP](https://modelcontextprotocol.io) server that exposes
Ghidra reverse-engineering as read-only LLM tools, with Ghidra running **isolated, headless,
and out-of-process**. The analyzed binary is treated as hostile input; containment of the
analyzer is the central security control.

> **Pre-1.0 / private:** the tool catalog, RPC, and envelope contracts are frozen for v0.1.0
> but may evolve before 1.0. See `docs/contracts/`.

### Added

**Core server & isolation**
- Out-of-process architecture (ADR-001): the MCP server process **never loads the JVM or
  parses a binary**; Ghidra runs only in a separate hardened worker. In-process PyGhidra is
  forbidden and guarded.
- Hardened worker container (ADR-003/004): **Ghidra 12.1.2 + JDK 21 pinned by digest**,
  rootless OCI, non-root, read-only rootfs, all capabilities dropped, seccomp `RuntimeDefault`,
  **no network/egress**, CPU/memory/pids limits, tmpfs scratch; gVisor (runsc) supported.
- Server ↔ worker over an internal **JSON-RPC 2.0 on a per-session Unix domain socket**; the
  server is the worker's sole client (ADR-009).
- Persistent **per-binary sessions** with TTL + idle eviction; **one worker per session, killed
  on eviction** with a **verified project-store wipe** (ADR-002).
- DoS controls: per-analysis wall-clock timeout that **kills the worker**, max input size
  enforced before Ghidra, worker-pool concurrency cap + backpressure.

**Tier-1 read-only tools** (the frozen `docs/contracts/tool-catalog.md`)
- decompile, disassemble, list/inspect functions, xrefs to/from, strings, symbols/labels,
  data types, comments (read), memory map/segments, bounded read-bytes, bounded search, and
  program metadata. **Read-only** — no mutation tools, no `runScript`.

**Untrusted-data handling**
- All binary-derived output (decompilation, disassembly, strings, symbols, comments, bytes) is
  wrapped in a typed **untrusted-data envelope** (ADR-005): never auto-executed, rendered, or
  followed — mitigating indirect prompt injection (OWASP LLM01/02).

**Semantic naming (v1.1)**
- Leaf-first call-graph **semantic-naming** read-only tools, a client-driven reference loop, a
  sandboxed compile evaluator (TB5: rootless, no-egress, ro-rootfs, caps dropped, kill-on-timeout,
  compile-only), and a tracked **`naming_accuracy`** metric (exact-match + token-set F1 vs DWARF
  ground truth). Validated across cJSON/zlib/lua fixtures (ADR-007/010).

**Tier-2 reporting & metrics (v1.1)**
- Eight read-only tools: cyclomatic complexity, code/data coverage, imports, exports, IOC scan,
  crypto-constant scan (incl. CRC-32), call-graph metrics, and a program-summary report
  (ADR-008).

**HTTP transport (v1.1 — ADR-011 / threat-model TB6)**
- MCP **Streamable HTTP** with a **secure-by-default exposure ladder**: stdio (default) →
  loopback TCP → Unix domain socket → **gated** network TCP. A non-loopback bind **fails closed
  at startup** unless TLS **and** an authenticator are configured.
- Pluggable **`Authenticator`** strategy port: **bearer** token (constant-time compare, generic
  401, token never logged), with mTLS/OAuth as port-ready stubs.
- `std-owasp-api` edge hardening: per-client rate limiting (429, size-bounded LRU bucket map so the
  limiter cannot itself grow memory without bound — CWE-400), request size cap (413), strict CORS
  (no `*`), security headers (nosniff / X-Frame-Options / Referrer-Policy; HSTS on TLS), and a
  consistent error envelope that leaks no internals. The runbook documents that per-client limiting
  degrades to per-proxy behind a reverse proxy (rate-limit at the proxy there).
- BOLA/API1 closed by construction for single-principal (256-bit CSPRNG session-id capability +
  one principal); a per-principal owner check is deferred to a future multi-principal increment.
- Operator runbook: `docs/runbooks/http-exposure.md`.

**Security, supply chain & docs**
- STRIDE threat model over six trust boundaries (TB1–TB6) in `docs/security/threat-model.md`.
- Merge-blocking CI gates: ruff (lint+format), mypy `--strict`, pytest with coverage
  (≥90% line+branch, 100% on critical paths), bandit + semgrep (SAST), pip-audit (SCA), gitleaks
  (secret scan), Trivy (image/IaC scan).
- Supply chain: Ghidra/JDK/base images/CI-actions/Python deps **pinned by digest**; on `v*` tags
  the worker + server images are built, scanned, **SBOM-attested (SLSA provenance + SBOM)**, and
  **cosign-signed** (keyless/OIDC) — see `.github/workflows/worker-image.yml`.
- Abuse/injection test suites (prompt-injection envelope handling, BOLA-safe session errors,
  decompile-bomb/oversized-input bounds, HTTP edge abuse) and a ground-truth e2e against the real
  worker on stripped OSS binaries.

### Security
- This release establishes the project's first network attack surface (HTTP/TB6); it is
  off-by-default and fail-closed. See `docs/security/threat-model.md` and `SECURITY.md` for the
  reporting channel.

[Unreleased]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/0xb007ab1e/ghidra-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/0xb007ab1e/ghidra-mcp/releases/tag/v0.1.0
