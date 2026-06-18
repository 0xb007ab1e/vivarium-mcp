# ADR-037: Classify the JVM heap-OOM self-exit as `resource-exhausted` (+ memory-sizing hint)

- **Status:** Accepted (v1.6; human-ratified 2026-06-18). Ratified: (D1) match `ExitCode==3` as OOM
  alongside 137/OOMKilled; (D2) enrich the `resource-exhausted` detail with the configured cap + knob
  name; (D4) full real-worker OOM live-verify. **Live-verify PASS (2026-06-18):** on the real worker
  image (JDK 21, production `JAVA_TOOL_OPTIONS`), a JVM heap OOM exits the container with
  `State.OOMKilled=false, ExitCode=3`; the real `exit_diagnosis()` classifies that container `"oom"`
  and the adapter returns `resource-exhausted` (503, not retryable) with the cap + knob in the detail.
  Completes ADR-023/F1's OOM classification: the **common** worker OOM
  — the embedded JVM hitting its heap ceiling and self-exiting via `-XX:+ExitOnOutOfMemoryError`
  (container `ExitCode=3`, `OOMKilled=false`) — is today mis-classified as `worker-unavailable`
  instead of `resource-exhausted`. Recognize `ExitCode==3` as OOM, and enrich the
  `resource-exhausted` detail with the configured memory cap so an operator knows what to raise.
- **Date:** 2026-06-18
- **Deciders:** Human (ratifies the exit-3 match + the detail-string change) + PM; recorded by the
  Software Architect.
- **Addresses:** `docs/roadmap-v1.6.md` §1 (OOM → `resource-exhausted` on the JVM self-exit path) and
  §3 (operator memory-sizing hint). Surfaced by the v1.5 #5 measurement spike.
- **Relates to / constrained by:** ADR-023 (configurable worker resources + the `resource-exhausted`
  error and the warn/reject size pre-flight — this refines its classification), ADR-001 (server
  parses no binary / loads no JVM — the diagnosis stays a container-engine metadata query),
  the frozen error-envelope contract (`docs/contracts/error-envelope.md`): **no contract change** —
  the `resource-exhausted` *type*/status/retryable are unchanged; only the per-occurrence `detail`
  wording (an explicitly non-frozen, "safe specific explanation" field) changes.

## Context

A worker can die from memory pressure two ways, and they have **different exit signatures**:

1. **Native / off-heap overrun** → the cgroup OOM-killer SIGKILLs the container → `OOMKilled=true`
   / `ExitCode=137`. ADR-023/F1 already classifies this as `resource-exhausted` (503, not retryable).
2. **JVM heap exhaustion** → the worker JVM runs with `-XX:MaxRAMPercentage=75.0` and
   `-XX:+ExitOnOutOfMemoryError` (Containerfile.worker). The heap ceiling (75% of the cap) is reached
   **before** the cgroup wall (100%), so HotSpot terminates the JVM *itself* with **`os::exit(3)`** —
   a clean process exit. The embedded JVM (PyGhidra/JPype, in the worker's Python process) exits the
   whole container with **`ExitCode=3`, `OOMKilled=false`**.

`ContainerWorkerProcess.exit_diagnosis()` (`ghidra/launcher.py`) only maps `OOMKilled==true` **or**
`ExitCode==137` to `"oom"`; everything else is `"other"` → `worker-unavailable`. So case (2) — the
**common** large-binary OOM — is mis-reported as a generic, *retryable* transport drop. The
**v1.5 #5 measurement spike** observed exactly this: `light @ 4 GiB` on a 192 MB binary OOM'd at the
~3 GB heap ceiling and surfaced as `worker-unavailable`. The Containerfile comment even bakes in the
stale expectation ("`-XX:+ExitOnOutOfMemoryError` … → worker-unavailable").

Two harms: (a) the client is told the failure is **retryable** when an identical retry against the
same cap will OOM again (it is not retryable — `resource-exhausted` is deliberately
`retryable=false`); (b) the operator loses the precise, actionable "raise worker memory / shrink
input" signal precisely on the large inputs where it matters most.

**Empirical grounding (live-captured 2026-06-18).** `-XX:+ExitOnOutOfMemoryError` exits with code
**`3`** on OpenJDK **17** and **25** (bracketing the worker's JDK 21), stderr `Terminating due to
java.lang.OutOfMemoryError: Java heap space`. It is a stable HotSpot constant, independent of what
triggers the OOM. **No collision:** the worker's own deliberate exit codes are `{0}` (`run_server`
clean) and `{2}` (`__main__` missing-session-id, pre-JVM); an uncaught Python error exits `1`, a hard
JVM crash `134` (SIGABRT). `3` can therefore only be the JVM's `ExitOnOutOfMemoryError`.

## Decision

- **D1 — Recognize `ExitCode==3` as an OOM in `exit_diagnosis()`.** Return `"oom"` when
  `OOMKilled=="true"` **or** `ExitCode` is `"137"` (cgroup OOM-kill, native/off-heap — unchanged)
  **or** `"3"` (the JVM `ExitOnOutOfMemoryError` heap-OOM self-exit — new). Everything else stays
  `"other"`; an engine-query failure stays `"unknown"` (fail closed — never invent an OOM). This is
  a pure server-side container-engine **metadata** query (ADR-001 intact). The adapter
  (`rpc_client.py`) then routes `"oom"` → `resource_exhausted()` exactly as today.

- **D2 — Enrich the `resource-exhausted` detail with the configured cap (the §3 sizing hint).**
  Change `resource_exhausted()` from the static *"…increase worker memory or reduce input size"* to
  include the **current configured worker memory** and the **knob name**, e.g.
  *"worker exhausted its memory limit (N MiB); increase `GHIDRA_MCP_WORKER_MEM_MIB` (currently N) or
  reduce input size."* `N` is the already-resolved `worker_mem_mib` the adapter holds (also used by
  the size pre-flight) — a server-computed integer + a fixed knob name, **no host paths, binary
  content, or engine internals** (error-envelope disclosure rules; same safety bar as today). The
  warn/reject pre-flight already logs `worker_mem_mib`; this puts the same actionable figure in the
  client-visible error. **Not frozen:** `detail` is the per-occurrence explanation field, free to
  change; `type`/`title`/`status`/`retryable` are unchanged.

- **D3 — No new error type, no contract change, no new env knob.** Reuses `resource-exhausted`
  (503, not retryable) and the existing `GHIDRA_MCP_WORKER_MEM_MIB`. The fix is classification
  completeness + a better message — deliberately the smallest change that closes the gap.

- **D4 — Verification.** Unit-test `exit_diagnosis()` for the `3` / `137` / `OOMKilled` / `other` /
  `unknown` / malformed-output matrix, and the enriched `resource_exhausted()` detail (asserting the
  cap + knob appear and nothing unsafe leaks). **Live-verify on the real worker** by reproducing the
  spike's `light @ 4 GiB` heap-OOM (the deterministic ~6-min `caido@4 GiB` repro) and confirming the
  dead container reports `ExitCode=3`/`OOMKilled=false`, `exit_diagnosis()` → `"oom"`, and the tool
  returns `resource-exhausted` (not `worker-unavailable`) — this confirms the embedded-JPype JVM's
  `os::exit(3)` does propagate to the *container* exit code (the one assumption the synthetic capture
  doesn't cover). Gated on a worker image rebuild.

## Consequences

**Positive.** The dominant large-binary OOM is now correctly `resource-exhausted` (non-retryable,
with a concrete "raise to > N MiB" hint) instead of a misleading retryable `worker-unavailable`. The
client stops pointless retries; the operator gets the lever and the current baseline in the error
itself. Pure server-side; ADR-001 and the frozen envelope are untouched.

**Negative / risks.** Matching a bare exit code `3` is a heuristic — if a *future* worker code path
were to adopt exit `3` for a non-OOM reason it would be mis-tagged as OOM. Mitigated by: the
documented worker exit-code contract (`{0,2}` deliberate; `3` reserved to the JVM), a unit test
pinning that contract, and a code comment. (A more robust but heavier alternative — a worker-side
structured exit-reason marker — is recorded under Alternatives and deferred.) The stale
Containerfile comment is corrected in the same change.

## Alternatives considered

- **Worker-side last-gasp marker / parse JVM stderr** (`"Terminating due to
  java.lang.OutOfMemoryError"`). More robust than an exit-code match, but requires capturing and
  reading worker stderr post-mortem (new surface, and stderr is the worker's offline diagnostic
  sink) for marginal gain over a stable, collision-free JVM constant. Deferred; revisit only if the
  exit-code contract is ever pressured.
- **Lower `MaxRAMPercentage` / set an absolute `-Xmx`** so the cgroup kills first (unifying on the
  137 path). Rejected: it wastes headroom, couples heap to the cap differently than ADR-023 intends,
  and a clean JVM self-exit at the heap ceiling is *healthier* than relying on a SIGKILL.
- **A distinct `oom-heap` vs `oom-native` slug.** Rejected: over-fitting; the operator action is
  identical ("raise memory / shrink input"), and it would be a frozen-contract change for no
  client-actionable difference.
- **A new env knob for an explicit sizing table.** Rejected (YAGNI): the spike showed the lever is
  already `GHIDRA_MCP_WORKER_MEM_MIB`; surfacing the current value in the error is the high-value,
  zero-config step. A documented size→memory table can be added later if asked.
