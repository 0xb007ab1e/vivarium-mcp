# ADR-029: Large-binary analysis — analyzer-profile selector + pre-flight reject mode (progress deferred)

- **Status:** Accepted (v1.4; human-ratified 2026-06-17). Ratified: **ship B + C now; defer A (progress) to ADR-030 and D (incremental) ** . **B** analyzer-profile selector — additive `profile: "default"|"light"|"deep"` on `session_analyze` (default = byte-for-byte current behavior; `light` skips the expensive passes; additive analyze-RPC param, PM-routed). **C** pre-flight reject — `GHIDRA_MCP_WORKER_PREFLIGHT ∈ {warn,reject,off}`, default `warn` (v1.3 preserved); `reject` fails fast with `resource-exhausted`. No progress signal this increment (F4 liveness + `light` are the interim relief). Addresses v1.4 backlog item #2.
  ratification"). **Design only** — no code lands until ratified and built via reviewed, gated PRs.
  Every Ghidra/MCP-binding assumption below is flagged **REQUIRES-LIVE-VERIFICATION**; the
  validation path is the ADR-028 recurring live-regression harness (the F2/F7 lesson:
  `# pragma: no cover - JVM edge` code is only proven by a real-worker run).
- **Date:** 2026-06-17
- **Deciders:** Human (ratifies D1–D6) + PM; recorded by the Software Architect.
- **Addresses:** v1.4 roadmap item 2 (`docs/archive/roadmap-v1.4.md` §2) — "Large-binary analysis: progress
  streaming, analyzer-profile selector, RAM-vs-size pre-flight." Folds in roadmap item 8 (`§8` /
  ADR-023 D3 — pre-flight reject mode).
- **Relates to / constrained by:**
  - **ADR-001** (server never loads the JVM / parses a binary; analysis runs only in the worker) —
    **unchanged**; both shipped sub-features keep all Ghidra work in `_jvm_bridge`/`_gh_analyze`.
  - **ADR-002** (one ephemeral worker per session; timeout-kill + verified wipe) — **unchanged**;
    the per-analysis timeout-kill still bounds a hung/slow analyze regardless of profile.
  - **ADR-004** (worker isolation: no network, mem/cpu/pids cgroups) — the memory cgroup remains the
    enforcing OOM control; the pre-flight is advisory/opt-in-reject on top of it.
  - **ADR-023 / F1** (configurable worker resources, `resource-exhausted`, warn-only pre-flight,
    `plausible_max_bytes`) — this ADR **completes D3** (the deferred reject mode) and adds the
    profile knob alongside the resource knobs.
  - **ADR-025 / F4** (in-flight session liveness: a long `analyze` won't idle-evict itself;
    `begin_call`/`end_call`; startup invariant `idle_s >= analysis_timeout_s`) — the model that any
    *concurrent* status read would have to coexist with; central to why progress (A) is deferred.
  - **TB2 frozen RPC contract** (`docs/contracts/rpc-protocol.md`) — synchronous JSON-RPC-2.0
    request/response over a per-session UDS, length-prefixed, kill-on-deadline. Sub-feature (B)
    touches it **additively** (one new optional `analyze` param); (A) would touch its **framing** and
    so is deferred to its own ADR.
- **Touches a trust boundary?** No new boundary. (B) is an **additive** parameter on the existing
  TB2 `analyze` method (routed through the PM per the frozen-contract posture). (C) is server-side
  config + an existing pre-flight branch. No new capability, no new agency (LLM08): the profile
  selector *reduces* analysis depth, it does not add a tool or a write.

## Context

### The finding (the 184 MiB blind target)

The original blind-acceptance target — a **184 MiB** ARM aarch64 ELF — exposed two real ceilings on
large binaries:

1. **It OOM-killed the worker.** Addressed in v1.3 by ADR-023/F1: configurable worker memory
   (`GHIDRA_MCP_WORKER_MEM_MIB`), the distinct `resource-exhausted` error on an OOM-classified worker
   death (`rpc_client.py:1075-1098`), and a **warn-only** size-vs-memory pre-flight
   (`rpc_client.py:281`, `plausible_max_bytes` in `security/limits.py:222`).
2. **`analyze` ran ~18–26 minutes as ONE opaque blocking call with zero progress signal** (and only
   ~7–18 s on a gzip re-run of a smaller input — so cost scales hugely, super-linearly, with size).
   The liveness half of this (the next call self-evicting the session) was fixed by ADR-025/F4; the
   **"no signal for 26 minutes" UX half is still open**, and is the hard one.

### Where the relevant code lives (read for this ADR)

- **`session_analyze` handler** — `src/ghidra_mcp/tools/registry.py:241` (`_handle_session_analyze`):
  authorize → `ctx.port.analyze(args)` → overlay authoritative lifecycle fields. The `_bind` wrapper
  (`registry.py:1317-1336`) already marks the session in-flight for the whole call (ADR-025/F4).
- **Adapter analyze** — `src/ghidra_mcp/ghidra/rpc_client.py:294` (`RpcGhidraAdapter.analyze`): clamps
  the client timeout DOWN to the configured ceiling, then issues a **synchronous** `_call(...,
  "analyze", {"timeout_seconds": ...}, timeout_s=deadline)`. The warn-only OOM pre-flight is in
  `import_binary` (`rpc_client.py:281`).
- **The synchronous RPC core** — `rpc_client.py:994` (`_call`): one `sendall` then a **blocking**
  `_read_frame` for the whole call duration; `sock.settimeout(timeout_s)` + SIGKILL-on-expiry. There
  is **one socket per session and the server is its sole client** (TB2 §2). Nothing reads that socket
  concurrently; a second frame mid-call is not part of the framing.
- **Worker analyze** — `src/ghidra_mcp/ghidra/_jvm_bridge.py:509` (`_gh_analyze`, marked
  `# pragma: no cover`): `import pyghidra; pyghidra.analyze(self._program)` — **one blocking call**
  that runs auto-analysis to completion, then returns the `ready` `SessionInfo` dict. The exact
  auto-analysis entrypoint on 12.1.2 is already flagged for live verification in the code comment
  (`_jvm_bridge.py:526-529`).
- **Schema** — `src/ghidra_mcp/tools/schemas.py:139` (`SessionAnalyzeIn`): currently only
  `timeout_seconds: int | None`.
- **Limits/pre-flight** — `security/limits.py:222` (`plausible_max_bytes`), `:241`
  (`check_binary_size`), `DEFAULT_WORKER_MEM_MIB`.
- **Config** — `config.py`: `GHIDRA_MCP_WORKER_*` knobs, `resolve_worker_resources`, the
  fail-closed startup validation pattern (`_read_choice`, `_startup_error`).

### Why the increment is scoped the way it is

The three live sub-features have **wildly different blast radii on the frozen TB2 contract**, and the
contract is the gating concern:

| Sub-feature | Touches frozen TB2? | Effort | Risk | Verdict |
|---|---|---|---|---|
| **(B) analyzer-profile selector** | Additive: one new optional `analyze` param (server→worker), PM-routed | Small–medium | Low (additive; default = today's behavior) | **SHIP in this increment** |
| **(C) pre-flight reject mode** | No (server config + existing branch) | Small | Low (opt-in; default stays warn-only) | **SHIP in this increment** |
| **(A) progress signal** | **Yes — changes framing** (a second frame type mid-call) OR breaks the sole-client/synchronous model | Large (protocol change) | High (re-opens a frozen, ratified contract) | **DEFER to its own ADR** |
| **(D) incremental/lazy analysis** | Deep Ghidra analysis-model change | Very large | High | **DEFER (assessed below; likely not v1.4)** |

This ADR ships the two low-risk, high-leverage wins (B + C) and **honestly defers (A) as a genuine
protocol change** rather than smuggling a framing change in under a "usability" banner.

## Decision

**D1 — Scope split.** The first v1.4 large-binary increment ships **(B) the analyzer-profile
selector** and **(C) the pre-flight reject mode**. **(A) progress** and **(D) incremental analysis**
are deferred, each with a recorded reason and a follow-up note (below). Rationale: B + C are additive,
low-risk, and directly relieve the two observed pains (B lets a huge binary finish in less heap/time;
C fails fast instead of wasting ~26 min on a doomed OOM run). A is a frozen-contract change that
deserves its own design + ratification, not a rider.

### D2 — (B) Analyzer-profile selector (SHIP)

Add an **additive, optional** `profile` field to `SessionAnalyzeIn` and thread it to the worker as an
additive `analyze` RPC param. The worker maps the profile to a **concrete preset of Ghidra
analyzer-option overrides** applied before running auto-analysis.

- **Schema (additive):**
  ```python
  # schemas.py — SessionAnalyzeIn
  profile: Literal["default", "light", "deep"] = "default"
  ```
  `extra="forbid"` + `frozen` already hold; an old client omitting it gets `"default"` =
  **exactly today's behavior** (backward compatible, no behavior change unless opted in).
- **Handler (`registry.py`):** `_handle_session_analyze` passes `args.profile` through; the closed
  `Literal` vocabulary is the validation (no free-form analyzer names from the client — least-agency:
  the client picks a *named preset*, never an arbitrary Ghidra option string). No new authorize/gate
  (analysis is already a read-only lifecycle op).
- **TB2 contract (additive, PM-routed):** the `analyze` method's `params` gains an optional
  `"profile"` string from the closed set; absent/unknown ⇒ `"default"`. Worker-facing only; the
  client-facing tool surface change is the one new enum field. This is the **same additive-param
  pattern** the `export_annotations` `targets` param used (rpc-protocol §4) — a precedent for an
  additive server→worker param without re-opening the framing.
- **Worker mapping (`_jvm_bridge._gh_analyze`):** before triggering auto-analysis, set analyzer
  options per the preset. **Presets (REQUIRES-LIVE-VERIFICATION — exact option names/keys must be
  pinned on Ghidra 12.1.2 via the ADR-028 harness):**
  - **`default`** — run auto-analysis with Ghidra's default analyzer set, unchanged (the current
    `pyghidra.analyze(program)` path). This is the no-op preset; it MUST be byte-for-byte the present
    behavior so existing results/eval baselines don't move.
  - **`light`** — disable the most expensive passes for a fast/low-heap first pass. Candidate
    disables (to be confirmed live): **Decompiler Parameter ID**, **Decompiler Switch Analysis**,
    aggressive **instruction/data finders** (e.g. "Aggressive Instruction Finder", "Decompiler-based
    data finders"), **demangler** where heavy. Keep the cheap structural passes (function creation,
    basic disassembly, references) so the call graph / symbol surface the read tools depend on still
    populates.
  - **`deep`** — default plus the optional thorough passes Ghidra ships disabled by default where
    they materially help (e.g. decompiler-driven re-analysis). Bounded by the same timeout-kill, so
    "deep" on a huge binary may still hit the deadline → `timeout` (acceptable; the operator chose
    depth).
- **How options are set (REQUIRES-LIVE-VERIFICATION):** the worker resolves the program's analysis
  options (e.g. via `getOptions(Program.ANALYSIS_PROPERTIES)` / the headless
  `-preScript`/option-setter path, or `AutoAnalysisManager` option registration) and sets the
  preset's booleans before `analyze`. The **exact API** (pyghidra helper vs. `GhidraProgramUtilities`
  / `AutoAnalysisManager.getAnalysisManager(program)` option access vs. headless `OptionsDialog`
  equivalents) is the JVM-edge symbol to pin on 12.1.2 — same caveat already attached to
  `_gh_analyze` in code. The preset → option-key map is the single auditable place this lives.
- **Observability:** log the chosen profile on the analyze intent (`profile` is a closed-vocabulary,
  non-binary-derived label — safe to log; never log analyzer output or binary content —
  topic-logging-observability). No new metric required for v1.4; the ADR-028 harness can track
  analyze wall-clock per profile over time.
- **Security posture:** the profile only *narrows or widens analysis depth*; it adds no tool, no
  write, no new RPC method, no client-controlled Ghidra string. A `light` analysis returns *less*
  recovered structure — that is a correctness/depth trade the operator opts into, not a security
  regression. The untrusted-data envelope (ADR-005) and worker isolation (ADR-004) are unchanged.

### D3 — (C) Pre-flight reject mode (SHIP)

Promote the v1.3 warn-only pre-flight to an **opt-in reject** mode (completes ADR-023 D3).

- **Config (`config.py`):** add `GHIDRA_MCP_WORKER_PREFLIGHT` read via the existing `_read_choice`
  pattern, allow-list `{"warn", "reject", "off"}`, **default `"warn"`** (preserves v1.3 behavior —
  fail-safe default, no surprise breakage). Carried on `Config` (or on the resolved worker-resources
  object). `"off"` is offered so an operator who finds the heuristic too aggressive can silence it
  without code changes (still bounded by the hard size cap + memory cgroup).
- **Adapter (`rpc_client.py`):** the existing `import_binary` branch at `:281` becomes:
  - `warn` (default) → log `worker.preflight_oversized` and **proceed** (today's behavior).
  - `reject` → raise `resource_exhausted()` (the existing ADR-023 `503`, **not retryable** — the
    input is structurally too large for this worker's memory; retrying changes nothing). Fail fast
    **before** spawning the analyze that would burn ~26 min then OOM. The detail stays safe
    (size + configured memory only — no path/content; error-envelope.md / master §5).
  - `off` → skip the check entirely.
- **Threshold:** unchanged — `plausible_max_bytes(worker_mem_mib)` (`limits.py:222`, default ratio
  2.0). The pre-flight runs at **import** time (size is known there), so reject pre-empts both
  `import` and the later `analyze`. The hard `check_binary_size` cap and the worker memory cgroup
  remain the *enforcing* controls; this is an earlier, friendlier fail.
- **Security posture:** reject is strictly *more* fail-closed than warn. No new surface. The
  heuristic is advisory by nature (a 2× ratio is a guess); offering `reject`/`warn`/`off` lets the
  operator choose how the guess behaves, with the safe default unchanged.

### D4 — (A) Progress signal (DEFER to its own ADR — it is a protocol change)

**Honest assessment of the three options the brief named:**

- **(i) MCP progress notifications, driven by Ghidra's `TaskMonitor`.** The *MCP* half is feasible:
  the pinned SDK (`mcp 1.12.0`; `mcp>=1.2.0`) exposes
  `Context.report_progress(progress, total, message)` and auto-injects a `Context` into a tool by
  type annotation (`mcp/server/fastmcp/tools/base.py:67`, `server.py:269`). **But the server has
  nothing to report from.** To emit progress the server would need *intermediate* signals from the
  worker's `TaskMonitor` while `analyze` runs — and the server is blocked in a single synchronous
  `_read_frame` (`rpc_client.py:1031`) for the whole call. So (i) **cannot stand alone**; it requires
  (ii) underneath it. (Also: the registry handlers are plain sync functions invoked through `_bind`;
  surfacing `Context` to `_handle_session_analyze` is itself non-trivial wiring, though tractable.)
- **(ii) Worker emits progress frames the server relays.** This is the only mechanism that actually
  produces progress, and it **changes the frozen TB2 framing** (rpc-protocol §3/§4): today one
  request ⇒ exactly one response frame. Progress requires the worker to send **N progress frames then
  a terminal result frame** on the same socket, and the server's `_call`/`_read_frame` to loop
  reading frames until the terminal one (while still honoring the deadline-kill). That is a real
  protocol revision: new frame type/discriminator, a read loop, deadline accounting across multiple
  reads, and the worker driving a `TaskMonitor` callback to emit frames (REQUIRES-LIVE-VERIFICATION
  that `pyghidra.analyze` even exposes a progress-callback hook on 12.1.2 — `pyghidra.analyze` may
  only take a program, in which case a custom `TaskMonitor` subclass + `AutoAnalysisManager` path is
  needed, which is itself an unverified JVM-edge change). **This re-opens a ratified frozen contract**
  and must be its own ADR with PM/SME sign-off.
- **(iii) Poll-able `session_status` / analysis-progress read, called concurrently mid-analyze.**
  **The architecture forbids this today.** There is **one socket per session and the server is its
  sole client** (TB2 §2); the synchronous `analyze` call holds that socket blocked end-to-end. A
  concurrent `session_status` that wanted *live analysis %* would need a second worker channel (back
  to ii's framing change) or a second socket (a TB2 transport change). The existing `session_status`
  reads only **server-side** lifecycle state (`registry.py:281` → `sessions.authorize`), which is
  fine and already concurrency-safe — but it can only ever report "analyzing" (a state), **not a
  progress percentage**, because the worker's progress isn't on the server side. ADR-025/F4's
  in-flight model keeps such a concurrent status call from idle-evicting the session, but it does not
  give the server any *analysis-progress data* to return.

**Conclusion:** real `analyze` progress (a moving %) is **a TB2 protocol change** (option ii, with i
layered for the client surface). It is genuinely the hard one and must not be rushed into a frozen
contract under a usability label. **Defer to a dedicated ADR-030 "analyze progress streaming over
TB2"** that designs the framing revision (or evaluates the gRPC-streaming option the rpc-protocol §1
table already parked as "revisit if streaming/perf demands it in v1.1"). **Interim mitigation already
shipped:** ADR-025/F4 stops the long call from self-evicting, and (B) `light` shortens the wait — so
the v1.4 user experience improves materially without the protocol change. A coarse, non-protocol
stopgap is noted as an option for ADR-030 (server emits *heartbeat* progress notifications on a timer
— "still analyzing, elapsed Ns" with no real %, requiring only that the analyze run on a thread the
server can ping from); flagged but **out of scope here**.

### D5 — (D) Incremental / lazy analysis (DEFER — likely not v1.4)

Ghidra's auto-analysis is a whole-program batch over the loaded program; there is no first-class
"analyze function X on demand" that the read tools could lean on without a much larger redesign
(session would hold a *partially* analyzed program; every read tool would need defined semantics for
"not yet analyzed here"; results would become non-deterministic w.r.t. call order — at odds with the
deterministic, bounded posture). The `light` profile (D2) is the pragmatic 80/20 of "do less work
up-front." **Defer**; revisit only if (B) proves insufficient on real large targets (measured via the
ADR-028 harness), and then as its own ADR.

### D6 — Validation path (the F2/F7 lesson)

Both shipped sub-features touch or depend on the `# pragma: no cover - JVM edge` (`_gh_analyze` +
analyzer-option API). Unit tests **structurally cannot** prove the Ghidra-12.1.2 option keys or the
preset effects. Therefore: the preset → option map and the `light`/`deep` effects MUST be validated
on a **real worker** via the **ADR-028 live-regression harness** before the increment is considered
done — add a profile dimension to the harness (e.g. assert `light` completes and still populates the
function/symbol surface the read tools need; assert `default` is unchanged vs. the existing baseline).
The pre-flight reject (C) is pure server-side and IS unit-testable (config parse + the branch) to the
100%-critical bar (`security/limits.py` is a critical path).

#### Live-verification result (2026-06-17 — recorded so the JVM-edge proof is durable, not ephemeral)
Run against a worker image built from this branch (gzip 1.13 target, real chain under crun):
- **default → analyze OK in 8.2 s · light → 6.7 s · deep → 13.8 s.** The timing spread (light <
  default < deep) empirically confirms the profile overlays take effect (not silent no-ops).
- A temporary in-`_gh_analyze` name-validation diag (compare each preset option name against
  `program.getOptions(ANALYSIS_PROPERTIES).getOptionNames()`, raise on any unknown) **did not fire** —
  so **every** preset analyzer-option name (`Decompiler Parameter ID`, `Aggressive Instruction Finder`,
  `Decompiler Switch Analysis`, `Embedded Media`, `Create Address Tables`) is a real Ghidra 12.1.2
  option. The diag was reverted before commit. (Follow-up: fold a profile dimension into the standing
  ADR-028 harness so this stays continuously verified.) **LANDED (2026-06-17, post-v0.6.0):**
  `tests/integration/test_analyze_profiles.py` runs `{default,light,deep}` as hard gates in the
  ADR-028 nightly (each analyzes + populates a surface on the real worker), so the option-overlay
  JVM edge is now continuously exercised — see ADR-028 §"Follow-ups (landed)". The stronger
  option-*existence* check (the reverted diag, made permanent + fail-closed in the worker) was
  considered and deferred as its own feature rather than a harness follow-up.

## Consequences

**Positive**
- Large binaries get a real lever today: `light` trades depth for completion-in-less-heap/time; the
  reject pre-flight stops a doomed ~26-min run before it starts.
- Zero frozen-contract risk this increment: (B) is an additive param (precedented by
  `export_annotations targets`); (C) is server-side. The ratified TB2 framing is untouched.
- Backward compatible: `profile` defaults to `"default"` (no behavior change); `GHIDRA_MCP_WORKER_PREFLIGHT`
  defaults to `"warn"` (no behavior change). Opt-in only.
- Security posture preserved: ADR-001 worker-only analysis, ADR-002 timeout-kill still bounds a slow
  analyze, ADR-004 isolation + memory cgroup unchanged, no new capability/agency (LLM08), additive
  contract only.

**Negative / costs**
- `light` returns *less* recovered structure (fewer params/types/switches) — the client must
  understand it's a shallower view (document in the tool catalog; consider surfacing the effective
  profile in the analyze result for honesty).
- The analyzer-option API is a JVM-edge unknown until live-verified (D6) — the main delivery risk;
  the preset names are committed, the exact option keys are not.
- Progress (the most-requested UX win) does **not** land this increment — mitigated by ADR-025/F4 +
  `light`, and explicitly tracked as ADR-030.

## Decisions needing human ratification

1. **D1 — Scope split.** Ship **(B) profile selector + (C) reject pre-flight** in the first v1.4
   large-binary increment; **defer (A) progress** to a dedicated ADR (it is a frozen-TB2 framing
   change, not a usability rider) and **(D) incremental analysis** (large, separate). Confirm.
2. **D2 — Profile presets, names, and default.** Names `default` / `light` / `deep`; **default =
   `default` = today's exact behavior**; `light` disables the expensive passes (decompiler
   parameter-ID, switch analysis, aggressive finders) while keeping function/disassembly/refs.
   Ratify the names + the default-is-no-op guarantee. (The exact Ghidra-12.1.2 option keys are
   implementation detail, live-verified per D6.)
3. **D2 — Additive TB2 contract touch.** Approve adding an optional `"profile"` param to the worker
   `analyze` RPC method (server→worker, closed vocab, absent ⇒ `default`) — **routed through the PM
   per the frozen-contract posture**, mirroring the `export_annotations targets` additive-param
   precedent. Confirm this is additive-only (no framing change) and acceptable.
4. **D3 — Reject-mode env/flag + default.** `GHIDRA_MCP_WORKER_PREFLIGHT` ∈ `{warn, reject, off}`,
   **default `warn`** (v1.3 behavior preserved); `reject` raises the existing `resource-exhausted`
   (503, non-retryable) at import time. Ratify the env name, the three-value vocabulary, and the
   default.
5. **D4 — Defer (A) to ADR-030.** Agree that real analyze progress is a TB2 protocol change (worker
   progress frames ± MCP `report_progress`), to be designed and ratified separately — and that the
   ADR-025/F4 liveness fix + `light` profile are the accepted interim mitigation. Decide whether the
   coarse **heartbeat** stopgap (timer-driven progress notifications, no real %) is worth prototyping
   in ADR-030 or dropped.
6. **D6 — Validation gate.** Agree the profile presets are validated on a **real worker via the
   ADR-028 harness** (not unit tests) before the increment is "done," and that the harness gains a
   profile dimension (`light` completes + populates the read surface; `default` matches baseline).

> **No code, no gated actions taken.** This ADR is design-only; implementation lands later as
> reviewed, gated PRs in an isolated worktree after ratification, with a `sdlc-reviewer` security
> pass and CI green (PLAN rhythm).
