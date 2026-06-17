# ADR-030: Progress signal during a long `analyze` (TB2 progress-frame streaming)

- **Status:** Accepted (v1.4; human-ratified 2026-06-17). Ratified: **Phase 1 (worker→server `$/progress` frames, LOG-ONLY) then Phase 2 (MCP client relay) — both this effort, staged to de-risk the TaskMonitor binding first**. Content = **percent + a closed phase enum ONLY** (never free-form/binary-derived TaskMonitor strings). Scope = **`analyze` only** (import deferred). TB2: an **additive `$/progress` JSON-RPC notification** frame, emitted ONLY when the call opts in (`params.progress:true`); progress frames **do NOT extend the deadline** (timeout-kill stays the in-flight bound — ADR-002); flood-bounded (max frames / min interval / size cap). Supersedes ADR-029 §D4.
  until ratified and built via reviewed, gated PRs in an isolated worktree, with an
  `sdlc-reviewer` security pass and CI green (PLAN rhythm).
- **Date:** 2026-06-17
- **Deciders:** Human (ratifies D1–D9) + PM; recorded by the Software Architect.
- **Supersedes the deferral in:** ADR-029 §D4 ("(A) progress signal — DEFER to its own ADR;
  it is a frozen-TB2 framing change, not a usability rider"). This is that ADR.
- **Addresses:** v1.4 roadmap item 2 (`docs/roadmap-v1.4.md` §2) — the "progress streaming" third of
  the large-binary work, after ADR-029 shipped the profile selector (B) + reject pre-flight (C).
- **Touches a trust boundary?** **Yes — TB2** (the internal server↔worker RPC,
  `docs/contracts/rpc-protocol.md`). This is the load-bearing change: it **revises the frozen
  framing** (§3/§4) from strict request→single-response to request→`N` progress
  notifications→terminal response, **additively and opt-in per method**. Also touches the
  **server→client MCP transport** (an existing, standard progress mechanism — no new boundary
  there). **No new TB** (no second socket, no network surface, no new tool, no new capability).
- **Relates to / constrained by:**
  - **ADR-001** (server never loads the JVM / parses a binary). **Unchanged.** Progress frames are
    emitted by the worker's `TaskMonitor` and only *relayed* by the server; the server still parses
    no binary. The progress `message`/`phase` is treated as untrusted worker output (ADR-005).
  - **ADR-002** (one ephemeral worker per session; **timeout-kill** + verified wipe). **Unchanged
    and load-bearing here:** progress frames MUST NOT reset or extend the per-analysis deadline.
    The deadline-kill remains the hard in-flight bound (see D5).
  - **ADR-004** (worker isolation: no network, mem/cpu/pids cgroups). **Unchanged.**
  - **ADR-005** (untrusted-data envelope). Progress text comes from Ghidra over hostile input →
    untrusted. Drives the redaction stance (D4).
  - **ADR-011 / ADR-017 / ADR-019/020** (HTTP transport; multi-principal authZ; mTLS/OAuth). The
    MCP progress relay must work identically on stdio and HTTP, and only ever for the **owning
    principal's** in-flight request (the progress notification rides the *same* MCP request context
    — no cross-principal leakage; see D6).
  - **ADR-024 / `rpc_framing.py`** (additive, redacted, log-only `data.detail`; forward-compat
    "unknown top-level members are tolerated" in `parse_response`). The progress frame design
    leans on the same additive + fail-closed posture.
  - **ADR-025 / F4** (in-flight session liveness: `begin_call`/`end_call` mark a session in-flight
    for the WHOLE call so a 18–26 min `analyze` can't idle-evict itself; startup invariant
    `idle_s >= analysis_timeout_s`). **Unchanged and confirmed:** progress does not alter the
    in-flight window — `_bind` still brackets the entire call (D5). Progress is observability
    *within* that window, not a new liveness mechanism.
  - **ADR-028** (recurring live-regression harness). The **validation path** for every
    `TaskMonitor`/`pyghidra` JVM-edge binding below (the F2/F7 lesson: a `# pragma: no cover - JVM
    edge` path is only proven by a real-worker run). See D9.
  - **ADR-029 B** (the `profile` additive `analyze` param). **Precedent:** progress reuses the same
    "additive, opt-in, default-is-no-op, PM-routed" posture for a frozen-contract touch — except
    progress changes *framing*, not just a param, so it is genuinely heavier and gets its own ADR.

---

## Context

### The finding

The v1.3 blind run's **184 MiB** ARM aarch64 ELF ran `analyze` for **~18–26 minutes as ONE opaque
blocking call with zero client feedback** (vs ~7–18 s on a smaller gzip re-run — cost scales hugely
super-linearly with size). ADR-029 shipped two interim reliefs: `light` profile (faster/less heap)
and (via ADR-025/F4) the fix that stops the long call self-evicting. **A long analyze is still
silent** — the most-requested UX gap. This ADR designs the actual progress signal.

### The three layers, concretely (what exists today)

**1. Worker / Ghidra `TaskMonitor`.** `_gh_analyze` (`src/ghidra_mcp/ghidra/_jvm_bridge.py:567-610`)
makes ONE blocking call: `pyghidra.analyze(self._program)` (`:608`). Ghidra auto-analysis drives a
`ghidra.util.task.TaskMonitor` internally (it reports `message` / `setProgress(long)` /
`setMaximum(long)` / `incrementProgress`). The code comment at `:519-521` already flags the exact
auto-analysis entrypoint as the last JVM symbol to pin (pyghidra helper vs.
`AutoAnalysisManager.getAnalysisManager(program).reAnalyzeAll(monitor)`). **Open JVM-edge question
(REQUIRES-LIVE-VERIFICATION):** does `pyghidra.analyze` accept a caller-supplied monitor, or must
the worker drop to the `AutoAnalysisManager` path to inject a custom `TaskMonitor`? (See D2.)

**2. RPC framing (TB2).** `docs/contracts/rpc-protocol.md` §3/§4: length-prefixed (4-byte
big-endian `N` + `N` bytes UTF-8 JSON), **one request ⇒ exactly one response frame**, JSON-RPC 2.0,
`id`-correlated, kill-on-deadline. The pure codec is `rpc_framing.py` (server-side
`decode_length_prefix`/`decode_body`/`parse_response`; worker-side `build_response`/`build_error`).
`parse_response` (`rpc_framing.py:169-199`) requires `jsonrpc:"2.0"`, an `id` matching the request,
and **exactly one of `result`/`error`** — a progress notification (no `id`, no `result`/`error`)
would be **rejected by today's reader**, which is why a new read path is required, not just a new
frame shape.

**3. Server `_call` loop.** `RpcGhidraAdapter._call` (`rpc_client.py:1074-1178`): one `sendall`,
then a **single blocking** `self._read_frame(sock)` (`:1111`, body `:1225-1244`) for the whole call,
with `sock.settimeout(timeout_s)` (`:1109`) and SIGKILL-on-expiry (`:1131-1139`). **One socket per
session; the server is its sole client** (TB2 §2) — nothing reads that socket concurrently. The
deadline for `analyze` is computed at `:387-391` (client override clamped DOWN to the configured
ceiling).

**4. Server→client (MCP).** `Context.report_progress(progress, total, message)` exists in the
pinned SDK (`mcp>=1.2.0`; system 1.12.x — `mcp/server/fastmcp/server.py:1049`). Critically it is a
**no-op when the client supplied no `progressToken`** (`server.py:1057-1060`: reads
`request_context.meta.progressToken`; `if progress_token is None: return`). FastMCP injects a
`Context` into a tool by **type annotation** (`mcp/server/fastmcp/tools/base.py:62-67`). Today
`_handle_session_analyze` (`registry.py:241-258`) is a plain sync `(ctx, args)` handler with **no
`Context`**; the `_bind` wrapper (`registry.py:1294-1341`) synthesizes a flat-kwargs signature from
the input model and brackets the call with `begin_call`/`end_call` (ADR-025/F4).

### The single hardest constraint (drives the whole design)

**The worker serve loop is strictly single-threaded and synchronous.** `serve_connection`
(`worker/dispatch.py:495-519`) → `handle_request` → `dispatch` → `backend.analyze(params)` →
`_gh_analyze` → blocking `pyghidra.analyze`. While analyze runs, **the worker's only thread is
inside the JVM call and cannot also be reading/writing the socket from the dispatch loop.** So a
`TaskMonitor` callback that wants to emit a progress frame **must write to the socket from inside the
analyze call stack** (the callback fires on the analyzing thread). That is feasible — the callback
holds the connection and does a bounded `sendall` of one pre-framed notification — but it means the
worker is writing progress frames *interleaved with* the eventual terminal response on the same
socket, single-threaded, in order. **No concurrency, no second channel.** This is actually the
*simplest* correct model and is what the framing design below assumes (D2/D3). (A thread-based
"separate emitter" is explicitly rejected in D3 — it adds JVM-thread/socket-write races for no gain.)

---

## Decision

### D1 — Mechanism: worker progress frames relayed to MCP progress notifications (option ii + i)

ADR-029 §D4 already established the only mechanism that produces *real* progress is **(ii) the
worker emits progress frames the server relays**, optionally surfaced to the client via **(i) MCP
`report_progress`**. We adopt ii as the substrate and layer i for the client surface. We **reject**
(iii) a concurrent pollable `session_status` for live % — it requires a second worker channel/socket
(a bigger TB2 transport change) and the existing `session_status` can only ever report the *state*
"analyzing", not a moving %.

**Phasing (recommended — least-risky path).** Ship in **two phases**, each independently
ratifiable and shippable:

- **Phase 1 — worker→server frames, log-only relay (no MCP client change).** Implement the TB2
  framing revision (D3) and the worker `TaskMonitor` binding (D2). The server `_call` loop reads and
  **logs** progress frames (rate/coalesce-bounded, redacted — D4) under the correlation id, and
  **does not** touch the MCP client surface. This proves the hard, security-sensitive part (the
  frozen-contract framing change + the JVM-edge monitor binding) on the ADR-028 harness **without**
  any client-visible behavior change and without wiring `Context` into the handler. Operators get
  server-side "still analyzing, phase X, 40%" log lines immediately; the protocol change is
  validated in isolation.
- **Phase 2 — full MCP relay.** Wire `Context`/`progressToken` into `_handle_session_analyze`
  (D6) and relay each progress frame to `Context.report_progress`, **only when the client supplied a
  `progressToken`**. No token ⇒ behaves exactly as Phase-1 (frames still logged) and exactly as
  pre-ADR-030 from the client's view.

Rationale: the framing change is the irreversible frozen-contract risk; isolating it in Phase 1
(log-only) lets us ratify + live-verify it before adding the client-facing wiring. Phase 2 is then a
low-risk additive relay on a proven substrate. **If the human prefers one increment, Phase 1+2 can
ship together — but the recommendation is split.**

### D2 — Worker side: a custom bounded `TaskMonitor` that emits progress frames

Replace the bare `pyghidra.analyze(self._program)` (`_jvm_bridge.py:608`) — **for the
progress-enabled call only** — with an analysis run driven by a worker-supplied
`ghidra.util.task.TaskMonitor` subclass (`_ProgressEmittingMonitor`) whose callbacks emit additive
worker→server progress frames.

- **The monitor subclass** overrides the `TaskMonitor` reporting methods (`setMessage`,
  `setProgress(long)`, `setMaximum(long)`, `incrementProgress(long)` — exact set
  **REQUIRES-LIVE-VERIFICATION** on Ghidra 12.1.2) and, on a state change, builds **one
  pre-redacted, pre-bounded progress notification** and writes it to the connection via a bounded
  `sendall`. It holds a reference to the connection + the originating request `id` + the framing
  cap + the redaction/coalescing policy.
- **JVM-edge binding (REQUIRES-LIVE-VERIFICATION — the central unknown):**
  - **Does `pyghidra.analyze` accept a monitor?** If `pyghidra.analyze(program, monitor=...)` (or
    similar) exists on 12.1.2, use it. **If not** (the comment at `:520-521` flags this), drop to
    `AutoAnalysisManager.getAnalysisManager(program).reAnalyzeAll(monitor)` (or the documented
    initialize/analyze API) inside a started transaction, passing the custom monitor. Either path
    is a JVM-edge change behind the existing `# pragma: no cover - JVM edge` and **must be proven on
    the ADR-028 harness**, not unit tests.
  - **`isCancelled()` semantics:** the monitor's `isCancelled()` returns `False` (the server's
    deadline-kill is the cancellation mechanism — D5; we do NOT use TaskMonitor cancellation as the
    bound, because a hostile analyzer could ignore it).
- **Default-is-no-op + opt-in.** The custom monitor is used **only** when the `analyze` RPC params
  carry the new `progress` opt-in flag (D3). When absent, `_gh_analyze` takes the **byte-for-byte
  unchanged** bare `pyghidra.analyze(program)` path (preserving ADR-029's default-is-no-op guarantee
  and not perturbing eval baselines). This means progress and the `light`/`deep` profile compose
  cleanly (the monitor wraps whichever analyzer set the profile selected).
- **Worker-side bounds (DoS self-limit, belt-and-suspenders with the server bounds in D4):** the
  monitor enforces a **min emit interval** (coalesce: emit at most one frame per `T` ms, e.g.
  500 ms — exact value D8) and a **monotonic frame counter** capped at `MAX_PROGRESS_FRAMES`
  (e.g. 5 000 — D8); past the cap it silently stops emitting (analysis continues). A `sendall`
  error in a callback is swallowed (best-effort — progress is observability; it must never crash or
  fail the analysis, and must never block the JVM thread on a slow reader → use a non-blocking /
  short-timeout send and drop on would-block).

> **Implementation reconciliation (Phase 1, 2026-06-17).** The numbers above were illustrative; the
> shipped values are: server-side `_MAX_PROGRESS_FRAMES = 10_000` (`rpc_client.py`) and worker-side
> coalesce interval `_WORKER_MIN_PROGRESS_INTERVAL_S = 0.25` — both still bounded; the contract
> (`rpc-protocol.md`) reflects 10 000. The worker emitter uses a **blocking** `conn.sendall` (matching
> the pre-existing terminal-response write), **not** the non-blocking send suggested above: a slow/stuck
> reader is bounded instead by the server's **one-shot deadline → SIGKILL** (D4/§6, ADR-002), which
> governs the whole exchange regardless of the emitter — so the JVM thread can stall at most until that
> kill. The send error / bad-phase swallow is implemented as specified.

### D3 — TB2 framing revision: additive `$/progress` JSON-RPC notification, opt-in per method

Revise `rpc-protocol.md` §3/§4 **additively** so a long-running, **opt-in** method may interleave
progress notifications before its single terminal response.

**Wire shape (the load-bearing frozen-contract change).** A progress frame is a JSON-RPC 2.0
**notification** (no `id`) on the same length-prefixed framing (same 4-byte prefix, same hard frame
cap — §3 unchanged for the prefix/cap):

```json
{ "jsonrpc": "2.0", "method": "$/progress",
  "params": { "id": "<originating-request-uuid>", "percent": 42, "phase": "decompiler" } }
```

- **`method: "$/progress"`** — the `$/`-prefixed namespace marks it an additive, ignorable
  notification (LSP convention; chosen so it is visibly *not* a domain RPC method and never collides
  with the frozen `RPC_METHODS` allow-list in `worker/dispatch.py:50-103`).
- **No top-level `id`** — it is a notification, so the existing `parse_response` correlation
  (`id` MUST match the request, `rpc_framing.py:188`) cannot be fooled into matching a progress
  frame to a response (D7). The originating request id is carried **inside `params.id`** purely so
  the relay can attribute the progress to the in-flight call (defense-in-depth; on a sole-client
  single-in-flight socket there is only ever one outstanding request, but carrying it lets the
  reader assert it matches and discard a mismatched frame fail-closed).
- **`params.percent`** — integer `0..100`, OR absent (indeterminate). **`params.phase`** — a value
  from a **closed enum** (D4), OR absent. **No free-form `message`** crosses to the client
  (redaction — D4).

**What §3/§4 gain (additive, opt-in):**
- §3 (Framing): add a paragraph — "A method MAY be **progress-enabled** (currently only `analyze`,
  opt-in via `params.progress: true`). A progress-enabled call MAY be preceded by zero or more
  `$/progress` **notification** frames (no `id`) before its single terminal `result`/`error` frame.
  All progress frames obey the same length prefix and hard frame cap. **Non-progress-enabled calls
  are byte-for-byte unchanged: exactly one response frame, no progress frames ever.**"
- §4 (Message model): add the `$/progress` notification object + note that it is **additive and
  opt-in**; a reader that does not recognize `$/progress` (an "old/strict reader") would frame it
  fine (length-prefixed) and then — under today's `parse_response` — reject it as "must contain
  exactly one of result/error" and kill the worker. **That is exactly why progress is opt-in per
  call:** the server only enters the progress read-loop (D5) for a call it *itself* opted in via
  `params.progress: true`, so a strict reader never opts in and never sees a progress frame.
  Conversely a worker MUST NOT emit `$/progress` for a call that did not request it (emitting one
  would be a protocol violation → the server's strict path kills it — fail closed).
- **`max_response_bytes` cap unchanged** and applies per frame (a progress frame is tiny by
  construction: percent + enum + uuid). Add an explicit, much smaller **progress-frame size
  sanity cap** (D4) so a hostile worker can't pad a `$/progress` frame up to 4 MiB × thousands.

**Reject the alternatives:** (a) a brand-new frame type with its own discriminator outside JSON-RPC
— rejected, it abandons the JSON-RPC envelope the whole protocol and `rpc_framing.py` are built on;
(b) embedding progress in the terminal response — impossible, it's the *interim* signal that's
wanted; (c) a second socket — a TB2 transport change (rpc-protocol §2), far larger blast radius.

### D4 — Redaction: percent + a CLOSED phase enum only; NO free-form, binary-derived message

**Stance: percent (`0..100`) + a small closed `phase` enum, and nothing else, crosses any boundary.
No raw `TaskMonitor` message string is ever sent to the server's client relay or logged verbatim.**

Rationale (master §5 / ADR-005): Ghidra's `TaskMonitor.setMessage` strings are **binary-derived and
hostile** — they routinely embed the current analyzer name *plus the symbol/function/address being
worked* (e.g. `"Analyzing function FUN_00401abc / <attacker-controlled name>"`). Forwarding them
would leak binary-derived text to the client outside the untrusted-data envelope and into server
logs — a redaction violation and an injection vector. Percent + a coarse phase enum convey the UX
("it's moving, it's in the decompiler pass, 60%") with **zero attacker-controlled content**.

- **`phase`** is mapped **worker-side** from the analyzer/`TaskMonitor` message to a **closed
  vocabulary** the worker controls — e.g. `loading`, `disassembly`, `functions`, `references`,
  `decompiler`, `data-types`, `finalizing`, `other`. The mapping is a small worker-side lookup over
  Ghidra's *analyzer names* (which are Ghidra-controlled labels, not binary-derived — but we still
  map to OUR closed enum rather than passing Ghidra's label, so the vocabulary is auditable and
  bounded, and an unrecognized analyzer name maps to `other`, never to its raw text).
- **`percent`** is derived from `setProgress`/`setMaximum` (`floor(100 * progress / maximum)`,
  clamped `0..100`; when `maximum<=0`/unknown, omit `percent` → indeterminate). Numbers are safe.
- **Progress-frame size sanity cap:** the server rejects any `$/progress` frame whose declared
  length exceeds a tiny bound (e.g. `_MAX_PROGRESS_FRAME_BYTES = 512`) — a frame this small cannot
  carry a payload; a larger one is a protocol violation → kill (D4 + D5). Defends against a hostile
  worker trying to smuggle binary-derived bytes in the notification.
- **Schema-validate every progress frame** before use: `method=="$/progress"`, `params.percent` is
  `int 0..100` or absent, `params.phase` is in the closed enum or absent, `params.id` is a string
  matching the in-flight request; **anything else → discard the frame and treat as a protocol
  violation → kill** (fail closed; a malformed progress frame is indistinguishable from a hostile
  one).
- **`Context.report_progress`** is then called with `progress=percent`, `total=100`, and
  `message=<the closed phase enum value>` (the enum string is server-controlled, safe to pass).

**Rejected:** a "scrubbed free-form message" (allow-list/strip the Ghidra string). Rejected because
robustly scrubbing attacker-controlled text is fragile (homoglyph/bidi/length games — `std-cwe`),
and percent+enum already delivers the UX. **Least data, closed vocabulary, no binary-derived
strings.**

### D5 — `_call` loop: read-until-terminal, the deadline bounds the WHOLE exchange

For a **progress-enabled** call, `RpcGhidraAdapter._call` (`rpc_client.py:1074-1178`) reads in a
**loop** instead of a single `_read_frame`:

```
deadline_at = monotonic() + timeout_s            # set ONCE, before the loop
while True:
    remaining = deadline_at - monotonic()
    if remaining <= 0: kill + TIMEOUT             # the hard bound — unchanged from ADR-002
    sock.settimeout(remaining)                    # the socket deadline shrinks toward deadline_at
    obj = self._read_frame(sock)                  # bounded by `remaining`
    if obj is a `$/progress` notification:
        validate + bound + redact (D4)            # per-frame size cap, schema, enum
        enforce per-call flood bounds (below)
        relay (Phase 2) / log (Phase 1)
        continue                                  # DOES NOT touch deadline_at
    else:
        return parse_response(obj, expected_id)   # the single terminal result/error frame
```

**Deadline integrity (the crux — recommend NO extension).** `deadline_at` is computed **once** from
the per-analysis deadline (`rpc_client.py:387-391`) and **progress frames never reset or extend
it.** Each `_read_frame` uses the *shrinking remaining* time, never a fresh `timeout_s`. This is
non-negotiable: if a progress frame reset the read timeout, **a hung or hostile worker could emit a
progress frame every few seconds forever and never finish — dodging the SIGKILL indefinitely**
(`std-owasp-llm` LLM04 cost-DoS / `topic-reliability`). The deadline-kill (ADR-002) stays the hard
in-flight bound: on `remaining <= 0` → `kill_worker` + `TIMEOUT` exactly as today (`:1131-1139`).

**Per-call flood bounds (server-side, in addition to the worker self-limit in D2):**
- **`MAX_PROGRESS_FRAMES` per call** (e.g. 5 000): exceeding it → kill + `worker-unavailable`
  (a worker spewing frames is buggy/hostile).
- **Min inter-frame interval / coalescing:** the server may simply drop (not relay) a progress
  frame that arrives within `MIN_PROGRESS_INTERVAL_MS` of the last relayed one (e.g. 500 ms) — it
  still counts toward `MAX_PROGRESS_FRAMES` (so flooding is bounded) but isn't relayed (so the
  client isn't spammed). **No server-side buffering/queue** — each frame is processed and discarded
  inline; nothing accumulates.
- **Per-frame size cap** (D4, `_MAX_PROGRESS_FRAME_BYTES`): a too-large declared progress frame →
  kill (reuses the existing `decode_length_prefix` cap mechanism, just a smaller bound for the
  notification path).
- Every existing kill trigger is unchanged: oversized terminal frame, protocol violation, crash,
  OOM-classification (ADR-023/F1) all still resolve to kill + evict.

**ADR-025/F4 confirmed intact.** `_bind` (`registry.py:1317-1336`) still brackets the *entire*
analyze call with `begin_call`/`end_call`; the read-loop runs inside that bracket, so the session
stays in-flight (won't idle-evict) for the whole exchange — **no change to the liveness model**.
Progress is observability *within* the existing in-flight window, not a new liveness signal.

**Non-progress calls are untouched:** every other RPC keeps the single blocking `_read_frame`
(`_tool_call` → `_call` with no progress opt-in), so the read-loop is entered only for `analyze`
with `params.progress: true`.

### D6 — Server→client MCP relay, only when the client gave a `progressToken` (Phase 2)

- **Reaching the `Context`:** add a `Context` parameter to the progress-enabled handler so FastMCP
  injects it (`tools/base.py:62-67`). Because `_bind` synthesizes the tool signature from the input
  *model* (`registry.py:1338` `_signature_from_model`), this needs a small, **localized** wiring
  change: either (a) a per-handler opt-in that appends a `Context`-annotated parameter to the
  synthesized signature for `session_analyze` only, or (b) a dedicated bound wrapper for the
  progress-enabled handler that requests `Context`. Recommend (b) — a single special-case wrapper
  for `analyze` keeps the generic `_bind` path (all other tools) byte-for-byte unchanged.
- **Token-gated:** the handler passes a relay callback (closure over `Context`) down to the adapter
  call. `Context.report_progress` is **already a no-op when no `progressToken`** (`server.py:1057-1060`)
  — so **with no token the relay is inert and behavior is exactly as today** (the built-in guarantee;
  we rely on it rather than re-checking). The worker still need not even be told whether a token
  exists — but as an optimization the server only sets `params.progress: true` (D3) when the client
  supplied a `progressToken` **or** Phase-1 log-relay is enabled, so a tokenless stdio call with
  logging off pays nothing.
- **Async boundary:** `report_progress` is `async`; the registry handlers/`_call` are sync and the
  analyze RPC blocks a thread. The relay must marshal each progress frame onto the MCP session's
  event loop (e.g. the SDK's anyio/`run_coroutine_threadsafe`-equivalent from the handler thread).
  **REQUIRES-LIVE-VERIFICATION** of the exact FastMCP sync-tool → async-`report_progress` bridge on
  the pinned SDK; if the bridge is awkward, **Phase 1 (log-only) still delivers value** and Phase 2
  can adopt whatever the SDK blesses. This async-bridge uncertainty is a second reason to phase.
- **Principal scoping (ADR-017/011):** the progress notification rides the **same MCP request
  context** as the in-flight `session_analyze` call, so it is delivered only to that request's
  caller — no cross-principal or cross-session leakage. The relay never reads another session's
  socket (one socket per session; TB2 §2).

### D7 — Correlation integrity

- Progress frames carry **no top-level `id`** → `parse_response` (`rpc_framing.py:169-199`) can
  never mistake one for a response (it requires `id == expected_id` and exactly one of
  `result`/`error`; a notification has neither). The read-loop (D5) **explicitly discriminates**
  `method == "$/progress"` *before* calling `parse_response`, so a progress frame is routed to the
  relay, and only a real terminal frame reaches `parse_response`.
- The in-loop check asserts `params.id == <originating request uuid>`; a mismatch → discard +
  treat as protocol violation → kill (fail closed). On the sole-client single-in-flight socket there
  is only ever one outstanding request, so this is defense-in-depth, not load-bearing — but it
  closes any future-proofing gap and makes the frame self-describing in logs.
- A worker that emits a `$/progress` frame for a call that did **not** opt in is a protocol
  violation: the server is in the single-read path (not the loop), `parse_response` rejects it →
  kill. So progress can never desync a non-progress call.

### D8 — Scope: which methods, which bounds

- **Methods:** **`analyze` only** in v1.4. It is the sole long-running call (18–26 min); every other
  RPC is sub-second-to-seconds and bounded by `tool_timeout_s`. **`import_binary` is NOT
  progress-enabled** in this ADR — import is comparatively fast and its dominant large-binary risk
  (OOM) is handled by ADR-023/F1 + ADR-029 C reject pre-flight; adding progress to import is a
  trivial future extension on the same substrate if measured to matter (note it, don't build it).
- **Bounds (initial values — ratify in D8, tune via the ADR-028 harness):**
  `MIN_PROGRESS_INTERVAL_MS = 500`, `MAX_PROGRESS_FRAMES = 5000` per call,
  `_MAX_PROGRESS_FRAME_BYTES = 512`. All are server-enforced; the worker self-limits to the same
  interval/count as belt-and-suspenders (D2).

### D9 — Validation path (the F2/F7 lesson)

Every Ghidra/MCP binding here is JVM-edge or SDK-edge and **structurally unprovable by unit tests**:
the `TaskMonitor` subclass + the `pyghidra.analyze`-with-monitor vs. `AutoAnalysisManager` path
(D2), and the FastMCP sync→async `report_progress` bridge (D6). Therefore:

- **Unit-testable (must hit the 100%-critical bar):** the pure framing additions in `rpc_framing.py`
  (build/parse a `$/progress` notification; reject a malformed/oversized one), the `_call`
  read-loop's **deadline accounting** (a fake worker that emits N progress frames then a result;
  a fake worker that emits progress frames forever → assert the deadline still fires the kill at
  `deadline_at`, NOT extended), the flood bounds (`MAX_PROGRESS_FRAMES` → kill), the redaction
  (percent/enum only; a frame with a free-form `message` → discarded/killed), and the dispatcher's
  refusal to relay a progress frame for a non-opted-in call.
- **Real-worker only (ADR-028 harness):** that the custom `TaskMonitor` actually fires during
  `analyze` on Ghidra 12.1.2 and produces a monotonic-ish percent + sensible phase sequence on a
  real (large) ELF; that `analyze` still completes and returns the same `ready` result as the
  baseline; that the deadline-kill still fires on a synthetically-slowed analyze with progress
  frames flowing. Add a **progress dimension** to the standing harness (assert: progress-enabled
  `analyze` emits ≥1 frame, ends in exactly one terminal frame, percent within `0..100`, and a
  no-token / non-opted-in run is byte-for-byte the existing baseline).
- Treat the JVM-edge code under `# pragma: no cover - JVM edge` and prove it live before "done"
  (the F2/F7 rule). Record the live-verification result in this ADR (as ADR-029 §D6 did) once run.

---

## Consequences

**Positive**
- The 26-minute silent analyze gets a real, moving progress signal — the most-requested v1.4 UX win.
- Frozen-contract change is **additive + opt-in + default-is-no-op**: non-progress calls and
  no-token clients are byte-for-byte unchanged; an old/strict reader never opts in and never sees a
  progress frame. Mirrors the ADR-029 B / `export_annotations targets` additive-param precedent,
  extended (honestly) to framing.
- Security posture preserved: ADR-001 (server parses nothing; only relays), ADR-002 deadline-kill
  **strengthened as the explicit, non-extendable bound**, ADR-004 isolation unchanged, ADR-005
  redaction enforced by **percent+closed-enum only** (no binary-derived strings cross), ADR-025/F4
  liveness intact, no new tool / capability / agency (LLM08). Flood + size + deadline bounds make a
  hostile worker's progress channel a non-threat.
- Phasing isolates the irreversible risk (framing change) in a log-only Phase 1 that's fully
  live-verifiable before any client-facing wiring.

**Negative / costs**
- It **does** revise the frozen TB2 framing — the read-loop, a new notification frame type, and
  deadline-across-multiple-reads accounting are real complexity on the most security-sensitive
  boundary. Mitigated by additive/opt-in design + the unit-test deadline-integrity suite.
- Two JVM/SDK edges remain unproven until live: the `TaskMonitor`-injection path (may force the
  `AutoAnalysisManager` route) and the FastMCP sync→async `report_progress` bridge. Both are why
  Phase 1 (log-only, no async bridge) is recommended first.
- Percent+enum is coarser than a verbose status — a deliberate redaction trade (no binary-derived
  text). Acceptable: the UX need is "moving / which phase / how far," not the analyzer's prose.

---

## Decisions needing human ratification

1. **D1 / phasing — the mechanism + the split.** Adopt **worker `$/progress` frames relayed to MCP
   `report_progress`** (option ii + i; reject pollable iii). Ship in **two phases** — Phase 1
   worker→server frames **log-only** (proves the framing + JVM-edge in isolation, no client change),
   Phase 2 full MCP client relay — **or** approve a single combined increment. **Recommend the
   split.** Confirm.
2. **D3 — the TB2 progress-frame design (load-bearing, PM-routed frozen-contract change).** Approve
   an **additive, opt-in-per-method** `$/progress` **JSON-RPC notification** (no top-level `id`;
   `method:"$/progress"`; `params:{id, percent?, phase?}`), interleaved before the single terminal
   response **only** for a call that set `params.progress: true`. Confirm it is additive-only (an
   old/strict reader never opts in, so never sees one), that a worker emitting one unsolicited is a
   kill-triggering protocol violation, and that §3/§4 gain exactly the paragraphs in D3.
3. **D4 — redaction stance.** Ratify **percent (`0..100`) + a closed `phase` enum only**; **no
   free-form / binary-derived `message`** crosses to the client or the logs; map Ghidra
   `TaskMonitor` text worker-side to OUR closed enum (`other` for unknown); add a tiny
   `_MAX_PROGRESS_FRAME_BYTES` sanity cap; schema-validate-or-kill every progress frame. (Reject the
   "scrubbed message" alternative.)
4. **D5 — deadline integrity (recommend NO).** Confirm progress frames **MUST NOT** reset or extend
   `analysis_timeout_s`: `deadline_at` is set once, each read uses the shrinking remaining time, and
   on expiry the worker is SIGKILLed exactly as ADR-002 — so a worker emitting progress forever
   cannot dodge the kill. **Recommend NO extension.** Confirm.
5. **D5 — flood bounds.** Ratify the server-side per-call bounds: `MAX_PROGRESS_FRAMES` (kill on
   exceed), `MIN_PROGRESS_INTERVAL_MS` (coalesce/drop, still counts), per-frame size cap, **no
   server-side buffering**. Confirm the initial values (5000 / 500 ms / 512 B) or set them.
6. **D6 — MCP relay (Phase 2).** Approve token-gating via the built-in `report_progress` no-op (no
   `progressToken` ⇒ inert ⇒ exactly today), the localized `Context`-injection wiring for
   `session_analyze` only (generic `_bind` untouched), and that the relay is principal/session-scoped
   via the same MCP request context. Acknowledge the sync→async bridge is a live-verification item.
7. **D8 — scope.** Confirm **`analyze` is the only progress-enabled method** in v1.4 (`import_binary`
   explicitly deferred). Confirm progress is **observability only** — no new MCP tool, no new
   capability/agency (LLM08).
8. **D9 — validation gate.** Agree the JVM/SDK-edge bindings (custom `TaskMonitor` + analyze-with-
   monitor path; FastMCP sync→async `report_progress`) are proven on a **real worker via the ADR-028
   harness** (with a new progress dimension) before "done," while the pure framing/read-loop/redaction
   logic hits the 100%-critical unit bar — including the **deadline-integrity test** (progress-
   forever → kill still fires un-extended).

> **No code, no gated actions taken.** Design-only. Every Ghidra/MCP binding above is flagged
> **REQUIRES-LIVE-VERIFICATION**; implementation lands later as reviewed, gated PRs in an isolated
> worktree after ratification, with an `sdlc-reviewer` security pass and CI green (PLAN rhythm).
> The TB2 contract edit (`docs/contracts/rpc-protocol.md` §3/§4) is **PM-routed per the frozen-
> contract / batch-atomicity posture** — not edited by a feature workstream.
