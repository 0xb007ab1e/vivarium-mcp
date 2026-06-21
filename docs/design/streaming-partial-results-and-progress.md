# Design: Streaming partial results and progress updates

> Status: **SUPERSEDED for Phase 2** by [`../adr/ADR-040-streaming-partial-results.md`](../adr/ADR-040-streaming-partial-results.md)
> (resolves the §7 open questions with concrete decisions + contract deltas). Phase 1 (progress)
> already shipped as ADR-030 + ADR-039. This document remains the problem framing / option survey;
> the binding decisions now live in ADR-040.

## 1. Goal and scope

Two related capabilities, requested together:

- **A. Streaming partial results.** For tools that extract over many units (decompiling or
  analyzing many functions, large string/symbol listings, whole-program sweeps), emit results
  incrementally as each unit becomes available, so the calling LLM can begin inference on the
  early results while extraction of the rest continues. Today these tools block until the whole
  batch is ready.
- **B. Progress and status updates.** A mechanism that keeps the end user and the client
  informed during a long operation: current phase, units done versus remaining, percent
  complete, elapsed time, and a rough estimate of time remaining.

Both stay within the existing posture: **read-only, output-only**, every binary-derived byte
wrapped in the untrusted-data envelope (ADR-005), bounded and killable per ADR-002. Streaming
must not weaken any of those guarantees; it only changes *when* results and status cross the
boundary, not *what* crosses or *how trusted* it is.

Out of scope for this sketch: a concrete schema, the chosen transport mechanism, and a
migration plan. Those belong in the ADR that follows acceptance.

## 2. Motivation

The triggering case is the full first-party decompile of the OpenSSL command-line binary:
roughly 15,750 functions, tens of minutes of wall-clock extraction. Under the current
request/response model the client receives nothing until the entire run finishes, so:

- The LLM sits idle for the whole extraction instead of reasoning over functions as they land.
  Decompilation and inference are naturally pipelineable: function N can be reasoned about while
  function N+1 is still being decompiled.
- The end user has no visibility into a long call. They cannot tell a slow-but-working run from
  a hung one, and they cannot estimate when it will finish.

The payoff of A is lower latency to first useful result and overlap of extraction with
inference. The payoff of B is operability: a long call becomes observable and cancelable with
confidence. The two compose: a streamed result set is naturally accompanied by progress.

## 3. Current behavior (the baseline this changes)

- Tools are single request, single response. A tool returns one structured result; there is no
  incremental delivery.
- Results are **bounded** by size and count caps enforced before the worker is called
  (project rules; tool-catalog). Streaming must keep an equivalent total bound, just expressed
  over the stream rather than one payload.
- There is already a narrow progress affordance: `session_analyze` accepts a `progress` flag.
  Capability B should generalize that one-off into a consistent mechanism, not a second
  parallel system.
- One hardened worker per session; the worker is killed on timeout or eviction with a verified
  store wipe (ADR-002). Any long-lived streaming job must live inside that lifetime, not extend
  it without bound.

## 4. Capability A: streaming partial results (candidate approaches)

The MCP base protocol models a tool call as one request and one response. It does **not** have
native incremental tool-result streaming. So partial results need one of the following shapes.

- **A1. Progress notifications carrying data.** Reuse MCP progress notifications to ship partial
  payloads. Simple to wire, but it abuses a status channel for data: notifications are not
  designed for large or ordered payloads, have weak delivery/ordering guarantees, and muddle
  "how far along" with "here is a result." Not recommended as the primary data path.
- **A2. Job plus cursor (pull).** A tool starts an extraction **job** and returns a job handle
  immediately. The client pulls results incrementally with a new read tool, for example
  `fetch_results(job, cursor, limit)`, which returns the next bounded batch plus the next
  cursor and a done flag. Transport-agnostic (works over stdio and HTTP), resumable by
  construction (the cursor is the resume point), and naturally bounded per pull. The cost is a
  client poll loop and server-side buffering of not-yet-pulled results within a cap.
- **A3. Server-initiated stream (push).** On the HTTP transport (ADR-011), stream chunks to the
  client as they are produced (an SSE-style channel or repeated resource-update notifications
  against a results resource). Lowest latency and no poll loop, but only available where the
  transport supports server push; stdio would still need a fallback.

Leaning: a **pull-based job plus cursor (A2) as the portable core**, optionally augmented by
**push (A3) on HTTP** so a capable client avoids polling. A2 alone already delivers the main
benefit (the LLM starts work on batch 1 while batch 2 extracts) and works on the v1 stdio
transport.

A second, independent axis: does the **worker** stream results to the server incrementally (an
RPC-protocol change, the worker emits per-unit as it decompiles), or does the server merely
chunk an already-complete worker result (much simpler, but yields no extraction/inference
overlap)? The motivation (overlap) requires genuine worker-to-server incremental delivery, so
the RPC protocol change is the substantive part of this work.

## 5. Capability B: progress and status updates (candidate approaches)

- **B1. MCP progress notifications.** When the client supplies a progress token on the call,
  the server emits `notifications/progress` with units done, total (when known), a phase label,
  and a short human message. This is the idiomatic MCP mechanism and generalizes the existing
  `session_analyze` progress flag.
- **B2. Pollable status tool.** A read tool, for example `job_status(job)` returning
  `{phase, done, total, eta_seconds, started_at, state}`, for clients or transports that do not
  consume notifications.

Leaning: **emit B1 progress notifications when a progress token is supplied, and also expose
B2** so progress is available regardless of whether the client consumes notifications. The two
read from the same server-side counter, so they cannot diverge.

## 6. Security and contract impact (must hold)

- **Untrusted envelope per chunk.** Every partial result chunk wraps binary-derived fields in
  the ADR-005 envelope exactly as a full result does. A chunk is inert data: never executed,
  rendered, or followed. Progress *messages* are server-authored status text, not
  binary-derived, and stay free of binary content (no decompiled text, strings, or paths in a
  progress message; only counts, phases, durations).
- **Bounds and backpressure.** The stream carries the same total caps as the batch it replaces,
  plus new per-stream limits: maximum buffered (un-pulled) chunks, maximum chunk size, and a
  per-session quota. A slow or absent consumer must apply backpressure (bounded buffer, then a
  defined shed or pause), never unbounded growth (topic-reliability; std-owasp-llm LLM04 is
  also a cost and resource concern here).
- **Worker lifetime (ADR-002).** A streaming job lives inside the worker's bounded lifetime. It
  does not extend the timeout or defer eviction indefinitely; on timeout or eviction the job
  ends, the store is wiped, and the stream terminates with an error chunk.
- **Ordering, resume, idempotency.** Chunks carry a monotonic sequence or cursor. Delivery is
  at-least-once in spirit; the client dedupes and resumes by cursor. No silent reordering.
- **Fail closed and honest.** On an extraction error mid-stream, emit a terminal error chunk;
  never end a stream early in a way indistinguishable from success (ADR-005 honesty: surfaced,
  not silently dropped).
- **Authorization (BOLA).** A job handle is authorized server-side and bound to its creating
  session and principal (multi-principal authZ, ADR-017). One principal cannot pull another's
  job.
- **Frozen contracts.** This changes `contracts/rpc-protocol.md` (worker emits incremental
  results) and the tool schemas (a job handle, a cursor, a status shape, the chunk envelope).
  Those are frozen and change only through the PM with an ADR, as a single atomic batch, not by
  an individual feature workstream.
- **Testing.** Streaming complicates hermetic, deterministic tests. New contract tests are
  needed for chunk ordering, resume-from-cursor, bound enforcement, the per-chunk envelope, and
  the terminal-error path. Time-based behavior (ETA, flush cadence) needs an injected clock so
  tests stay deterministic.

## 7. Open questions (resolve before the ADR)

1. **Transport.** Do we require the HTTP transport for true push streaming and let stdio fall
   back to pull-only, or make pull (A2) the single path on both? (Leaning: pull on both, push
   as an HTTP enhancement.)
2. **Push versus pull versus both.** Is the first increment pull-only for simplicity, with push
   deferred?
3. **Unit granularity.** What is a streamed unit: one decompiled function, a fixed batch of N,
   or a time-based flush (every T seconds, whatever is ready)? This trades per-chunk overhead
   against latency to first result.
4. **Backpressure policy.** When the consumer is slow and the buffer is full: pause extraction,
   shed oldest, or fail the job with a clear reason?
5. **Worker RPC change scope.** Incremental worker-to-server delivery is the high-value, higher-
   risk change. Is a first phase that only chunks an already-complete result worth shipping, or
   does it add surface without the overlap benefit?
6. **Cancellation.** Should a job be explicitly cancelable (a `cancel(job)` tool) in addition to
   worker-timeout termination, so a client that has seen enough can stop extraction and free the
   worker early?
7. **Which tools get streaming.** Start with the clear win (bulk decompile and whole-program
   sweeps), or define one generic streaming contract that any large-result tool can adopt?

## 8. Rough phasing (sketch, not a commitment)

- **Phase 1, progress (lower risk).** Generalize the `session_analyze` progress flag into a
  consistent progress mechanism: emit MCP progress notifications on a supplied progress token
  and add a pollable `job_status` / `session_status` read. Reuses existing plumbing, no result
  streaming yet, immediate operability win (capability B).
- **Phase 2, pull-based partial results.** Add the job-plus-cursor model (A2) for bulk
  extraction, with the worker streaming units to the server incrementally (the RPC protocol
  change), bounded and resumable. Delivers the extraction/inference overlap on stdio and HTTP.
- **Phase 3, push on HTTP.** Optional server-initiated streaming on the HTTP transport so a
  capable client avoids the poll loop.

## 9. Acceptance criteria (when this is eventually built)

- Measurable reduction in latency to first useful result on a large extraction, and demonstrated
  overlap of client inference with ongoing extraction.
- Progress is accurate (done and total reconcile with the final result) and available both as
  notifications and via a status read.
- All bounds enforced: total caps preserved, per-stream buffer and chunk caps enforced,
  backpressure demonstrated under a slow consumer.
- Every chunk carries the untrusted-data envelope; progress messages contain no binary-derived
  content.
- Streams are resumable by cursor and terminate honestly (explicit done or explicit error,
  never an ambiguous early stop).
- No regression to worker lifetime, eviction, or store-wipe guarantees (ADR-002).
- Hermetic, deterministic contract tests cover ordering, resume, bounds, envelope, and the
  error path.

## References

- Project contracts: [`../contracts/rpc-protocol.md`](../contracts/rpc-protocol.md),
  [`../contracts/tool-catalog.md`](../contracts/tool-catalog.md).
- ADRs: ADR-002 (worker lifecycle, kill-on-timeout, store wipe), ADR-005 (untrusted-data
  envelope and honesty), ADR-011 (HTTP transport), ADR-017 (multi-principal authorization).
- Rule modules: `topic-reliability` (timeouts, backpressure, bounded buffers),
  `topic-realtime` (streaming connection patterns, reconnect, backpressure),
  `std-owasp-llm` (LLM04 unbounded consumption as a cost and resource concern),
  `topic-event-driven` (at-least-once delivery, idempotent consumers, ordering).
