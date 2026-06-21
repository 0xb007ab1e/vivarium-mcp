# ADR-040: Streaming partial results (pull-based job + cursor)

- **Status:** Proposed (v1.x; human-requested 2026-06-21). Supersedes the Phase-2 sketch in
  `docs/design/streaming-partial-results-and-progress.md` with concrete decisions and contract
  deltas. **Phase 1 (progress) already shipped** as ADR-030 (worker `$/progress` frames +
  client relay) and ADR-039 (CI run status) plus the `session_status` read — this ADR is
  **Phase 2: partial results**.
- **Date:** 2026-06-21
- **Deciders:** Human (requested) + PM; recorded by the Software Architect.
- **Context source:** the full first-party OpenSSL decompile (~15.7k functions, tens of minutes)
  delivers nothing to the client until the whole run finishes — the LLM sits idle instead of
  reasoning over functions as they land, and a long call is not observably distinct from a hang.

## Context

The MCP base protocol models a tool call as one request and one response; it has no native
incremental tool-result streaming. To let the client begin inference on early results while the
worker keeps extracting, results must be delivered in bounded, ordered, resumable chunks without
weakening any v1 guarantee: read-only, output-only, every binary-derived byte wrapped in the
ADR-005 untrusted envelope, bounded and killable per ADR-002, job authorized to its
session+principal per ADR-017.

The design doc (`docs/design/streaming-partial-results-and-progress.md`) surveyed the options and
left seven open questions (§7). This ADR resolves them.

## Decisions

- **D1 — Pull-based job + cursor is the portable core; push is deferred.** A tool starts an
  extraction **job** and returns an opaque job handle immediately. The client pulls bounded
  batches with `fetch_job_results(session_id, job, cursor, limit)` → `{chunks, next_cursor,
  done}`. This works identically on stdio and HTTP (resolves design Q1/Q2). Server-initiated push
  (SSE on HTTP, design Phase 3 / A3) is **out of scope here** and may be added later behind the
  same job model without a contract break.

- **D2 — Genuine worker→server incremental emission (not server-side chunking of a finished
  result).** The overlap benefit requires the worker to emit per-unit as it decompiles. The
  worker streams results to the server during **one** long RPC call as `$/chunk` **notifications**
  (new frame type, framed exactly like the existing `$/progress` notification: a JSON-RPC
  notification with `params.id` correlating to the originating call, no top-level `id`). The
  server buffers them into a bounded per-job buffer the client pulls from. The client never
  round-trips to the worker per fetch — the **server buffer is the decoupling point** (resolves
  design Q5: incremental worker emit is in scope; pure server-chunking is rejected as benefit-free).

- **D3 — One generic job contract; bulk decompile is the first (and only, this increment) start
  tool.** A single reusable job machinery (handle + `fetch_job_results` + `job_status` +
  `cancel_job`) plus per-kind `start_*` tools keeps the surface explicit and allow-listed (the
  Tier-1 catalog is a deliberate allow-list, not a generic "run any extraction" endpoint). This
  increment adds exactly **`start_decompile_stream`** (bulk decompile over a function set) — the
  motivating win. Other bulk tools (`list_functions`, `list_strings`, whole-program sweeps) can
  add their own `start_*` later, reusing the same fetch/status/cancel and buffer (resolves Q7).

- **D4 — Unit granularity: worker emits per function; server batches on fetch.** The worker emits
  one `$/chunk` per decompiled function (the natural unit, lowest latency to first result). The
  server buffers per-function chunks; `fetch_job_results` returns up to `limit` of them (default
  32, max 256) with the next cursor. Worker emit cadence is thus decoupled from client pull size
  (resolves Q3).

- **D5 — Backpressure = pause, never silent drop.** The server's per-job buffer is bounded by
  **max buffered chunks** and **max buffered bytes** (both configurable in `Limits`). When the
  buffer is full the server stops reading the worker socket; UDS/TCP flow control naturally
  **pauses** the worker's writes until the client drains via `fetch_job_results`. No chunk is ever
  shed or reordered (ADR-005 honesty). If the worker is killed (timeout/eviction) the buffer is
  drained to the client where already-pulled, then the stream terminates with a **terminal error
  chunk** (resolves Q4).

- **D6 — Explicit cancellation.** `cancel_job(session_id, job)` aborts the in-flight extraction
  RPC (the server stops the worker call and discards the buffer) so a client that has seen enough
  frees worker capacity early, without waiting for the per-call deadline (resolves Q6). Cancel is
  idempotent and authorized like any session-scoped call.

- **D7 — Ordering, resume, idempotency.** Each chunk carries a **monotonic `seq`** (0-based, gap-
  free per job). The cursor is the opaque "next seq" token. Delivery to the client is
  at-least-once in spirit: a client may re-`fetch` from an earlier cursor and **must dedupe by
  `seq`**. The server never reorders. `next_cursor` + `done` are authoritative for completion.

- **D8 — Bounds preserved + new per-stream caps.** The job's **total** is capped equal to the
  batch it replaces (the existing bulk-decompile function-count cap); reaching it sets the final
  chunk's job `done=true` with a job-level `truncated=true` when the requested set exceeded the
  cap — honestly surfaced, not silently cut. New caps: max buffered chunks, max buffered bytes,
  max chunk size, and **one active streaming job per session** (a second `start_*` while one is
  active is rejected `limit-exceeded`) to bound worker and memory cost (std-owasp-llm LLM04).

- **D9 — Per-chunk untrusted envelope; progress stays content-free.** Every chunk wraps its
  binary-derived fields (decompiled C, function name) via the existing `core.envelope.wrap(...,
  origin=DataOrigin.GHIDRA|BINARY)` chokepoint, exactly as a non-streamed result does. A chunk is
  inert data. Progress (`$/progress`, `job_status`) carries only counts/phase/eta — never
  binary-derived text (master §5, unchanged from ADR-030).

- **D10 — Authorization (BOLA) + lifetime.** A job handle is bound to its creating session (and
  therefore its principal, ADR-017); `fetch`/`status`/`cancel` authorize through the existing
  `SessionManager` session-ownership chokepoint — one principal cannot touch another's job. A job
  lives **inside** the worker's bounded lifetime (ADR-002): session TTL/idle/close/eviction ends
  the job and wipes the store; the job never extends the worker deadline.

## Contract deltas (this PR — the frozen-contract atomic batch)

- **`docs/contracts/rpc-protocol.md`:** add the `$/chunk` notification frame (correlated by
  `params.id`, carrying `{seq, kind, payload}`; payload is plain JSON the server envelopes); add
  worker methods `start_decompile_stream` (long call that emits `$/chunk` then a terminal
  response with `{total, truncated, done}`) and the control method `cancel_stream`; document the
  ordering rule (zero-or-more `$/progress` and `$/chunk` interleaved, then exactly one response),
  the per-job buffer/flow-control contract, and the terminal-error-chunk path.
- **`docs/contracts/tool-catalog.md`:** add Tier-1 tools `start_decompile_stream`,
  `fetch_job_results`, `job_status`, `cancel_job` (catalog count 51 → 55). Each session-scoped
  and BOLA-authorized; `fetch`/`status`/`cancel` are generic over a job handle.
- **`docs/contracts/untrusted-envelope.md`:** note that streamed chunks carry the same envelope
  per chunk (no new envelope shape — reuse `Untrusted[T]`).

## Execution plan (increments, each its own PR after this ADR + contracts merge)

1. **This PR — ADR-040 + contract deltas only** (no code). The frozen-contract change as one
   reviewed atomic batch (project rule), so WS implementation builds to a settled contract.
2. **Worker incremental emit + server job buffer.** Worker `start_decompile_stream` emits
   `$/chunk` per function; `RpcGhidraAdapter` grows a bounded per-job buffer + flow control; a
   `JobManager` (or `_Session.jobs`) tracks job identity/cursor/state within the session lifetime.
   Unit tests with the fake port: ordering, buffer-bound/backpressure, terminal-error.
3. **The four tools + schemas.** `start_decompile_stream` / `fetch_job_results` / `job_status` /
   `cancel_job` with frozen pydantic `*In`/`*Out`; per-chunk envelope; BOLA authorize; one-active-
   job cap. Catalog allow-list test 51→55.
4. **Contract + integration tests.** Hermetic contract tests (resume-by-cursor dedupe, bounds,
   envelope, done/error terminality, injected clock for eta/flush). Gated live-worker integration:
   real bulk decompile of the committed OpenSSL fixture, asserting first-chunk latency ≪ full-run
   latency and overlap, under the live-regression harness.

## Acceptance criteria

Carried from the design doc §9: measurable latency-to-first-result reduction + demonstrated
overlap; progress accurate and available as both notification and `job_status`; all bounds
enforced and backpressure demonstrated under a slow consumer; every chunk enveloped; streams
resumable by cursor and terminating honestly (explicit done or explicit error); no regression to
ADR-002 worker lifetime/eviction/store-wipe; hermetic deterministic contract tests cover ordering,
resume, bounds, envelope, and the error path.

## Consequences

- **Positive:** the LLM overlaps inference with extraction (the core ask); long calls are
  observable and cancelable; the job machinery is reusable for future bulk tools.
- **Negative / cost:** new server-side buffering state and a backpressure path to test; a second
  delivery shape (notifications + pull) alongside the one-shot model; more contract surface. Held
  in check by the one-active-job cap, the bounded buffer, and reusing the `$/progress` framing and
  the `wrap()` envelope chokepoint rather than inventing new mechanisms.

## References

- Design: `docs/design/streaming-partial-results-and-progress.md` (the §7 questions this resolves).
- ADRs: ADR-002 (worker lifecycle/kill/wipe), ADR-005 (untrusted envelope + honesty), ADR-011
  (HTTP transport), ADR-017 (multi-principal authZ), ADR-030 (analyze progress — Phase 1).
- Contracts: `docs/contracts/rpc-protocol.md`, `docs/contracts/tool-catalog.md`,
  `docs/contracts/untrusted-envelope.md`.
- Rules: `topic-reliability` (timeouts, backpressure, bounded buffers), `topic-realtime`
  (streaming/backpressure/resume), `topic-event-driven` (at-least-once, idempotent consumers,
  ordering), `std-owasp-llm` (LLM04 unbounded consumption).
