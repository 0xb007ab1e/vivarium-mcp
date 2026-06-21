# ADR-041: Mid-stream cancellation of a decompile stream

- **Status:** Proposed (v1.x; human-requested 2026-06-21). Refines the cancellation path of
  **ADR-040** (streaming partial results). Supersedes the `cancel_stream` **request/response** worker
  method with a `$/cancel` **control notification** the worker observes *between functions*.
- **Date:** 2026-06-21
- **Deciders:** Human (requested) + PM; recorded by the Software Architect.
- **Context source:** ADR-040 shipped with a documented limitation (the #134 handoff): the
  single-threaded worker cannot notice a cancel while mid-`start_decompile_stream`, so `cancel_job`
  is authoritative server-side but the *worker* only frees on the bounded deadline / eviction / SIGKILL.

## Context

`cancel_job` (ADR-040 D6) is already correct and authoritative on the **server**: it marks the job
cancelled, drops the buffer (BOLA-checked), and clears the active-job slot immediately, so the client
is freed at once. What it does **not** do is stop the **worker** promptly: the worker's
`serve_connection` loop (`worker/dispatch.py`) reads one request, then blocks for the entire
`start_decompile_stream` call producing `$/chunk` frames, and only reads the socket again after the
call returns. A `cancel_stream` request therefore sits unread in the worker's recv buffer until the
stream finishes on its own — so the worker keeps decompiling the whole bounded set even after the
client has cancelled. On a large set that wastes minutes of worker time and holds the session's
single worker (ADR-002 one-worker-per-session) for no benefit.

The machinery to stop early already exists worker-side: a per-stream `_stream_cancelled` flag
(`_jvm_bridge.py`) checked **between functions** in the decompile loop (`is_cancelled()`,
`_jvm_bridge.py:1013`). The only missing piece is **delivering** the cancel to that flag while the
stream is in flight, without breaking the single-threaded worker model or the ADR-002 isolation.

## Decisions

- **D1 — `$/cancel` control notification, not a request.** Replace the `cancel_stream`
  request/response worker method with a `$/cancel` **notification** (no top-level `id`), joining the
  existing `$/progress` / `$/chunk` control-frame family:
  ```json
  { "jsonrpc": "2.0", "method": "$/cancel", "params": { "id": "<streaming-call-uuid>" } }
  ```
  A notification (not a request) is the right shape because the streaming socket already carries
  worker→server notifications interleaved with one terminal response; adding a *server→worker*
  control notification avoids interleaving a second request/response pair onto a socket mid-stream
  (which would force the adapter's chunk reader to disambiguate a cancel-ack from chunk frames). The
  stream's existing **terminal response** is the acknowledgement: on cancel the worker ends the
  stream early and returns its terminal summary (`{total, truncated, done}` with the produced count),
  exactly as it does on normal completion — so the adapter's reader needs no new frame type.

- **D2 — Cooperative non-blocking poll between functions (stay single-threaded).** Keep the worker
  one-thread-per-connection (no reader thread, no second socket — both would complicate the ADR-002
  hardened-worker model and JVM/socket thread-safety). The dispatch layer (which owns the `conn`)
  builds a `poll_cancel()` predicate for the streaming call: a **non-blocking** `select([conn], 0)`;
  if readable, read one framed control notification; if it is `$/cancel` for this request id, set the
  cancel flag. The predicate is passed to the backend's decompile loop, which already calls a
  between-functions `is_cancelled()` — so the only change to the JVM loop is *what* `is_cancelled`
  consults. The socket stays owned by dispatch; the JVM backend never touches it (ADR-001 boundary
  preserved).

- **D3 — Granularity = between functions (unchanged).** Cancel takes effect at the next function
  boundary, not mid-decompile-of-one-function (a single `decompileFunction` call is not interruptible
  and is bounded by its own timeout). This is the existing `is_cancelled()` contract; D1/D2 only make
  the flag reachable in time. Worst-case extra work after a cancel is one function's decompile.

- **D4 — Reads are bounded + fail-closed.** The between-functions poll reads **at most one** control
  frame per boundary, subject to the existing §3 frame-size cap; a malformed/oversized control frame,
  or any `method` other than `$/cancel` (with no top-level `id`) arriving on the stream socket, is a
  protocol violation → kill + evict (§6), exactly like any other bad frame. A non-blocking poll that
  finds a partial frame does not block the producer (it only reads when a full control frame is
  available, or within a tiny bounded read for the small control frame).

- **D5 — Server side: `cancel_job` sends `$/cancel`; authority unchanged.** `cancel_job` keeps its
  current authoritative server-side effect (mark cancelled, drop buffer, free the slot — BOLA first),
  and additionally sends the best-effort `$/cancel` notification on the session socket so the worker
  stops early. Sending is best-effort (a send error is logged, never fatal — the deadline/eviction
  remains the backstop). The adapter serializes the `$/cancel` send against its own socket use.

- **D6 — Idempotent + safe.** `$/cancel` for an unknown/already-finished stream id is a no-op. Cancel
  remains idempotent (ADR-040 D6). No client-facing change: the `cancel_job` tool + schema are
  unchanged; this is purely the worker↔server cancel mechanism.

## Contract delta (this PR — atomic with the ADR)

- **`docs/contracts/rpc-protocol.md`:** replace the `cancel_stream` worker **method** with the
  `$/cancel` **notification** (server→worker); document that the worker polls for it **between
  functions** during `start_decompile_stream`, that the stream's terminal response is the
  acknowledgement, and that a bad control frame on the stream socket is a §6 protocol violation.
  `start_decompile_stream` stays a worker method; `fetch_job_results`/`job_status`/`cancel_job`
  remain server-side job ops. Tool catalog + client schemas are **unchanged** (no tool-count change).

## Execution plan (increments, after this ADR + contract delta merge)

1. **This PR — ADR-041 + the rpc-protocol delta only** (no code).
2. **Framing + worker:** add `CANCEL_METHOD`/`is_cancel_notification`/`parse_cancel`/`build_cancel`
   to `rpc_framing.py` (pure, mirrors `$/progress`/`$/chunk`); dispatch builds the `poll_cancel()`
   predicate from `conn` and threads it into `start_decompile_stream`; drop `cancel_stream` from
   `RPC_METHODS`. Hermetic unit tests: a fake `conn` scripted to deliver a `$/cancel` mid-stream →
   the producer stops at the next boundary; an unknown-id `$/cancel` is a no-op; a bad control frame
   → protocol violation.
3. **Adapter:** `cancel_job` sends `$/cancel` (replacing the `cancel_stream` request); the stream
   reader is unchanged (it still ends on the terminal response). Unit tests with a fake socket.
4. **Live validation:** extend the gated `test_decompile_stream_openssl_blind` (or add a sibling) to
   start a stream, `cancel_job` after the first chunk, and assert the worker stops **promptly** (the
   terminal response/`done` arrives well before the full set would have — a cancel-latency bound),
   under the live-regression harness.

## Acceptance criteria

- A `cancel_job` during an in-flight stream stops the **worker** within one function boundary
  (demonstrated: terminal/`done` arrives markedly sooner than the full bounded set would take).
- Single-threaded worker preserved; ADR-002 isolation + ADR-001 server/worker boundary unchanged.
- `$/cancel` is idempotent and safe for unknown/finished ids; bad control frames fail closed.
- No client-facing change (tool surface/schemas/catalog count unchanged); hermetic unit tests cover
  the poll/stop/no-op/bad-frame paths; the live test proves prompt cancellation.

## Consequences

- **Positive:** cancel frees the worker promptly (no wasted minutes / held session); reuses the
  existing between-functions hook and control-frame family; no new thread or socket.
- **Negative / cost:** the worker now does a tiny non-blocking socket poll per function boundary
  (negligible); a small contract change (one internal worker method → one control notification).
  Cancellation granularity stays one-function (acceptable — a single decompile is short and
  separately bounded).

## References

- ADR-040 (streaming partial results; D6 cancellation), ADR-002 (worker lifecycle/isolation),
  ADR-001 (server never loads the JVM; worker owns Ghidra), `docs/contracts/rpc-protocol.md`.
- Rules: `topic-concurrency` (prefer single-thread + cooperative cancellation over threads),
  `topic-reliability` (bounded, fail-closed), `std-owasp-llm` (LLM04 bounded resource use).
