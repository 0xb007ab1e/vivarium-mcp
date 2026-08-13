# Contract: Server ↔ Worker RPC Protocol (FROZEN — WS0)

> Trust boundary **TB2** (PLAN §4). The server is the **sole** client of the worker. This is an
> **internal** protocol — never exposed to the MCP client or the network.

## 1. Recommendation & rationale (sign-off requested)

**Recommended: JSON-RPC 2.0 over a per-session Unix domain socket (UDS), with length-prefixed
framing.** (Open item PLAN §9 — flagged for PM/SME sign-off; see §8.)

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| **JSON-RPC 2.0 / UDS** (recommended) | No network surface (UDS only, file-perm scoped); simple, debuggable, language-agnostic (Python server ↔ JVM/PyGhidra worker); easy strict-schema validation; mature libraries | JSON is verbose for large byte payloads (mitigated: bytes are hex/base64 + size-capped) | **Chosen** — best fit for a local, sole-client, no-network boundary |
| gRPC / UDS | Strong typed contracts, streaming, codegen | Heavier dependency (protobuf + grpc) on both sides incl. the JVM worker; more moving parts than needed for a local sole-client link | Deferred — revisit if streaming/perf demands it in v1.1 |
| Raw pipe + custom framing | Minimal deps | Reinvents request/response correlation + errors; more bug surface | Rejected |

**Why UDS over TCP/localhost:** UDS has no network namespace exposure, is scoped by filesystem
permissions, and cannot be reached by a remote attacker even if the worker were ever
mis-networked. Aligns with the worker's **no-network** stance (ADR-004).

## 2. Transport & addressing

- One **UDS per session** in a **per-session subdirectory**:
  `${VIVARIUM_RPC_SOCKET_DIR}/<token>/<session_id>.sock` (default dir `/run/vivarium`), where
  `<token>` is a SHORT prefix of the session id (first 16 chars). The per-session dir is created
  `0700` (owner = server user) and is the **only** thing bind-mounted into that worker (mounted at
  the in-container `/run/vivarium`), so a worker can reach **only its own** socket — sibling
  sessions' sockets are not present in its mount namespace (ADR-009). The session id is
  opaque/high-entropy (BOLA defense). *(Reconciled 2026-06-10: the path gained the per-session
  subdir so the WS3 launcher mount could isolate sockets per session; the subdir uses a short id
  prefix — not the full id — because the full 43-char id in BOTH the dir and the `<sid>.sock`
  filename overflows the `AF_UNIX` ~107-byte path limit at realistic socket dirs (the default
  `/run/vivarium` reached 108). PM-routed contract update.)*
- Inside the container the worker still binds `/run/vivarium/<session_id>.sock`; the host side of
  that is the per-session path above via the bind mount.
- The worker connects to (or listens on) only its own session socket; there is no shared socket.
- The socket (and its per-session dir) is removed on session eviction (part of the verified cleanup).

## 3. Framing

- **Length-prefixed:** each message = a 4-byte big-endian unsigned length `N` (of the JSON body)
  followed by exactly `N` bytes of UTF-8 JSON.
- **Hard frame cap:** `N` MUST NOT exceed the configured `max_response_bytes` (default 4 MiB);
  a larger declared length is a protocol error → the server closes the socket and **kills the
  worker** (defense against a malicious/buggy worker declaring a huge frame). (TB2-D/I)
- No partial-frame execution: a frame is parsed + schema-validated fully before dispatch.

## 4. Message model (JSON-RPC 2.0)

Request (server → worker):
```json
{ "jsonrpc": "2.0", "id": "<uuid>", "method": "<rpc_method>", "params": { ... } }
```
Success response (worker → server):
```json
{ "jsonrpc": "2.0", "id": "<uuid>", "result": { ... } }
```
Error response (worker → server):
```json
{ "jsonrpc": "2.0", "id": "<uuid>",
  "error": { "code": <int>, "message": "<safe>", "data": { "type": "<error-slug>" } } }
```

- `id` correlates request/response and the originating tool call in logs.
- `params` and `result` shapes mirror the tool schemas (`tools/schemas.py`) minus the
  `session_id` (the socket already identifies the session). The **server** wraps `result` content
  in the untrusted-data envelope; the worker returns plain structured data.
- Every frame is validated against its schema on receipt; unknown methods/fields are rejected.

**`$/progress` — additive analysis-progress NOTIFICATION (v1.4 — ADR-030 Phase 1; worker → server,
OPT-IN):** during an opted-in `analyze` the worker MAY send zero or more `$/progress`
**notifications** on the same socket BEFORE the single response:
```json
{ "jsonrpc": "2.0", "method": "$/progress",
  "params": { "id": "<analyze-uuid>", "percent": <0..100|null>, "phase": "<closed-enum>" } }
```
- **A notification, not a response — NO top-level `id`.** Per JSON-RPC 2.0 a notification carries no
  top-level `id`; the analyze request's `id` rides inside `params.id` purely to correlate the frame
  to the in-flight call. The absence of a top-level `id` is the structural invariant that a progress
  frame can **never** be confused with the request's correlated response (and vice-versa): the server
  classifies a frame as progress **iff** `method == "$/progress"` AND it has no top-level `id`; a
  frame carrying both is NOT treated as progress (it falls through to response parsing, which then
  rejects it). No correlation desync is possible.
- **Opt-in only.** The worker emits these **only** when the request's `params.progress` is `true`
  (the additive `analyze` flag below). When progress is not requested the worker emits **no
  `$/progress` frames** and the exchange is byte-for-byte today's single response — additive, no
  existing field repurposed, tool count unchanged.
- **Ordering.** Zero or more `$/progress` notifications, in order, then **exactly one** response
  (`result` or `error`). Progress never replaces or follows the response.
- **Redaction (master §5).** `params` carries the SAFE **`percent`** (int `0..100`, or `null` when
  the monitor is indeterminate) and a **`phase`** from the CLOSED vocabulary
  `{ "importing", "analyzing", "finalizing" }` ONLY. Ghidra's free-form `TaskMonitor` message
  (which embeds attacker-controlled symbol/function names) is **never** placed on the wire; an
  out-of-range `percent` or out-of-vocabulary `phase` is a protocol violation and is rejected
  fail-closed.
- **Flood bounds (TB2/TB3 — the worker is potentially hostile).** The server accepts at most
  `_MAX_PROGRESS_FRAMES` (10 000) progress frames per opted-in call; exceeding the count is a
  protocol violation → kill + evict (§6). Frames relayed to the server log are rate-limited (a frame
  sooner than a min interval since the last relayed one is coalesced — counted but not logged). The
  per-frame §3 size cap also applies; frames are processed and discarded one at a time (no unbounded
  server-side buffering).
- **The analysis deadline is NOT extended by progress** (see §6): the one-shot per-analysis deadline
  is computed once at call start; progress frames do not reset or push it, so a chatty or hung worker
  still hits the kill-on-timeout. Phase 1 relays each frame to the **server log only** (no MCP-client
  relay — that is Phase 2).
- **Phase 2 (MCP client relay) — server-internal, worker protocol UNCHANGED.** The worker↔server
  `$/progress` frame, its opt-in (`params.progress`), and all bounds above are identical in Phase 2;
  the worker is unaware of any client. Phase 2 only adds a **server→client** hop: when the MCP client
  supplied a `progressToken`, the server forwards each frame as a standard MCP `notifications/progress`
  (percent out of 100; closed-vocab phase as the message). A `progressToken` makes the server set
  `params.progress:true` automatically; with no token the server behaves byte-for-byte as Phase 1.

**`$/chunk` — additive partial-result NOTIFICATION (v1.x — ADR-040 Phase 2; worker → server):**
during a streaming extraction call (e.g. `start_decompile_stream`) the worker emits zero or more
`$/chunk` notifications on the same socket BEFORE the single terminal response, one per extracted
unit (e.g. one decompiled function):
```json
{ "jsonrpc": "2.0", "method": "$/chunk",
  "params": { "id": "<call-uuid>", "seq": <int ≥ 0>, "kind": "<closed-enum>", "payload": { … } } }
```
- **A notification, not a response — NO top-level `id`** (identical structural invariant to
  `$/progress`: classified as a chunk iff `method == "$/chunk"` AND no top-level `id`; a frame with
  both is not a chunk). `params.id` correlates to the in-flight streaming call.
- **`seq`** is a monotonic, 0-based, gap-free counter per call (ordering + resume key). The worker
  emits in `seq` order; the server never reorders.
- **`kind`** is from a closed vocabulary per stream (`start_decompile_stream`: `"function"`);
  out-of-vocabulary `kind` or a non-monotonic `seq` is a protocol violation → kill + evict (§6).
- **`payload`** is plain structured data (mirrors the streamed unit's schema minus envelope); the
  **server** wraps every binary-derived field in the untrusted-data envelope before it reaches the
  client — exactly as it does for a one-shot `result`. The worker never envelopes.
- **Server buffering + backpressure (ADR-040 D5).** The server buffers chunks into a bounded
  per-job buffer (caps: max buffered chunks, max buffered bytes — `security/limits.py`). When the
  buffer is full the server **stops reading the socket**; UDS flow control pauses the worker's
  writes until the client drains the buffer via `fetch_job_results`. Chunks are **never** shed or
  reordered (ADR-005 honesty). The per-frame §3 size cap applies to each chunk.
- **Ordering & termination.** Zero or more `$/progress` and `$/chunk` notifications, interleaved in
  emission order, then **exactly one** response: a `result` carrying `{total, truncated, done:true}`
  on success, or an `error` (§5) on failure. The server surfaces a worker mid-stream failure to the
  client as a **terminal error chunk** after the already-buffered chunks — a stream never ends in a
  way indistinguishable from success (ADR-005). The streaming call's deadline (§6) is computed once
  and **not** extended by chunks or progress; on timeout/eviction the buffer is drained to the
  client where already-pulled, then the stream terminates with a terminal error.

**`$/cancel` — additive mid-stream cancel NOTIFICATION (v1.x — ADR-041; server → worker):** to stop
an in-flight `start_decompile_stream` promptly (on client `cancel_job`), the server sends a
`$/cancel` notification on the same socket:
```json
{ "jsonrpc": "2.0", "method": "$/cancel", "params": { "id": "<streaming-call-uuid>" } }
```
- **A notification, not a request — NO top-level `id`** (same structural invariant as `$/progress`/
  `$/chunk`; `params.id` correlates to the in-flight streaming call). It supersedes the former
  `cancel_stream` request method (ADR-041): a notification avoids interleaving a second
  request/response pair onto the streaming socket.
- **The worker observes it BETWEEN functions** via a non-blocking poll of the socket during the
  decompile loop (single-threaded; no reader thread / second socket). It sets the per-stream cancel
  flag the loop already checks, so production stops at the next function boundary (granularity: one
  function — a single `decompileFunction` is not interruptible and is separately bounded).
- **The stream's terminal response is the acknowledgement** — on cancel the worker ends the stream
  early and returns its terminal summary `{total, truncated, done}` with the produced count, exactly
  as on normal completion; there is no separate cancel-ack frame.
- **Idempotent + safe.** A `$/cancel` for an unknown/already-finished stream id is a no-op. Sending
  is best-effort (the §6 deadline + eviction remain the backstop). A malformed/oversized control
  frame, or any non-`$/cancel` frame arriving on the stream socket server→worker, is a protocol
  violation → kill + evict (§6).

### RPC methods (worker-facing; one per Ghidra-touching operation)
`import_binary`, `analyze`, `decompile_function`, `disassemble`, `get_pcode` (ADR-052 low p-code
listing — read-only; lifts each instruction's raw p-code ops, no execution), `get_high_pcode`
(ADR-053 high/SSA p-code — read-only; the decompiler's refined constant-folded IR for a function),
`stack_frame` (ADR-054 recovered stack layout — read-only; the function's locals/parameters with
offsets, types, sizes from the Stack analyzer), `basic_blocks` (ADR-055 control-flow graph —
read-only; each basic block's address range + intraprocedural successor edges from
`BasicBlockModel`), `list_functions`, `get_function`,
`xrefs_to`, `xrefs_from`, `list_strings`, `list_symbols`, `get_symbol`, `list_data`,
`get_data_type`, `list_data_types` (ADR-056 the list-counterpart to `get_data_type` — read-only;
paginated summary rows over the program's DataTypeManager), `get_comments`, `memory_map`, `read_bytes`,
`emulate` (ADR-049 p-code emulation —
bounded, read-effect-only; interpreter, no native exec/syscalls/IO), `demangle` (ADR-050 C++
demangler — read-only, program-independent; GNU/Itanium + MSVC), `search_bytes`, `search_strings`,
`program_metadata`, the v1.1 semantic-naming extraction primitives `call_graph` and
`referenced_strings` (ADR-007), the v1.1 Tier-2 extraction primitives `function_cfg`, `imports`,
`exports`, and `coverage` (ADR-008), the **Function ID library-match primitive**
`identify_functions` (ADR-042 Phase 1 — READ-ONLY; runs the Ghidra FID service over the analyzed
program and returns one row per surviving candidate `{address, matched_name, library, score}`,
filtering below the effective score threshold — `min_score` when supplied, else the FID default —
and bounding to the requested `limit` with a `truncated` flag; the server caps `limit` and wraps the
binary-derived `matched_name`/`library` as untrusted) — all worker-only extraction per ADR-001 —
the v1.1 **mutation
(write) primitives** `rename_function`, `rename_symbol`, `set_comment`, and `undo` (ADR-012 — each
performs a single Ghidra write inside **one transaction**, commit on success / `endTransaction(…,
False)` roll-back + `analysis-failed` on failure; the server gates these behind per-session
write-consent and validates the inputs first), the v1.1 **structural-write primitives**
`rename_local_variable` and `rename_parameter` (ADR-013 Phase A — decompiler HighFunction path,
**name-only**, gated additionally by `allow_structural`; same one-transaction + rollback semantics),
`set_function_signature` and `apply_data_type` (ADR-014 Phase B — **structured** input: each `TypeRef`
is RESOLVED against the program's `DataTypeManager` / a closed base vocab, **never parsed from a C
string**; an unresolvable ref fails closed; same gate + transaction semantics), the v1.8
**bundled type-archive apply** `apply_type_archive` (ADR-051 — applies a CLOSED-allow-list bundled
`.gdt`'s function signatures to same-named functions; the worker resolves the archive name to a path
in the pinned Ghidra install, NEVER a client path — CWE-22; structural, one transaction), the v1.1
**composite-creation primitives** `define_struct` and `define_union` (ADR-015 Phase C — the empty
composite is pre-registered in the DTM at the start of the transaction so self-`named` pointers
resolve; a by-value self-embed is rejected, a name collision is fail-closed rejected, and the
1 MiB size cap + transactional rollback bound the rest; structured `FieldSpec`s, no C parsed), the
v1.2 **multi-type composite batch primitive** `define_types` (ADR-021 — a BATCH of interdependent new
composites created in ONE transaction: the worker pre-registers ALL empty composites in the batch so
an in-batch `named` ref resolves, resolves + adds each, batch-total size-caps, and rolls back the
WHOLE batch on any failure; the server runs a **by-value cycle detector** at the boundary — by-value
cycles rejected, pointer cycles allowed — and name-collision/intra-batch-dup is fail-closed REJECT;
structured `FieldSpec`s, no C parsed), the
v1.4 **composite-deletion primitive** `delete_type` (ADR-031 — `params = {"name": str}`; deletes one
composite by name in ONE transaction with rollback, returning `{"name", "deleted",
"dependents_reverted"}`. The worker resolves the name read-only, rejects a non-composite/built-in
(defense in depth), counts dependents read-only, then `DataTypeManager.remove`s it. **Authority is
server-side:** the server only ever sends a name it has confirmed is **session-authored** (in the
ADR-027 change-log) — the worker neither knows nor enforces that. A not-session-authored name is
rejected by the server with **no `delete_type` RPC at all**; thus an injection can delete at most the
current session's own created types, never a Ghidra-recovered/built-in type), the
v1.2 **annotation-export read-out primitive** `export_annotations` (ADR-018/ADR-027 — read-only;
returns an inert plain document, dependency-ordered + bounded; over the entry cap →
`limit-exceeded`. **Symbols + signatures** are enumerated filtered by `SourceType.USER_DEFINED`
(never auto-analysis). **Comments + composites** carry no reliable Ghidra provenance signal, so the
worker reads ONLY a server-supplied **`targets`** selection — the session change-log of what THIS
session's gated writes authored — instead of blind-enumerating, which over-included Ghidra
auto-analysis content (F7). `params = {"targets": {"comments": [{"address", "comment_type"}],
"composites": [name]}}` — an **additive, server→worker** param: identity keys ONLY (addresses,
slots, composite names), never a binary-derived value; the **client-facing
`session_export_annotations` tool surface is unchanged** (no client-supplied targets, no slug
repurposed). An empty/missing `targets` emits no comments/composites. **ADR-032:** the worker emits
all reconstructable session-authored composites as ONE `define_types` batch entry (schema_version
**2**) so mutually-recursive pointer composites round-trip; >`_MAX_TYPES_PER_BATCH` (64) →
`limit-exceeded`), the v1.x **streaming-extraction primitive** `start_decompile_stream` (ADR-040
Phase 2 — a long call that decompiles a bounded function set, emitting one `$/chunk`
(`kind:"function"`) per function as it is produced, then a terminal response `{total, truncated,
done}`; read-only/output-only per ADR-001; the worker streams incrementally while the server
buffers + applies backpressure; bounded by the existing bulk-decompile total cap; aborted
mid-stream by the `$/cancel` control notification below — ADR-041), plus a `ping`/`shutdown` control
pair.
(`fetch_job_results`, `job_status`, and `cancel_job` are **server-side** job operations against the
server's per-job buffer — they read/drain buffered chunks and job state the server already holds;
they are **not** worker RPC methods. Only `start_decompile_stream` touches the worker to produce;
`$/cancel` (below) is the server→worker control notification that aborts production.)
(Session create/status/close **and the write-consent grant/revoke** `session_enable_writes`/
`session_disable_writes` are **server-side** lifecycle, not worker RPC methods. The derived
tools compute server-side with **no dedicated worker method**: `callees`/`callers`/`analysis_order`/
`function_context` from `call_graph`+`referenced_strings`; the Tier-2 `cyclomatic_complexity` from
`function_cfg`, `ioc_scan` from `list_strings`, `crypto_constant_scan` from `search_bytes`,
`call_graph_metrics` from `call_graph`, and `program_summary` by aggregation — all per ADR-001.
**Annotation import (`session_import_annotations`, ADR-018 TB8) adds NO worker method** — it is
**server-side orchestration** (the registry) that schema-validates + hash-binds + consent-gates the
client document, then **replays each entry through the existing write RPCs above** (each its own
transaction). No `import_annotations` RPC exists; import's blast radius equals the existing gated
writes', no more.)

**`analyze` — additive `profile` param (v1.4 — ADR-029 B; server → worker, OPTIONAL):** the
`analyze` RPC params MAY carry a `profile` string (`"light"` | `"deep"`) selecting an analyzer-depth
preset. **The default (`"default"`) omits the key entirely** — when no/`default` profile is
requested the params are byte-for-byte identical to today's `{ "timeout_seconds": … }`, so the worker
takes the unchanged auto-analysis code path (the default-is-no-op guarantee). `light` disables the
most expensive analyzers (faster / less heap, less depth); `deep` enables a fuller set. **Additive
and worker-only**: no existing field is repurposed, the client-facing `session_analyze` tool surface
gains only the same additive optional field, and the **tool count is unchanged**. The profile only
REDUCES/adjusts analysis depth — it grants no new capability/agency (ADR-001 intact).

**`analyze` — additive `progress` param (v1.4 — ADR-030 Phase 1; server → worker, OPTIONAL):** the
`analyze` RPC params MAY carry a boolean `progress`. **The default (`false`) omits the key
entirely** — when progress is not requested the params are byte-for-byte identical to today's
`{ "timeout_seconds": … }` (plus `profile` only when non-default), the worker emits no `$/progress`
frames, and the server uses the unchanged single-frame read path. When `true` the worker streams the
bounded, redacted `$/progress` notifications described in §4 BEFORE the single response. **Additive,
opt-in, worker-only**: no existing field is repurposed, the client-facing `session_analyze` tool
surface gains only this additive optional field, and the **tool count is unchanged**. The flag adds
no capability/agency — it only emits progress (ADR-001 intact); the analysis deadline is unchanged
(§6).

**`import_binary` — additive loader hints (v1.8 — ADR-045, F1; server → worker, OPTIONAL):** the
`import_binary` RPC params MAY carry `loader` (`"binary"`) with `processor` (a Ghidra `LanguageID`),
`base_addr` (int), and optional `entry` (int). **The default (auto) omits every key** — when no
loader hint is requested the params are byte-for-byte identical to today's `{ "source_ref": …,
"expected_sha256": … }` and the worker takes the unchanged opinion/container-loader path. When
`loader = "binary"` the worker drives `BinaryLoader` with the (server-allow-listed) `processor`,
rebases the raw image to `base_addr`, and optionally seeds `entry` — for **headerless raw/firmware
images**. When `loader` is `"intel-hex"` or `"motorola-hex"` (ADR-046) the worker drives
`IntelHexLoader`/`MotorolaHexLoader` with `processor` only — the hex records carry their own load
addresses, so `base_addr`/`entry` are not sent. When `loader` is `"dex"`, `"macho"`, or `"apk"` (ADR-047) the
worker forces `DexLoader`/`MachoLoader`/`ApkLoader` with no `processor` at all — the self-describing
format supplies the language + layout (`auto` also detects these; the forced value pins the loader).
A fat/universal Mach-O loads its default slice, or the slice named by an optional `processor` on `loader="macho"` (ADR-048, via the `program_loader` builder); DYLD-component selection is deferred (fixture-blocked). The server validates the hint combination + the
`processor` allow-list + address-width bounds **before** the worker (CWE-20); the worker
**re-validates** the language against the installed set and fails closed `not-found` if absent
(defense in depth). **Additive, opt-in, no new capability/agency** — read-only import, no script
execution, tool count unchanged (ADR-001 intact).

## 5. Error model (worker → server)

The worker returns JSON-RPC errors with a `data.type` slug that the server maps to the public
[error envelope](error-envelope.md):

| JSON-RPC `code` | `data.type` | → public `ErrorType` |
|-----------------|-------------|----------------------|
| -32602 | `invalid-params` | `validation-error` |
| -32004 | `not-found` | `not-found` |
| -32008 | `limit-exceeded` | `limit-exceeded` |
| -32010 | `analysis-failed` | `analysis-failed` |
| -32603 | `internal-error` | `internal-error` |

Worker error `message` MUST be safe (no host paths/stack); full detail stays in worker logs. The
server never forwards a worker stack trace to the client.

**Optional `data.detail` (v1.3 — ADR-024 / F2-F3 PR-1; ADDITIVE, worker → server only):** the error
object MAY carry an optional `data.detail` string, **redacted at the worker** to the *exception class
name + a fixed template* (never the raw `str(exc)`, which can echo binary-derived text) and
length-capped. The server logs it (redacted, under the correlation id) to make an otherwise-opaque
`internal-error` diagnosable; it is **never** placed on the client-facing `ErrorEnvelope` (which has
no `data` field and forbids extras). Optional + ignorable; no existing field changes.

## 6. Timeout & kill semantics (TB2/TB3 — DoS)

- Every RPC call carries a **deadline** = the per-tool timeout (or per-analysis timeout for
  `analyze`). The server starts a timer on send.
- On deadline expiry the server **kills the worker** (SIGKILL the container/process), closes the
  socket, marks the session for eviction, and returns a `timeout` error envelope. There is **no
  "graceful" wait** for a hostile/hung JVM.
- A worker that crashes/closes the socket mid-call → `worker-unavailable` + eviction.
- **Worker-death classification (v1.3 — ADR-023 / F1):** on a transport failure (crash/closed
  socket), before killing, the server queries the container engine's METADATA (`OOMKilled` flag /
  exit 137 — NO binary parsing, ADR-001) to classify the death. An OOM-killed worker (it blew its
  configured memory cap on a hostile input) is surfaced as the distinct, ADDITIVE
  `resource-exhausted` (503, **not retryable** — see `error-envelope.md`); every other transport
  failure stays `worker-unavailable`. The classification fails closed to `worker-unavailable` if
  the engine query errors. No existing slug is repurposed.
- Kill is the universal failure handler: timeout, protocol violation, oversized frame, OOM, or
  poisoning all resolve to **kill + evict** (ADR-002). Eviction then verified-wipes the store.
- **`$/progress` does NOT extend the deadline (v1.4 — ADR-030 Phase 1):** for an opted-in `analyze`,
  the one-shot per-analysis deadline is computed once at call start and bounds the whole
  progress-read loop; arriving `$/progress` frames never reset or push it. A worker that streams
  progress forever (or hangs after some progress) still hits the un-extended deadline → SIGKILL +
  evict, and a `$/progress` flood beyond the per-call cap is itself a protocol violation → kill +
  evict. The kill-on-timeout bound (above) is unchanged by the progress increment.

## 7. Security properties (summary)

- No network; UDS file-perm scoped; per-session socket (no cross-session reachability).
- Strict schema validation both directions; bounded frame size; bounded time (kill on expiry).
- Worker output treated as **untrusted** by the server (wrapped per ADR-005); no worker-supplied
  path/code is executed or trusted.

## 8. Sign-off

- **RATIFIED (PM, 2026-06-03):** JSON-RPC-2.0-over-UDS is the chosen mechanism (PLAN §9). gRPC
  deferred to a possible v1.1 revisit if streaming/perf demands it. This contract is **frozen**;
  WS1/WS2 fork against it.
- Concrete socket-permission and container-mount wiring is WS3 (deploy); the **protocol** above is
  frozen.
