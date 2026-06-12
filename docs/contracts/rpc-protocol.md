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
  `${GHIDRA_MCP_RPC_SOCKET_DIR}/<token>/<session_id>.sock` (default dir `/run/ghidra-mcp`), where
  `<token>` is a SHORT prefix of the session id (first 16 chars). The per-session dir is created
  `0700` (owner = server user) and is the **only** thing bind-mounted into that worker (mounted at
  the in-container `/run/ghidra-mcp`), so a worker can reach **only its own** socket — sibling
  sessions' sockets are not present in its mount namespace (ADR-009). The session id is
  opaque/high-entropy (BOLA defense). *(Reconciled 2026-06-10: the path gained the per-session
  subdir so the WS3 launcher mount could isolate sockets per session; the subdir uses a short id
  prefix — not the full id — because the full 43-char id in BOTH the dir and the `<sid>.sock`
  filename overflows the `AF_UNIX` ~107-byte path limit at realistic socket dirs (the default
  `/run/ghidra-mcp` reached 108). PM-routed contract update.)*
- Inside the container the worker still binds `/run/ghidra-mcp/<session_id>.sock`; the host side of
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

### RPC methods (worker-facing; one per Ghidra-touching operation)
`import_binary`, `analyze`, `decompile_function`, `disassemble`, `list_functions`, `get_function`,
`xrefs_to`, `xrefs_from`, `list_strings`, `list_symbols`, `get_symbol`, `list_data`,
`get_data_type`, `get_comments`, `memory_map`, `read_bytes`, `search_bytes`, `search_strings`,
`program_metadata`, the v1.1 semantic-naming extraction primitives `call_graph` and
`referenced_strings` (ADR-007), the v1.1 Tier-2 extraction primitives `function_cfg`, `imports`,
`exports`, and `coverage` (ADR-008) — all worker-only extraction per ADR-001 — the v1.1 **mutation
(write) primitives** `rename_function`, `rename_symbol`, `set_comment`, and `undo` (ADR-012 — each
performs a single Ghidra write inside **one transaction**, commit on success / `endTransaction(…,
False)` roll-back + `analysis-failed` on failure; the server gates these behind per-session
write-consent and validates the inputs first), plus a `ping`/`shutdown` control pair.
(Session create/status/close **and the write-consent grant/revoke** `session_enable_writes`/
`session_disable_writes` are **server-side** lifecycle, not worker RPC methods. The derived
tools compute server-side with **no dedicated worker method**: `callees`/`callers`/`analysis_order`/
`function_context` from `call_graph`+`referenced_strings`; the Tier-2 `cyclomatic_complexity` from
`function_cfg`, `ioc_scan` from `list_strings`, `crypto_constant_scan` from `search_bytes`,
`call_graph_metrics` from `call_graph`, and `program_summary` by aggregation — all per ADR-001.)

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

## 6. Timeout & kill semantics (TB2/TB3 — DoS)

- Every RPC call carries a **deadline** = the per-tool timeout (or per-analysis timeout for
  `analyze`). The server starts a timer on send.
- On deadline expiry the server **kills the worker** (SIGKILL the container/process), closes the
  socket, marks the session for eviction, and returns a `timeout` error envelope. There is **no
  "graceful" wait** for a hostile/hung JVM.
- A worker that crashes/closes the socket mid-call → `worker-unavailable` + eviction.
- Kill is the universal failure handler: timeout, protocol violation, oversized frame, or
  poisoning all resolve to **kill + evict** (ADR-002). Eviction then verified-wipes the store.

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
