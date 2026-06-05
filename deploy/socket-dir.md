# Per-session UDS wiring — server ↔ worker RPC socket layout (deploy)

Concretizes the socket-permission + container-mount wiring that `docs/contracts/rpc-protocol.md`
§2 explicitly hands to WS3 ("Concrete socket-permission and container-mount wiring is WS3"). The
**protocol** is frozen; this is the **runtime realization**.

## Layout

```
${GHIDRA_MCP_RPC_SOCKET_DIR}            default /run/ghidra-mcp
   owner = server user (65532:65532), mode 0700  (private; not world-readable)
   │
   ├── <session_id_A>/                  per-session subdir, 0700, server-owned
   │      └── <session_id_A>.sock       the UDS, 0600, server-owned
   ├── <session_id_B>/
   │      └── <session_id_B>.sock
   ...
```

- The top dir is created/owned by the **server** (the `Containerfile.server` creates it 0700; or
  `deploy/server-run.sh` mounts a tmpfs there).
- The server creates a **per-session subdirectory** (0700) and the worker's socket lives inside it
  at `0600`, owner = server user (rpc-protocol.md §2). The session id is opaque/high-entropy (BOLA
  defense — a client cannot guess another session's socket path, and even if it did, the file perms
  + the no-network worker make it unreachable).
- **Only that one subdir** is bind-mounted into the corresponding worker
  (`--volume ${RPC_SOCKET_DIR}/<session_id>:/run/ghidra-mcp` in `deploy/worker-run.sh`). A worker
  therefore sees **only its own** session socket directory — never any other session's. This is the
  cross-session isolation boundary at the filesystem layer (defense in depth with ADR-002's
  one-worker-per-session).

## Connection model

Either party may own the listen end; the frozen contract allows both. Recommended:
**the worker listens, the server connects** — so the server (sole client) initiates, and a worker
that dies simply makes the socket unconnectable (→ `worker-unavailable` → evict). If WS2 chooses
**server-listens / worker-connects**, the same per-session subdir mount applies unchanged.

> COORDINATION ITEM (WS2): confirm listen/connect direction. The mount + perms above work for
> either; the socket *path* is fixed by the contract (`<session_id>.sock` under the mounted dir).

## Permissions rationale (least privilege, fail-closed)

| Path | Mode | Owner | Why |
|------|------|-------|-----|
| `${RPC_SOCKET_DIR}` | `0700` | server | private root; no other user can enumerate sessions |
| `${RPC_SOCKET_DIR}/<sid>` | `0700` | server | per-session; only this worker's mount sees it |
| `.../<sid>.sock` | `0600` | server | only server (and the mapped worker uid) can open the UDS |

Rootless podman with `--userns keep-id` maps the worker's in-container uid `65532` to the server
user's uid on the host, so the bind-mounted socket dir is owned consistently across the boundary.

## Cleanup (ADR-002 — part of the verified wipe)

On eviction the session manager (WS2) kills the worker, then **removes the per-session subdir**
(socket + any residue) and the project store, and **verifies** they no longer exist
(`store_wiped: true`). `deploy/wipe-session.sh` is the reference helper. A wipe failure
(`store_wiped: false`) is a **confidentiality incident** (ADR-002) → alert + `evict-poisoned-worker`
runbook.
