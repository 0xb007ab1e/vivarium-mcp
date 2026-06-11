# ADR-009 — Concrete worker launcher, import-root mount, per-session socket subdir

- **Status:** Accepted (2026-06-10)
- **Context:** WS2/WS3 seam. Surfaced by the ground-truth e2e (`tests/e2e/test_groundtruth_oss.py`),
  the first thing to drive the *real* `server → worker` chain end-to-end.

## Context

The server's composition root (`__main__.py:_default_port_factory`) was a placeholder
(`RpcGhidraAdapter()` with no args), and there was **no concrete `WorkerLauncher`** — only the
abstract type alias plus the audited `deploy/worker-run.sh` recipe. So the real MCP server could
not start with the real adapter, and no worker could be spawned. This was invisible to the unit
suite (which injects a fake `WorkerProcess`) and to `tests/integration/test_worker_analysis.py`
(which drives `PyGhidraBackend` *directly inside a hand-run container*, bypassing the server +
launcher). Reading the contracts to build the launcher also exposed two inconsistencies:

1. **Binary delivery.** `import_binary` sends the **`source_ref` string** over RPC (not bytes); the
   worker opens it. So the input must be reachable *inside* the container — but the launcher
   signature `(session_id, socket_path)` carries no binary, and `start_worker` precedes
   `import_binary`. There was no mechanism to make the binary available to the worker.
2. **Socket path.** The adapter computed a flat `<dir>/<sid>.sock`, while `worker-run.sh` used a
   per-session subdir mounted to `/run/ghidra-mcp`. To isolate sockets per session (so a hostile
   worker can't reach siblings) the launcher must mount only that session's dir — which requires
   the adapter's path to live in a per-session subdir too.

## Decision

- **Concrete launcher** `ghidra_mcp.ghidra.launcher.ContainerWorkerLauncher` implements
  `WorkerLauncher` by translating `deploy/worker-run.sh` (ADR-004) into a `podman run` **argv**
  (never `shell=True`): `--network none`, `--read-only`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`/`seccomp`, `--user 65532`, tmpfs scratch + project store,
  `--memory/--cpus/--pids-limit`, gVisor `--runtime`. Returns a `ContainerWorkerProcess`
  (`kill()` → `rm -f`; `is_alive()` → `inspect`). The subprocess runner is injected (unit-tested
  argv + lifecycle with no engine); a non-zero spawn raises `WorkerLaunchError` (fail closed).
- **Import-root mount.** A confined host dir (`GHIDRA_MCP_IMPORT_ROOT`, `Config.import_root`) is
  bind-mounted **read-only at the same path** into every worker; `source_ref` is a path under it
  (so the worker opens it directly). `make_confined_resolver` enforces the input resolves strictly
  under the root (CWE-22) and returns its size for the pre-Ghidra cap — **before** the worker is
  contacted (ADR-001/F7 preserved). A hostile worker gets the input **read-only** and nothing else.
- **Per-session socket subdir.** `<dir>/<token>/<sid>.sock` (adapter `_socket_path` + rpc-protocol §2
  reconciled, PM-routed). The launcher creates the `0700` per-session dir and mounts **only it** to
  the in-container `/run/ghidra-mcp` → a worker sees only its own socket. `<token>` is a SHORT prefix
  of the session id (first 16 chars), **not** the full id: `AF_UNIX` paths are capped (~107 bytes on
  Linux) and the 43-char (256-bit) id already appears in the `<sid>.sock` filename — using it for the
  directory too overflowed the limit (the default `/run/ghidra-mcp` reached 108 → `AF_UNIX path too
  long`, surfaced by the gated e2e on GitHub runners and latent in prod). The token stays unique for
  the small live-session set; the full id remains the filename + the server-side identity, so
  isolation/BOLA are unchanged.
- **Composition root** wires the launcher + confined resolver + timeouts/caps from `Config`.

## Consequences

- The full `server → launch hardened worker → RPC → analyze → return` chain is now wired; the
  gated `e2e-groundtruth` run validates it against real OSS ground truth (cJSON/zlib/lua).
- `rpc-protocol.md §2` changed (frozen WS0 contract) — recorded here; the worker still binds
  `/run/ghidra-mcp/<sid>.sock` in-container, only the host layout gained the subdir.
- The launcher's real-engine path is validated only by the gated e2e/integration runs (the unit
  tests cover argv construction, lifecycle, fail-closed, and the resolver hermetically).

## Related

ADR-001 (out-of-process), ADR-002 (one worker/session, kill + verified wipe), ADR-003 (pinned
image), ADR-004 (isolation tier / `deploy/worker-run.sh`); `rpc-protocol.md`; `workflow-threat-model`.
