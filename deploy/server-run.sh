#!/usr/bin/env bash
# =============================================================================
# deploy/server-run.sh — reference rootless-podman invocation for the MCP server (control plane)
# =============================================================================
# The TRUSTED control plane (ADR-001: no JVM, no binary parsing). stdio transport in v1 → NO PORTS.
# It is also hardened (defense in depth): the server is small and auditable, but a control-plane
# compromise is the worst case, so it too runs non-root / ro-rootfs / caps-dropped / seccomp.
#
# Unlike the worker, the server must (a) speak MCP over stdio to its client, and (b) spawn workers
# via the container runtime. Both are deliberate, reviewed couplings handled here.
#
# >>> GATED (PLAN §6): NOT executed by WS3. Running it mounts the container-runtime socket (so the
# >>> server can spawn workers) + the shared UDS dir, and uses the server image — reviewed actions.
# >>> Provided as the runtime contract + documented manual command. <<<
#
# Rules: topic-container-k8s, std-cis, ADR-001/002/004, rpc-protocol.md.
set -euo pipefail
IFS=$'\n\t'

SERVER_IMAGE="${GHIDRA_MCP_SERVER_IMAGE:-ghcr.io/OWNER/ghidra-mcp-server@sha256:REPLACE_WITH_PINNED_DIGEST}"

# Shared UDS dir (host) — server OWNS it (0700); workers get only their own per-session subdir
# bind-mounted in (see deploy/worker-run.sh + deploy/socket-dir.md).
RPC_SOCKET_DIR="${GHIDRA_MCP_RPC_SOCKET_DIR:-/run/ghidra-mcp}"

# Path to the rootless podman API socket the server uses to spawn/kill workers. This is the ONE
# privileged-ish coupling — scope it tightly (see SECURITY NOTE below). Rootless podman exposes a
# user-scoped socket (no host root).
PODMAN_SOCK="${GHIDRA_MCP_PODMAN_SOCK:-/run/user/$(id -u)/podman/podman.sock}"

# stdio MCP: the server talks to its client over stdin/stdout. Run with -i (interactive stdio),
# NO -t (no TTY needed), and the client wires the pipes. NO -p / --publish — there are no ports.
exec podman run \
  --rm \
  --interactive \
  `# --- non-root control plane ---` \
  --user 65532:65532 \
  --userns keep-id \
  `# --- drop all caps; the server needs none ---` \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt seccomp=RuntimeDefault \
  `# --- read-only rootfs; writable scratch via tmpfs only ---` \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  `# --- the server creates per-session sockets here; shared (read-write) with the workers it spawns ---` \
  --volume "${RPC_SOCKET_DIR}:/run/ghidra-mcp:rw,Z" \
  `# --- SECURITY NOTE: mounting the runtime socket grants worker-spawn ability. It is the server's ` \
  `#     one elevated coupling. Mitigations: rootless podman (no host root), the socket is the ` \
  `#     server user's own, and the server only ever spawns the pinned worker image with the ` \
  `#     deploy/worker-run.sh spec. A future increment SHOULD move spawning behind a thin, ` \
  `#     least-privilege "worker-broker" sidecar that only accepts "spawn pinned-image with fixed ` \
  `#     hardened spec" requests, never raw runtime API — tracked as a hardening follow-up. ---` \
  --volume "${PODMAN_SOCK}:/run/podman/podman.sock:rw,Z" \
  --env "GHIDRA_MCP_RPC_SOCKET_DIR=/run/ghidra-mcp" \
  --env "GHIDRA_MCP_LOG_FORMAT=${GHIDRA_MCP_LOG_FORMAT:-json}" \
  --env "GHIDRA_MCP_LOG_LEVEL=${GHIDRA_MCP_LOG_LEVEL:-INFO}" \
  --env "GHIDRA_MCP_WORKER_IMAGE=${GHIDRA_MCP_WORKER_IMAGE:-ghcr.io/OWNER/ghidra-mcp-worker@sha256:REPLACE_WITH_PINNED_DIGEST}" \
  --env "GHIDRA_MCP_WORKER_RUNTIME=${GHIDRA_MCP_WORKER_RUNTIME:-runsc}" \
  --env "GHIDRA_MCP_MAX_SESSIONS=${GHIDRA_MCP_MAX_SESSIONS:-4}" \
  --env "GHIDRA_MCP_SESSION_TTL_SECONDS=${GHIDRA_MCP_SESSION_TTL_SECONDS:-3600}" \
  --env "GHIDRA_MCP_SESSION_IDLE_SECONDS=${GHIDRA_MCP_SESSION_IDLE_SECONDS:-900}" \
  --env "GHIDRA_MCP_MAX_BINARY_BYTES=${GHIDRA_MCP_MAX_BINARY_BYTES:-134217728}" \
  --env "GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS=${GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS:-600}" \
  --env "GHIDRA_MCP_TOOL_TIMEOUT_SECONDS=${GHIDRA_MCP_TOOL_TIMEOUT_SECONDS:-60}" \
  --env "GHIDRA_MCP_MAX_RESPONSE_BYTES=${GHIDRA_MCP_MAX_RESPONSE_BYTES:-4194304}" \
  "${SERVER_IMAGE}"
