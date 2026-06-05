#!/usr/bin/env bash
# =============================================================================
# deploy/worker-run.sh — reference rootless-podman invocation for ONE Ghidra worker
# =============================================================================
# Realizes ADR-004 (isolation tier) as code. This is the EXACT, auditable runtime spec the server's
# RPC adapter (src/ghidra_mcp/ghidra/rpc_client.py, WS2) translates into its container-spawn call,
# and the reference a maintainer/operator runs by hand for a smoke test.
#
# ONE WORKER PER SESSION (ADR-002): the server spawns one of these per session and KILLS it on
# eviction/timeout/poison, then verified-wipes the per-session store.
#
# >>> GATED (PLAN §6): this script is NOT executed by WS3. Running it binds a host path (the UDS
# >>> dir) into the worker and pulls/uses the worker image — both are reviewed, human-approved
# >>> actions. It is provided as the runtime contract + a documented manual smoke-test command. <<<
#
# Rules: topic-container-k8s (CIS hardening), std-cis, topic-reliability (resource bounds),
#        topic-resource-management (lifecycle), ADR-004.
set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Inputs (the server supplies these per session; defaults mirror security/limits.py + .env.example).
# -----------------------------------------------------------------------------
SESSION_ID="${1:?usage: worker-run.sh <session_id> [binary_path]}"   # opaque, high-entropy (BOLA).
BINARY_PATH="${2:-}"                                                  # host path to the binary (optional at start).

# Pinned BY DIGEST (ADR-003). GATED ITEM W-IMG: a maintainer pins the real digest; placeholder
# mirrors .env.example's GHIDRA_MCP_WORKER_IMAGE convention.
WORKER_IMAGE="${GHIDRA_MCP_WORKER_IMAGE:-ghcr.io/OWNER/ghidra-mcp-worker@sha256:REPLACE_WITH_PINNED_DIGEST}"

# gVisor by default (ADR-004); falls back to the rootless OCI baseline only where runsc is absent.
WORKER_RUNTIME="${GHIDRA_MCP_WORKER_RUNTIME:-runsc}"

# Per-session UDS directory on the host (server-owned, private 0700 — see deploy/socket-dir.md).
RPC_SOCKET_DIR="${GHIDRA_MCP_RPC_SOCKET_DIR:-/run/ghidra-mcp}"

# Resource bounds — MIRROR src/ghidra_mcp/security/limits.py defaults + .env.example (F7 DoS).
MEM_LIMIT="${GHIDRA_MCP_WORKER_MEM:-4g}"          # hard memory ceiling (OOM-kills the worker → evict).
CPU_LIMIT="${GHIDRA_MCP_WORKER_CPUS:-2}"          # CPU quota.
PIDS_LIMIT="${GHIDRA_MCP_WORKER_PIDS:-512}"       # cap process/thread explosion (fork-bomb defense).
ANALYSIS_TIMEOUT_S="${GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS:-600}"
TMPFS_SCRATCH_SIZE="${GHIDRA_MCP_WORKER_TMPFS:-2g}"    # JVM/tmp scratch (tmpfs, noexec, nosuid).
PROJECT_STORE_SIZE="${GHIDRA_MCP_WORKER_PROJECT_TMPFS:-4g}"  # per-session Ghidra project store (tmpfs).

# Deterministic per-session container name → the server can target kill/inspect (ADR-002 lifecycle).
CONTAINER_NAME="ghidra-mcp-worker-${SESSION_ID}"

# Stricter seccomp profile is OPT-IN after validation (infra/seccomp/README.md); default RuntimeDefault.
SECCOMP_PROFILE="${GHIDRA_MCP_WORKER_SECCOMP:-RuntimeDefault}"

# -----------------------------------------------------------------------------
# The hardened run command (ADR-004). Each flag annotated with the control it realizes.
# -----------------------------------------------------------------------------
# NOTE: rootless podman is assumed (no host root). The UDS dir is bind-mounted read-write so the
# worker can create/serve ITS OWN session socket; everything else is read-only.
exec podman run \
  --name "${CONTAINER_NAME}" \
  --rm \
  `# --- gVisor user-space kernel boundary around the hostile JVM (ADR-004 strong tier) ---` \
  --runtime "${WORKER_RUNTIME}" \
  `# --- NO NETWORK / NO EGRESS: the worker never needs the network; removes exfiltration path ---` \
  --network none \
  `# --- non-root (image USER is 65532; assert here too; rootless maps to an unprivileged host uid) ---` \
  --user 65532:65532 \
  --userns keep-id \
  `# --- drop ALL Linux capabilities; add back NONE (a headless analyzer needs none) ---` \
  --cap-drop ALL \
  `# --- no privilege escalation via setuid binaries etc. ---` \
  --security-opt no-new-privileges \
  `# --- seccomp RuntimeDefault (verified to load by deploy/verify-isolation.sh) ---` \
  --security-opt "seccomp=${SECCOMP_PROFILE}" \
  `# --- read-only root filesystem: the entire image FS is immutable at runtime ---` \
  --read-only \
  `# --- writable scratch ONLY via tmpfs (noexec,nosuid,nodev): JVM /tmp + Ghidra temp ---` \
  --tmpfs /tmp/ghidra:rw,noexec,nosuid,nodev,size="${TMPFS_SCRATCH_SIZE}" \
  `# --- per-session project store on tmpfs: NEVER persisted to disk; vanishes on kill (ADR-002) ---` \
  --tmpfs /work/project:rw,noexec,nosuid,nodev,size="${PROJECT_STORE_SIZE}" \
  `# --- resource limits (DoS bounds F7); OOM kills the worker → server evicts ---` \
  --memory "${MEM_LIMIT}" \
  --memory-swap "${MEM_LIMIT}" \
  --cpus "${CPU_LIMIT}" \
  --pids-limit "${PIDS_LIMIT}" \
  --oom-kill-disable=false \
  `# --- per-session UDS dir: server-owned, private; the ONLY shared surface (rpc-protocol.md §2) ---` \
  --volume "${RPC_SOCKET_DIR}/${SESSION_ID}:/run/ghidra-mcp:rw,Z" \
  `# --- the binary (if provided): READ-ONLY mount; the worker can never modify host input ---` \
  ${BINARY_PATH:+--volume "${BINARY_PATH}:/work/input.bin:ro,Z"} \
  `# --- pass resolved bounds into the worker (defense in depth; worker enforces its own too) ---` \
  --env "GHIDRA_MCP_SESSION_ID=${SESSION_ID}" \
  --env "GHIDRA_MCP_RPC_SOCKET_DIR=/run/ghidra-mcp" \
  --env "GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS=${ANALYSIS_TIMEOUT_S}" \
  `# --- no host env leakage; an explicit, minimal allow-list only (the --env lines above) ---` \
  --env-host=false \
  "${WORKER_IMAGE}"
# COORDINATION ITEM (WS2): if the WS2 entrypoint takes the session id / socket path as ARGS rather
# than env, append them after the image, e.g.:  "${WORKER_IMAGE}" --session "${SESSION_ID}"
