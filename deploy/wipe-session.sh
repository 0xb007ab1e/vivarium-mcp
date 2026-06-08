#!/usr/bin/env bash
# =============================================================================
# deploy/wipe-session.sh — kill worker + VERIFIED wipe of the per-session store (ADR-002)
# =============================================================================
# Reference helper the session manager (WS2) drives on eviction (TTL / idle / explicit close /
# poison / shutdown). Realizes ADR-002's kill-then-verified-wipe contract:
#   1. kill the session's worker container (SIGKILL — no graceful wait for a hostile/hung JVM),
#   2. remove the per-session socket dir + project store,
#   3. VERIFY both are gone; print store_wiped:true|false. Idempotent.
#
# Because the per-session project store is a **tmpfs inside the worker** (deploy/worker-run.sh),
# killing the container ALREADY discards the store (tmpfs is destroyed with the container). This
# helper additionally wipes the host-side per-session socket dir and asserts removal. If a future
# config moves the store to a host volume, the volume-removal branch below covers it.
#
# >>> GATED (PLAN §6): NOT executed by WS3 (it kills containers / removes paths on a real host).
# >>> Provided as the eviction contract + the command the evict-poisoned-worker runbook references. <<<
#
# Usage: wipe-session.sh <session_id>
# Rules: ADR-002, topic-resource-management (verified wipe), workflow-incident-response.
set -euo pipefail
IFS=$'\n\t'

SESSION_ID="${1:?usage: wipe-session.sh <session_id>}"
RPC_SOCKET_DIR="${GHIDRA_MCP_RPC_SOCKET_DIR:-/run/ghidra-mcp}"
CONTAINER_NAME="ghidra-mcp-worker-${SESSION_ID}"
SESSION_SOCK_DIR="${RPC_SOCKET_DIR}/${SESSION_ID}"
# Optional host-side project store (only if a deployment opts out of tmpfs-only stores).
SESSION_STORE_DIR="${GHIDRA_MCP_PROJECT_STORE_DIR:-}/${SESSION_ID}"

store_wiped=true

# 1. Kill the worker (SIGKILL). Idempotent: ignore "no such container".
echo "evicting session ${SESSION_ID}: killing worker ${CONTAINER_NAME}"
podman kill --signal SIGKILL "${CONTAINER_NAME}" 2>/dev/null || true
podman rm --force "${CONTAINER_NAME}" 2>/dev/null || true
# Killing the container destroys its tmpfs project store (the common case).

# 2. Remove the host-side per-session socket dir (and the named volume / store dir if used).
rm -rf -- "${SESSION_SOCK_DIR}" 2>/dev/null || true
if [ -n "${GHIDRA_MCP_PROJECT_STORE_DIR:-}" ]; then
  rm -rf -- "${SESSION_STORE_DIR}" 2>/dev/null || true
fi
# If a per-session named podman volume is used instead, remove it too (idempotent).
podman volume rm --force "ghidra-mcp-store-${SESSION_ID}" 2>/dev/null || true

# 3. VERIFY removal (the load-bearing step — an unverified wipe is not a wipe).
if [ -e "${SESSION_SOCK_DIR}" ]; then
  echo "WIPE FAILURE: socket dir still present: ${SESSION_SOCK_DIR}" >&2
  store_wiped=false
fi
if [ -n "${GHIDRA_MCP_PROJECT_STORE_DIR:-}" ] && [ -e "${SESSION_STORE_DIR}" ]; then
  echo "WIPE FAILURE: project store still present: ${SESSION_STORE_DIR}" >&2
  store_wiped=false
fi
if podman container exists "${CONTAINER_NAME}" 2>/dev/null; then
  echo "WIPE FAILURE: worker container still present: ${CONTAINER_NAME}" >&2
  store_wiped=false
fi

# 4. Report (the session manager logs this; store_wiped:false is a CONFIDENTIALITY INCIDENT → alert).
echo "{\"event\":\"session_evicted\",\"session_id\":\"${SESSION_ID}\",\"store_wiped\":${store_wiped}}"
if [ "${store_wiped}" != "true" ]; then
  exit 1   # fail closed → caller alerts (ADR-002) and runs evict-poisoned-worker / incident-response.
fi
