#!/usr/bin/env bash
# =============================================================================
# deploy/worker-run.sh — reference rootless-podman invocation for ONE Ghidra worker
# =============================================================================
# Realizes ADR-004 (isolation tier) as code. This is the EXACT, auditable runtime spec the server's
# RPC adapter (src/vivarium/ghidra/rpc_client.py, WS2) translates into its container-spawn call,
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
# mirrors .env.example's VIVARIUM_WORKER_IMAGE convention.
WORKER_IMAGE="${VIVARIUM_WORKER_IMAGE:-ghcr.io/0xb007ab1e/vivarium-worker@sha256:921cd0ec9b2fbf2456b405acdd0ab8c4458c1cd4424d55f7d3d4539300f2c3c7}"

# gVisor by default (ADR-004); falls back to the rootless OCI baseline only where runsc is absent.
WORKER_RUNTIME="${VIVARIUM_WORKER_RUNTIME:-runsc}"

# Per-session UDS directory on the host (server-owned, private 0700 — see deploy/socket-dir.md).
RPC_SOCKET_DIR="${VIVARIUM_RPC_SOCKET_DIR:-/run/vivarium}"

# Resource bounds — MIRROR src/vivarium/security/limits.py defaults + .env.example (F7 DoS).
MEM_LIMIT="${VIVARIUM_WORKER_MEM:-4g}"          # hard memory ceiling (OOM-kills the worker → evict).
CPU_LIMIT="${VIVARIUM_WORKER_CPUS:-2}"          # CPU quota.
PIDS_LIMIT="${VIVARIUM_WORKER_PIDS:-512}"       # cap process/thread explosion (fork-bomb defense).
ANALYSIS_TIMEOUT_S="${VIVARIUM_ANALYSIS_TIMEOUT_SECONDS:-600}"
TMPFS_SCRATCH_SIZE="${VIVARIUM_WORKER_TMPFS:-2g}"    # JVM/tmp scratch (tmpfs, noexec, nosuid).
PROJECT_STORE_SIZE="${VIVARIUM_WORKER_PROJECT_TMPFS:-4g}"  # per-session Ghidra project store (tmpfs).

# Deterministic per-session container name → the server can target kill/inspect (ADR-002 lifecycle).
CONTAINER_NAME="vivarium-worker-${SESSION_ID}"

# Stricter seccomp profile is OPT-IN after validation (infra/seccomp/README.md); default RuntimeDefault.
SECCOMP_PROFILE="${VIVARIUM_WORKER_SECCOMP:-RuntimeDefault}"

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
  `# --- writable scratch ONLY via tmpfs (noexec,nosuid,nodev). mode=1777: a fresh tmpfs is ---` \
  `# --- root-owned, but the worker runs as uid 65532 under the read-only rootfs; 1777 (the /tmp ---` \
  `# --- model) lets the non-root worker write its user.home + java.io.tmpdir + project store. ---` \
  `# --- Without it Ghidra LaunchSupport -save fails ("user home directory does not exist") and ---` \
  `# --- the JVM never boots — caught by the real-worker integration test (tests/integration). ---` \
  --tmpfs /tmp/ghidra:rw,noexec,nosuid,nodev,mode=1777,size="${TMPFS_SCRATCH_SIZE}" \
  `# --- per-session project store on tmpfs: NEVER persisted to disk; vanishes on kill (ADR-002) ---` \
  --tmpfs /work/project:rw,noexec,nosuid,nodev,mode=1777,size="${PROJECT_STORE_SIZE}" \
  `# --- resource limits (DoS bounds F7); OOM kills the worker → server evicts ---` \
  --memory "${MEM_LIMIT}" \
  --memory-swap "${MEM_LIMIT}" \
  --cpus "${CPU_LIMIT}" \
  --pids-limit "${PIDS_LIMIT}" \
  --oom-kill-disable=false \
  `# --- per-session UDS dir: server-owned, private; the ONLY shared surface (rpc-protocol.md §2) ---` \
  --volume "${RPC_SOCKET_DIR}/${SESSION_ID}:/run/vivarium:rw,Z" \
  `# --- the binary (if provided): READ-ONLY mount; the worker can never modify host input ---` \
  ${BINARY_PATH:+--volume "${BINARY_PATH}:/work/input.bin:ro,Z"} \
  `# --- pass resolved bounds into the worker (defense in depth; worker enforces its own too) ---` \
  --env "VIVARIUM_SESSION_ID=${SESSION_ID}" \
  --env "VIVARIUM_RPC_SOCKET_DIR=/run/vivarium" \
  --env "VIVARIUM_ANALYSIS_TIMEOUT_SECONDS=${ANALYSIS_TIMEOUT_S}" \
  `# --- no host env leakage; an explicit, minimal allow-list only (the --env lines above) ---` \
  --env-host=false \
  "${WORKER_IMAGE}"
# ENTRYPOINT CONTRACT (WS3, RECONCILED): the worker image ENTRYPOINT is `python -m worker`
# (worker/__main__.py). It is ENV-ONLY — it takes NO positional args. It reads:
#   * VIVARIUM_SESSION_ID      (required; passed above) — names the per-session UDS <sid>.sock,
#   * VIVARIUM_RPC_SOCKET_DIR  (=/run/vivarium above) — the bind-mounted private socket dir,
# derives VIVARIUM_RPC_SOCKET=<dir>/<sid>.sock, then runs worker_main() (rpc-protocol.md §2).
# Inside the container the socket therefore lands at /run/vivarium/<SESSION_ID>.sock; the host
# side of that path is "${RPC_SOCKET_DIR}/${SESSION_ID}/<SESSION_ID>.sock" via the volume above —
# the server's RPC client connects to the host path, the worker binds the in-container path.
# A missing VIVARIUM_SESSION_ID makes the launcher exit non-zero BEFORE the JVM starts → the
# server observes worker-unavailable and evicts (fail closed). Do NOT append args after the image.
