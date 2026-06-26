#!/usr/bin/env bash
# =============================================================================
# deploy/verify-isolation.sh — ADR-004 acceptance criteria, VERIFIED (not assumed)
# =============================================================================
# ADR-004 requires WS3 to VERIFY each isolation control actually applies at runtime. This script is
# that verification harness. It spawns a worker container with the deploy/worker-run.sh spec and
# asserts, from INSIDE the worker, that every control is in force. Any failed assertion exits
# non-zero (fail closed) — an unverified control is treated as MISSING.
#
# >>> GATED (PLAN §6): NOT executed by WS3 (it runs a container + uses the worker image). Run by a
# >>> maintainer after the worker image digest is pinned + approved. This is the game-day / drill
# >>> harness referenced by ADR-004 and the runbooks. <<<
#
# Usage (after approval):  deploy/verify-isolation.sh
# Rules: ADR-004, topic-container-k8s, std-cis, topic-reliability.
set -euo pipefail
IFS=$'\n\t'

WORKER_IMAGE="${VIVARIUM_WORKER_IMAGE:?set VIVARIUM_WORKER_IMAGE to the pinned @sha256 digest}"
WORKER_RUNTIME="${VIVARIUM_WORKER_RUNTIME:-runsc}"
SECCOMP_PROFILE="${VIVARIUM_WORKER_SECCOMP:-RuntimeDefault}"

# "RuntimeDefault" = the engine's built-in seccomp profile, applied by OMITTING the flag. Passing
# the literal string makes podman/runsc try to open a profile FILE named "RuntimeDefault" and fail
# ("opening seccomp profile failed: ... no such file or directory") — the same gotcha
# ContainerWorkerLauncher avoids by dropping the flag. Only pass --security-opt for a real profile.
SECCOMP_OPT=()
if [ "${SECCOMP_PROFILE}" != "RuntimeDefault" ]; then
  SECCOMP_OPT=(--security-opt "seccomp=${SECCOMP_PROFILE}")
fi

fail() { echo "ISOLATION CHECK FAILED: $*" >&2; exit 1; }
pass() { echo "  [PASS] $*"; }

# Helper: run a probe command inside a worker with the FULL hardened spec, capture output.
# We override the entrypoint to a probe; everything else matches deploy/worker-run.sh.
probe() {
  podman run --rm \
    --runtime "${WORKER_RUNTIME}" \
    --network none \
    --user 65532:65532 --userns keep-id \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    "${SECCOMP_OPT[@]}" \
    --read-only \
    --tmpfs /tmp/ghidra:rw,noexec,nosuid,nodev,size=256m \
    --tmpfs /work/project:rw,noexec,nosuid,nodev,size=256m \
    --memory 2g --memory-swap 2g --cpus 1 --pids-limit 256 \
    --entrypoint "" \
    "${WORKER_IMAGE}" "$@"
}

echo "== ADR-004 isolation verification =="
echo "image:   ${WORKER_IMAGE}"
echo "runtime: ${WORKER_RUNTIME}"
echo "seccomp: ${SECCOMP_PROFILE}"
echo

# 1. Syscall confinement ACTUALLY active (ADR-004: "verified, not assumed"). The mechanism — and
#    how to verify it from inside the guest — differs by runtime tier:
#      - runc/crun: a host seccomp-BPF filter, guest-visible at /proc/self/status Seccomp
#        (0=disabled, 1=strict, 2=filter). Require >= 1.
#      - runsc/gVisor: the userspace kernel IS the syscall boundary; the host wraps the runsc
#        sandbox in seccomp-BPF that the GUEST cannot see (guest Seccomp is 0 by design), so the
#        guest-Seccomp check is N/A. Instead assert the worker is ACTUALLY running under gVisor —
#        the container both ran under --runtime runsc AND /proc/version carries the gVisor
#        signature (a runc fallback would not). That signature IS the confinement proof here.
# NOTE: the runsc-tier branch is keyed on the runtime NAME, but the /proc/version gVisor signature
# below is what actually CATCHES a silent runc fallback (a non-gVisor kernel lacks the token →
# fail) — so the name assumption is self-checking, not load-bearing on its own.
echo "[1] syscall confinement active"
if [ "${WORKER_RUNTIME}" = "runsc" ]; then
  PROC_VERSION="$(probe sh -c 'cat /proc/version 2>/dev/null' || true)"
  printf '%s\n' "${PROC_VERSION}" | grep -qi 'gvisor' \
    || fail "worker is not running under gVisor (proc/version: '${PROC_VERSION:-<empty>}')"
  pass "gVisor is the syscall boundary (proc/version carries the gVisor signature)"
else
  SECCOMP_MODE="$(probe sh -c 'grep -E "^Seccomp:" /proc/self/status | awk "{print \$2}"' || true)"
  [ "${SECCOMP_MODE:-0}" -ge 1 ] 2>/dev/null || fail "seccomp not active (Seccomp=${SECCOMP_MODE}); expected >=1"
  pass "seccomp mode = ${SECCOMP_MODE} (filter active)"
fi

# 2. ALL capabilities dropped.
#    CapEff (effective capability bitmask) MUST be 0000000000000000.
echo "[2] all capabilities dropped"
CAP_EFF="$(probe sh -c 'grep -E "^CapEff:" /proc/self/status | awk "{print \$2}"' || true)"
[ "${CAP_EFF}" = "0000000000000000" ] || fail "non-empty effective capabilities: CapEff=${CAP_EFF}"
pass "CapEff = ${CAP_EFF} (no capabilities)"

# 3. non-root.
echo "[3] non-root user"
UID_IN="$(probe sh -c 'id -u' || true)"
[ "${UID_IN}" != "0" ] || fail "worker is running as root (uid 0)"
pass "uid = ${UID_IN} (non-root)"

# 4. no_new_privs set. runc/crun reflect it in /proc/self/status (NoNewPrivs: 1). gVisor's emulated
#    /proc OMITS the field (empty), so under runsc verify it BEHAVIOURALLY via
#    prctl(PR_GET_NO_NEW_PRIVS=39) — gVisor implements that prctl and it is the kernel-authoritative
#    source (1 = set). This is a real verification, not an assumption.
echo "[4] no-new-privileges"
NNP="$(probe sh -c 'grep -E "^NoNewPrivs:" /proc/self/status | awk "{print \$2}"' || true)"
if [ -n "${NNP}" ]; then
  [ "${NNP}" = "1" ] || fail "NoNewPrivs not set (/proc: got '${NNP}')"
  pass "NoNewPrivs = 1 (/proc/self/status)"
else
  # /proc field absent (gVisor) — ask the kernel directly via prctl.
  NNP_PRCTL="$(probe python -c 'import ctypes; print(ctypes.CDLL(None, use_errno=True).prctl(39,0,0,0,0))' 2>/dev/null || true)"
  [ "${NNP_PRCTL}" = "1" ] || fail "no_new_privs not enforced (/proc field absent; prctl PR_GET_NO_NEW_PRIVS returned '${NNP_PRCTL:-<none>}')"
  pass "no_new_privs enforced (prctl PR_GET_NO_NEW_PRIVS = 1; gVisor /proc omits the field)"
fi

# 5. read-only root filesystem — a write to a non-tmpfs path MUST fail.
echo "[5] read-only rootfs"
if probe sh -c 'touch /opt/should-not-write 2>/dev/null'; then
  fail "rootfs is writable (wrote /opt/should-not-write)"
fi
pass "rootfs is read-only (write to /opt rejected)"
#    ...and tmpfs scratch IS writable.
probe sh -c 'touch /tmp/ghidra/ok && rm -f /tmp/ghidra/ok' || fail "tmpfs scratch /tmp/ghidra not writable"
pass "tmpfs scratch /tmp/ghidra is writable"

# 6. NO network reachability — there must be no usable interface beyond loopback, and no route out.
echo "[6] no network / no egress"
IFACES="$(probe sh -c 'ls /sys/class/net 2>/dev/null | tr "\n" " "' || true)"
case "${IFACES}" in
  *eth*|*en*|*wl*) fail "unexpected network interface present: ${IFACES}" ;;
esac
pass "no external network interface (ifaces: '${IFACES:-none}')"
#    Attempt an outbound TCP connect — MUST fail (no route / blocked). We don't rely on DNS.
if probe sh -c 'echo > /dev/tcp/10.255.255.1/53' 2>/dev/null; then
  fail "outbound TCP connect succeeded — network egress is reachable"
fi
pass "outbound TCP connect blocked (no egress)"

echo
echo "== ALL ISOLATION CHECKS PASSED =="
echo "Run a full import->analyze->decompile smoke test against a SYNTHETIC binary next"
echo "(no real malware in CI/repo — master §5)."
