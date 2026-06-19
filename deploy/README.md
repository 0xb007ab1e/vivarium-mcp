# deploy/ — runtime isolation specs (ADR-004) and lifecycle helpers (ADR-002)

The **runtime** half of the worker isolation story. The images are built by `Containerfile.worker`
/ `Containerfile.server`; the hardening that ADR-004 calls "load-bearing" is applied **here, at run
time** (a Dockerfile cannot set `--network=none`, `--cap-drop`, seccomp, gVisor, or cgroup limits —
those are runtime flags). Everything in this directory is a **reference spec + documented command**;
**nothing here is executed by WS3** — running a container that binds host paths/sockets or uses the
images is **GATED** (PLAN §6).

## Files

| File | Purpose |
|------|---------|
| `worker-run.sh` | Hardened rootless-podman spec for **one** Ghidra worker (ADR-004). The server's RPC adapter (WS2) mirrors this spec when it spawns a worker. |
| `server-run.sh` | Hardened spec for the MCP control-plane server (stdio, no ports; spawns workers). |
| `verify-isolation.sh` | **ADR-004 acceptance harness** — asserts seccomp/caps/non-root/ro-rootfs/no-network are actually in force inside a worker. Fail-closed. |
| `wipe-session.sh` | **ADR-002 kill-then-verified-wipe** of a session's worker + store; emits `store_wiped:true\|false`. |
| `socket-dir.md` | Per-session UDS layout, permissions, and mount wiring (rpc-protocol.md §2). |

Supporting config lives in `infra/`: `seccomp/` (profiles + verification note), `hadolint.yaml`
(Dockerfile lint), `trivy.yaml` (image/IaC/secret scan), `Makefile` (build/scan target stubs).

## How each ADR-004 control is realized

| Control (ADR-004) | Where | How |
|---|---|---|
| non-root | image + run | `USER 65532` in Containerfiles; `--user 65532:65532 --userns keep-id` at run |
| read-only rootfs | run | `--read-only` + writable surfaces only via `--tmpfs` |
| all caps dropped | run | `--cap-drop ALL` (add back none) |
| no-new-privileges | run | `--security-opt no-new-privileges` |
| seccomp RuntimeDefault (verified) | run + verify | `--security-opt seccomp=RuntimeDefault`; `verify-isolation.sh` asserts `Seccomp>=1` |
| no network / no egress | run + verify | `--network none`; `verify-isolation.sh` asserts no iface + blocked egress |
| CPU/mem/pids limits | run | `--cpus --memory --memory-swap --pids-limit` (mirror `security/limits.py`) |
| tmpfs scratch only | run | `--tmpfs /tmp/ghidra` + `--tmpfs /work/project` (noexec,nosuid,nodev) |
| gVisor (runsc) strong tier | run | `--runtime runsc` (default; rootless OCI baseline is the floor fallback) |
| minimal pinned base (ADR-003) | image | multi-stage; bases pinned by digest (placeholders, gated) |
| one-worker-per-session + verified wipe (ADR-002) | run + helper | per-session container name + tmpfs store; `wipe-session.sh` |

## CI isolation relaxation (live-regression / e2e jobs only)

The gated CI jobs that drive a **real** worker (`.github/workflows/live-regression.yml`,
`e2e-groundtruth.yml`) run the worker under **crun**, NOT gVisor (`runsc`): stock GitHub runners
have no gVisor available. This is a **CI-only** relaxation of the single "strong tier" control —
**every other ADR-004 floor still holds** (non-root, read-only rootfs, all caps dropped,
no-new-privileges, seccomp RuntimeDefault, `--network none`, cgroup limits, tmpfs-only scratch).
The OCI runtime does not change Ghidra's recovered output, so the correctness/regression gates are
unaffected. The inputs are **benign, locally-built synthetic micro-binaries** (master §5 — no real
malware). **Production keeps `runsc`/gVisor** (`--runtime runsc`, the table above); the gVisor tier
is validated separately by `verify-isolation.sh` at deploy. See ADR-028 (live-regression harness).

## GATED commands a maintainer runs after approval

> Each is a PLAN §6 gated action (image pull/build, dependency install, or a container run binding
> host paths/sockets). Run **in order**, after the supply-chain gate (digests/lock approved).

### 0. Resolve + pin all digests (supply-chain gate — see the gate list in the WS3 handoff)
```
# Resolve each REPLACE_WITH_DIGEST_FOR_<tag> to its @sha256 and replace in-place after VETTING.
# Both images are on Chainguard/Wolfi (PLAN §9 distroless migration); see infra/pin-supply-chain.sh.
podman pull cgr.dev/chainguard/wolfi-base        && podman inspect --format '{{index .RepoDigests 0}}' cgr.dev/chainguard/wolfi-base         # worker
podman pull cgr.dev/chainguard/python:latest-dev && podman inspect --format '{{index .RepoDigests 0}}' cgr.dev/chainguard/python:latest-dev  # server build
podman pull cgr.dev/chainguard/python:latest     && podman inspect --format '{{index .RepoDigests 0}}' cgr.dev/chainguard/python:latest      # server run
# Ghidra release: download the 12.1.2 zip + verify the publisher SHA-256 (set the build ARGs).
# Generate the hash-pinned Python lockfile (gated): uv lock   (or pip-compile --generate-hashes)
```

### 1. Build the images (after digests pinned)
```
podman build -f Containerfile.worker \
  --build-arg GHIDRA_VERSION=<11.x> \
  --build-arg GHIDRA_ZIP_URL=<url> \
  --build-arg GHIDRA_ZIP_SHA256=<sha256> \
  -t vivarium-worker:local .
podman build -f Containerfile.server -t vivarium-server:local .
```

### 2. Scan (fail-closed on HIGH/CRITICAL)
```
hadolint --config infra/hadolint.yaml Containerfile.worker Containerfile.server
trivy image --config infra/trivy.yaml vivarium-worker:local
trivy image --config infra/trivy.yaml vivarium-server:local
trivy config --config infra/trivy.yaml .            # IaC/misconfig (also covered by ci.yml)
```

### 3. Verify isolation (ADR-004 acceptance — REQUIRED before trusting the worker)
```
VIVARIUM_WORKER_IMAGE=<pinned@sha256> deploy/verify-isolation.sh
```

### 4. Smoke test (synthetic binary ONLY — no real malware, master §5)
```
# spawn one worker, import->analyze->decompile a benign synthetic ELF/PE built by the test suite,
# confirm RPC over the UDS works end to end, then evict + verify the wipe:
deploy/worker-run.sh <session_id> <path/to/synthetic.bin>
deploy/wipe-session.sh <session_id>     # expect {"...","store_wiped":true}
```

## Rollback

- **Image:** images are immutable by digest. Revert the pinned digest in `deploy/*` + `.env.example`
  to the previous value (still in git history) and redeploy — see `docs/runbooks/rollback.md` and
  `docs/runbooks/dependency-patch.md` (digest-bump rollback).
- **Runtime spec change:** revert the `deploy/*.sh` change; re-run `verify-isolation.sh` to confirm
  the prior, known-good isolation posture before resuming traffic.
- **Failed isolation check:** do **not** run workers — a control that won't verify is treated as
  absent (fail closed). Fall back to the rootless OCI baseline only if `runsc` is unavailable
  (ADR-004 fallback), never to fewer controls.
