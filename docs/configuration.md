# Configuration reference

Vivarium is configured entirely from the **environment** (12-Factor). Every value is read and
**validated at startup** — an invalid or out-of-range value makes the server **fail closed** (refuse
to boot) rather than run misconfigured. The read set is a single auditable allow-list in
[`src/vivarium/config.py`](../src/vivarium/config.py); limit defaults live in
`src/vivarium/security/limits.py` and auth defaults in `src/vivarium/server/auth.py`.

For local development, copy [`.env.example`](../.env.example) to a git-ignored `.env`. **Secrets
never live in this file or in `.env`** — bearer tokens and the reverse-proxy shared secret come from
a secret manager / injected env at runtime (see [workflow-secrets] and the
[HTTP exposure runbook](runbooks/http-exposure.md)).

> **Secure by default.** The default transport is **stdio** (no network, no auth boundary). Only the
> variables in the first tables are read in that mode; the HTTP tables apply only when
> `VIVARIUM_TRANSPORT=http`.

## Logging & observability

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_LOG_LEVEL` | `INFO` | `DEBUG`\|`INFO`\|`WARNING`\|`ERROR`. DEBUG must never emit binary content. |
| `VIVARIUM_LOG_FORMAT` | `json` | `json`\|`text`. Structured JSON to stdout/stderr in prod. |
| `VIVARIUM_METRICS_SNAPSHOT_INTERVAL_SECONDS` | `60` | Interval between metrics-snapshot log lines (SLI trend). |

## Sessions

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_SESSION_TTL_SECONDS` | `3600` | Absolute session lifetime before eviction. |
| `VIVARIUM_SESSION_IDLE_SECONDS` | `900` | Idle timeout before eviction. |
| `VIVARIUM_SESSION_REAP_INTERVAL_SECONDS` | `60` | How often the background reaper sweeps expired sessions. |
| `VIVARIUM_MAX_SESSIONS` | `4` | Worker-pool concurrency cap (backpressure above this). |
| `VIVARIUM_MAX_SESSIONS_PER_OWNER` | _unset_ | Optional per-principal cap (multi-principal); unset = global cap only. |

## DoS / resource bounds (enforced BEFORE the worker)

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_MAX_BINARY_BYTES` | `134217728` (128 MiB) | Hard cap on imported binary size. |
| `VIVARIUM_ANALYSIS_TIMEOUT_SECONDS` | `600` | Per-analysis wall-clock; on expiry the worker is **killed** (ADR-002). |
| `VIVARIUM_TOOL_TIMEOUT_SECONDS` | `60` | Per-tool-call wall-clock (e.g. one decompile). |
| `VIVARIUM_MAX_RESPONSE_BYTES` | `4194304` (4 MiB) | Cap on any single tool response payload. |
| `VIVARIUM_MAX_STREAM_BUFFER_CHUNKS` | _see limits.py_ | Cap on buffered streaming chunks (backpressure — ADR-040). |
| `VIVARIUM_MAX_STREAM_REPLAY_CHUNKS` | _see limits.py_ | Cap on replayable chunks for stream resume. |

## Worker / Ghidra (container-only — ADR-003/004)

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_WORKER_IMAGE` | _pinned by digest_ | Worker image ref. The **trusted** digest CI verifies is [`.github/worker-image.pin`](../.github/worker-image.pin) — keep `.env` in sync. |
| `VIVARIUM_WORKER_RUNTIME` | `runsc` | Container runtime — `runsc` (gVisor) for strong isolation (ADR-004). |
| `VIVARIUM_WORKER_UID` | `65532` | Worker container uid (hardened non-root). |
| `VIVARIUM_WORKER_GID` | `65532` | Worker container gid. |
| `VIVARIUM_RPC_SOCKET_DIR` | `/run/vivarium` | Directory for per-session Unix-domain sockets. |
| `VIVARIUM_IMPORT_ROOT` | `/work/imports` | Confined root a `source_ref` must resolve under (CWE-22, ADR-009). |
| `VIVARIUM_WORKER_PREFLIGHT` | `warn` | Over-size OOM pre-flight: `warn`\|`reject`\|`off` (ADR-029). |

### Worker container resource bounds (ADR-023) — tunable, clamped to a hard ceiling

| Variable | Default | Ceiling | Purpose |
|---|---|---|---|
| `VIVARIUM_WORKER_MEM_MIB` | `4096` | `32768` | Worker memory cap (MiB). `--memory-swap` is pinned equal (no swap). |
| `VIVARIUM_WORKER_CPUS` | `2` | `16` | Whole-CPU quota. |
| `VIVARIUM_WORKER_PIDS` | `512` | `4096` | Process/thread cap (fork-bomb bound). |
| `VIVARIUM_WORKER_TMPFS_SCRATCH_MIB` | `2048` | `16384` | Scratch tmpfs (`/tmp/ghidra`) size (MiB). |
| `VIVARIUM_WORKER_TMPFS_PROJECT_MIB` | `4096` | `32768` | Project-store tmpfs (`/work/project`) size (MiB). |

> Env may lower **or** raise within bounds; an above-ceiling value is clamped **down** (never widen
> the DoS surface). A bool/non-int/`<1` value fails closed at startup.

## HTTP transport (ADR-011) — read only when `VIVARIUM_TRANSPORT=http`

The default transport is stdio; set `VIVARIUM_TRANSPORT=http` to expose the network boundary (TB6).
Bind to a loopback or tailnet address — **never** `0.0.0.0` on an untrusted network. See the
[HTTP exposure runbook](runbooks/http-exposure.md).

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_TRANSPORT` | `stdio` | `stdio`\|`http`. |
| `VIVARIUM_HTTP_BIND` | `127.0.0.1:8765` | `host:port` for the HTTP listener. |
| `VIVARIUM_HTTP_AUTH` | _required for http_ | `none`\|`bearer`\|`mtls`\|`oauth`\|`mtls-proxy`. |
| `VIVARIUM_HTTP_RATE_PER_SECOND` | `10` | Per-principal request rate (token bucket). |
| `VIVARIUM_HTTP_RATE_BURST` | `20` | Token-bucket burst. |
| `VIVARIUM_HTTP_MAX_BODY_BYTES` | `1048576` (1 MiB) | Request body cap. |
| `VIVARIUM_HTTP_CORS_ORIGINS` | _empty_ | Comma-separated origin allow-list; empty = no cross-origin. |
| `VIVARIUM_HTTP_TLS_CERT` / `VIVARIUM_HTTP_TLS_KEY` | _unset_ | Server TLS cert/key paths (terminate TLS at the server). |

### Auth-mode variables

**Bearer** (`VIVARIUM_HTTP_AUTH=bearer`):

| Variable | Purpose |
|---|---|
| `VIVARIUM_HTTP_BEARER_TOKEN` | **Secret.** Single token → the `bearer` principal (back-compat). |
| `VIVARIUM_HTTP_BEARER_TOKENS` | **Secret.** Newline/comma list of `principal-id:token` pairs (multi-principal, ADR-017). |

**mTLS** (`VIVARIUM_HTTP_AUTH=mtls`, ADR-019):

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_HTTP_TLS_CLIENT_CA` | _required_ | CA bundle path used to verify client certs (a path, not a secret). |
| `VIVARIUM_HTTP_MTLS_PRINCIPAL_FIELD` | _see auth.py_ | Which cert field maps to the principal id. |

**OAuth** (`VIVARIUM_HTTP_AUTH=oauth`, ADR-019/033) — the access token is per-request, never stored:

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_HTTP_OAUTH_ISSUER` | _required_ | Expected `iss`. |
| `VIVARIUM_HTTP_OAUTH_AUDIENCE` | _required_ | Expected `aud`. |
| `VIVARIUM_HTTP_OAUTH_JWKS_URI` | _required_ | JWKS endpoint for signature keys. |
| `VIVARIUM_HTTP_OAUTH_PRINCIPAL_CLAIM` | _see auth.py_ | Claim used as the principal id. |
| `VIVARIUM_HTTP_OAUTH_ALGORITHMS` | _pinned allow-list_ | Asymmetric algs only — `none`/`HS*` rejected. |
| `VIVARIUM_HTTP_OAUTH_LEEWAY_SECONDS` | _see auth.py_ | Clock-skew leeway. |
| `VIVARIUM_HTTP_OAUTH_WRITE_SCOPE` | _unset_ | Scope granting write capability (per-tool authZ, ADR-033); unset = identity-only. |

**Reverse-proxy mTLS** (`VIVARIUM_HTTP_AUTH=mtls-proxy`, ADR-034):

| Variable | Purpose |
|---|---|
| `VIVARIUM_HTTP_PROXY_SHARED_SECRET` | **Secret** — the trust anchor between the proxy and the server. |
| `VIVARIUM_HTTP_PROXY_SECRET_HEADER` | Header carrying the shared secret. |
| `VIVARIUM_HTTP_PROXY_IDENTITY_HEADER` | Header carrying the proxy-verified client identity. |

## Readiness

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_READINESS_CACHE_TTL_SECONDS` | `1` | TTL for the cached `/readyz` capacity answer (bounds the pre-auth occupancy oracle, gap P3). |

## Worker-only variables

These are read **inside the worker** (the JVM/PyGhidra edge in `vivarium.ghidra._jvm_bridge`), not by
the server `Config` — the server never touches Ghidra (ADR-001):

| Variable | Default | Purpose |
|---|---|---|
| `VIVARIUM_FID_DB_DIR` | `/opt/vivarium/fid` | Directory of bundled packed ELF FunctionID DBs (`*.fidbf`); missing/empty = no-op (ADR-043). |
| `VIVARIUM_WORKER_PROJECT_DIR` | _worker-set_ | Ghidra project store path inside the worker. |
| `VIVARIUM_RPC_SOCKET` | _worker-set_ | The worker's own RPC socket path. |
| `GHIDRA_INSTALL_DIR` | _worker-set_ | Ghidra install root inside the image. |

[workflow-secrets]: runbooks/secret-rotation.md
