# ADR-023: Configurable worker resources + distinct OOM/exit error

- **Status:** Accepted (v1.3; human-ratified 2026-06-15). Ratified: **D1** bounds configurable via
  MiB-integer env (defaults = current values; ceilings ~32 GiB mem / 16 CPU / 32 GiB project-tmpfs);
  **D2** a **new `ErrorType` `resource-exhausted`** (HTTP 503, `retryable=False`) for worker OOM/exit;
  **D3** pre-flight size check **warn-only by default** (no reject mode this increment). Addresses
  **finding F1** (`docs/roadmap-v1.3-findings.md`). Extends **ADR-009** (the concrete launcher) and **ADR-004**
  (isolation tier / resource bounds); refines the worker-death → error mapping in
  `ghidra.rpc_client` (rpc-protocol §3/§6). **No new trust boundary** — this is resource-bound
  *tuning* (the bounds stay clamped) plus *error clarity*.
- **Deciders:** Human (ratifies the defaults, hard ceilings, the new `ErrorType` name vs. reuse,
  and the pre-flight policy) + PM; recorded by the Software Architect.
- **Relates to:** ADR-001 (server never loads the JVM / parses the binary — preserved), ADR-002
  (kill-on-evict + verified store wipe), ADR-004 (`deploy/worker-run.sh` hardening invariants),
  ADR-009 (`ContainerWorkerLauncher` argv), ADR-011 (HTTP error surface). Ties: `topic-reliability`
  (bounded resources, fail-fast, actionable failure), `topic-container-k8s` (limits as policy),
  `std-cwe` (CWE-400 uncontrolled resource consumption), the frozen `error-envelope.md` /
  `rpc-protocol.md` contracts.

## Context

A 184 MiB binary OOM-killed the worker JVM ~18 min into `analyze`. Three defects compounded:

1. **The resource bounds are hardcoded and non-overridable.** `ContainerWorkerLauncher`
   (`src/ghidra_mcp/ghidra/launcher.py`) fixes `mem="4g"`, `cpus="2"`, `pids=512`,
   `tmpfs_scratch="2g"`, `tmpfs_project="4g"` (lines 110-114) and wires them into
   `--memory`/`--memory-swap`/`--cpus`/`--pids-limit` (lines 176-185). `config.py` threads
   `worker_image`/`worker_runtime`/`worker_uid`/`worker_gid` from `_ENV_*` but has **no env knob for
   any resource bound** — unlike `limits.py`, which already resolves `max_binary_bytes` /
   `analysis_timeout_s` etc. through `resolve_limits` with default + hard-ceiling clamps. An operator
   on bigger hardware cannot lift the worker to 16 GiB without editing source and rebuilding.

2. **The JVM heap tracks the cgroup limit.** `Containerfile.worker` (line 202) sets
   `JAVA_TOOL_OPTIONS=-XX:+ExitOnOutOfMemoryError -XX:MaxRAMPercentage=75.0 …` → ~3 GiB heap inside
   the 4 GiB cap. `MaxRAMPercentage` is *relative*, so once `mem` becomes configurable the heap
   scales with it automatically — but `ExitOnOutOfMemoryError` means a heap-exhaustion exits the
   JVM, and the cgroup `--memory` wall means a native/off-heap overrun is **OOM-killed** by the
   kernel. Both paths kill the worker.

3. **A worker death is indistinguishable from any other transport drop.** When the JVM exits or the
   cgroup kills it, the socket closes mid-frame; `_call` (`rpc_client.py` lines 998-1012) catches
   `(ConnectionError, EOFError, OSError)` and maps **everything** to `WORKER_UNAVAILABLE` ("worker
   unavailable", retryable). The operator saw a generic transient error and retried the same
   oversized binary — burning another 18 minutes. Nothing told them *the worker ran out of memory*
   or *this input is too big for the configured heap*.

The fix is bounded tuning + a distinct, actionable failure — **no relaxation of the ADR-004
hardening invariants** (non-root, ro-rootfs, caps dropped, `--network none`, seccomp default,
`no-new-privileges`, **no swap**). Only the numeric bounds become configurable, each clamped.

## Decision (proposed — pending ratification)

### D1 — Make the five worker resource bounds configurable via env + config, each with a safe default and a hard ceiling.

Add a `WorkerResources` validated value object resolved exactly like `Limits` — defaults = the
current hardcoded values; a misconfigured env may only make a bound *stricter or larger up to a hard
ceiling*, never unbounded (master §2 secure-by-default; CWE-400). The launcher takes resolved values
instead of literals; the composition root threads them from `Config`.

| Bound | env var (`_ENV_*`) | default (`_DEFAULT_*`) | hard ceiling (`HARD_MAX_*`) | unit / validation |
|---|---|---|---|---|
| `mem` | `GHIDRA_MCP_WORKER_MEM_MIB` | `4096` (4 GiB) | **`32768` (32 GiB)** *(ratify)* | MiB, positive int |
| `cpus` | `GHIDRA_MCP_WORKER_CPUS` | `2` | **`16`** *(ratify)* | whole CPUs, positive int |
| `pids` | `GHIDRA_MCP_WORKER_PIDS` | `512` | **`4096`** *(ratify)* | positive int |
| `tmpfs_scratch` | `GHIDRA_MCP_WORKER_TMPFS_SCRATCH_MIB` | `2048` (2 GiB) | **`16384` (16 GiB)** *(ratify)* | MiB, positive int |
| `tmpfs_project` | `GHIDRA_MCP_WORKER_TMPFS_PROJECT_MIB` | `4096` (4 GiB) | **`32768` (32 GiB)** *(ratify)* | MiB, positive int |

Design rules:

- **Integer MiB / whole-CPU env values, not free-form `"4g"` strings.** The current dataclass holds
  engine strings (`"4g"`, `"2"`). Accepting free-form strings from the environment would feed an
  unvalidated token straight into the `podman run` argv (a value-injection / parse-ambiguity smell —
  `std-owasp-proactive` #5, validate-all-input). Instead: env vars are **non-negative integers**
  parsed by the existing `_read_int`/`_read_positive_int` (config.py lines 260-302), clamped, then
  **rendered** to the engine spelling at argv-build time (`{mib}m`, `str(cpus)`). The resolver is a
  pure function — 100% test target.
- **Clamp downward AND upward to the ceiling**, mirroring `resolve_limits` (`min(value, ceiling)`,
  reject `bool`/non-int/`< 1` with a fail-closed `VALIDATION` error — limits.py lines 88-125). A
  value *below* the default is allowed (stricter is always safe); a value *above* the ceiling is
  clamped to the ceiling, never honored unbounded.
- **`--memory-swap` stays pinned equal to `--memory`** (launcher line 179) — **no swap** is an
  ADR-004 invariant and is *not* tunable. The OOM wall must remain a hard wall, not a slow
  swap-thrash. (Reaffirmed explicitly so a future edit doesn't "helpfully" add swap.)
- **`MaxRAMPercentage` is left as-is** (Containerfile line 202). Because it is relative, the JVM heap
  auto-scales with the configured `mem` — no per-deployment Containerfile edit, and the image stays
  pinned-by-digest (ADR-003 / supply chain). The cgroup `--memory` remains the authoritative wall.
- **Placement of the resolver:** add `resolve_worker_resources(overrides)` + `WorkerResources` to
  `security/limits.py` (it already owns the default + hard-ceiling pattern and the fail-closed
  validation helpers) — keeping one home for "bounded-by-default resource policy." `config.py` reads
  the five `_ENV_*`, builds an overrides dict (only keys explicitly set), and calls the resolver,
  exactly as it does for `Limits` (config.py lines 669-683).

> All ADR-004 hardening flags in the launcher argv (lines 145-200) are **unchanged**. Only the five
> numeric operands of `--memory`/`--cpus`/`--pids-limit`/the two `--tmpfs` size= fields move from
> literals to resolved-and-clamped config.

### D2 — Map worker OOM / unexpected exit to a distinct, actionable error.

Introduce a new frozen `ErrorType` member (name to ratify; recommendation below) so an
out-of-resource worker death is **not** the generic `worker-unavailable` transport drop:

```
RESOURCE_EXHAUSTED = "resource-exhausted"   # recommended
# alt: WORKER_OOM = "worker-oom"
```

- **Detection (no JVM in the server — ADR-001 preserved).** On the `(ConnectionError, EOFError,
  OSError)` path in `_call` (rpc_client.py lines 998-1012), before mapping to `worker-unavailable`,
  inspect the dead worker's **exit signal/code** via the already-available `WorkerProcess` handle —
  the container engine reports it. A cgroup OOM-kill surfaces as `OOMKilled=true` /
  `inspect .State.OOMKilled` (podman/docker) or exit `137` (128+SIGKILL); `ExitOnOutOfMemoryError`
  exits the JVM with a non-zero code. When the death is attributable to OOM/resource exhaustion →
  `RESOURCE_EXHAUSTED`; otherwise the existing `WORKER_UNAVAILABLE` (crash/closed-socket of unknown
  cause). This adds a small `ContainerWorkerProcess` method (e.g. `exit_diagnosis()` returning an
  enum: `OOM` / `OTHER` / `UNKNOWN`) reading `inspect`; **server-side only, a stat-like query, no
  binary parsing**.
- **Envelope wiring** (`_errors.py`): add `RESOURCE_EXHAUSTED → status 503` *(or 507 Insufficient
  Storage — ratify; 503 keeps it in the "worker problem" family)*, title "Worker out of resources",
  `retryable=False` (retrying the *same* oversized input on the *same* `mem` will fail identically —
  this is the deliberate fix for the 18-minute retry loop; the actionable remedy is "raise
  `GHIDRA_MCP_WORKER_MEM_MIB` or shrink the input," surfaced in the detail).
- **Fail-closed + redaction preserved.** `detail` is a fixed safe string ("the worker exhausted its
  memory limit analyzing this input; increase the worker memory bound or reduce the input size") —
  **no binary content, no host paths, no JVM stack** (error-envelope.md disclosure rules). The
  precise exit code / `OOMKilled` flag is logged server-side under the correlation id only
  (`topic-logging-observability`, master §5), mirroring the existing `worker.rpc_failed` log
  (rpc_client.py lines 1002-1010).
- **Contract is additive.** Adding an `ErrorType` member is explicitly allowed by the frozen-contract
  rule ("Add new members for new categories; never repurpose an existing slug" — errors.py lines
  22-27). Existing clients that branch only on known slugs degrade gracefully (an unknown slug is
  still a structured envelope). `error-envelope.md` + `rpc-protocol.md` get the new member appended
  (PM-routed, batch-atomicity — this is a WS0 contract touch).

### D3 — Optional pre-flight: warn/reject when the input size is implausible for the configured heap.

A cheap, ADR-001-safe guard *before* the multi-minute analyze: the server already `stat`s the input
size in `make_confined_resolver` (launcher line 250) and enforces `max_binary_bytes`
(`check_binary_size`, limits.py 128-161) — a **size stat is not parsing the binary**, so this stays
inside ADR-001.

- **Policy (ratify):** derive a soft advisory threshold from the configured `mem` —
  `plausible_max_bytes = mem_mib * MiB * RATIO` (a conservative ratio, e.g. **1×–2× of RAM**, since
  Ghidra's working set is a multiple of the input; exact ratio to ratify). Two modes to choose
  between:
  - **(a) Warn-only (recommended default):** emit a structured `worker.preflight_oversized` log
    (size + configured mem, no content) and proceed — Ghidra *may* still succeed; we don't want a
    heuristic to block a legitimate large analysis (false-positive risk). Operators see the warning
    and can raise `mem`.
  - **(b) Reject (opt-in):** when `size > plausible_max_bytes`, fail closed *immediately* with the
    new `RESOURCE_EXHAUSTED` (or `LIMIT_EXCEEDED`) error and the actionable detail — saves the
    18-minute burn entirely. Gate behind an env flag (`GHIDRA_MCP_WORKER_PREFLIGHT=warn|reject`,
    default `warn`).
- This is **distinct from `max_binary_bytes`** (an absolute DoS ceiling): the pre-flight is a
  *RAM-relative plausibility* check that moves with the configured `mem`. It never widens
  `max_binary_bytes`; both apply (the stricter wins).
- The threshold computation is a **pure function — 100% test target**, with explicit boundary cases.

## Consequences

- Operators size the worker to their hardware via env (12-Factor) without rebuilding the
  pinned-by-digest image; the heap auto-scales via the relative `MaxRAMPercentage`. Bounds stay
  clamped (CWE-400) — a fat-fingered `mem` env can't grant an unbounded container.
- An OOM is now an **actionable, non-retryable** `RESOURCE_EXHAUSTED` instead of a generic retryable
  transport drop — directly killing the observed 18-minute retry loop. The remedy (raise `mem` /
  shrink input) is in the (redacted) detail and the server log.
- Threat-model delta is **small and recorded, not a new boundary:** TB3 (hostile input → worker)
  resource-DoS controls are *strengthened* (still bounded; an attacker can't widen them past the
  ceiling), and the worker-death classification gains fidelity. The new `exit_diagnosis()` reads
  container engine metadata only — no new code path touches the binary, ADR-001 intact. Append the
  delta to `docs/security/threat-model.md` (Spoofing/Tampering unchanged; **Denial-of-Service**:
  tunable-but-clamped bounds + clearer DoS signal; **Information disclosure**: confirm the new error
  detail + log carry no binary content / host paths).
- `MaxRAMPercentage` staying relative means the *one* place the heap is set (Containerfile) needs no
  per-deploy change — but it is now load-bearing on `mem` being correct, so it is called out in the
  runbook.

## Alternatives considered

- **Free-form `"4g"`-style env strings passed straight to the engine.** Rejected: unvalidated tokens
  in the argv, parse ambiguity across engines, no clean clamp. Integer-MiB + render is validated and
  clampable.
- **Reuse `WORKER_UNAVAILABLE` with a richer `detail`.** Rejected: clients branch on the *slug*, not
  the prose; the retryable flag (currently `True` for `worker-unavailable`) is the wrong signal for
  an OOM. A distinct, non-retryable type is the actionable contract.
- **Reuse `LIMIT_EXCEEDED` for OOM.** Considered: it is the right *family* for the pre-flight reject
  case (a bound was exceeded) but wrong for a *runtime* OOM (no declared client limit was exceeded;
  the worker ran out of RAM). Recommendation: `RESOURCE_EXHAUSTED` for the runtime OOM;
  `LIMIT_EXCEEDED` acceptable for the pre-flight *reject* path (ratify).
- **Make swap tunable to soften OOMs.** Rejected — violates the ADR-004 no-swap invariant; swap
  turns a fast fail into a slow thrash and weakens the hard memory wall.

## Implementation increment (for the PM to fan out — design only; not implemented here)

1. **`security/limits.py`** — add `WorkerResources` (frozen, slots) + `resolve_worker_resources`
   (default + `_HARD_CEILINGS`-style clamps, fail-closed `VALIDATION` reuse). **Pure → 100% coverage**
   incl. boundary/over-ceiling/`bool`/non-int/`<1` cases.
2. **`config.py`** — add the five `_ENV_WORKER_*` names + `_DEFAULT_*`, build the overrides dict
   (only explicitly-set keys), call the resolver, add a `WorkerResources` field to `Config`.
   Mirror the `Limits` wiring (lines 669-683). Update `.env.example`.
3. **`ghidra/launcher.py`** — `ContainerWorkerLauncher` takes resolved ints; render `{mib}m` /
   `str(cpus)` into the argv (lines 173-184); keep `--memory-swap == --memory` pinned. Add
   `ContainerWorkerProcess.exit_diagnosis()` (reads `inspect`/`OOMKilled` via the injected runner —
   unit-tested with a fake runner). All ADR-004 flags unchanged.
4. **`core/errors.py`** — add the new `ErrorType` member (ratified name/slug).
5. **`ghidra/_errors.py`** — add the member to `_STATUS`/`_TITLE`/`_RETRYABLE` (status + retryable
   ratified). Optionally a `resource_exhausted()` factory like `session_invalid()`.
6. **`ghidra/rpc_client.py`** — on the transport-error path (`_call`, lines 998-1012), classify via
   `exit_diagnosis()` → `RESOURCE_EXHAUSTED` vs `WORKER_UNAVAILABLE`; keep kill-on-failure + the
   redacted server log.
7. **(If D3 ratified) pre-flight** — pure `plausible_max_bytes(mem_mib, ratio)` + the warn/reject
   hook at the existing size-stat point; env flag in config. **100% on the pure threshold fn.**
8. **Contracts (WS0, PM-routed):** append the new `ErrorType` to `docs/contracts/error-envelope.md`
   + `docs/contracts/rpc-protocol.md` (worker-death classification); note no slug repurposed.
9. **Threat model:** append the TB3 DoS-tuning + error-clarity delta to
   `docs/security/threat-model.md` (no new boundary).
10. **Tests:** unit (resolver clamps, launcher argv rendering, `exit_diagnosis` parse, error mapping,
    pre-flight threshold) + a gated e2e note that a known-oversized synthetic input surfaces
    `RESOURCE_EXHAUSTED` (no real malware — synthetic large benign fixture, master §5).
11. **Runbook:** update the evict-poisoned-worker / sizing runbook with "raise
    `GHIDRA_MCP_WORKER_MEM_MIB`" as the OOM remedy and the `MaxRAMPercentage`-tracks-`mem` note.
