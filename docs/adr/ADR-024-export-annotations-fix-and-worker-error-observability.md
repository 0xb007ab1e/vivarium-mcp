# ADR-024: Fix `export_annotations` on real programs + worker-error observability

- **Status:** Accepted (v1.3; human-ratified 2026-06-15). Ratified: **bundle F3 with F2** in this ADR
  but ship in **two PRs — PR-1 observability/diagnosis first, PR-2 the `_jvm_bridge` export fix**;
  worker error detail is **log-only + redacted** (additive worker→server `data.detail`; client
  `ErrorEnvelope` unchanged); strict scrub (exception class + fixed template, drop free-form `str()`);
  strip value-echoing `ValidationError` message lines from rendered tracebacks; transient stderr
  capture, **no persistence** (ADR-002); regression fixture = `/bin/gzip` (benign, gitignored). Driven
  by blind-acceptance findings **F2** + **F3** (`docs/archive/roadmap-v1.3-findings.md` 2026-06-15).
- **Deciders:** Human (ratifies scope + the worker-error-detail surface/redaction stance) + PM;
  recorded by the Software Architect.
- **Relates to:** ADR-018 (the export design this fixes — `USER_DEFINED` enumeration), ADR-001
  (server never parses a binary; enumeration is worker-only), ADR-002 (per-session ephemeral wipe —
  no durable state; `--rm --detach` worker), ADR-005 (untrusted-data envelope on exported strings),
  ADR-017 (owner-scoped sessions), ADR-009 (worker launcher — `launcher.py` spawn/`--rm`). No new
  trust boundary: TB8 (annotation import/export) already covers this surface; this is a
  **correctness + observability** fix, not a new capability.

## Context

The blind end-to-end acceptance run (gzip 1.13, x86-64, 100 KB) applied **39 real
`rename_function` writes** through the consent gate, then called `session_export_annotations`
(ADR-018). The export **failed with `internal worker error`** mapped to the public
`internal-error` envelope. The chain is:

```
registry._handle_session_export_annotations   (registry.py:929-957)
  → ctx.port.export_annotations
  → rpc_client.export_annotations              (rpc_client.py:911-915)
  → worker RPC "export_annotations"            (_jvm_bridge.py:433-445 dispatch → _gh_export_annotations)
  → _gh_export_annotations                     (_jvm_bridge.py:2113-2225)  ← raises a JVM exception
  → worker dispatch.handle_request `except Exception` (dispatch.py:380-381)
        returns build_error(..., CODE_INTERNAL, "internal worker error")  ← detail dropped here
  → rpc_client._call RpcCallError branch       (rpc_client.py:970-973)
        etype = map_worker_slug("internal-error") → INTERNAL; message = "internal worker error"
  → public envelope: internal-error
```

**Two problems, tightly coupled:**

- **F2 (correctness, High):** `_gh_export_annotations` raises on a *real, renamed* program. Only
  synthetic fixtures existed for ADR-018 export, so the gap hid the fault. The enumeration walks
  composites → signatures → function renames → symbol renames → comments
  (`_jvm_bridge.py:2153-2219`) and calls helpers (`_composite_export_kind` 2679,
  `_composite_fields_export` 2705, `_function_signature_export` 2736, `_to_text` 2529) that touch a
  broad slice of the Ghidra `DataTypeManager` / `Listing` / `SymbolTable` API on a real program.

- **F3 (observability, Med):** the fault is **undiagnosable from logs**. Three concrete defects:
  1. The worker's `except Exception` (`dispatch.py:380-381`) collapses **every** non-`WorkerError`
     to the fixed string `"internal worker error"` with slug `internal-error` — the real JVM
     exception type/message is **discarded inside the worker** and never crosses the RPC.
  2. The worker container is `--rm --detach` (`launcher.py:143-144`), so its **stderr (the JVM
     traceback) is not captured server-side** — it dies with the container.
  3. Even where the server *does* have the exception, `_RedactingJsonFormatter` (`logging.py:108-131`)
     **never renders `record.exc_info`** — `exc_info` is in `_RESERVED_RECORD_ATTRS`
     (`logging.py:37`), so `_safe_extra` (`logging.py:90-105`) drops it and `_log.exception()` emits
     **no traceback**. And `_safe_extra` does not guard reserved `LogRecord` keys, so a caller
     passing `extra={"msg": ...}` (or `name`, `args`, `module`, …) crashes the handler with
     `KeyError: "Attempt to overwrite 'msg' in LogRecord"`.

Because of (1)+(2) we **cannot name the exact JVM fault** today. So this ADR is **diagnosis-first**:
fix observability so the worker tells us *what* broke, reproduce it, then fix F2 surgically.

## Decision (proposed)

### D1 — One ADR, sequenced two-PR delivery; **observability lands first**.
F3 is the instrument that makes F2 diagnosable; they are designed together but **shipped in order**:
**PR-1 = observability/diagnosis** (worker error-detail surface + stderr capture + formatter
`exc`/reserved-key guard + a *reproduction* integration test that captures the real exception),
then **PR-2 = the F2 worker fix** (now that the exception is known) + the
export-after-real-renames integration test + coverage gates. PR-1 is independently valuable (it
fixes the whole `internal-error` blind spot, not just export) and unblocks PR-2's diagnosis.

### D2 — Surface a **redacted worker-error `detail`/`slug`** on method errors; **no new `ErrorType`**.
The worker's exception detail is **server-domain text** (a Python/Java exception class name + a
short message about *its own* enumeration logic) — it is **not** binary-derived content. ADR-005's
untrusted envelope and the logging-redaction rule govern *binary-derived* bytes (decompilation,
strings, symbol values, comments); a `ghidra.program.model.*` `NullPointerException` /
`AttributeError` from our enumerator is code-domain, like the socket-error type/errno we already log
on transport faults (`rpc_client.py:1000-1009`). It is surfaced **to the server log only**, never to
the client envelope (the public `internal-error` `detail` stays generic per `errors.py:51-52` and
`error-envelope.md`). Mechanism:

- Worker: `dispatch.handle_request`'s `except Exception` records the exception **type name +
  truncated message** as the JSON-RPC error `data.detail` (a *new optional field* alongside the
  existing `data.type` slug — additive, contract-compatible), still with slug `internal-error` and
  the fixed safe `message`. **Defense in depth:** the detail is **length-capped** and passed through
  a small **boundary scrubber** before it leaves the worker, so even if a future enumerator
  interpolates a binary-derived value into an exception message it cannot leak (see "Security").
- Server (`rpc_client._call`, the `RpcCallError` branch, `rpc_client.py:970-973`): log the worker
  `data.detail`+`slug` under the existing redacting logger (`worker.rpc_failed`-style event,
  `method`, `cause="method"`, `slug`, `detail` truncated) **before** raising the public envelope.
  The client envelope is unchanged.

> **Why not a new public `detail` on the error envelope?** Tempting, but the envelope is a **frozen
> WS0 contract** (`errors.py:1`, `error-envelope.md`) whose disclosure rule is *no internals to the
> client*. Worker-internal detail belongs in **server logs under the correlation id**, which is the
> design the envelope already assumes (`errors.py:9-11`, `ErrorEnvelope.correlation_id`). **Ratify**
> the log-only stance (recommended) vs. adding a redacted public field.

### D3 — Capture worker stderr to the server log stream on **abnormal** worker exit; **no durable state**.
`--rm --detach` discards the JVM traceback. ADR-002 forbids durable confidential state — so we do
**not** write worker stderr to a file or keep a log volume. Instead, **on abnormal exit / kill** the
launcher/RPC-client path performs a **bounded, one-shot read** of the engine's captured stderr
(`podman logs <name>` or the detach handle's stream) **before** the `--rm` reaps it, length-caps it
(e.g. ≤2000 chars, as `engine_stderr` already does at `launcher.py:223`), passes it through the same
boundary scrubber, and emits it once on the **server log stream** (stderr, redacted, correlation
id). It is **transient** — nothing is persisted; this mirrors the existing `engine_stderr` capture
already used for launch failures. Worker stderr **may** contain a binary-derived value if PyGhidra
or our code logged one, so the scrub + cap here are **mandatory** (treat worker stderr as
potentially binary-tainted, unlike the structured `data.detail` of D2 which we control).

### D4 — F3 formatter fix: render `exc_info` as **frames-only** `payload["exc"]`; guard reserved keys.
- In `_RedactingJsonFormatter.format` (and the text formatter), when `record.exc_info` is present,
  set `payload["exc"] = self.formatException(record.exc_info)` — the standard library's
  **traceback frames + exception type/message**, **no local variables** (`formatException` never
  echoes locals). Keep `exc_info` in `_RESERVED_RECORD_ATTRS` (so `_safe_extra` still won't blindly
  copy the raw tuple) but render it explicitly through `formatException` in `format`.
- In `_safe_extra` (`logging.py:90-105`): the current loop already skips `_RESERVED_RECORD_ATTRS`,
  so a caller-supplied `extra={"foo": ...}` is fine — **but** the *crash* happens earlier, inside
  the stdlib `LogRecord.__init__` / `Logger.makeRecord`, when `extra` contains a reserved key. Add a
  **`safe_log` boundary helper** (or a thin `LoggerAdapter`) that **drops/renames** any `extra` key
  in a reserved-key set **before** the record is created, so `extra={"msg": ...}` can never reach
  `makeRecord` and crash a handler. Belt-and-braces: `_safe_extra` continues to skip reserved keys
  on the read side too.

### D5 — F2 worker fix, once the exception is known; preserve all ADR-018 invariants.
The repro from PR-1 names the fault. Likely-suspect areas, ranked by how the enumerator touches a
*real* program vs. the synthetic fixtures (do not pre-judge — the repro decides):

1. **Symbol enumeration breadth (steps 3-4, `_jvm_bridge.py:2173-2197`).** A real renamed program
   has many `USER_DEFINED` symbols beyond functions; `getAllSymbols(False)` plus
   `getSymbolType() == SymbolType.FUNCTION` filtering can encounter symbol kinds whose
   `getAddress()` is **null** (e.g. a `USER_DEFINED` symbol with no address, or an external/library
   symbol), making `str(symbol.getAddress())` raise an NPE-via-`str(None-Java)`. **Most likely**,
   given the run was *renames only*.
2. **`getCommentAddressIterator(program.getMemory(), …)` (step 5, `:2207`).** The exact PyGhidra
   binding/overload (memory-set arg) is an ADR-018 "confirm at image build" item (`:2129-2131`); a
   wrong overload or a `None` address from the iterator could raise. (No comments were set in the
   run, but the iterator still runs.)
3. **A composite/signature shape the helpers don't handle** (`_composite_fields_export` returns
   `None` to *skip*, but `_function_signature_export` falls back to `void` — a `getParameters()` /
   `getReturnType()` returning an unexpected `None`/derived type could still raise before the
   fallback). Lower likelihood for a renames-only run.
4. **A `None`/optional field** crossing `_to_text` or an `int(...)` cast on a Java value that is
   `None` (e.g. `getOffset()` on a non-struct, already guarded — but audit the casts).

The fix is **surgical and fail-safe**: skip-not-guess for any element that is not faithfully
representable (matching the existing `_composite_*_export` → `None` skip discipline at `:2160-2162`
and `:2724-2725`), never emit a partial/unfaithful entry, and **never** broaden what counts as
`USER_DEFINED`. Preserve every ADR-018 invariant:

- **ADR-001:** enumeration stays worker-only; the server still assembles inert JSON
  (`registry.py:940-947`) and overlays the authoritative `binary.sha256` (never trusts the worker
  for the binding key).
- **ADR-005:** every binary-derived string stays wrapped at the adapter chokepoint
  (`rpc_client._build_exported_annotation_document` 2031, `_build_exported_entry`).
- **ADR-017:** owner-scoping via `ctx.sessions.authorize` (`registry.py:939`) unchanged.
- **Bounds:** the `_emit` entry-count cap → `limit-exceeded` (`:2146-2151`) and size caps unchanged;
  a fix must not turn a real over-cap program into a crash or a silent truncation.

## The reproduction + capture step (diagnosis-first — the heart of PR-1)

We cannot patch a fault we cannot name. The capture path (D2+D3+D4) is built **first** and proven by
a **reproduction integration test** in the real-worker suite:

1. Build the real worker image (pinned, ADR-003/009); run the existing local real-worker recipe
   (`gmcp-venv` + worker uid override + crun, per `acceptance_run.py` / the bring-up memory).
2. Import `/bin/gzip` (or an equivalently real, stripped fixture — **benign, not malware**, master
   §5; binary samples gitignored), analyze, apply a **batch of real `rename_function` writes**
   through the consent gate (reproducing the run that triggered F2).
3. Call `session_export_annotations`. **Assert it currently raises** (`internal-error`) **and** that
   the **server log now contains a redacted worker `detail`** naming the exception type — i.e. prove
   the D2/D3/D4 instrumentation surfaces the cause. This test is the *negative* repro; it flips to a
   pass in PR-2 (export succeeds, this assertion changes to a success path → kept as the
   export-after-real-renames regression test).

This makes the F2 fix evidence-driven, and **closes the observability coverage gap** F3 named
("can an operator find the cause?").

## Security (no new boundary — correctness + observability hardening)

STRIDE delta vs. ADR-018's TB8 (which is unchanged):

- **Information disclosure (I) — the one real risk here.** Surfacing worker-error detail and worker
  stderr must not leak **binary-derived content** (decompilation, strings, symbol values, comments)
  or session secrets (logging-redaction rule; master §5; ADR-005). Controls:
  - **D2 `data.detail`** is **server-domain** (exception class + message about *our* enumeration
    code). To be safe against a future enumerator interpolating a binary value into a message, the
    worker passes it through a **boundary scrubber + hard length cap** before it crosses the RPC,
    and the server logs it via the **existing redacting formatter** (sensitive-key scrub at
    `logging.py:56-104`). Recommendation: the worker scrubber emits **type name + a fixed-template
    message** and **drops the free-form exception `str()`** unless it matches a safe allow-list —
    i.e. *prefer the exception class name over its message*. **Ratify** how aggressive this is.
  - **D3 worker stderr** is treated as **potentially binary-tainted** (PyGhidra/our code may have
    logged a value): **mandatory** scrub + cap, emitted once, transient (no persistence — ADR-002).
  - **D4 `exc` traceback** is **code frames only** via `formatException` — **no locals echo**. The
    residual risk: a **pydantic `ValidationError`** (or similar) message can echo the **offending
    value** in its text (e.g. "input should be … got 'X'"). When 'X' is binary-derived (an exported
    name/comment), the traceback's *exception message line* could carry it. Mitigation: in the
    formatter, when rendering `exc`, **strip the exception message line of any `ValidationError`-class
    exception to the type + field-locator only** (or render frames without the final message line
    for known value-echoing exception types), so a validation message can't echo a value. **Call
    this out for ratification** — it is the subtle redaction trap in F3's fix.
- **Tampering / Elevation:** unchanged — no new write primitive, no new capability, no broadened
  `USER_DEFINED` scope. The F2 fix only makes a **read** succeed.
- **DoS:** the entry-count/size caps (`limit-exceeded`) stay; the new captures are length-capped and
  one-shot (no unbounded log growth — `topic-resource-management`).
- **Repudiation:** the export audit log (`registry.py:948-956`, sizes/counts only) is unchanged; the
  new worker-error log lines add diagnosability under the correlation id (`topic-logging-observability`).

## Architecture & invariants
- **Ports & adapters:** no port change. `GhidraPort.export_annotations` and the RPC stay as-is; the
  fix is inside `_gh_export_annotations` (worker) + the dispatch/transport observability seams.
- **ADR-001 / ADR-002 / ADR-005 / ADR-017:** all preserved (see D5). No durable state added (D3).
- **Contracts:** the **error envelope is unchanged** (recommended — D2 log-only). The RPC error
  `data` object gains an **optional** `detail` field — additive and backward-compatible
  (`rpc-protocol.md §5`); document it as worker→server-only (never client-facing). No tool-catalog
  change (no new/changed tools).

## Consequences
- The annotation persistence **round-trip works on real programs** (F2), unblocking the resume-triage
  workflow ADR-018 designed.
- **Every `internal-error`** becomes diagnosable from server logs, not just export (F3) — a broad win:
  worker faults now carry a redacted cause + (on abnormal exit) the worker's last stderr, and
  `_log.exception()` finally emits tracebacks.
- The `extra={"msg": ...}` **handler crash** class is eliminated (a latent reliability bug).
- **Coverage gaps closed:** an export-after-real-renames integration test (the gap that hid F2) and an
  observability test ("can an operator find the cause?").
- **Deferred / out of scope:** the F1 worker-OOM/memory work (separate ADR — F1), F4 idle-clock
  heartbeat, F5 name-collision tooling, F6 harness landing. A *general* worker-stderr ring buffer /
  log volume is **rejected** (durable state — ADR-002); D3 is one-shot transient only.

## Alternatives considered
- **Surface a redacted worker `detail` on the public error envelope** (not just logs): more
  convenient for a client, but widens a **frozen** contract and risks the *no-internals-to-client*
  disclosure rule. **Rejected** for log-only (D2) unless human ratifies a public redacted field.
- **Persist worker stderr to a per-session log file/volume:** the natural way to never lose a
  traceback, but reintroduces durable (potentially binary-tainted) state. **Rejected** (ADR-002) —
  D3's one-shot transient read instead.
- **Fix F2 blind (defensively guard every `getAddress()`/cast in the enumerator without a repro):**
  faster to write, but a guess — it could mask the real fault, skip legitimate annotations, or leave
  the next enumeration path broken. **Rejected** — diagnosis-first (D1), repro-driven (D5).
- **Render full `exc_info` including locals** (`logging.Formatter` with a locals-dumping handler):
  maximally informative, but echoes values → **direct binary-content-leak** path. **Rejected** —
  frames-only `formatException` (D4) + the validation-message strip.
- **One PR for F2+F3 together:** simpler bookkeeping, but you cannot diagnose F2 without F3's
  instrument; PR-1-first (D1) is both safer and independently valuable.

## Implementation increment (follows this design PR; honors batch-atomicity — disjoint files per PR)

**PR-1 — observability + diagnosis (lands first):**
1. **worker `dispatch.py`:** `handle_request`'s `except Exception` (`:380-381`) captures the
   exception **type name + scrubbed, capped message** into the JSON-RPC error `data.detail`
   (additive), keeping slug `internal-error` + the fixed safe `message`. Add the boundary scrubber.
2. **`rpc_client.py`:** in the `RpcCallError` branch (`:970-973`), log the worker `slug`+`detail`
   (redacted, truncated) under the existing logger before raising the public envelope. Where the
   transport path can read engine stderr on abnormal exit (`launcher.py` kill/`--rm` path,
   alongside the existing `engine_stderr` cap at `:223`), emit a one-shot redacted, capped worker
   stderr line.
3. **`logging.py`:** render `payload["exc"] = self.formatException(record.exc_info)` in both
   formatters (frames-only; strip value-echoing `ValidationError` message lines); add the
   `safe_log`/adapter reserved-key guard so `extra={"msg":...}` can't crash a handler. Unit-test
   both with a known-bad input (prove the formatter emits a traceback **and** that a reserved-key
   `extra` does **not** crash — and that a binary-ish value in a validation message is **not**
   echoed). Watch the testing-rule false-pass trap: use **public-named** probe modules, not
   `_probe.py`.
4. **integration (real-worker suite):** the **reproduction test** — import gzip → analyze → batch
   real renames → export → assert it raises **and** the server log now names the exception type
   (D2/D3/D4 proven). Benign fixture only; samples gitignored.

**PR-2 — the F2 worker fix (after PR-1 names the fault):**
5. **`_jvm_bridge.py` `_gh_export_annotations`** (+ the suspect helpers `:2173-2219`, `:2679-2763`):
   surgical fix per the named exception — skip-not-guess for non-representable elements, guard the
   identified `None`/null path, **no broadened `USER_DEFINED` scope**; preserve ADR-001/005/017 +
   bounds.
6. **integration:** flip the PR-1 repro to the **export-after-real-renames regression test** (export
   succeeds; round-trips through a same-binary import to confirm replayability, reusing the ADR-018
   import path). Add coverage gates: the worker enumerator paths are JVM-edge (`# pragma: no cover`
   server-side, exercised by the real-worker integration suite — `topic-testing`); the **server-side
   builders + the formatter/observability changes hit the §4 line+branch gate** and the
   error-handling paths are **critical-path** (fail-closed) — assert the negative paths.
