# Contract: Error Envelope (FROZEN — WS0)

> Pydantic source of truth: [`src/vivarium/core/errors.py`](../../src/vivarium/core/errors.py).
> RFC 9457 (Problem Details) style, adapted to the MCP tool context. Returned on **any** failure.

## Shape

```jsonc
{
  "type":           "validation-error",   // stable machine-readable category (slug)
  "title":          "Invalid arguments",  // short human summary (stable per type)
  "detail":         "field 'address' is not a valid hex address",  // safe, specific; NO internals
  "status":         400,                  // optional, mirrors HTTP semantics
  "correlation_id": "c-1a2b3c",           // ties to redacted server-side logs
  "retryable":      false                 // transient vs terminal; default false (fail closed)
}
```

- **Frozen**, rejects extra fields. `title`/`detail` length-bounded; `status` in 400–599.

## `type` values (stable; clients may branch on these)

| `type` | meaning | typical `status` | retryable |
|--------|---------|------------------|-----------|
| `validation-error` | tool args failed boundary validation (TB1) | 400 | no |
| `not-found` | requested object doesn't exist | 404 | no |
| `session-invalid` | session unknown/expired/evicted (**BOLA-safe**) | 404 | no |
| `forbidden` | authenticated + owns the target, but not permitted for this op (ADR-036) | 403 | no |
| `limit-exceeded` | size/count/time bound hit (DoS control) | 413 / 429 | maybe |
| `timeout` | per-tool/analysis deadline elapsed; worker may be killed | 408 / 504 | maybe |
| `worker-unavailable` | worker unreachable/crashed/evicted mid-call | 503 | yes |
| `resource-exhausted` | worker OOM-killed / exited from resource pressure (ADR-023) | 503 | no |
| `analysis-failed` | Ghidra couldn't analyze the input (not a server bug) | 422 | no |
| `internal-error` | unexpected server fault; detail is generic | 500 | no |

> **`forbidden` (v1.5 — ADR-036):** an ADDITIVE slug — no existing slug is repurposed. Returned when
> the caller is authenticated and owns the target session but lacks permission for **this** operation:
> a missing OAuth capability (ADR-033 scope→tool authZ) or absent write/structural consent (ADR-012).
> **Distinct from `validation-error`** ("your request was malformed") and **from `session-invalid`**.
> **Critical invariant:** an ownership / cross-caller denial is NEVER `forbidden` — it stays
> `session-invalid` (404) so a 403 cannot become an existence oracle (BOLA — `std-owasp-api` API1).
> So `forbidden` only ever fires *after* the owner check has passed. `detail` is a fixed, value-free
> string (never the token, scope contents, or which capability). Not retryable.
>
> **`resource-exhausted` (v1.3 — ADR-023 / F1):** an ADDITIVE slug — no existing slug is repurposed.
> Distinct from `worker-unavailable` so a client can surface a precise "increase worker memory or
> reduce input size" hint. **Not retryable** (the same input against the same memory cap would OOM
> again — the operator must raise `VIVARIUM_WORKER_MEM_MIB` or the client shrink the input). The
> `detail` is a safe string that may name the configured cap + the `VIVARIUM_WORKER_MEM_MIB` knob
> (ADR-037 §3 sizing hint) — still no binary content / host paths, and `type`/`title`/`status`/
> `retryable` are unchanged (`detail` is the non-frozen per-occurrence field). The worker's death is
> classified server-side via a container-engine metadata query — the `OOMKilled` flag, the cgroup
> OOM-kill exit `137`, or the JVM `ExitOnOutOfMemoryError` heap-OOM self-exit `3` (ADR-037) — NO
> binary parsing (ADR-001).

## Disclosure rules (master §5, `topic-error-handling`)

- `detail` is a **safe** summary: **never** a stack trace, host/file path, JVM/dependency version,
  or any binary-derived content. Full diagnostics are logged server-side under `correlation_id`.
- **`session-invalid` is BOLA-safe:** the same response is returned whether the id is unknown,
  expired, or belongs to another caller — it never reveals that another session exists.
- **Fail closed:** anything not raised as a typed `GhidraMcpError` maps to a generic
  `internal-error` envelope (never leak the underlying exception).
