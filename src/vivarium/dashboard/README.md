# Vivarium status dashboard (read-only, display-only MVP)

A small, **separate** Starlette ASGI app that surfaces in-process status for a human to validate in
real time — live analysis sessions (progress + tool timeline + output for review) and the
build/deliverable snapshot (tool catalog, gates, PRs, benchmark). It is **read-only**: no tool
invocation, no mutation, no gated action.

## Run

```bash
pip install -e ".[dashboard]"          # pulls uvicorn (starlette is already a base dep)
python -m vivarium.dashboard            # binds 127.0.0.1:8760 by default
```

Config (env):

| Var | Meaning | Default |
|---|---|---|
| `VIVARIUM_DASHBOARD_BIND` | `host:port`. Host MUST be loopback or a `100.64.0.0/10` tailnet IP. | `127.0.0.1:8760` |
| `VIVARIUM_DASHBOARD_TOKEN` | Optional shared bearer token gating every request (constant-time compare). | unset |

Tailnet pattern (`topic-tailnet-dev-access`): run one instance on loopback for on-host tooling and
one on the tailnet IP for phone/laptop access, e.g. `VIVARIUM_DASHBOARD_BIND=100.x.y.z:8760`.

## Security posture (baked in, not retrofitted)

- **Untrusted rendering (ADR-005).** Every binary-derived field vivarium returns is hostile,
  attacker-controlled data. The API tags such fields (`UiValue{untrusted: true}`) and the browser
  renders them as **inert text only** (`textContent`, never `innerHTML`) under a strict, inline-free
  CSP. The envelope stays inert end-to-end.
- **Strict CSP + hardening headers.** `default-src 'none'`, no `unsafe-inline`/`unsafe-eval`, all
  JS/CSS external; `nosniff`, `no-referrer`, `X-Frame-Options: DENY` + `frame-ancestors 'none'`,
  a tight `Permissions-Policy`, `Cache-Control: no-store`.
- **Read-only, GET-only.** No write verb; the app holds no write path and cannot invoke a tool.
- **Fail-closed bind.** The runner refuses any public / `0.0.0.0` / non-tailnet bind and exits
  non-zero — you cannot accidentally expose it.
- **Optional bearer gate.** When `VIVARIUM_DASHBOARD_TOKEN` is set, every request must present it.

## Architecture

The data source is pluggable via the `StatusProvider` Protocol so the UI is decoupled from its
source. The MVP ships `DemoProvider` — deterministic synthetic data (no I/O, clock, or randomness)
that exercises every render path, so the frontend and the untrusted-render harness are buildable and
reviewable before a live provider exists.

## Follow-ups (before any wider exposure)

- **Dedicated STRIDE pass.** A browser surface is a **new trust boundary**. The MVP is scoped
  read-only + tailnet-only precisely so it ships behind that reduced surface; the full STRIDE pass
  over this TB (aligned with `docs/security/threat-model.md`) is required before production.
- **Reuse the server's principals.** Production auth reuses the server's per-principal authZ
  (ADR-017/019), never invents its own — the MVP bearer gate is an interim, tailnet-scoped control.
- **Live provider.** A live `StatusProvider` over `session_status` + `$/progress` (ADR-030) +
  streaming jobs (ADR-040) + metrics (ADR-044) and `gh`/CI — same interface, no UI change.
