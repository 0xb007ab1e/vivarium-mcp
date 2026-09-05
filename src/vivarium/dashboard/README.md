# Vivarium status dashboard (read-only, display-only MVP)

A small, **separate** Starlette ASGI app that surfaces in-process status for a human to validate in
real time — live analysis sessions (progress + tool timeline + output for review), the richer
per-session analysis panels (**binary format**, **imports**, **exports**, **strings**, **call
graph**), and the build/deliverable snapshot (tool catalog, gates, PRs, benchmark). It is
**read-only**: no tool invocation, no mutation, no gated action.

## Analysis panels (streamed)

Beyond the progress + timeline, the SSE stream carries structured panel events —
`metadata` (format/arch/bits/endian/entry/size + program/compiler), `imports`, `exports`,
`strings`, and `callgraph` (rendered as an accessible caller→callees adjacency list). Each carries a
`data` payload. **Tagging convention (ADR-005):** `data` holds *safe* scalars (counts, hex
addresses, closed labels); every binary-derived leaf (symbol names, strings, call-graph labels) is a
tagged value `{"value": …, "untrusted": true}` — never a bare string — and the browser renders every
tagged leaf **inert** (`textContent`), exactly like a decompiled-output pane. Build a leaf with
`vivarium.dashboard.models.tag()`.

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
| `VIVARIUM_DASHBOARD_STATE` | Optional path to a JSON state file. When set, the dashboard serves **live** data from it (`FileStatusProvider`); unset, it serves the deterministic `DemoProvider`. | unset |

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
source:

- **`DemoProvider`** — deterministic synthetic data (no I/O, clock, or randomness) that exercises
  every render path; the default, for building/reviewing the frontend + untrusted-render harness.
- **`FileStatusProvider`** (`state.py`) — the first **live** path: reads a JSON **state file** and
  tails it for SSE. A producer driving a real analysis through the vivarium MCP tools writes the
  file via `DashboardState` (`upsert_session` / `append_event` / `set_build`, atomic replace on each
  save). This is an intentionally decoupled bridge — the dashboard process never links the MCP
  server; the file is the channel. Binary-derived event `content` stays tagged `untrusted` end to
  end (the bridge never downgrades the ADR-005 envelope). The state file is a local dev artifact
  (loopback/tailnet only) holding no secret.

## Follow-ups (before any wider exposure)

- **Dedicated STRIDE pass.** A browser surface is a **new trust boundary**. The MVP is scoped
  read-only + tailnet-only precisely so it ships behind that reduced surface; the full STRIDE pass
  over this TB (aligned with `docs/security/threat-model.md`) is required before production.
- **Reuse the server's principals.** Production auth reuses the server's per-principal authZ
  (ADR-017/019), never invents its own — the MVP bearer gate is an interim, tailnet-scoped control.
- **Direct live provider.** The file bridge is the first live path; a provider that taps the server
  directly (`session_status` + `$/progress` (ADR-030) + streaming jobs (ADR-040) + metrics
  (ADR-044) and `gh`/CI) is the next step — same `StatusProvider` interface, no UI change.
