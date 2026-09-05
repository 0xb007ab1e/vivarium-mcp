# Vivarium status dashboard (read-only, display-only MVP)

A small, **separate** Starlette ASGI app that surfaces in-process status for a human to validate in
real time — live analysis sessions (progress + tool timeline + output for review), the richer
per-session analysis panels (**binary format**, **imports**, **exports**, **strings**, **call
graph**), and the build/deliverable snapshot (tool catalog, gates, PRs, benchmark). It is
**read-only**: no tool invocation, no mutation, no gated action.

## Layout (VSCode-style workbench)

The UI is a three-region shell: a **titlebar**, an **Explorer sidebar**, a **central artifact
viewer**, and a **status bar**. The Explorer lists each session and its artifacts (Overview,
Imports, Exports, Strings, Call graph, each decompiled output, Verdict, Timeline) plus Build;
selecting one renders it type-appropriately in the viewer — colorized C **code blocks** (line-number
gutter) for decompiled output, tables for imports/exports/strings, a key/value grid for the binary
format, an adjacency list for the call graph. Syntax colorization is a small self-contained
tokenizer in `app.js` (no external libraries — strict CSP) that emits **every** token via
`textContent`, so binary-derived content stays inert even while highlighted (ADR-005).

## Workflows (RE workbench — Phase 1)

The dashboard is growing into an RE workbench. **Explorer → Workflows → Catalog** shows the
**operation palette** (vivarium tools grouped: session / listing / code / graph-xrefs / scans /
similarity / annotate; compute/write ops are marked **gated**) and the **prebuilt workflows** —
Triage, Call-tree exploration, AI annotation pass, Scans & similarity — as ordered steps, served
read-only at `/api/catalog`. A per-session **Runs** view renders the streamed `workflow` run kind as
a step tracker (per-step state + links to each step's produced artifact).

**Phase 1 is author + visualize only:** the dashboard stays read-only and decoupled — workflows are
executed by the agent out-of-band and their results stream back into the session views. A custom
**step-list builder** is next; interactive execution (browser → server) and the gated,
propose-first AI-annotation flow come after a dedicated STRIDE threat model + write-consent/authZ.

## Interactive call graph

The **Call graph** view is an interactive, hand-built inline-SVG graph (no external library — strict
CSP). Nodes are typed — **functions**, **imports** (external calls), **strings/data** — connected by
directed **call** edges and dashed **data-reference** edges (arrowheads show inbound vs outbound).
Interactions: **drag** a node to move it, **drag** the background to pan, **scroll** to zoom,
**click** a node to open its artifact detail, **double-click** to expand its neighbors into the
graph; a **depth** control bounds how many hops from the focus are shown. Initial node placement is a
**per-viewer preference** (persisted in `localStorage`, guarded): **layered** (top-down by call
direction), **force-directed**, or **radial**. The function detail's **"show in graph"** button
focuses the graph on that function. Node labels are real DOM text (`textContent`), so untrusted
names stay inert even in the graph (ADR-005); the callers/callees/xref lists in the function view are
the accessible, keyboard-navigable equivalent.

## RE browser (functions, cross-references, lineage)

The viewer is a reverse-engineering browser. The Explorer lists each session's **functions**;
selecting one opens a **call-hierarchy** view: decompiled C (colorized, with **jump-to-symbol**
links) plus **Callers**, **Callees**, and **Cross-references** panels and a **variables/params**
table. Every relationship is a clickable cross-link that navigates by address; strings, imports, and
exports carry `referenced_by` back-references, so you can walk both directions (jumping to a table
highlights the target row). Each artifact shows a **lineage** footer (source tool + address).

Per-function data streams as the `function` event kind (keyed by a safe address `id`) and may arrive
in parts — a stub (name + callers/callees) first, then a hydration event with the same `id` adding
decompile / variables / xrefs. The browser **merges by id** (progressive hydrate) and updates an
open artifact **in place** (scroll preserved). Build a navigable reference with
`vivarium.dashboard.models.sym_ref(address, name, **safe_extras)` — a safe `id` + a tagged untrusted
`name`. Every link label is rendered `textContent`-only, so content stays inert even while navigable
(ADR-005).

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
