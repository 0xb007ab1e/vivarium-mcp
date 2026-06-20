# ADR-039: Run status reporting to the end user

- **Status:** Accepted (v1.7; human-requested 2026-06-20). Ratified: **CI workflow runs report
  status to the end user (start + completion) via GitHub annotations + job summary always, and an
  optional ntfy push when `STATUS_NTFY_URL` is set (no-op without it); in-band progress for the
  server's own long operations is NOT in scope here — it already exists as ADR-030.**
- **Date:** 2026-06-20
- **Deciders:** Human (requested the feature) + PM; recorded by the Software Architect.
- **Context source:** Dispatched/scheduled `live-regression` runs were silent — the end user had
  to poll for status during and after a run instead of being told.

## Context

Long-running work surfaces in two distinct places, and "report status to the end user" means
different mechanisms for each:

1. **The Vivarium MCP server's own long operations** (e.g. `session_analyze`). These already report
   live status in-band over MCP: a client-supplied `progressToken` causes the server to stream
   `notifications/progress` (percent + a closed-vocabulary phase, never binary-derived text) over
   both the stdio and HTTP/SSE transports. That is **ADR-030** (Accepted; Phase 1 worker→server log
   frames, Phase 2 MCP client relay) and is the correct, product-native channel for server
   operations. This ADR does **not** change it; it adds an end-to-end integration test that proves
   those notifications actually reach a real MCP client (previously only unit-tested with a fake
   Context).

2. **CI workflow runs** (the `live-regression` GitHub Actions workflow). The MCP server is not in
   the loop for a CI run, so MCP/SSE cannot carry its status. These runs were silent: the only way
   to learn the result was to open the Actions UI or ask. This ADR fixes that.

## Decisions

- **D1 — CI run status is reported at start and on completion.** `live-regression` emits a `start`
  status (run id, event, ref) and a `completion` status (overall job result plus per-suite
  pass/fail/skip counts parsed from the hard-gate and advisory JUnit reports).
- **D2 — Three delivery layers, degrading gracefully.** (a) GitHub annotations (`::notice::` /
  `::error::`) visible on the run page during the run; (b) a rich `$GITHUB_STEP_SUMMARY` on
  completion; (c) an optional **ntfy push** to `secrets.STATUS_NTFY_URL` so it reaches a
  phone/desktop. The push is a **no-op when the secret is unset**, so the workflow is safe in
  forks/PRs and needs no secret to function.
- **D3 — Reusable composite action.** The annotate + summary + push logic lives in
  `.github/actions/run-status/` so other workflows can adopt it. Inputs are passed via env (never
  interpolated into the shell body) to avoid command injection.
- **D4 — Notifications are best-effort and never fail the job.** A push timeout/error emits a
  `::warning::` and continues; status reporting must not turn a green run red.
- **D5 — Redaction.** Status messages carry only run metadata and test counts — no binary-derived
  content (master §5), consistent with ADR-030's progress-frame constraint.
- **D6 — Channel choice.** ntfy is the default push target (matches the operator's existing
  notification stack). A Slack/Discord/generic webhook can be added later behind the same composite
  action without changing the workflow.

## Execution plan

1. Add the `.github/actions/run-status` composite action (annotation + summary + optional ntfy).
2. Wire `live-regression` to notify at start and to run a final `Report run status` step (`always()`).
3. Add `tests/integration/test_analyze_progress_client.py` — a gated, real-worker test asserting a
   real MCP client receives `notifications/progress` during `session_analyze` (closes the ADR-030
   end-to-end gap); run it in the advisory live-regression step.
4. Configure `STATUS_NTFY_URL` as a repo secret to enable the push (optional; the run works without).
