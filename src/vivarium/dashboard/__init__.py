"""Read-only status dashboard for Vivarium (display-only MVP).

A small, SEPARATE Starlette ASGI app that surfaces in-process status + work-in-progress for a human
to validate in real time: live analysis sessions (progress + tool timeline + output for review) and
the build/deliverable snapshot (tool catalog, gates, PRs, benchmark). Read-only — NO tool
invocation, NO mutation, NO gated action. Interactivity (driving vivarium from the UI) is a
deliberate later increment behind the existing write-consent + per-principal authz.

**Non-negotiables (baked in from the MVP):**

- **Untrusted rendering (ADR-005).** Every binary-derived field vivarium returns is hostile
  attacker-controlled data. The dashboard API tags such fields (:class:`~vivarium.dashboard.
  models.UiValue` with ``untrusted=True``) and the browser renders them as INERT text only
  (``textContent``, never ``innerHTML``) under a strict, inline-free CSP. Inert end-to-end.
- **New trust boundary.** A browser surface is a new TB — it gets its own STRIDE pass before
  production (see ``README.md``); it reuses the server's principals (ADR-017/019), never invents
  auth.
- **Tailnet-only dev access (`topic-tailnet-dev-access`).** The runner binds loopback + the tailnet
  IP and FAILS CLOSED on a public/``0.0.0.0`` bind — never the public internet.

The data source is pluggable (:class:`~vivarium.dashboard.providers.StatusProvider`): the MVP ships
a deterministic :class:`~vivarium.dashboard.providers.DemoProvider`; a live provider tapping the MCP
server's ``session_status`` / ``$/progress`` (ADR-030) / streaming jobs (ADR-040) / metrics
(ADR-044) and ``gh``/CI is the next increment (same interface).
"""

from vivarium.dashboard.app import build_app

__all__ = ["build_app"]
