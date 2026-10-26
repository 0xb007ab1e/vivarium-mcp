"""Live ADR-076 / TB9 dashboard interactive backend e2e (GATED, real worker).

Closes the ``pragma: no cover`` gap on the live transport (:class:`McpToolCaller`): it proves the
dashboard interactive path end-to-end — browser ``POST /api/command`` → :func:`commands.dispatch`
→ a worker-capable executor → ``McpToolCaller`` → a REAL ``python -m vivarium`` MCP server (which
spawns a hardened Ghidra worker). The hermetic suite (``test_dashboard.py``) covers policy, gating,
and the executors against fakes; this exercises the actual live wiring.

What it asserts (TB9 invariants, live):

- A read-only op returns a live result with binary-derived leaves **Untrusted-wrapped** (ADR-005) —
  the dashboard renders them inert; here we just confirm the envelope survives the round-trip.
- A **write** op (``rename_function``) stops at the endpoint with **202 needs-approval** and is
  **never executed** against the live program — program mutation stays on the human-approved
  write-consent path (ADR-012), exactly as the policy promises.
- Compute ops (``session_import``/``session_analyze``) run only because a worker-capable executor
  (:class:`WorkerExecutor`) is explicitly wired — the gated operator enablement (ADR-076).

Gated like the other ``_oss`` real-worker e2e (``VIVARIUM_INTEGRATION`` + built fixtures + a worker
image + a container engine); otherwise the module skips cleanly. Runs under
``.github/workflows/e2e-groundtruth.yml``. No real malware — the benign OSS fixture only.

Note: ``McpToolCaller`` runs a daemon thread + a spawned stdio server with no explicit close API;
both are reaped when the pytest process exits (adequate for a single gated e2e).
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from starlette.testclient import TestClient

from tests.e2e.test_abuse_composite_oss import _unwrap
from tests.e2e.test_abuse_containment_oss import (
    _SKIP,
    _first_valid_fixture,
    _fixtures_dir,
    _timeout,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]


def _post(client: TestClient, op: str, params: dict[str, Any] | None = None, *, tok: str) -> Any:
    """POST one command to ``/api/command`` with the bearer token; return the httpx response."""
    body: dict[str, Any] = {"op": op}
    if params is not None:
        body["params"] = params
    return client.post("/api/command", json=body, headers={"authorization": f"Bearer {tok}"})


def test_dashboard_interactive_live_mcptoolcaller() -> None:
    """Drive the dashboard interactive backend over a REAL vivarium server (ADR-076 / TB9)."""
    from vivarium.dashboard.app import build_app
    from vivarium.dashboard.catalog import catalog
    from vivarium.dashboard.executor import McpToolCaller, WorkerExecutor
    from vivarium.dashboard.providers import DemoProvider

    fixtures = _fixtures_dir()
    fixture = _first_valid_fixture()
    tok = "e2e-interactive-tok"  # ephemeral per-test bearer, not a real credential
    prev_token = os.environ.get("VIVARIUM_DASHBOARD_TOKEN")
    prev_root = os.environ.get("VIVARIUM_IMPORT_ROOT")
    # build_app reads the bearer from env; McpToolCaller spawns `python -m vivarium` inheriting
    # os.environ, so the import root must be exported for the spawned server (like _server_params).
    os.environ["VIVARIUM_DASHBOARD_TOKEN"] = tok
    os.environ["VIVARIUM_IMPORT_ROOT"] = str(fixtures)
    caller: McpToolCaller | None = None
    try:
        caller = McpToolCaller(timeout=_timeout().total_seconds())
        client = TestClient(build_app(DemoProvider(), executor=WorkerExecutor(catalog(), caller)))

        # session_create (read-only → allow) executes live and returns a session id.
        r = _post(client, "session_create", {"label": "dash-e2e"}, tok=tok)
        assert r.status_code == 200, r.text
        sid = r.json()["result"]["session_id"]
        assert sid

        # session_import + session_analyze are COMPUTE ops — run only via the wired WorkerExecutor.
        r = _post(
            client, "session_import", {"session_id": sid, "source_ref": str(fixture)}, tok=tok
        )
        assert r.status_code == 200, r.text
        r = _post(client, "session_analyze", {"session_id": sid}, tok=tok)
        assert r.status_code == 200, r.text

        # program_metadata (read-only) returns a live result with safe scalar fields.
        r = _post(client, "program_metadata", {"session_id": sid}, tok=tok)
        assert r.status_code == 200, r.text
        assert r.json()["result"].get("format")

        # list_functions (read-only): a binary-derived name leaf survives as an Untrusted envelope.
        r = _post(client, "list_functions", {"session_id": sid}, tok=tok)
        assert r.status_code == 200, r.text
        fns = r.json()["result"]["functions"]
        assert fns, "expected functions from a real analyzed binary"
        # Assert the ENVELOPE shape, not just presence (`_unwrap` passes bare values through):
        # FunctionListOut.name is Untrusted[str], so it must arrive wrapped (ADR-005) — a regression
        # that stopped wrapping would be caught here, which `_unwrap(...) is not None` alone misses.
        raw_name = fns[0]["name"]
        assert isinstance(raw_name, dict) and "value" in raw_name, (
            f"expected an Untrusted envelope for a binary-derived name, got {raw_name!r}"
        )
        assert _unwrap(raw_name) is not None

        # A WRITE op stops at the endpoint — 202 needs-approval, NEVER executed against the live
        # program (ADR-012 write-consent; the worker-capable executor is not even consulted).
        r = _post(client, "rename_function", tok=tok)
        assert r.status_code == 202
        assert r.json()["decision"] == "needs-approval"
    finally:
        for key, prev in (
            ("VIVARIUM_DASHBOARD_TOKEN", prev_token),
            ("VIVARIUM_IMPORT_ROOT", prev_root),
        ):
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev
