"""E2E-suite gating: skip cleanly until the MCP server shell (WS1) is implemented (WS5).

The end-to-end tests drive the real server over the MCP **stdio** transport with a
:class:`tests.conftest.FakeGhidraPort` injected at the composition root — no real Ghidra worker is
needed (the fake stands in for the adapter), but the server application factory and stdio runner
(``vivarium.server.app.build_app`` / ``run_stdio``) are WS1 stubs in Wave-1. Until they are
implemented, these tests must skip cleanly rather than error.

The guard probes whether ``build_app`` is still a reserved stub; if so, every e2e test is skipped.
Unlike the integration suite, e2e does NOT require a gated image pull — only the server code — so
it activates automatically once WS1 lands (Wave-2), no env flag required.
"""

from __future__ import annotations

from typing import Any, cast

import pytest


def _server_shell_ready() -> bool:
    """Return whether the WS1 server shell is implemented (``build_app`` no longer a stub).

    Calls the factory with placeholder args inside a guard: a ``NotImplementedError`` means the
    stub is still reserved (Wave-1) → e2e is skipped. Any other outcome (success or a different,
    argument-related error) means the shell exists and e2e can attempt to drive it.

    The factory is invoked through an ``Any`` view so this hermetic stub-probe does not have to
    satisfy the (now-tightened) typed ``build_app`` signature — the call deliberately passes
    placeholder ``None`` args only to distinguish "reserved stub" from "implemented".
    """
    from vivarium.server import app

    build_app = cast(Any, app.build_app)
    try:
        build_app(None, session_manager=None)
    except NotImplementedError:
        return False
    except Exception:
        # Any other failure (e.g. a TypeError from the placeholder args) means the shell is
        # implemented, not a reserved stub.
        return True
    return True


@pytest.fixture(scope="session")
def server_shell_ready() -> bool:
    """Session fixture exposing whether the server shell is implemented."""
    return _server_shell_ready()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip all e2e tests until the WS1 server shell exists (keeps Wave-1 runs green)."""
    if _server_shell_ready():
        return
    skip_e2e = pytest.mark.skip(
        reason="e2e disabled: vivarium.server.app.build_app is still a WS1 stub (Wave-1)"
    )
    for item in items:
        item.add_marker(skip_e2e)
