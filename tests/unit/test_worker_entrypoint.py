"""Unit tests for the worker container entrypoint (``worker/__main__.py``) — JVM-free (gap N6).

The launcher reconciles the per-session socket path from the deploy-injected environment and hands
off to the JVM bridge. The path reconciliation and the fail-closed missing-id guard are pure stdlib
(testable without PyGhidra); only the final ``worker_main()`` call touches the JVM, which we stub.
This closes the entrypoint's coverage gap now that ``worker/`` is under the gate.
"""

from __future__ import annotations

import os

import pytest
from worker.__main__ import _resolve_socket_path, main


def test_resolve_socket_path_default_dir() -> None:
    """A bare session id resolves under the default /run/vivarium dir as <sid>.sock."""
    assert _resolve_socket_path({"VIVARIUM_SESSION_ID": "abc123"}) == "/run/vivarium/abc123.sock"


def test_resolve_socket_path_custom_dir_strips_trailing_slash() -> None:
    """A custom socket dir is honored; a trailing slash does not double up the separator."""
    env = {"VIVARIUM_SESSION_ID": "sid", "VIVARIUM_RPC_SOCKET_DIR": "/run/vivarium/x/"}
    assert _resolve_socket_path(env) == "/run/vivarium/x/sid.sock"


@pytest.mark.parametrize("env", [{}, {"VIVARIUM_SESSION_ID": ""}, {"VIVARIUM_SESSION_ID": "   "}])
def test_resolve_socket_path_missing_id_fails_closed(env: dict[str, str]) -> None:
    """A missing/empty/whitespace session id raises (the worker must not start without identity)."""
    with pytest.raises(ValueError, match="VIVARIUM_SESSION_ID is required"):
        _resolve_socket_path(env)


def test_main_missing_session_id_returns_2_before_any_jvm(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """main() with no session id exits 2 with a stderr diagnostic, before any JVM import."""
    monkeypatch.delenv("VIVARIUM_SESSION_ID", raising=False)
    rc = main([])
    assert rc == 2
    assert "fatal" in capsys.readouterr().err.lower()


def test_main_exports_socket_and_runs_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    """main() derives + exports VIVARIUM_RPC_SOCKET, then returns the worker's exit code."""
    monkeypatch.setenv("VIVARIUM_SESSION_ID", "sid42")
    monkeypatch.setenv("VIVARIUM_RPC_SOCKET_DIR", "/run/vivarium")
    monkeypatch.delenv("VIVARIUM_RPC_SOCKET", raising=False)
    # Stub the lazily-imported JVM bridge entry so no PyGhidra/JVM is needed.
    monkeypatch.setattr("vivarium.ghidra._jvm_bridge.worker_main", lambda: 0, raising=True)
    rc = main([])
    assert rc == 0
    assert os.environ["VIVARIUM_RPC_SOCKET"] == "/run/vivarium/sid42.sock"
