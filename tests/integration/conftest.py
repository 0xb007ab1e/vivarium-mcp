"""Integration-suite gating: skip cleanly unless a real Ghidra worker is available (WS5).

The integration tests require a real, hardened Ghidra worker container pinned by digest (WS3) — an
image pull and container run are GATED supply-chain/runtime actions (PLAN §6), so they MUST NOT
run in the unit/coverage CI job. This conftest centralizes the skip guard: every integration test
is collected but skipped unless ``GHIDRA_MCP_INTEGRATION`` is set to a truthy value AND the worker
prerequisites are met.

A skipped (not errored, not failed) integration suite keeps the default ``pytest`` run green while
the worker image does not yet exist; the dedicated integration job sets the env var.
"""

from __future__ import annotations

import os

import pytest

_ENV_FLAG = "GHIDRA_MCP_INTEGRATION"


def _integration_enabled() -> bool:
    """Return whether integration tests are explicitly enabled via the environment flag."""
    return os.environ.get(_ENV_FLAG, "").strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(scope="session")
def integration_enabled() -> bool:
    """Session fixture exposing whether the integration flag is set (for conditional asserts)."""
    return _integration_enabled()


@pytest.fixture
def worker_image() -> str:
    """Resolve the pinned-by-digest worker image reference, or skip if unset.

    The image reference is provided by the integration environment (WS3 pins it by digest). When
    absent, the dependent test is skipped rather than failing — there is no worker to talk to.
    """
    ref = os.environ.get("GHIDRA_MCP_WORKER_IMAGE", "").strip()
    if not ref:
        pytest.skip("no GHIDRA_MCP_WORKER_IMAGE pinned-by-digest reference set")
    return ref


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip every ``@pytest.mark.integration`` item unless the integration flag is enabled.

    Applied at collection time so the unit/coverage job (which never sets the flag) reports the
    integration tests as *skipped*, not as errors — keeping the default run green and hermetic.
    """
    if _integration_enabled():
        return
    skip_integration = pytest.mark.skip(
        reason=f"integration suite disabled; set {_ENV_FLAG}=1 with a real worker to run"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
