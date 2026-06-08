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

#: Default worker-image reference for LOCAL validation when ``GHIDRA_MCP_WORKER_IMAGE`` is unset.
#: CI pins the image BY DIGEST via the env var (WS3, std-supplychain); this convenience default is
#: the locally-built dev tag used by the manual in-worker smoke. It only takes effect once the
#: integration flag is already set, so the unit/coverage job (flag unset) never reaches it.
_DEFAULT_WORKER_IMAGE = "localhost/ghidra-mcp-worker:dev"


def _integration_enabled() -> bool:
    """Return whether integration tests are explicitly enabled via the environment flag."""
    return os.environ.get(_ENV_FLAG, "").strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(scope="session")
def integration_enabled() -> bool:
    """Session fixture exposing whether the integration flag is set (for conditional asserts)."""
    return _integration_enabled()


@pytest.fixture
def worker_image() -> str:
    """Resolve the pinned-by-digest worker image reference (falling back to the dev tag).

    The image reference is provided by the integration environment (WS3 pins it by digest). When
    the env var is unset, fall back to the locally-built dev tag (``_DEFAULT_WORKER_IMAGE``) so a
    maintainer can validate against a freshly-built image without exporting the var; CI always
    exports the pinned-by-digest reference. This fixture is only reached when the integration flag
    is enabled, so the unit/coverage job never depends on an image existing.
    """
    return os.environ.get("GHIDRA_MCP_WORKER_IMAGE", "").strip() or _DEFAULT_WORKER_IMAGE


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
