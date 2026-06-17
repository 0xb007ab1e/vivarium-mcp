"""Self-test for the acceptance-run harness over a benign OSS fixture (WS5; GATED).

Drives ``scripts/acceptance_run.py`` mode **analyze** end-to-end against the benign,
source-available cJSON fixture (the same stripped OSS binary the ground-truth / naming-eval e2e
use — master §5, no
malware, no committed sample) through the REAL hardened worker chain, and asserts the harness
produced its artifacts: the manifest, at least one per-function JSON, the names template, the
progress ``run.log`` (with ``step``/``function`` lines), and ``summary.json``.

This is an acceptance/dogfooding tool's smoke test, NOT a unit feature — it is
``integration``-marked so the unit/coverage job skips it, and additionally skips cleanly unless the
gated real-worker
prerequisites (the integration flag, a built fixtures dir, a pinned worker image, and a container
engine) are all present. It never uses a real/unknown binary; the input is the benign OSS fixture.

The out dir is an isolated ``tmp_path`` (never the repo); the harness writes the (binary-derived)
analysis output there and only safe scalars to the progress log.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_ENV_INTEGRATION = "GHIDRA_MCP_INTEGRATION"
_ENV_FIXTURES = "GHIDRA_MCP_FIXTURES"
_ENV_WORKER_IMAGE = "GHIDRA_MCP_WORKER_IMAGE"
_ENV_ENGINE = "GHIDRA_MCP_CONTAINER_ENGINE"

#: The acceptance harness lives in ``scripts/`` (not an installed package); load it by path.
_HARNESS_PATH = Path(__file__).resolve().parents[2] / "scripts" / "acceptance_run.py"


def _truthy(value: str | None) -> bool:
    """Return whether an env flag is set to a truthy token."""
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _skip_reason() -> str | None:
    """Return a human reason to skip, or ``None`` if every real-chain prerequisite is met."""
    if not _truthy(os.environ.get(_ENV_INTEGRATION)):
        return f"{_ENV_INTEGRATION} not set (gated real-worker acceptance smoke)"
    fixtures = os.environ.get(_ENV_FIXTURES, "").strip()
    if not fixtures or not (Path(fixtures) / "cjson.stripped").is_file():
        return f"{_ENV_FIXTURES} not set or missing cjson.stripped (run build_fixtures.py)"
    if not os.environ.get(_ENV_WORKER_IMAGE, "").strip():
        return f"{_ENV_WORKER_IMAGE} not set (pinned worker image required)"
    engine = os.environ.get(_ENV_ENGINE, "podman")
    if shutil.which(engine) is None:
        return f"container engine {engine!r} not found on PATH"
    if not _HARNESS_PATH.is_file():
        return f"acceptance harness not found at {_HARNESS_PATH}"
    return None


_SKIP = _skip_reason()


def _load_harness() -> object:
    """Import ``scripts/acceptance_run.py`` by path (it is not an installed module)."""
    spec = importlib.util.spec_from_file_location("acceptance_run", _HARNESS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["acceptance_run"] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")
def test_analyze_mode_produces_artifacts_on_benign_fixture(tmp_path: Path) -> None:
    """Mode 'analyze' on cjson.stripped writes manifest + per-function JSON + names template + log.

    Runs the harness CLI in-process (``main(["analyze", ...])``) against the benign OSS fixture
    through the real worker chain, then asserts the artifact set the post-hoc source comparison
    depends on is present and well-shaped, and that the progress log carries ``step``/``function``
    lines (progress is a first-class requirement).
    """
    harness = _load_harness()
    fixtures_dir = Path(os.environ[_ENV_FIXTURES])
    binary = fixtures_dir / "cjson.stripped"
    out = tmp_path / "acceptance-out"

    rc = harness.main(  # type: ignore[attr-defined]
        ["analyze", "--binary", str(binary), "--cap", "8", "--out", str(out)]
    )
    assert rc == 0, "acceptance harness analyze mode failed (see run.log)"

    # Manifest: well-shaped, selected non-empty, hash present.
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["binary_sha256"] and len(manifest["binary_sha256"]) == 64
    assert manifest["total_functions"] >= 1
    assert manifest["selected"], "expected at least one selected function"
    assert isinstance(manifest["order"], list)

    # Per-function artifacts: one JSON per selected address, each with the contract fields.
    function_files = list((out / "functions").glob("*.json"))
    assert function_files, "expected per-function artifact JSON files"
    sample = json.loads(function_files[0].read_text())
    for key in ("address", "current_name", "decompiled_c", "context", "referenced_strings"):
        assert key in sample, f"function artifact missing {key!r}"

    # Names template: one slot per selected address, proposed fields null (the naming pass fills).
    template = json.loads((out / "names.template.json").read_text())
    assert set(template) == set(manifest["selected"])
    first = next(iter(template.values()))
    assert first["proposed_name"] is None and first["proposed_c"] is None

    # summary.json + the progress run.log with the required i/N lines.
    summary = json.loads((out / "summary.json").read_text())
    assert summary["mode"] == "analyze"
    assert summary["selected"] == len(manifest["selected"])
    log_text = (out / "run.log").read_text()
    assert "step 1/6:" in log_text, "expected phase progress lines"
    assert "function 1/" in log_text, "expected per-function progress lines"
