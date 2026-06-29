"""Unit tests for the pure helpers of ``scripts/drill_runbooks.py`` (gap N10).

The dry-run drill harness lives in ``scripts/`` (not an installed package), so — like
``test_naming_eval_script.py`` — it is loaded by path. These cover the PURE, hermetic pieces: the
session-id injection guard, the prior-digest parser, the rollback + evict plan builders, and the
report renderer's pass/fail roll-up. The I/O shell (git/which fact-gathering) is not exercised here
(no subprocess, no repo state — it is glue over these pure functions).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "drill_runbooks.py"


def _load() -> Any:
    """Import ``scripts/drill_runbooks.py`` by path (it is not an installed module)."""
    spec = importlib.util.spec_from_file_location("drill_runbooks", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["drill_runbooks"] = module
    spec.loader.exec_module(module)
    return module


_MOD = _load()


@pytest.mark.parametrize("sid", ["abc", "DRILLSID0000", "a_b-c1", "f" * 64])
def test_validate_session_id_accepts_safe_tokens(sid: str) -> None:
    """A well-formed opaque session id passes through unchanged."""
    assert _MOD.validate_session_id(sid) == sid


@pytest.mark.parametrize(
    "sid",
    ["", "bad;rm -rf /", "a b", "$(whoami)", "x/../y", "`id`", "a" * 65, "semi;colon"],
)
def test_validate_session_id_rejects_injection(sid: str) -> None:
    """Anything outside [A-Za-z0-9_-]{1,64} is rejected (fail closed — injection guard)."""
    with pytest.raises(ValueError, match="session id"):
        _MOD.validate_session_id(sid)


def test_extract_prior_digest_returns_first_distinct() -> None:
    """The first digest in the log that differs from the current one is the revert target."""
    log = "sha256:" + "a" * 64 + "\n...\nsha256:" + "b" * 64
    assert _MOD.extract_prior_digest(log, "sha256:" + "a" * 64) == "sha256:" + "b" * 64


def test_extract_prior_digest_none_when_only_current() -> None:
    """If history holds only the current digest, there is no prior revert target."""
    cur = "sha256:" + "c" * 64
    assert _MOD.extract_prior_digest(f"{cur}\n{cur}", cur) is None


def test_extract_prior_digest_none_on_empty_log() -> None:
    """Empty git-log output yields no prior digest (rollback lever unavailable)."""
    assert _MOD.extract_prior_digest("", None) is None


def test_build_rollback_plan_all_levers_present_passes() -> None:
    """With pin+prior-digest+prior-tag+gh present, every gating precondition passes."""
    steps = _MOD.build_rollback_plan(
        pin_file_exists=True,
        prior_digest="sha256:" + "d" * 64,
        prior_tag="v0.12.0",
        gh_available=True,
    )
    _, ok = _MOD.render_report("Rollback", steps)
    assert ok is True
    assert any("v0.12.0" in (s.command or "") for s in steps)


def test_build_rollback_plan_missing_prior_digest_fails() -> None:
    """No distinct prior digest → the revert-worker-pin precondition fails (lever unavailable)."""
    steps = _MOD.build_rollback_plan(
        pin_file_exists=True, prior_digest=None, prior_tag="v1", gh_available=True
    )
    _, ok = _MOD.render_report("Rollback", steps)
    assert ok is False
    revert = next(s for s in steps if s.name == "revert-worker-pin")
    assert revert.precondition_ok is False


def test_build_evict_plan_embeds_validated_sid_and_engine() -> None:
    """The evict plan threads the sid + engine into the exact (data-only) commands."""
    steps = _MOD.build_evict_plan(
        "sid42", engine="podman", socket_dir="/run/vivarium", engine_available=True
    )
    kill = next(s for s in steps if s.name == "orchestrator-kill")
    assert kill.command is not None
    assert "vivarium-worker-sid42" in kill.command
    assert kill.command.startswith("podman kill")
    # The informational verify step never gates the drill (precondition_ok is None).
    verify = next(s for s in steps if s.name == "verify-wipe")
    assert verify.precondition_ok is None


def test_build_evict_plan_engine_absent_fails_gating_steps() -> None:
    """When the container engine is missing, the engine-dependent steps fail the drill."""
    steps = _MOD.build_evict_plan(
        "sid42", engine="podman", socket_dir="/run/vivarium", engine_available=False
    )
    _, ok = _MOD.render_report("Evict", steps)
    assert ok is False


def test_render_report_ignores_informational_steps() -> None:
    """A plan whose only non-passing steps are informational (None) still reports all-OK."""
    step_ok = _MOD.DrillStep(name="a", action="x", precondition_ok=True, detail="", command="cmd")
    step_info = _MOD.DrillStep(name="b", action="y", precondition_ok=None, detail="", command=None)
    text, ok = _MOD.render_report("T", [step_ok, step_info])
    assert ok is True
    assert "DRILL (dry-run): T" in text
