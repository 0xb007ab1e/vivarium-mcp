"""Unit tests for ADR-067 `binary_diff` — schema boundary + result builder.

The worker's two-program load/index/classify is a `# pragma: no cover` JVM edge validated against a
real worker; these cover the server-side contract: input validation (match_by enum, required refs,
caps) and the `_build_binary_diff` mapper (name Untrusted-wrapping, summary honesty, change enum).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vivarium.core.envelope import Untrusted
from vivarium.ghidra.rpc_client import _build_binary_diff
from vivarium.tools import schemas as s

# --- schema boundary -----------------------------------------------------------------------------


def test_defaults_name_bounded() -> None:
    """Absent match_by/max_entries default to a bounded name diff."""
    m = s.BinaryDiffIn(session_id="s", program_a="a.bin", program_b="b.bin")
    assert m.match_by == "name"
    assert m.max_entries == 1000


@pytest.mark.parametrize("mode", ["name", "function_hash", "bsim"])
def test_match_modes_accepted(mode: str) -> None:
    """All three supported pairing modes validate (name, function_hash, bsim)."""
    m = s.BinaryDiffIn(session_id="s", program_a="a", program_b="b", match_by=mode)  # type: ignore[arg-type]
    assert m.match_by == mode


def test_unknown_match_by_rejected() -> None:
    """A match_by outside the closed set fails closed."""
    with pytest.raises(ValidationError):
        s.BinaryDiffIn(session_id="s", program_a="a", program_b="b", match_by="rot13")  # type: ignore[arg-type]


def test_min_similarity_default_and_bounds() -> None:
    """`min_similarity` defaults to 0.7 (bsim pairing floor) and is bounded to [0, 1]."""
    assert s.BinaryDiffIn(session_id="s", program_a="a", program_b="b").min_similarity == 0.7
    m = s.BinaryDiffIn(
        session_id="s", program_a="a", program_b="b", match_by="bsim", min_similarity=0.9
    )
    assert m.min_similarity == 0.9
    with pytest.raises(ValidationError):
        s.BinaryDiffIn(session_id="s", program_a="a", program_b="b", min_similarity=1.5)


def test_include_unchanged_defaults_off_and_accepts_true() -> None:
    """`include_unchanged` defaults False (deltas-only) and accepts an explicit True."""
    assert s.BinaryDiffIn(session_id="s", program_a="a", program_b="b").include_unchanged is False
    m = s.BinaryDiffIn(session_id="s", program_a="a", program_b="b", include_unchanged=True)
    assert m.include_unchanged is True


def test_both_programs_required() -> None:
    """program_a and program_b are required, non-empty."""
    with pytest.raises(ValidationError):
        s.BinaryDiffIn(session_id="s", program_a="a")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        s.BinaryDiffIn(session_id="s", program_a="a", program_b="")


def test_max_entries_bounded() -> None:
    """max_entries is >= 1 and clamped by the schema ceiling."""
    with pytest.raises(ValidationError):
        s.BinaryDiffIn(session_id="s", program_a="a", program_b="b", max_entries=0)


# --- result builder ------------------------------------------------------------------------------


def test_builder_wraps_names_and_keeps_summary() -> None:
    """`_build_binary_diff` wraps every function name UNTRUSTED; addresses/summary stay safe."""
    out = _build_binary_diff(
        {
            "added": [{"address": "0x00401100", "name": "new_fn"}],
            "removed": [{"address": "0x00401200", "name": "gone_fn"}],
            "changed": [
                {
                    "address_a": "0x00401000",
                    "address_b": "0x00401000",
                    "name": "patched_fn",
                    "change": "body",
                }
            ],
            "summary": {"added": 5, "removed": 3, "changed": 7},
            "truncated": True,
        }
    )
    assert out.truncated is True
    # summary is the FULL count (honest), independent of the (clipped) list lengths.
    assert (out.summary.added, out.summary.removed, out.summary.changed) == (5, 3, 7)
    assert out.added[0].address == "0x00401100"
    assert isinstance(out.added[0].name, Untrusted)
    assert isinstance(out.removed[0].name, Untrusted)
    assert out.changed[0].address_a == "0x00401000"
    assert out.changed[0].change == "body"
    assert isinstance(out.changed[0].name, Untrusted)


def test_builder_tolerates_empty_diff() -> None:
    """Two identical programs yield empty lists + zero summary (a valid no-difference diff)."""
    out = _build_binary_diff(
        {
            "added": [],
            "removed": [],
            "changed": [],
            "summary": {"added": 0, "removed": 0, "changed": 0},
        }
    )
    assert out.added == [] and out.removed == [] and out.changed == []
    assert (out.summary.added, out.summary.removed, out.summary.changed) == (0, 0, 0)
    # A pre-follow-up payload without `unchanged` maps to an empty list + zero count (back-compat).
    assert out.unchanged == [] and out.summary.unchanged == 0
    assert out.truncated is False


def test_builder_maps_unchanged_when_present() -> None:
    """An `unchanged` payload maps to the correspondence list + honest count; names UNTRUSTED."""
    out = _build_binary_diff(
        {
            "added": [],
            "removed": [],
            "changed": [],
            "unchanged": [
                {"address": "0x00401000", "name": "same_fn"},
                {"address": "0x00401050", "name": "also_same"},
            ],
            "summary": {"added": 0, "removed": 0, "changed": 0, "unchanged": 2},
        }
    )
    assert out.summary.unchanged == 2
    assert [u.address for u in out.unchanged] == ["0x00401000", "0x00401050"]
    assert all(isinstance(u.name, Untrusted) for u in out.unchanged)
