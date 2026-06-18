"""Unit tests for the pure analyzer-profile → option-overlay mapping (ADR-029 B).

The profile→preset selection is a pure data table + selector in the worker bridge
(:func:`ghidra_mcp.ghidra._jvm_bridge._analyzer_options_for_profile`). The JVM option-SETTING that
consumes the overlay is a ``# pragma: no cover`` edge (validated only on a real worker via the
ADR-028 harness — the option names are flagged REQUIRES-LIVE-VERIFICATION). These tests pin the pure
selector hermetically, with NO JVM and NO real worker (ADR-001): the JVM symbols in ``_jvm_bridge``
are imported inside functions, so importing this pure helper is safe (same pattern as the
address-keyable guard tests).

Key guarantees asserted:

- DEFAULT-IS-NO-OP: the ``default`` profile (and ``None``/unknown) maps to an EMPTY overlay, so the
  analyze path takes the byte-for-byte unchanged code path (no options object touched).
- ``light`` DISABLES the expensive analyzers; ``deep`` ENABLES the fuller set.
- The selector returns a COPY (mutating the result cannot corrupt the shared preset table).
- ADR-035 existence guard (the PURE half): :func:`_missing_profile_options` returns the overlay
  names absent from a given available-options set (the fail-closed condition). The JVM enumeration
  that produces the available set is the ``# pragma: no cover`` edge, validated on a real worker.
"""

from __future__ import annotations

from ghidra_mcp.ghidra._jvm_bridge import (
    _PROFILE_PRESETS,
    _analyzer_options_for_profile,
    _missing_profile_options,
)


def test_default_profile_is_empty_overlay_no_op() -> None:
    """``default`` maps to an empty overlay — the byte-for-byte no-op path (ADR-029 B)."""
    assert _analyzer_options_for_profile("default") == {}


def test_none_and_unknown_profile_fall_back_to_empty_no_op() -> None:
    """``None`` / an out-of-set value fail SAFE to the empty (no-op) overlay — never widen depth."""
    assert _analyzer_options_for_profile(None) == {}
    assert _analyzer_options_for_profile("aggressive") == {}
    assert _analyzer_options_for_profile("") == {}


def test_light_profile_disables_expensive_analyzers() -> None:
    """``light`` yields a non-empty overlay that turns the expensive analyzers OFF."""
    overlay = _analyzer_options_for_profile("light")
    assert overlay  # non-empty
    # Every option in the light overlay is a DISABLE (False) — light only ever reduces depth.
    assert all(enabled is False for enabled in overlay.values())
    assert overlay.get("Decompiler Parameter ID") is False


def test_deep_profile_enables_fuller_set() -> None:
    """``deep`` yields a non-empty overlay that turns the fuller analyzer set ON."""
    overlay = _analyzer_options_for_profile("deep")
    assert overlay  # non-empty
    assert all(enabled is True for enabled in overlay.values())
    assert overlay.get("Decompiler Parameter ID") is True


def test_selector_returns_a_copy_not_the_shared_preset() -> None:
    """Mutating the returned overlay must not corrupt the shared preset table (defensive copy)."""
    overlay = _analyzer_options_for_profile("light")
    overlay["Decompiler Parameter ID"] = True  # caller mutation
    # The shared table is unchanged for the next caller.
    assert _PROFILE_PRESETS["light"]["Decompiler Parameter ID"] is False
    assert _analyzer_options_for_profile("light")["Decompiler Parameter ID"] is False


# --- ADR-035 existence guard: the PURE membership decision ----------------------------------------


def test_missing_profile_options_all_present_returns_empty() -> None:
    """When every overlay name is available, there is nothing missing (overlay safe to apply)."""
    overlay = _analyzer_options_for_profile("light")
    available = set(overlay) | {"Some Other Analyzer", "Stack"}
    assert _missing_profile_options(overlay, available) == []


def test_missing_profile_options_reports_absent_names_sorted() -> None:
    """Overlay names absent from the available set are returned, sorted, for a stable diagnostic."""
    overlay = {"Zeta Analyzer": True, "Alpha Analyzer": False, "Present One": True}
    available = ["Present One", "Unrelated"]
    # Absent: "Zeta Analyzer", "Alpha Analyzer" → sorted.
    assert _missing_profile_options(overlay, available) == ["Alpha Analyzer", "Zeta Analyzer"]


def test_missing_profile_options_empty_overlay_is_never_missing() -> None:
    """The ``default`` (empty) overlay can never be missing anything (the guard is skipped)."""
    assert _missing_profile_options({}, []) == []
    assert _missing_profile_options({}, ["anything"]) == []


def test_missing_profile_options_accepts_any_iterable() -> None:
    """``available`` is consumed as any iterable (e.g. a JVM ``getOptionNames()`` result)."""
    overlay = {"A": True, "B": False}
    assert _missing_profile_options(overlay, iter(["A"])) == ["B"]


def test_real_presets_against_empty_available_are_all_missing() -> None:
    """If the build exposed NO analyzer options, every real preset name would be reported missing.

    Sanity that the guard would fire loudly in the degenerate case — the live worker supplies the
    real available-options set (the happy path is verified there, not here).
    """
    for profile in ("light", "deep"):
        overlay = _analyzer_options_for_profile(profile)
        assert _missing_profile_options(overlay, []) == sorted(overlay)
