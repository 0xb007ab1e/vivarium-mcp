"""Unit tests for the worker-side pure export-targets parser (ADR-027 D4).

``_parse_export_targets`` is the hermetic, JVM-free half of the worker's ``export_annotations``
edge: it extracts the server-supplied change-log selection (comment ``(address, comment_type)``
pairs + composite names) from the RPC params, so the un-coverable ``_gh_export_annotations`` JVM
edge only consumes already-parsed identity keys. These tests pin the parsing decision hermetically
(the F2 lesson: extract every testable decision out of the JVM edge). No JVM, no network.
"""

from __future__ import annotations

from ghidra_mcp.ghidra._jvm_bridge import _parse_export_targets


def test_parses_full_targets() -> None:
    params = {
        "targets": {
            "comments": [
                {"address": "0x401000", "comment_type": "PLATE"},
                {"address": "0x401004", "comment_type": "EOL"},
            ],
            "composites": ["cfg_t", "widget_t"],
        }
    }
    comments, composites = _parse_export_targets(params)
    assert comments == [("0x401000", "PLATE"), ("0x401004", "EOL")]
    assert composites == ["cfg_t", "widget_t"]


def test_missing_targets_yields_empty() -> None:
    # No targets key (defensive) ⇒ two empty lists: export emits no comments/composites (F7 fix).
    comments, composites = _parse_export_targets({})
    assert comments == []
    assert composites == []


def test_null_targets_yields_empty() -> None:
    # An explicit None targets is treated as empty (fail-closed to no-emit, never a raise).
    comments, composites = _parse_export_targets({"targets": None})
    assert comments == []
    assert composites == []


def test_partial_targets_missing_keys_yield_empty_sublists() -> None:
    # comments present, composites absent (and vice-versa) — absent keys default to empty.
    comments, composites = _parse_export_targets(
        {"targets": {"comments": [{"address": "0x1", "comment_type": "PRE"}]}}
    )
    assert comments == [("0x1", "PRE")]
    assert composites == []

    comments, composites = _parse_export_targets({"targets": {"composites": ["t"]}})
    assert comments == []
    assert composites == ["t"]


def test_values_are_coerced_to_str() -> None:
    # Identity keys are normalized to str (defensive against non-str JSON scalars).
    comments, composites = _parse_export_targets(
        {"targets": {"comments": [{"address": 1, "comment_type": "EOL"}], "composites": [2]}}
    )
    assert comments == [("1", "EOL")]
    assert composites == ["2"]
