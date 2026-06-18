"""Unit tests for the pure helpers of ``scripts/naming_eval.py`` (v1.5 #7; ADR-010).

The scorer lives in ``scripts/`` (not an installed package), so — like ``test_acceptance_run.py`` —
it is loaded by path. These tests cover the PURE, hermetic helpers only: proposed-names parsing
(the shapes the harness/namers emit), the scorecard assembly, and the hex-address guard. The I/O
paths (ELF build-id read, DWARF extraction, debuginfod HTTP fetch) are exercised on-demand against
real benign binaries, not here (no network, no binaries in unit CI — master §5).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "naming_eval.py"


def _load() -> Any:
    """Import ``scripts/naming_eval.py`` by path (it is not an installed module)."""
    spec = importlib.util.spec_from_file_location("naming_eval", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["naming_eval"] = module
    spec.loader.exec_module(module)
    return module


_MOD = _load()


def test_load_proposed_names_flat_object(tmp_path: Path) -> None:
    """A flat ``{addr: name}`` object loads verbatim (skipping empty entries)."""
    path = tmp_path / "names.json"
    path.write_text(json.dumps({"0x401000": "parse", "0x401286": "decode", "": "x"}))
    assert _MOD.load_proposed_names(path) == {"0x401000": "parse", "0x401286": "decode"}


def test_load_proposed_names_list_of_rows(tmp_path: Path) -> None:
    """A list of rows accepts ``new_name``/``name``/``proposed`` and ``address``/``addr``."""
    path = tmp_path / "names.json"
    path.write_text(
        json.dumps(
            [
                {"address": "0x401000", "new_name": "parse_value"},
                {"addr": "0x401286", "name": "decode_frame"},
                {"address": "0x402000"},  # no name → skipped
            ]
        )
    )
    assert _MOD.load_proposed_names(path) == {
        "0x401000": "parse_value",
        "0x401286": "decode_frame",
    }


def test_load_proposed_names_functions_wrapper(tmp_path: Path) -> None:
    """A ``{"functions": [...]}`` wrapper is unwrapped to the rows."""
    path = tmp_path / "names.json"
    path.write_text(json.dumps({"functions": [{"address": "0x401000", "proposed": "init"}]}))
    assert _MOD.load_proposed_names(path) == {"0x401000": "init"}


def test_load_proposed_names_rejects_bad_shape(tmp_path: Path) -> None:
    """A scalar/non-object/non-list JSON document is a usage error (fail closed)."""
    path = tmp_path / "names.json"
    path.write_text(json.dumps(42))
    with pytest.raises(ValueError, match="expected an object or a list"):
        _MOD.load_proposed_names(path)


def test_is_hex_guards_unparseable_addresses() -> None:
    """``_is_hex`` accepts hex forms and rejects junk (defensive address guard)."""
    assert _MOD._is_hex("0x401000") and _MOD._is_hex("401286")
    assert not _MOD._is_hex("zzzz") and not _MOD._is_hex("")


def test_build_scorecard_aggregate_and_rows() -> None:
    """The scorecard carries the aggregate + a per-function row for each joined proposed name."""
    proposed = {"0x401000": "cjson_parse", "0x401286": "get_size", "0x499999": "orphan"}
    truth = {"0x401000": "cJSON_Parse", "0x401286": "cJSON_GetArraySize"}
    accuracy = _MOD.score_name_map(proposed, truth)
    card = _MOD.build_scorecard(proposed, truth, accuracy)

    assert card["aggregate"]["scored"] == 2  # the orphan address isn't in truth
    assert card["aggregate"]["unscored"] == 1
    assert card["aggregate"]["exact_matches"] == 1  # cjson_parse ≈ cJSON_Parse
    # Only joined rows appear (the orphan is excluded); sorted by address; exact flag + token_f1.
    addrs = [row["address"] for row in card["functions"]]
    assert addrs == ["0x401000", "0x401286"]
    first = card["functions"][0]
    assert first["proposed"] == "cjson_parse" and first["truth"] == "cJSON_Parse"
    # Exact by normalized equality ("cjsonparse"); token_f1 is partial (<1.0) because the camelCase
    # split tokenizes differently ({cjson,parse} vs {c,json,parse}) — exact and token-F1 are
    # independent signals, as designed.
    assert first["exact"] is True
    assert 0.0 < first["token_f1"] < 1.0
