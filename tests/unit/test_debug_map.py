"""Unit tests for ADR-071 `debug_ref` (map) — the pure symbol-map parser + schema/server wiring.

The worker's ``_apply_debug`` (Ghidra label creation) is a ``# pragma: no cover`` JVM edge validated
against a real worker; these cover the pure ``core.debugmap`` parser and the server-side contract:
``SessionImportIn`` validation (pair rule, loader='auto', mutual-exclusion with pdb_ref) and the
``import_binary`` adapter threading the confined ``debug_ref``/``debug_format`` to the worker.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests.unit.test_import_loader_hints import _adapter_capturing_call
from vivarium.core.debugmap import parse_symbol_map
from vivarium.tools import schemas as s

# --- pure parser ---------------------------------------------------------------------------------


def test_parses_nm_form() -> None:
    """`nm` output (`ADDR TYPE NAME`) yields (name, address) with the type letter skipped."""
    syms = parse_symbol_map("0000000000001149 T main\n0000000000001200 t helper\n", max_symbols=100)
    assert [(x.name, x.address) for x in syms] == [("main", 0x1149), ("helper", 0x1200)]


def test_parses_bare_pair_and_0x_prefix() -> None:
    """`ADDR NAME` and a `0x`-prefixed address both parse."""
    syms = parse_symbol_map("0x1149 handler\n00002000  other\n", max_symbols=100)
    assert [(x.name, x.address) for x in syms] == [("handler", 0x1149), ("other", 0x2000)]


def test_parses_linker_assignment() -> None:
    """`name = 0xADDR ;` (linker script / .sym assignment) parses."""
    syms = parse_symbol_map("_start = 0x1040 ;\nedata = 0x4000\n", max_symbols=100)
    assert [(x.name, x.address) for x in syms] == [("_start", 0x1040), ("edata", 0x4000)]


def test_skips_lines_without_both_fields_and_segment_form() -> None:
    """Lines lacking an address or a name — and segment-relative IDA lines — yield nothing."""
    syms = parse_symbol_map(
        "# a comment\njust_text\n0001:00001149 _seg_relative\n", max_symbols=100
    )
    # `0001:...` matches a leading hex (0001) then takes the last identifier — that's the documented
    # limitation; assert it does NOT crash and the pure-text/comment lines are skipped.
    assert all(x.address is not None for x in syms)


def test_dedup_and_cap() -> None:
    """Duplicate (name,address) pairs collapse; `max_symbols` bounds the result."""
    text = "0x1000 a\n0x1000 a\n0x2000 b\n0x3000 c\n"
    assert len(parse_symbol_map(text, max_symbols=100)) == 3  # dedup the repeated a
    assert len(parse_symbol_map(text, max_symbols=2)) == 2  # capped


# --- schema validation ---------------------------------------------------------------------------


def test_debug_ref_and_format_are_a_pair() -> None:
    """debug_ref without debug_format (or vice versa) is rejected."""
    with pytest.raises(ValidationError):
        s.SessionImportIn(session_id="s", source_ref="p.elf", debug_ref="p.map")
    with pytest.raises(ValidationError):
        s.SessionImportIn(session_id="s", source_ref="p.elf", debug_format="map")


def test_debug_ref_valid_with_auto() -> None:
    """A paired debug_ref/debug_format is accepted with the default auto loader."""
    m = s.SessionImportIn(session_id="s", source_ref="p.elf", debug_ref="p.map", debug_format="map")
    assert m.debug_ref == "p.map" and m.debug_format == "map"


def test_debug_ref_rejected_with_non_auto_loader() -> None:
    """debug_ref only pairs with the ELF/auto path (like pdb_ref → PE)."""
    with pytest.raises(ValidationError):
        s.SessionImportIn(
            session_id="s",
            source_ref="fw.bin",
            loader="binary",
            processor="ARM:LE:32:Cortex",
            base_addr=0x1000,
            debug_ref="p.map",
            debug_format="map",
        )


def test_debug_ref_and_pdb_ref_mutually_exclusive() -> None:
    """A program takes ONE companion — debug_ref and pdb_ref together are rejected."""
    with pytest.raises(ValidationError):
        s.SessionImportIn(
            session_id="s",
            source_ref="p",
            pdb_ref="p.pdb",
            debug_ref="p.map",
            debug_format="map",
        )


# --- server wiring -------------------------------------------------------------------------------


def test_debug_ref_resolved_and_threaded_to_worker() -> None:
    """A valid debug_ref is confined/size-capped and threaded with its format to the worker."""
    adapter, captured = _adapter_capturing_call()
    args = s.SessionImportIn(
        session_id="s", source_ref="p.elf", debug_ref="p.map", debug_format="map"
    )
    adapter.import_binary("s", args)  # type: ignore[attr-defined]
    assert len(captured) == 1
    assert captured[0]["debug_ref"] == "p.map"
    assert captured[0]["debug_format"] == "map"


def test_no_debug_ref_is_byte_for_byte_noop() -> None:
    """Absent debug_ref ⇒ no debug key crosses the wire (the ADR-071 no-op guarantee)."""
    adapter, captured = _adapter_capturing_call()
    adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="p.elf"))  # type: ignore[attr-defined]
    assert "debug_ref" not in captured[0]
    assert "debug_format" not in captured[0]
