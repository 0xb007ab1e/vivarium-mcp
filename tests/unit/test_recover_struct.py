"""Unit tests for ADR-069 `recover_struct` — schema boundary + result builder.

The worker's HighFunction access walk is a `# pragma: no cover` JVM edge validated by the gated
integration test; these cover the server-side contract: input validation (access enum on output,
caps, required fields) and the `_build_recover_struct` mapper (Untrusted wrapping of the inferred
type, None-safety, propose-only shape).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vivarium.core.envelope import Untrusted
from vivarium.ghidra.rpc_client import _build_recover_struct
from vivarium.tools import schemas as s

# --- schema boundary -----------------------------------------------------------------------------


def test_defaults_bounded() -> None:
    """Absent caps default to bounded values."""
    m = s.RecoverStructIn(session_id="sess", function="0x1000", base="param_1")
    assert m.max_fields == 256
    assert m.max_accesses == 1024


def test_function_and_base_required() -> None:
    """Both function and base are required, non-empty."""
    with pytest.raises(ValidationError):
        s.RecoverStructIn(session_id="s", base="p")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        s.RecoverStructIn(session_id="s", function="f", base="")


def test_caps_bounded() -> None:
    """max_fields/max_accesses are >= 1 and clamped by the schema ceiling."""
    with pytest.raises(ValidationError):
        s.RecoverStructIn(session_id="s", function="f", base="p", max_fields=0)
    with pytest.raises(ValidationError):
        s.RecoverStructIn(session_id="s", function="f", base="p", max_accesses=0)


def test_field_access_enum_closed() -> None:
    """ProposedField.access is a closed set; offset/size are non-negative."""
    with pytest.raises(ValidationError):
        s.ProposedField(offset=0, size=4, access="mutate")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        s.ProposedField(offset=-1, size=4, access="load")


# --- result builder (rpc_client) -----------------------------------------------------------------


def test_builder_wraps_inferred_type_and_maps_fields() -> None:
    """`_build_recover_struct` wraps inferred_type untrusted; offsets/sizes stay safe scalars."""
    out = _build_recover_struct(
        {
            "base": "param_1",
            "fields": [
                {"offset": 0, "size": 8, "inferred_type": "void *", "access": "load"},
                {"offset": 8, "size": 4, "inferred_type": "int", "access": "store"},
            ],
            "total_span": 12,
            "truncated": True,
        }
    )
    assert out.base == "param_1"
    assert out.total_span == 12
    assert out.truncated is True
    assert len(out.fields) == 2
    assert out.fields[0].offset == 0
    assert out.fields[0].size == 8
    assert out.fields[0].access == "load"
    assert out.fields[0].confidence == "observed"
    # inferred_type is decompiler-derived -> wrapped untrusted.
    assert isinstance(out.fields[0].inferred_type, Untrusted)
    assert isinstance(out.fields[1].inferred_type, Untrusted)


def test_builder_tolerates_missing_type_and_span() -> None:
    """An access with no inferred type yields None (not a bare Untrusted); span defaults to 0."""
    out = _build_recover_struct(
        {
            "base": "iVar1",
            "fields": [{"offset": 16, "size": 8, "inferred_type": None, "access": "addr"}],
        }
    )
    assert out.fields[0].inferred_type is None
    assert out.fields[0].access == "addr"
    assert out.total_span == 0
    assert out.truncated is False
