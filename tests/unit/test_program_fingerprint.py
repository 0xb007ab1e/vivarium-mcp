"""Unit tests for ADR-073 D1 `program_fingerprint` — schema boundary + result builder + wiring.

The worker's Ghidra fact-gathering (mnemonic hashers, external-symbol walk, coverage) is a
`# pragma: no cover` JVM edge validated by the gated integration test; these cover the server-side
contract: input validation, the `_build_program_fingerprint` mapper (safe scalars + reused coverage
ratios), and that the tool is registered read-only.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vivarium.ghidra.rpc_client import _build_program_fingerprint
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

# --- schema boundary -----------------------------------------------------------------------------


def test_input_is_session_scoped_only() -> None:
    """The input carries only session_id (no other knobs) and rejects unknown fields."""
    m = s.ProgramFingerprintIn(session_id="sess")
    assert m.session_id == "sess"
    with pytest.raises(ValidationError):
        s.ProgramFingerprintIn(session_id="sess", function="f")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        s.ProgramFingerprintIn()  # type: ignore[call-arg]


def test_output_import_digest_optional() -> None:
    """import_digest defaults to None (a no-import program is representable)."""
    cov = s.CoverageOut(
        total_bytes=10,
        defined_code_bytes=4,
        defined_data_bytes=2,
        undefined_bytes=4,
        code_ratio=0.4,
        data_ratio=0.2,
        function_count=1,
    )
    out = s.ProgramFingerprintOut(
        structure_digest="a" * 64, function_count=1, import_count=0, coverage=cov
    )
    assert out.import_digest is None


# --- result builder (rpc_client) -----------------------------------------------------------------


def _worker_result(*, with_imports: bool) -> dict[str, object]:
    r: dict[str, object] = {
        "structure_digest": "d" * 64,
        "function_count": 3,
        "import_count": 5 if with_imports else 0,
        "coverage": {
            "total_bytes": 2000,
            "defined_code_bytes": 30,
            "defined_data_bytes": 10,
            "function_count": 3,
        },
    }
    if with_imports:
        r["import_digest"] = "e" * 64
    return r


def test_builder_maps_all_fields_and_computes_ratios() -> None:
    """The builder yields safe scalars and computes coverage undefined+ratios server-side."""
    out = _build_program_fingerprint(_worker_result(with_imports=True))
    assert out.structure_digest == "d" * 64
    assert out.import_digest == "e" * 64
    assert out.function_count == 3
    assert out.import_count == 5
    # coverage ratios/undefined are recomputed by the reused _build_coverage (pure).
    assert out.coverage.undefined_bytes == 2000 - 30 - 10
    assert out.coverage.code_ratio == pytest.approx(30 / 2000)
    assert out.coverage.data_ratio == pytest.approx(10 / 2000)


def test_builder_import_digest_absent_maps_to_none() -> None:
    """A worker result without import_digest (no imports) maps to None, not KeyError."""
    out = _build_program_fingerprint(_worker_result(with_imports=False))
    assert out.import_digest is None
    assert out.import_count == 0


def test_builder_missing_required_field_fails_closed() -> None:
    """A malformed worker result (missing a required field) fails closed, not silently."""
    bad = _worker_result(with_imports=True)
    del bad["structure_digest"]
    with pytest.raises(Exception):  # noqa: B017 - _fail_closed maps to a safe error envelope
        _build_program_fingerprint(bad)


# --- registry wiring -----------------------------------------------------------------------------


def test_registered_and_read_only() -> None:
    """program_fingerprint is in the frozen allow-list, handled, and NOT a write tool."""
    assert "program_fingerprint" in reg.TIER1_TOOL_NAMES
    assert "program_fingerprint" in reg._HANDLERS
    assert "program_fingerprint" not in reg.WRITE_TOOLS
    # same capability as a known read-only tool (avoids importing the CAP_READ constant).
    assert reg.required_capability("program_fingerprint") == reg.required_capability(
        "decompile_function"
    )
