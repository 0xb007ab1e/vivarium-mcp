"""Contract tests for the Tier-1 tool schemas (FROZEN — WS0).

Assert the cross-cutting guarantees every tool schema must keep: inputs are immutable, reject
unknown fields (mass-assignment defense), and bound list/read/search args with hard caps (DoS —
PLAN §3 F7). Also asserts the registry's catalog matches the schema set.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ghidra_mcp.tools import schemas as s
from ghidra_mcp.tools.registry import TIER1_TOOL_NAMES


@pytest.mark.critical
def test_session_scoped_inputs_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        s.DecompileFunctionIn(  # unknown field rejected
            session_id="abc",
            function="main",
            danger="rm -rf",  # type: ignore[call-arg]
        )


@pytest.mark.critical
def test_inputs_are_frozen() -> None:
    a = s.ReadBytesIn(session_id="abc", address="0x1000", length=16)
    with pytest.raises(ValidationError):
        a.length = 999  # frozen


@pytest.mark.critical
@pytest.mark.parametrize(
    ("model", "kwargs"),
    [
        (s.ListFunctionsIn, {"session_id": "s", "limit": 10_001}),
        (s.ListStringsIn, {"session_id": "s", "limit": 10_001}),
        (s.SearchBytesIn, {"session_id": "s", "pattern_hex": "90", "limit": 10_001}),
        (s.SearchStringsIn, {"session_id": "s", "query": "a", "limit": 10_001}),
        (s.ReadBytesIn, {"session_id": "s", "address": "0x0", "length": 1_048_577}),
        (s.DisassembleIn, {"session_id": "s", "max_instructions": 10_001}),
    ],
)
def test_bounded_args_reject_over_cap(model: type, kwargs: dict[str, object]) -> None:
    # Every bounded tool must reject a request above its hard cap (no unbounded result sets).
    with pytest.raises(ValidationError):
        model(**kwargs)


@pytest.mark.critical
def test_paged_defaults_are_safe() -> None:
    a = s.ListFunctionsIn(session_id="s")
    assert a.offset == 0
    assert a.limit == 100  # conservative default page size


@pytest.mark.critical
def test_read_bytes_requires_positive_length() -> None:
    with pytest.raises(ValidationError):
        s.ReadBytesIn(session_id="s", address="0x0", length=0)


@pytest.mark.critical
def test_expected_sha256_pattern_enforced() -> None:
    with pytest.raises(ValidationError):
        s.SessionImportIn(session_id="s", source_ref="ref", expected_sha256="not-a-hash")
    # A valid 64-hex digest is accepted.
    ok = s.SessionImportIn(session_id="s", source_ref="ref", expected_sha256="ab" * 32)
    assert ok.expected_sha256 == "ab" * 32


@pytest.mark.critical
def test_catalog_count_matches_registry() -> None:
    # 22 Tier-1 tools per the frozen catalog; registry list is the single source for registration.
    assert len(TIER1_TOOL_NAMES) == len(set(TIER1_TOOL_NAMES))  # no dupes
    assert len(TIER1_TOOL_NAMES) == 22


@pytest.mark.critical
def test_output_models_carry_untrusted_fields() -> None:
    # Spot-check that binary-derived output is wrapped, not bare (ADR-005 at the type level).
    from ghidra_mcp.core.envelope import DataOrigin, Untrusted

    out = s.DecompiledFunction(
        address="0x1000",
        name=Untrusted(value="main", origin=DataOrigin.BINARY),
        c_code=Untrusted(value="int main(){}", origin=DataOrigin.GHIDRA),
        signature=Untrusted(value="int main(void)", origin=DataOrigin.GHIDRA),
    )
    assert isinstance(out.c_code, Untrusted)
    assert out.address == "0x1000"  # server-computed scalar stays bare
