"""Contract tests for the Tier-1 tool schemas (FROZEN — WS0).

Assert the cross-cutting guarantees every tool schema must keep: inputs are immutable, reject
unknown fields (mass-assignment defense), and bound list/read/search args with hard caps (DoS —
PLAN §3 F7). Also asserts the registry's catalog matches the schema set.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vivarium.tools import schemas as s
from vivarium.tools.registry import TIER1_TOOL_NAMES


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
def test_session_analyze_profile_defaults_to_default() -> None:
    """``session_analyze`` profile is additive and defaults to the no-op ``default`` (ADR-029 B)."""
    a = s.SessionAnalyzeIn(session_id="s")
    assert a.profile == "default"


@pytest.mark.critical
@pytest.mark.parametrize("profile", ["default", "light", "deep"])
def test_session_analyze_accepts_each_profile(profile: str) -> None:
    """Each of the three closed-set profiles is accepted (ADR-029 B)."""
    a = s.SessionAnalyzeIn(session_id="s", profile=profile)  # type: ignore[arg-type]
    assert a.profile == profile


@pytest.mark.critical
def test_session_analyze_rejects_unknown_profile() -> None:
    """An out-of-set profile is rejected by the Literal (fail closed — ADR-029 B)."""
    with pytest.raises(ValidationError):
        s.SessionAnalyzeIn(session_id="s", profile="aggressive")  # type: ignore[arg-type]


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
    # 56 tools per the frozen catalog: 22 Tier-1 read-only + 5 v1.1 semantic-naming (ADR-007)
    # + 8 v1.1 Tier-2 reporting/metrics (ADR-008) + 6 v1.1 mutation/write (ADR-012) + 2 v1.1
    # structural mutation (ADR-013 Phase A) + 2 v1.1 structural type-aware mutation (ADR-014
    # Phase B) + 2 v1.1 composite-type creation (ADR-015 Phase C) + 2 v1.2 annotation persistence
    # (ADR-018: export + import) + 1 v1.2 multi-type composite batch (ADR-021: define_types)
    # + 1 v1.4 composite deletion (ADR-031: delete_type) + 4 v1.x streaming-extraction tools
    # (ADR-040: start_decompile_stream + fetch_job_results/job_status/cancel_job) + 1 Function ID
    # library-match tool (ADR-042 Phase 1: identify_functions). The registry list is the source.
    assert len(TIER1_TOOL_NAMES) == len(set(TIER1_TOOL_NAMES))  # no dupes
    assert len(TIER1_TOOL_NAMES) == 65


@pytest.mark.critical
def test_output_models_carry_untrusted_fields() -> None:
    # Spot-check that binary-derived output is wrapped, not bare (ADR-005 at the type level).
    from vivarium.core.envelope import DataOrigin, Untrusted

    out = s.DecompiledFunction(
        address="0x1000",
        name=Untrusted(value="main", origin=DataOrigin.BINARY),
        c_code=Untrusted(value="int main(){}", origin=DataOrigin.GHIDRA),
        signature=Untrusted(value="int main(void)", origin=DataOrigin.GHIDRA),
    )
    assert isinstance(out.c_code, Untrusted)
    assert out.address == "0x1000"  # server-computed scalar stays bare


def test_streaming_job_state_literal_matches_enum() -> None:
    # The frozen client schema mirrors the server-side JobState enum vocabulary without importing it
    # (no cycle). Keep them in lockstep: any new state must be added to BOTH.
    import typing

    from vivarium.jobs.streaming import JobState

    literal_states = set(typing.get_args(s._JOB_STATE))
    enum_states = {st.value for st in JobState}
    assert literal_states == enum_states


def test_decompiled_chunk_carries_per_chunk_untrusted_envelope() -> None:
    from vivarium.core.envelope import DataOrigin, Untrusted

    chunk = s.DecompiledChunk(
        seq=0,
        address="0x401000",
        name=Untrusted(value="FUN_00401000", origin=DataOrigin.BINARY),
        code=Untrusted(value="int FUN_00401000(void){}", origin=DataOrigin.GHIDRA),
        signature=Untrusted(value="int FUN_00401000(void)", origin=DataOrigin.GHIDRA),
    )
    assert isinstance(chunk.code, Untrusted)  # per-chunk envelope (ADR-040 D9)
    assert chunk.address == "0x401000"  # server-normalized scalar stays bare
    assert chunk.seq == 0


def test_job_status_out_has_no_untrusted_fields() -> None:
    # job_status carries server counters only — NO binary content (master §5 / ADR-040 D9).
    from vivarium.core.envelope import Untrusted

    out = s.JobStatusOut(
        state="running", phase="running", done=False, total=10, buffered=2, started_at=1.5
    )
    for value in out.model_dump().values():
        assert not isinstance(value, Untrusted)


def test_fetch_job_results_in_bounds() -> None:
    assert s.FetchJobResultsIn(session_id="x", job="j").limit == 32  # default 32
    with pytest.raises(ValidationError):
        s.FetchJobResultsIn(session_id="x", job="j", limit=257)  # > max 256


@pytest.mark.critical
def test_emulate_defaults_and_step_cap() -> None:
    """emulate defaults to a 100k step budget; rejects a request above the 1M cap (ADR-049)."""
    a = s.EmulateIn(session_id="s", start="0x1000")
    assert a.max_steps == 100_000  # conservative default budget
    with pytest.raises(ValidationError):
        s.EmulateIn(session_id="s", start="0x1000", max_steps=1_000_001)  # > 1M hard cap
    with pytest.raises(ValidationError):
        s.EmulateIn(session_id="s", start="0x1000", max_steps=0)  # ge=1


@pytest.mark.critical
@pytest.mark.parametrize(
    "kwargs",
    [
        {"set_registers": {f"r{i}": 0 for i in range(65)}},  # > 64-register cap
        {"read_registers": [f"r{i}" for i in range(65)]},  # > 64-register cap
        {"write_memory": [{"address": "0x0", "data_hex": "90"}] * 17},  # > 16-region cap
        {"read_memory": [{"address": "0x0", "length": 1}] * 17},  # > 16-region cap
        # two per-region-legal writes whose batch total exceeds the 64 KiB cap
        {"write_memory": [{"address": "0x0", "data_hex": "00" * 40_000}] * 2},
    ],
)
def test_emulate_rejects_over_cap(kwargs: dict[str, object]) -> None:
    # Every emulate list/size cap fails closed (hostile-code DoS guards — ADR-049 / CWE-400).
    with pytest.raises(ValidationError):
        s.EmulateIn(session_id="s", start="0x1000", **kwargs)  # type: ignore[arg-type]


@pytest.mark.critical
def test_emulate_output_wraps_binary_values_untrusted() -> None:
    # Register/memory VALUES are binary-derived emulation output — wrapped, not bare (ADR-005/049).
    from vivarium.core.envelope import DataOrigin, Untrusted

    out = s.EmulateOut(
        steps_executed=4,
        stop_reason="stop-address",
        registers=[
            s.RegisterValue(name="RAX", value=Untrusted(value="08", origin=DataOrigin.BINARY))
        ],
        memory=[
            s.MemoryRegion(
                address="0x402000",
                data=Untrusted(value="00", origin=DataOrigin.BINARY),
                length=1,
            )
        ],
    )
    assert isinstance(out.registers[0].value, Untrusted)
    assert isinstance(out.memory[0].data, Untrusted)
    assert out.registers[0].name == "RAX"  # server-known scalar stays bare


@pytest.mark.critical
def test_demangle_defaults_and_bounds() -> None:
    """demangle defaults to the ``auto`` scheme and bounds the mangled string length (ADR-050)."""
    a = s.DemangleIn(session_id="s", mangled="_ZN3foo3barEi")
    assert a.scheme == "auto"  # try GNU then MSVC by default
    with pytest.raises(ValidationError):
        s.DemangleIn(session_id="s", mangled="")  # min_length=1
    with pytest.raises(ValidationError):
        s.DemangleIn(session_id="s", mangled="a" * 8_193)  # > 8 KiB cap
    with pytest.raises(ValidationError):
        s.DemangleIn(session_id="s", mangled="x", scheme="rust")  # type: ignore[arg-type]


@pytest.mark.critical
def test_demangle_output_wraps_name_untrusted_and_allows_no_match() -> None:
    # The demangled name is binary-derived and wrapped; a non-mangled input yields None (not error).
    from vivarium.core.envelope import DataOrigin, Untrusted

    matched = s.DemangleOut(
        demangled=Untrusted(value="foo::bar(int)", origin=DataOrigin.BINARY), scheme="gnu"
    )
    assert isinstance(matched.demangled, Untrusted)
    assert matched.scheme == "gnu"

    unmatched = s.DemangleOut()  # nothing matched — both fields default to None
    assert unmatched.demangled is None
    assert unmatched.scheme is None


@pytest.mark.critical
def test_apply_type_archive_closed_allowlist_and_safe_result() -> None:
    """apply_type_archive accepts only allow-listed archive names; result carries no Untrusted."""
    from vivarium.core.envelope import Untrusted

    a = s.ApplyTypeArchiveIn(session_id="s", archive="generic_clib_64")
    assert a.archive == "generic_clib_64"
    with pytest.raises(ValidationError):
        s.ApplyTypeArchiveIn(session_id="s", archive="/etc/passwd")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        s.ApplyTypeArchiveIn(session_id="s", archive="glibc")  # type: ignore[arg-type]  # not on the list

    # No arbitrary path can slip through; result fields are all SAFE scalars (no binary echo).
    out = s.ApplyTypeArchiveResult(archive="generic_clib_64", functions_updated=7, applied=True)
    for value in out.model_dump().values():
        assert not isinstance(value, Untrusted)


@pytest.mark.critical
def test_get_pcode_bounds_and_untrusted_output() -> None:
    """get_pcode is bounded like disassemble; mnemonic + each p-code op are wrapped Untrusted."""
    from vivarium.core.envelope import DataOrigin, Untrusted

    a = s.GetPcodeIn(session_id="s", start="0x1000")
    assert a.max_instructions == 256  # conservative default
    with pytest.raises(ValidationError):
        s.GetPcodeIn(session_id="s", start="0x1000", max_instructions=10_001)  # > hard cap
    with pytest.raises(ValidationError):
        s.GetPcodeIn(session_id="s", start="0x1000", max_instructions=0)  # ge=1

    out = s.PcodeInstruction(
        address="0x401000",
        mnemonic=Untrusted(value="ADD", origin=DataOrigin.GHIDRA),
        pcode=[Untrusted(value="(register, 0x0, 4) INT_ADD ...", origin=DataOrigin.GHIDRA)],
    )
    assert isinstance(out.mnemonic, Untrusted)
    assert all(isinstance(op, Untrusted) for op in out.pcode)
    assert out.address == "0x401000"  # server-normalized scalar stays bare


@pytest.mark.critical
def test_get_high_pcode_bounds_and_untrusted_output() -> None:
    """get_high_pcode requires a function, is bounded, and wraps each op Untrusted (ADR-053)."""
    from vivarium.core.envelope import DataOrigin, Untrusted

    a = s.GetHighPcodeIn(session_id="s", function="main")
    assert a.max_ops == 256  # conservative default
    with pytest.raises(ValidationError):
        s.GetHighPcodeIn(session_id="s", function="")  # function is required (min_length=1)
    with pytest.raises(ValidationError):
        s.GetHighPcodeIn(session_id="s", function="main", max_ops=10_001)  # > hard cap
    with pytest.raises(ValidationError):
        s.GetHighPcodeIn(session_id="s", function="main", max_ops=0)  # ge=1

    op = s.HighPcodeOp(
        address="0x401000",
        op=Untrusted(value="(register, 0x0, 8) COPY (const, 0x8, 8)", origin=DataOrigin.GHIDRA),
    )
    assert isinstance(op.op, Untrusted)
    assert op.address == "0x401000"  # server-normalized scalar stays bare


@pytest.mark.critical
def test_stack_frame_requires_function_and_wraps_names_untrusted() -> None:
    """stack_frame requires a function; recovered name + type are Untrusted, offsets/sizes bare."""
    from vivarium.core.envelope import DataOrigin, Untrusted

    s.StackFrameIn(session_id="s", function="main")  # ok
    with pytest.raises(ValidationError):
        s.StackFrameIn(session_id="s", function="")  # function required (min_length=1)

    out = s.StackFrameOut(
        frame_size=16,
        variables=[
            s.StackVariable(
                name=Untrusted(value="local_c", origin=DataOrigin.GHIDRA),
                stack_offset=-12,
                data_type=Untrusted(value="undefined4", origin=DataOrigin.BINARY),
                size=4,
                is_parameter=False,
            )
        ],
    )
    var = out.variables[0]
    assert isinstance(var.name, Untrusted)
    assert isinstance(var.data_type, Untrusted)
    assert var.stack_offset == -12 and var.size == 4  # server/worker scalars stay bare
    assert out.frame_size == 16


@pytest.mark.critical
def test_basic_blocks_bounds_and_safe_scalars() -> None:
    """basic_blocks requires a function, is bounded, and carries only SAFE address/count fields."""
    from vivarium.core.envelope import Untrusted

    a = s.BasicBlocksIn(session_id="s", function="main")
    assert a.max_blocks == 256  # conservative default
    with pytest.raises(ValidationError):
        s.BasicBlocksIn(session_id="s", function="")  # function required (min_length=1)
    with pytest.raises(ValidationError):
        s.BasicBlocksIn(session_id="s", function="main", max_blocks=10_001)  # > hard cap
    with pytest.raises(ValidationError):
        s.BasicBlocksIn(session_id="s", function="main", max_blocks=0)  # ge=1

    out = s.BasicBlocksOut(
        blocks=[
            s.BasicBlock(
                address="0x401000",
                end_address="0x401003",
                size=4,
                successors=["0x401004", "0x401006"],
            )
        ]
    )
    blk = out.blocks[0]
    assert blk.address == "0x401000" and blk.successors == ["0x401004", "0x401006"]
    # CFG structure is server-normalized addresses/counts — nothing untrusted.
    for value in out.model_dump().values():
        assert not isinstance(value, Untrusted)


@pytest.mark.critical
def test_list_data_types_paginated_and_name_untrusted() -> None:
    """list_data_types is a bounded page; each type name is Untrusted, kind/size bare (ADR-056)."""
    from vivarium.core.envelope import DataOrigin, Untrusted

    a = s.ListDataTypesIn(session_id="s")
    assert a.offset == 0  # safe defaults
    with pytest.raises(ValidationError):
        s.ListDataTypesIn(session_id="s", limit=10_001)  # > hard cap

    out = s.DataTypeListOut(
        data_types=[
            s.DataTypeSummary(
                name=Untrusted(value="widget_t", origin=DataOrigin.BINARY), kind="struct", size=8
            )
        ],
        total=1,
    )
    dt = out.data_types[0]
    assert isinstance(dt.name, Untrusted)
    assert dt.kind == "struct" and dt.size == 8  # server/worker scalars stay bare
    assert out.total == 1


@pytest.mark.critical
def test_function_hash_requires_function_and_is_all_safe() -> None:
    """function_hash requires a function; all result fields are SAFE (opaque digests/scalars)."""
    from vivarium.core.envelope import Untrusted

    s.FunctionHashIn(session_id="s", function="main")  # ok
    with pytest.raises(ValidationError):
        s.FunctionHashIn(session_id="s", function="")  # function required (min_length=1)

    out = s.FunctionHashOut(
        address="0x401000",
        exact_bytes="-74093867017437165",
        exact_instructions="4495632401614105116",
        exact_mnemonics="8291194091361135616",
        instruction_count=2,
    )
    # The three hashes are opaque equality tokens; no field is binary-derived content.
    for value in out.model_dump().values():
        assert not isinstance(value, Untrusted)
    assert out.exact_instructions == "4495632401614105116"
