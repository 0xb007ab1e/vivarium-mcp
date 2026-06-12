"""Unit tests for the naming-quality eval metrics (ADR-010).

Hermetic: the compile runner is a deterministic fake (a real one must sandbox the untrusted C —
ADR-010 §Security). Cover name coverage (incl. placeholder detection), and scoring with/without a
compiler.
"""

from __future__ import annotations

from ghidra_mcp.naming.loop import FunctionNaming, RenamedProgram
from ghidra_mcp.naming.metrics import (
    CompileResult,
    name_coverage,
    naming_accuracy,
    score,
)


def _program(*functions: FunctionNaming, tu: str = "int x(void){return 0;}\n") -> RenamedProgram:
    return RenamedProgram(functions=tuple(functions), translation_unit=tu)


def _inferred(addr: str, name: str) -> FunctionNaming:
    return FunctionNaming(
        address=addr,
        original_name=f"FUN_{addr[2:]}",
        assigned_name=name,
        is_external=False,
        inferred=True,
        renamed_c=f"int {name}(void){{return 0;}}",
    )


def _external(addr: str, name: str) -> FunctionNaming:
    return FunctionNaming(
        address=addr, original_name=name, assigned_name=name, is_external=True, inferred=False
    )


def test_name_coverage_counts_only_meaningful_names() -> None:
    prog = _program(
        _inferred("0x401000", "parse_header"),  # meaningful
        _inferred("0x401100", "FUN_00401100"),  # still a placeholder → not counted
        _external("0x402000", "puts"),  # external → not in denominator
    )
    # 1 of 2 inferred functions got a meaningful name.
    assert name_coverage(prog) == 0.5


def test_name_coverage_zero_when_nothing_inferred() -> None:
    assert name_coverage(_program(_external("0x402000", "malloc"))) == 0.0


def test_score_without_compiler_measures_coverage_only() -> None:
    prog = _program(_inferred("0x401000", "decode"), _external("0x402000", "free"))
    m = score(prog)
    assert m.total_functions == 2
    assert m.inferred_functions == 1
    assert m.external_functions == 1
    assert m.named_functions == 1
    assert m.name_coverage == 1.0
    assert m.compiles is None and m.compile_diagnostics is None
    assert m.behavioral_equivalence is None  # deferred (research-hard)


def test_score_with_compiler_records_result() -> None:
    prog = _program(_inferred("0x401000", "main"))
    captured: list[str] = []

    def fake_compiler(src: str) -> CompileResult:
        captured.append(src)
        return CompileResult(ok=False, diagnostics="error: implicit declaration")

    m = score(prog, compile_runner=fake_compiler)
    assert captured == [prog.translation_unit]  # the TU was handed to the (sandboxed) compiler
    assert m.compiles is False
    assert "implicit declaration" in (m.compile_diagnostics or "")


def test_score_with_passing_compiler() -> None:
    prog = _program(_inferred("0x401000", "ok"))
    m = score(prog, compile_runner=lambda _src: CompileResult(ok=True))
    assert m.compiles is True
    assert m.compile_diagnostics == ""


# --- naming_accuracy (vs ground truth) -----------------------------------------------------------


def test_naming_accuracy_exact_and_semantic_partial_credit() -> None:
    prog = _program(
        _inferred("0x401286", "case_insensitive_strcmp"),  # exact
        _inferred("0x402865", "skip_whitespace"),  # truth buffer_skip_whitespace → partial
        _inferred("0x404075", "get_array_size"),  # truth cJSON_GetArraySize → partial
        _inferred("0x401eac", "wat"),  # truth parse_hex4 → miss
    )
    truth = {
        "0x401286": "case_insensitive_strcmp",
        "0x402865": "buffer_skip_whitespace",
        "0x404075": "cJSON_GetArraySize",
        "0x401eac": "parse_hex4",
    }
    acc = naming_accuracy(prog, truth)
    assert acc.scored == 4 and acc.unscored == 0
    assert acc.exact_matches == 1  # only case_insensitive_strcmp is a normalized-exact hit
    assert acc.exact_match_rate == 0.25
    # skip_whitespace⊂buffer_skip_whitespace: P=2/2, R=2/3 → F1=0.8; get_array_size vs
    # cJSON_GetArraySize: overlap{get,array,size}=3, P=3/3, R=3/5 → F1=0.75; exact=1.0; miss=0.0.
    assert acc.mean_token_f1 == (1.0 + 0.8 + 0.75 + 0.0) / 4


def test_naming_accuracy_unscored_when_no_truth_entry() -> None:
    prog = _program(
        _inferred("0x401000", "parse_value"),  # in truth
        _inferred("0x409999", "helper"),  # NOT in truth → unscored, not penalized
        _external("0x402000", "memcpy"),  # external → never scored
    )
    acc = naming_accuracy(prog, {"0x401000": "parse_value"})
    assert acc.scored == 1 and acc.unscored == 1
    assert acc.exact_matches == 1 and acc.exact_match_rate == 1.0 and acc.mean_token_f1 == 1.0


def test_naming_accuracy_joins_regardless_of_hex_formatting() -> None:
    # Program reports "00401286"; truth key is "0x401286" — same address, must join.
    prog = _program(_inferred("00401286", "parse_string"))
    acc = naming_accuracy(prog, {"0x401286": "parse_string"})
    assert acc.scored == 1 and acc.exact_matches == 1


def test_naming_accuracy_empty_when_nothing_scored() -> None:
    acc = naming_accuracy(_program(_external("0x402000", "free")), {"0x402000": "free"})
    assert acc.scored == 0 and acc.exact_match_rate == 0.0 and acc.mean_token_f1 == 0.0


def test_naming_accuracy_ignores_unparseable_addresses() -> None:
    # A non-hex address simply doesn't join (defensive) — counted unscored, never raises.
    prog = _program(_inferred("not-an-address", "x"))
    acc = naming_accuracy(prog, {"zzzz": "y", "0x401000": "z"})
    assert acc.scored == 0 and acc.unscored == 1


def test_score_wires_ground_truth() -> None:
    prog = _program(_inferred("0x401000", "decode"))
    assert score(prog).naming_accuracy is None  # not measured without truth
    m = score(prog, ground_truth={"0x401000": "decode"})
    assert m.naming_accuracy is not None
    assert m.naming_accuracy.exact_match_rate == 1.0
