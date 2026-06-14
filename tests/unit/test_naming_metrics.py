"""Unit tests for the naming-quality eval metrics (ADR-010, ADR-016).

Hermetic: the compile runner is a deterministic fake (a real one must sandbox the untrusted C —
ADR-010 §Security). Cover name coverage (incl. placeholder detection), scoring with/without a
compiler, and the pure ADR-016 ``behavioral_equivalence`` differential oracle (100% line+branch on
the critical comparison core — it executes NOTHING, only compares inert captured run-results).
"""

from __future__ import annotations

from ghidra_mcp.naming.loop import FunctionNaming, RenamedProgram
from ghidra_mcp.naming.metrics import (
    CompileResult,
    RunResult,
    behavioral_equivalence,
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


def test_naming_accuracy_handles_empty_token_identifiers() -> None:
    # An all-punctuation proposed name tokenizes to an empty set; token-F1's empty-set branch
    # must score 0.0 against a real-token truth (not crash) and a non-zero exact rate is impossible.
    prog = _program(_inferred("0x401000", "__"))
    acc = naming_accuracy(prog, {"0x401000": "parse_value"})
    assert acc.scored == 1 and acc.mean_token_f1 == 0.0
    # Two empty-token identifiers are token-equal → F1 1.0 (the ``pt == tt`` side of the branch).
    same = _program(_inferred("0x401000", "__"))
    assert naming_accuracy(same, {"0x401000": "++"}).mean_token_f1 == 1.0


def test_score_wires_ground_truth() -> None:
    prog = _program(_inferred("0x401000", "decode"))
    assert score(prog).naming_accuracy is None  # not measured without truth
    m = score(prog, ground_truth={"0x401000": "decode"})
    assert m.naming_accuracy is not None
    assert m.naming_accuracy.exact_match_rate == 1.0


# --- behavioral_equivalence (ADR-016 differential oracle — pure, executes nothing) ---------------


def _run(exit_code: int, stdout: bytes, *, ok: bool = True) -> RunResult:
    return RunResult(ok=ok, exit_code=exit_code, stdout=stdout)


def test_behavioral_equivalence_all_match_is_one() -> None:
    # Both builds agree on (exit_code, stdout) for every vector → perfect equivalence.
    a = [_run(0, b"hello\n"), _run(0, b"42\n")]
    b = [_run(0, b"hello\n"), _run(0, b"42\n")]
    assert behavioral_equivalence(a, b) == 1.0


def test_behavioral_equivalence_partial_match_is_fraction() -> None:
    # Vector 1 matches; vector 2 differs in stdout; vector 3 differs in exit code → 1/3.
    a = [_run(0, b"x"), _run(0, b"y"), _run(0, b"z")]
    b = [_run(0, b"x"), _run(0, b"DIFFERENT"), _run(7, b"z")]
    assert behavioral_equivalence(a, b) == 1 / 3


def test_behavioral_equivalence_byte_exact_no_normalization() -> None:
    # A single trailing-whitespace difference is a NON-match (byte-exact, no normalization — D2).
    a = [_run(0, b"result\n")]
    b = [_run(0, b"result \n")]
    assert behavioral_equivalence(a, b) == 0.0


def test_behavioral_equivalence_failed_build_scores_zero() -> None:
    # A stub / non-recompiling candidate (ok=False) matches NOTHING — low score is honest (D2).
    a = [_run(0, b"out"), _run(0, b"out2")]
    b = [RunResult(ok=False), RunResult(ok=False)]
    assert behavioral_equivalence(a, b) == 0.0


def test_behavioral_equivalence_one_side_failed_is_nonmatch() -> None:
    # Even if exit/stdout would line up, ok=False on EITHER side is a non-match.
    a = [_run(0, b"same")]
    b = [RunResult(ok=False, exit_code=0, stdout=b"same")]
    assert behavioral_equivalence(a, b) == 0.0


def test_behavioral_equivalence_none_when_no_reference() -> None:
    # No trusted reference (build A) → unavailable, never a fabricated number (D1).
    assert behavioral_equivalence(None, [_run(0, b"x")]) is None
    assert behavioral_equivalence([_run(0, b"x")], None) is None
    assert behavioral_equivalence(None, None) is None


def test_behavioral_equivalence_none_when_empty() -> None:
    # No input vectors → nothing to compare → unavailable.
    assert behavioral_equivalence([], []) is None
    assert behavioral_equivalence([], [_run(0, b"x")]) is None


def test_behavioral_equivalence_none_when_lengths_differ() -> None:
    # A misaligned vector set has no shared basis → unavailable, not a partial guess.
    assert behavioral_equivalence([_run(0, b"x")], [_run(0, b"x"), _run(0, b"y")]) is None


def test_score_wires_behavioral_runs_when_supplied() -> None:
    prog = _program(_inferred("0x401000", "decode"))
    # No runs supplied → behavioral_equivalence stays None (honest unavailability — D1).
    assert score(prog).behavioral_equivalence is None
    # Reference (A) and candidate (B) runs supplied → measured match-rate is populated.
    ref = [_run(0, b"ok"), _run(0, b"two")]
    cand = [_run(0, b"ok"), _run(0, b"NOPE")]
    m = score(prog, behavioral_runs=(ref, cand))
    assert m.behavioral_equivalence == 0.5


def test_score_behavioral_runs_none_propagates_when_unavailable() -> None:
    # A supplied-but-degenerate run pair (mismatched lengths) → the metric is None, not a crash.
    prog = _program(_inferred("0x401000", "decode"))
    m = score(prog, behavioral_runs=([_run(0, b"x")], []))
    assert m.behavioral_equivalence is None
