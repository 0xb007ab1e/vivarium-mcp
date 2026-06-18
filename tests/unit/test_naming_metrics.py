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
    behavioral_equivalence_normalized,
    generate_fuzz_vectors,
    name_coverage,
    naming_accuracy,
    normalize_output,
    score,
    score_name_map,
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


# --- score_name_map (the public map-vs-map core reused by the on-demand scorer, ADR-010/v1.5) -----


def test_score_name_map_exact_and_partial_credit() -> None:
    """The pure map-vs-map scorer: exact (case/underscore-insensitive) + token-F1 partial credit."""
    proposed = {"0x401000": "cjson_parse", "0x401286": "get_array_size"}
    truth = {"0x401000": "cJSON_Parse", "0x401286": "cJSON_GetArraySize"}
    acc = score_name_map(proposed, truth)
    assert acc.scored == 2
    assert acc.exact_matches == 1  # cjson_parse ≈ cJSON_Parse (normalized equal)
    assert acc.exact_match_rate == 0.5
    assert 0.0 < acc.mean_token_f1 <= 1.0  # second pair earns partial token-set credit


def test_score_name_map_unscored_when_absent_from_truth() -> None:
    """A proposed entry whose address isn't in the ground truth is unscored (honest denominator)."""
    acc = score_name_map({"0x401000": "x", "0x499999": "y"}, {"0x401000": "parse"})
    assert acc.scored == 1 and acc.unscored == 1


def test_score_name_map_joins_regardless_of_hex_formatting() -> None:
    """Addresses join by integer value (``0x401286`` vs ``401286`` are the same key)."""
    acc = score_name_map({"401286": "parse_string"}, {"0x401286": "parse_string"})
    assert acc.scored == 1 and acc.exact_matches == 1


def test_score_name_map_matches_naming_accuracy_projection() -> None:
    """score_name_map over the program's inferred projection equals naming_accuracy (delegation)."""
    prog = _program(_inferred("0x401000", "decode"), _external("0x402000", "free"))
    truth = {"0x401000": "decode_frame", "0x402000": "free"}
    projected = {"0x401000": "decode"}  # only the inferred function (externals aren't scored)
    assert score_name_map(projected, truth) == naming_accuracy(prog, truth)


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
    assert m.behavioral_equivalence_normalized is None


# --- normalize_output (ADR-022 D1 — conservative, pure, executes nothing) ------------------------


def test_normalize_output_masks_pointer_like_hex() -> None:
    # A printed pointer address is volatile (varies build-to-build) → masked to a constant.
    assert normalize_output(b"ptr=0x401286 done") == b"ptr=<X> done"
    # Bare decimals and ordinary hex-looking words (no 0x) are NOT touched — conservative.
    assert normalize_output(b"count=42 hexish=deadbeef") == b"count=42 hexish=deadbeef"


def test_normalize_output_masks_timestamps() -> None:
    # Clock time HH:MM:SS (with/without fraction) and ISO-8601 dates/datetimes are volatile.
    assert normalize_output(b"at 12:34:56 ok") == b"at <X> ok"
    assert normalize_output(b"t=12:34:56.789") == b"t=<X>"
    assert normalize_output(b"on 2026-06-15 fine") == b"on <X> fine"
    assert normalize_output(b"ts=2026-06-15T12:34:56") == b"ts=<X>"
    # An ordinary colon-delimited key:value (not HH:MM:SS) is left alone — conservative.
    assert normalize_output(b"ratio=3:4 key:value") == b"ratio=3:4 key:value"


def test_normalize_output_masks_labelled_pids_only() -> None:
    # A clearly-labelled pid is volatile and masked; a bare number is NEVER treated as a pid.
    assert normalize_output(b"pid=1234 alive") == b"<X> alive"
    assert normalize_output(b"PID: 99 up") == b"<X> up"
    # No "pid" label → the digits are ordinary data, untouched.
    assert normalize_output(b"value 1234 here") == b"value 1234 here"


def test_normalize_output_canonicalizes_whitespace_and_line_endings() -> None:
    # CRLF / lone CR → LF; trailing spaces/tabs stripped per line and at end of output.
    assert normalize_output(b"a  \r\nb\t\rc   ") == b"a\nb\nc"


def test_normalize_output_non_masking_case_does_not_over_strip() -> None:
    # Ordinary text with NO volatile tokens must round-trip byte-identically (proves it only
    # loosens where a volatile shape actually matches — no over-stripping of normal output).
    text = b"parsed 3 records: name=foo, ok=true\nresult value is 42\n"
    assert normalize_output(text) == text


def test_normalize_output_is_idempotent() -> None:
    # Applying the normalizer twice is a no-op (stable) — required for a sound looser compare.
    once = normalize_output(b"addr 0x10 at 12:00:00 pid=7  \r\n")
    assert normalize_output(once) == once


# --- behavioral_equivalence_normalized (ADR-022 D1 — looser oracle, executes nothing) ------------


def test_normalized_equivalence_pointer_only_diff_strict_below_one_normalized_one() -> None:
    # THE headline case (ADR-022): two builds whose stdout differs ONLY in a printed pointer
    # address. Byte-exact (strict) penalizes it (< 1.0); normalized masks the pointer → 1.0.
    a = [_run(0, b"result at 0x401286\n")]
    b = [_run(0, b"result at 0x7ffe00\n")]
    strict = behavioral_equivalence(a, b)
    assert strict is not None and strict < 1.0
    assert strict == 0.0
    assert behavioral_equivalence_normalized(a, b) == 1.0


def test_normalized_equivalence_exit_code_still_exact() -> None:
    # exit_code is NEVER normalized — a differing exit code is a non-match even if stdout aligns.
    a = [_run(0, b"x at 0x1\n")]
    b = [_run(7, b"x at 0x2\n")]
    assert behavioral_equivalence_normalized(a, b) == 0.0


def test_normalized_equivalence_ge_strict_invariant_on_mixed_set() -> None:
    # On a mixed set: v1 byte-exact match; v2 differs only in a pointer (normalized-equal);
    # v3 a genuine behavioral diff (different text). normalized (2/3) >= strict (1/3).
    a = [_run(0, b"same\n"), _run(0, b"p=0x10\n"), _run(0, b"alpha\n")]
    b = [_run(0, b"same\n"), _run(0, b"p=0x20\n"), _run(0, b"beta\n")]
    strict = behavioral_equivalence(a, b)
    norm = behavioral_equivalence_normalized(a, b)
    assert strict == 1 / 3
    assert norm == 2 / 3
    assert norm is not None and strict is not None and norm >= strict


def test_normalized_equivalence_failed_build_is_nonmatch() -> None:
    # ok=False on either side is still a non-match under the normalized oracle (honest).
    a = [_run(0, b"out 0x1\n")]
    b = [RunResult(ok=False, exit_code=0, stdout=b"out 0x2\n")]
    assert behavioral_equivalence_normalized(a, b) == 0.0


def test_normalized_equivalence_unavailable_like_strict() -> None:
    # Same unavailability rules as the strict oracle: None / empty / mismatched length → None.
    assert behavioral_equivalence_normalized(None, [_run(0, b"x")]) is None
    assert behavioral_equivalence_normalized([_run(0, b"x")], None) is None
    assert behavioral_equivalence_normalized([], []) is None
    mism = behavioral_equivalence_normalized([_run(0, b"x")], [_run(0, b"x"), _run(0, b"y")])
    assert mism is None


def test_score_wires_both_strict_and_normalized() -> None:
    # score() reports BOTH signals; the pointer-only diff is strict<1.0 but normalized==1.0.
    prog = _program(_inferred("0x401000", "decode"))
    ref = [_run(0, b"addr 0x401286\n")]
    cand = [_run(0, b"addr 0xdead00\n")]
    m = score(prog, behavioral_runs=(ref, cand))
    assert m.behavioral_equivalence == 0.0
    assert m.behavioral_equivalence_normalized == 1.0


# --- generate_fuzz_vectors (ADR-022 D2 — pure, deterministic, bounded) ---------------------------


def test_generate_fuzz_vectors_deterministic_same_seed() -> None:
    # A fixed seed → byte-identical vectors across calls (reproducible, hermetic — no wall-clock).
    assert generate_fuzz_vectors(seed=1234, count=8, max_len=16) == generate_fuzz_vectors(
        seed=1234, count=8, max_len=16
    )


def test_generate_fuzz_vectors_different_seed_differs() -> None:
    # Different seeds yield (with overwhelming probability) different vector sets.
    assert generate_fuzz_vectors(seed=1, count=8, max_len=16) != generate_fuzz_vectors(
        seed=2, count=8, max_len=16
    )


def test_generate_fuzz_vectors_respects_bounds() -> None:
    vectors = generate_fuzz_vectors(seed=42, count=20, max_len=12)
    assert len(vectors) == 20
    assert all(isinstance(v, bytes) and 0 <= len(v) <= 12 for v in vectors)


def test_generate_fuzz_vectors_zero_count_is_empty() -> None:
    assert generate_fuzz_vectors(seed=0, count=0, max_len=10) == []


def test_generate_fuzz_vectors_zero_max_len_is_all_empty() -> None:
    # max_len 0 → every vector is empty bytes (still exactly `count` of them).
    vectors = generate_fuzz_vectors(seed=7, count=5, max_len=0)
    assert vectors == [b""] * 5


def test_generate_fuzz_vectors_fails_closed_on_negative_bounds() -> None:
    # Defensive bound: negative count/max_len fail closed (ValueError), never silently misbehave.
    import pytest

    with pytest.raises(ValueError, match="count must be >= 0"):
        generate_fuzz_vectors(seed=0, count=-1, max_len=4)
    with pytest.raises(ValueError, match="max_len must be >= 0"):
        generate_fuzz_vectors(seed=0, count=1, max_len=-1)
