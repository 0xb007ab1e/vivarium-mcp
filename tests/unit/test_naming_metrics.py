"""Unit tests for the naming-quality eval metrics (ADR-010).

Hermetic: the compile runner is a deterministic fake (a real one must sandbox the untrusted C —
ADR-010 §Security). Cover name coverage (incl. placeholder detection), and scoring with/without a
compiler.
"""

from __future__ import annotations

from ghidra_mcp.naming.loop import FunctionNaming, RenamedProgram
from ghidra_mcp.naming.metrics import CompileResult, name_coverage, score


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
