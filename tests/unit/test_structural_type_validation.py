"""Unit tests for the ADR-014 Phase B structured-type validators — critical-path (100% target).

Covers ``validate_type_ref`` / ``validate_signature`` / ``validate_calling_convention`` — the typed
barrier that REPLACES the C parser (ADR-014 §3). These are the new agency surface, so they get full
line + branch coverage: every allow-list, bound, and fail-closed branch is asserted. The validators
are pure/I/O-free; a violation raises a ``VALIDATION``/``LIMIT_EXCEEDED`` envelope that never echoes
the rejected value.
"""

from __future__ import annotations

import pytest

from ghidra_mcp.core import validation as v
from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.tools import schemas as s


def _ref(**kw: object) -> s.TypeRef:
    """Build a ``TypeRef`` (defaults to a valid ``int`` leaf)."""
    base = kw.pop("base", "int")
    return s.TypeRef(base=base, **kw)  # type: ignore[arg-type]


# --- validate_calling_convention --------------------------------------------------------------
@pytest.mark.critical
def test_calling_convention_none_is_allowed() -> None:
    assert v.validate_calling_convention(None) is None


@pytest.mark.critical
@pytest.mark.parametrize("cc", sorted(v.CALLING_CONVENTIONS))
def test_calling_convention_allows_each_member(cc: str) -> None:
    assert v.validate_calling_convention(cc) == cc


@pytest.mark.critical
@pytest.mark.parametrize("bad", ["__bogus", "cdecl", "", "void f()", "DEFAULT"])
def test_calling_convention_rejects_non_members(bad: str) -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_calling_convention(bad)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    if bad.strip():  # the rejected (untrusted) value is never echoed in the safe detail
        assert bad.strip() not in exc.value.envelope.detail


@pytest.mark.critical
def test_calling_convention_rejects_non_string() -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_calling_convention(123)  # type: ignore[arg-type]
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_type_ref: base leaf -------------------------------------------------------------
@pytest.mark.critical
@pytest.mark.parametrize("base", sorted(v.BASE_TYPE_VOCAB))
def test_type_ref_accepts_each_base(base: str) -> None:
    v.validate_type_ref(_ref(base=base))  # no raise


@pytest.mark.critical
def test_type_ref_named_leaf_accepts_identifier() -> None:
    v.validate_type_ref(s.TypeRef(named="MyStruct"))  # no raise


@pytest.mark.critical
def test_type_ref_named_leaf_rejects_c_declaration_syntax() -> None:
    # A named ref carrying C-declaration syntax is not a valid identifier and is never parsed.
    for payload in ("struct{int x;}", "int*", "a;b", "../p"):
        with pytest.raises(GhidraMcpError) as exc:
            v.validate_type_ref(s.TypeRef(named=payload))
        assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_type_ref_rejects_neither_leaf() -> None:
    # model_construct bypasses pydantic's model validator so the validator's own branch is hit.
    ref = s.TypeRef.model_construct(base=None, named=None, pointer_levels=0, array_len=None)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_type_ref_rejects_both_leaves() -> None:
    ref = s.TypeRef.model_construct(base="int", named="X", pointer_levels=0, array_len=None)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_type_ref_rejects_out_of_vocab_base() -> None:
    ref = s.TypeRef.model_construct(base="quad", named=None, pointer_levels=0, array_len=None)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_type_ref: modifiers (bounds + types) --------------------------------------------
@pytest.mark.critical
def test_type_ref_accepts_pointer_and_array_at_bounds() -> None:
    v.validate_type_ref(_ref(pointer_levels=v.MAX_POINTER_DEPTH))
    v.validate_type_ref(_ref(array_len=v.MAX_ARRAY_LEN))
    v.validate_type_ref(_ref(pointer_levels=0, array_len=1))


@pytest.mark.critical
def test_type_ref_rejects_pointer_depth_over_bound() -> None:
    ref = s.TypeRef.model_construct(
        base="int", named=None, pointer_levels=v.MAX_POINTER_DEPTH + 1, array_len=None
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_type_ref_rejects_negative_pointer_depth() -> None:
    ref = s.TypeRef.model_construct(base="int", named=None, pointer_levels=-1, array_len=None)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_type_ref_rejects_non_int_pointer_depth() -> None:
    ref = s.TypeRef.model_construct(base="int", named=None, pointer_levels=True, array_len=None)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_type_ref_rejects_array_len_over_bound() -> None:
    ref = s.TypeRef.model_construct(
        base="int", named=None, pointer_levels=0, array_len=v.MAX_ARRAY_LEN + 1
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_type_ref_rejects_zero_array_len() -> None:
    ref = s.TypeRef.model_construct(base="int", named=None, pointer_levels=0, array_len=0)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_type_ref_rejects_non_int_array_len() -> None:
    ref = s.TypeRef.model_construct(base="int", named=None, pointer_levels=0, array_len=True)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_type_ref(ref)
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_signature -----------------------------------------------------------------------
@pytest.mark.critical
def test_signature_accepts_minimal_valid_payload() -> None:
    sig = s.SetFunctionSignatureIn(
        session_id="sid",
        function="FUN_00401000",
        return_type=_ref(base="void"),
        parameters=[],
        calling_convention=None,
    )
    v.validate_signature(sig)  # no raise


@pytest.mark.critical
def test_signature_accepts_params_and_convention() -> None:
    sig = s.SetFunctionSignatureIn(
        session_id="sid",
        function="main",
        return_type=_ref(base="int"),
        parameters=[
            s.ParamSpec(name="argc", type=_ref(base="int")),
            s.ParamSpec(name="argv", type=_ref(base="char", pointer_levels=2)),
        ],
        calling_convention="__cdecl",
    )
    v.validate_signature(sig)  # no raise


@pytest.mark.critical
def test_signature_rejects_bad_function_selector() -> None:
    sig = s.SetFunctionSignatureIn(
        session_id="sid",
        function="bad\x01name",
        return_type=_ref(base="int"),
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_signature(sig)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_signature_rejects_injection_param_name() -> None:
    sig = s.SetFunctionSignatureIn(
        session_id="sid",
        function="f",
        return_type=_ref(base="int"),
        parameters=[s.ParamSpec(name="../evil", type=_ref(base="int"))],
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_signature(sig)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_signature_rejects_bad_param_type() -> None:
    # A param type with a bad named leaf trips validate_type_ref inside the loop.
    bad_type = s.TypeRef.model_construct(base=None, named="int*", pointer_levels=0, array_len=None)
    sig = s.SetFunctionSignatureIn.model_construct(
        session_id="sid",
        function="f",
        return_type=_ref(base="int"),
        parameters=[s.ParamSpec.model_construct(name="p", type=bad_type)],
        calling_convention=None,
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_signature(sig)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_signature_rejects_bad_return_type() -> None:
    bad_return = s.TypeRef.model_construct(
        base="nope", named=None, pointer_levels=0, array_len=None
    )
    sig = s.SetFunctionSignatureIn.model_construct(
        session_id="sid",
        function="f",
        return_type=bad_return,
        parameters=[],
        calling_convention=None,
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_signature(sig)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_signature_rejects_oversized_param_list() -> None:
    # model_construct bypasses pydantic max_length so the validator's own LIMIT branch is exercised.
    over = [s.ParamSpec(name=f"p{i}", type=_ref(base="int")) for i in range(v.MAX_PARAMS + 1)]
    sig = s.SetFunctionSignatureIn.model_construct(
        session_id="sid",
        function="f",
        return_type=_ref(base="int"),
        parameters=over,
        calling_convention=None,
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_signature(sig)
    assert exc.value.envelope.type is ErrorType.LIMIT_EXCEEDED


@pytest.mark.critical
def test_signature_rejects_bad_calling_convention() -> None:
    sig = s.SetFunctionSignatureIn(
        session_id="sid",
        function="f",
        return_type=_ref(base="int"),
        calling_convention="__bogus",
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_signature(sig)
    assert exc.value.envelope.type is ErrorType.VALIDATION
