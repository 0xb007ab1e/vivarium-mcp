"""Unit tests for the ADR-015 Phase C composite-type validators — critical-path (100% target).

Covers ``validate_field_spec`` / ``validate_composite`` — the typed barrier for the program's type
universe (ADR-015 §4). These are the new agency surface, so they get full line + branch coverage:
every allow-list, bound, the duplicate-member-name check, and the **by-value self-embed boundary
rejection** (the recursion crux, ADR-015 §3.2) are asserted. The validators are pure/I/O-free; a
violation raises a ``VALIDATION``/``LIMIT_EXCEEDED`` envelope that never echoes the rejected value.
The composite total-size cap is a worker concern (it needs resolved ``DataType.getLength()``), so it
is NOT enforced here (asserted as an integration-gated abuse case).
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


def _field(name: str = "f", **kw: object) -> s.FieldSpec:
    """Build a ``FieldSpec`` (defaults to an ``int`` member)."""
    ref = kw.pop("type", _ref())
    return s.FieldSpec(name=name, type=ref, **kw)  # type: ignore[arg-type]


# --- validate_field_spec ----------------------------------------------------------------------
@pytest.mark.critical
def test_field_spec_accepts_minimal_member() -> None:
    v.validate_field_spec(_field())  # no raise


@pytest.mark.critical
def test_field_spec_accepts_offset_at_bounds() -> None:
    v.validate_field_spec(_field(offset=0))
    v.validate_field_spec(_field(offset=v.MAX_COMPOSITE_SIZE - 1))


@pytest.mark.critical
def test_field_spec_accepts_named_type_member() -> None:
    v.validate_field_spec(s.FieldSpec(name="next", type=s.TypeRef(named="Node", pointer_levels=1)))


@pytest.mark.critical
@pytest.mark.parametrize("malicious", ["<script>", "../path", "has space", "rtl‮name"])
def test_field_spec_rejects_injection_member_name(malicious: str) -> None:
    field = s.FieldSpec.model_construct(name=malicious, type=_ref(), offset=None)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_field_spec(field)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert malicious.strip() not in exc.value.envelope.detail


@pytest.mark.critical
def test_field_spec_rejects_injection_named_type() -> None:
    # A FieldSpec.type with C-declaration syntax in `named` trips validate_type_ref (never parsed).
    bad = s.TypeRef.model_construct(
        base=None, named="struct{int x;}", pointer_levels=0, array_len=None
    )
    field = s.FieldSpec.model_construct(name="f", type=bad, offset=None)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_field_spec(field)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_field_spec_rejects_negative_offset() -> None:
    field = s.FieldSpec.model_construct(name="f", type=_ref(), offset=-1)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_field_spec(field)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_field_spec_rejects_offset_over_bound() -> None:
    field = s.FieldSpec.model_construct(name="f", type=_ref(), offset=v.MAX_COMPOSITE_SIZE)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_field_spec(field)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_field_spec_rejects_non_int_offset() -> None:
    field = s.FieldSpec.model_construct(name="f", type=_ref(), offset=True)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_field_spec(field)
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_composite: struct ---------------------------------------------------------------
@pytest.mark.critical
def test_composite_accepts_minimal_struct() -> None:
    payload = s.DefineStructIn(
        session_id="sid", name="Packet", fields=[_field("id"), _field("len")]
    )
    v.validate_composite(payload, kind="struct")  # no raise


@pytest.mark.critical
def test_composite_accepts_struct_with_offsets() -> None:
    payload = s.DefineStructIn(
        session_id="sid",
        name="Packet",
        fields=[_field("a", offset=0), _field("b", offset=8)],
        packed=True,
    )
    v.validate_composite(payload, kind="struct")  # no raise


@pytest.mark.critical
def test_composite_accepts_pointer_to_self() -> None:
    # A linked-list `next` pointer-to-self is fixed-size and ALLOWED (ADR-015 §3.1).
    payload = s.DefineStructIn(
        session_id="sid",
        name="Node",
        fields=[
            _field("value"),
            s.FieldSpec(name="next", type=s.TypeRef(named="Node", pointer_levels=1)),
        ],
    )
    v.validate_composite(payload, kind="struct")  # no raise


@pytest.mark.critical
def test_composite_accepts_opaque_void_pointer_self_idiom() -> None:
    payload = s.DefineStructIn(
        session_id="sid",
        name="Node",
        fields=[s.FieldSpec(name="next", type=s.TypeRef(base="void", pointer_levels=1))],
    )
    v.validate_composite(payload, kind="struct")  # no raise


@pytest.mark.critical
def test_composite_rejects_bad_name() -> None:
    payload = s.DefineStructIn.model_construct(
        session_id="sid", name="../evil", fields=[_field()], packed=False
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="struct")
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_composite_rejects_empty_field_list() -> None:
    # model_construct bypasses pydantic min_length so the validator's own non-empty branch fires.
    payload = s.DefineStructIn.model_construct(
        session_id="sid", name="Empty", fields=[], packed=False
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="struct")
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_composite_rejects_oversized_field_count() -> None:
    over = [_field(f"f{i}") for i in range(v.MAX_FIELDS + 1)]
    payload = s.DefineStructIn.model_construct(
        session_id="sid", name="Big", fields=over, packed=False
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="struct")
    assert exc.value.envelope.type is ErrorType.LIMIT_EXCEEDED


@pytest.mark.critical
def test_composite_rejects_duplicate_member_names() -> None:
    payload = s.DefineStructIn(session_id="sid", name="Dup", fields=[_field("x"), _field("x")])
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="struct")
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_composite_rejects_injection_member_name() -> None:
    payload = s.DefineStructIn.model_construct(
        session_id="sid",
        name="S",
        fields=[s.FieldSpec.model_construct(name="../evil", type=_ref(), offset=None)],
        packed=False,
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="struct")
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- the recursion crux: by-value self-embed rejected (ADR-015 §3.2) --------------------------
@pytest.mark.critical
def test_composite_rejects_by_value_self_embed() -> None:
    # A member of type `Node` (no pointer, no array) embeds Node by value → infinite size → REJECT.
    payload = s.DefineStructIn.model_construct(
        session_id="sid",
        name="Node",
        fields=[
            s.FieldSpec.model_construct(
                name="self",
                type=s.TypeRef.model_construct(
                    base=None, named="Node", pointer_levels=0, array_len=None
                ),
                offset=None,
            )
        ],
        packed=False,
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="struct")
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_composite_rejects_array_of_self_embed() -> None:
    # An array-of-self is still a by-value embed (ADR-015 §3.2) → REJECT.
    payload = s.DefineStructIn.model_construct(
        session_id="sid",
        name="Node",
        fields=[
            s.FieldSpec.model_construct(
                name="kids",
                type=s.TypeRef.model_construct(
                    base=None, named="Node", pointer_levels=0, array_len=4
                ),
                offset=None,
            )
        ],
        packed=False,
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="struct")
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_composite_allows_pointer_to_self_not_rejected() -> None:
    # Pointer-to-self must NOT trip the self-embed reject (the boundary check is pointer_levels==0).
    payload = s.DefineStructIn.model_construct(
        session_id="sid",
        name="Node",
        fields=[
            s.FieldSpec.model_construct(
                name="next",
                type=s.TypeRef.model_construct(
                    base=None, named="Node", pointer_levels=1, array_len=None
                ),
                offset=None,
            )
        ],
        packed=False,
    )
    v.validate_composite(payload, kind="struct")  # no raise


# --- validate_composite: union ----------------------------------------------------------------
@pytest.mark.critical
def test_composite_accepts_minimal_union() -> None:
    payload = s.DefineUnionIn(session_id="sid", name="U", fields=[_field("a"), _field("b")])
    v.validate_composite(payload, kind="union")  # no raise


@pytest.mark.critical
def test_composite_union_rejects_member_offset() -> None:
    # A union overlays all members at 0 — an offset is a struct-only field (foot-gun) → REJECT.
    payload = s.DefineUnionIn.model_construct(
        session_id="sid",
        name="U",
        fields=[s.FieldSpec.model_construct(name="a", type=_ref(), offset=4)],
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="union")
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_composite_union_rejects_by_value_self_embed() -> None:
    payload = s.DefineUnionIn.model_construct(
        session_id="sid",
        name="U",
        fields=[
            s.FieldSpec.model_construct(
                name="self",
                type=s.TypeRef.model_construct(
                    base=None, named="U", pointer_levels=0, array_len=None
                ),
                offset=None,
            )
        ],
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_composite(payload, kind="union")
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- the schema model validators are a duplicate barrier (defense in depth) -------------------
def test_struct_schema_rejects_by_value_self_embed_at_construction() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        s.DefineStructIn(
            session_id="sid",
            name="Node",
            fields=[s.FieldSpec(name="self", type=s.TypeRef(named="Node"))],
        )


def test_union_schema_rejects_member_offset_at_construction() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        s.DefineUnionIn(
            session_id="sid",
            name="U",
            fields=[s.FieldSpec(name="a", type=s.TypeRef(base="int"), offset=0)],
        )
