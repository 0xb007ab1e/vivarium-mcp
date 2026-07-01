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

hypothesis = pytest.importorskip("hypothesis")  # skip cleanly if the property-test extra is absent
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from vivarium.core import validation as v  # noqa: E402
from vivarium.core.errors import ErrorType, GhidraMcpError  # noqa: E402
from vivarium.tools import schemas as s  # noqa: E402


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


# =================================================================================================
# ADR-021 — multi-type composite batch validator (validate_types_batch + the by-value cycle
# detector). The detector is the load-bearing NEW control → full line + branch coverage: every
# edge-build branch (by-value vs pointer, in-batch vs out-of-batch, array-of-self), every cycle
# shape (self / A↔B / 3-cycle), and the allow cases (pointer cycle, diamond) are asserted.
# =================================================================================================
def _spec(kind: str, name: str, fields: list[s.FieldSpec], **kw: object) -> s.CompositeSpec:
    """Build a ``CompositeSpec`` (model_construct — bypass the schema validator to reach the pure
    ``validate_types_batch`` reject branches with a known-bad shape)."""
    return s.CompositeSpec.model_construct(
        kind=kind, name=name, fields=fields, packed=bool(kw.get("packed", False))
    )


def _batch(types: list[s.CompositeSpec]) -> s.DefineTypesIn:
    """Build a ``DefineTypesIn`` (model_construct) from a list of composite entries."""
    return s.DefineTypesIn.model_construct(session_id="sid", types=types)


def _named_field(
    name: str, target: str, pointer_levels: int = 0, array_len: int | None = None
) -> s.FieldSpec:
    """A member whose type is a ``named`` reference to ``target`` (pointer/array modifiers)."""
    return s.FieldSpec.model_construct(
        name=name,
        type=s.TypeRef.model_construct(
            base=None,
            named=target,
            pointer_levels=pointer_levels,
            array_len=array_len,
        ),
        offset=None,
    )


# --- validate_types_batch: acceptance --------------------------------------------------------
@pytest.mark.critical
def test_batch_accepts_minimal_single_type() -> None:
    v.validate_types_batch(_batch([_spec("struct", "A", [_field("x")])]))  # no raise


@pytest.mark.critical
def test_batch_accepts_mixed_struct_and_union() -> None:
    batch = _batch(
        [
            _spec("struct", "A", [_field("x")]),
            _spec("union", "U", [_field("a"), _field("b")]),
        ]
    )
    v.validate_types_batch(batch)  # no raise — mixed kinds allowed (ADR-021 D1)


@pytest.mark.critical
def test_batch_accepts_a_referencing_new_b_by_value_acyclic() -> None:
    # A embeds B by value, B references nothing back → acyclic → allowed (the headline capability).
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("b", "B")]),
            _spec("struct", "B", [_field("x")]),
        ]
    )
    v.validate_types_batch(batch)  # no raise


@pytest.mark.critical
def test_batch_accepts_diamond_without_cycle() -> None:
    # A→B, A→C, B→D, C→D (all by value) — a DAG/diamond, no cycle → allowed.
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("b", "B"), _named_field("c", "C")]),
            _spec("struct", "B", [_named_field("d", "D")]),
            _spec("struct", "C", [_named_field("d", "D")]),
            _spec("struct", "D", [_field("x")]),
        ]
    )
    v.validate_types_batch(batch)  # no raise


@pytest.mark.critical
def test_batch_dedups_repeated_by_value_edge_to_same_target() -> None:
    # A has TWO by-value members (distinct names) both of type B -> a single A->B edge (the dedup
    # `named not in targets` skip). No cycle -> allowed.
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("b1", "B"), _named_field("b2", "B")]),
            _spec("struct", "B", [_field("x")]),
        ]
    )
    v.validate_types_batch(batch)  # no raise


def test_batch_revisits_shared_target_via_two_parents_no_cycle() -> None:
    # A -> C and A -> B (field order), B -> C — a DAG where C is reached via two parents. With the
    # detector's deterministic (field-order) adjacency, C is pushed by A, then re-pushed by B before
    # the stale A-entry is popped, so the "node already visited via another path -> skip" branch is
    # exercised deterministically. No by-value cycle -> allowed (regression: this coverage must not
    # depend on set/hash order).
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("c", "C"), _named_field("b", "B")]),
            _spec("struct", "B", [_named_field("c", "C")]),
            _spec("struct", "C", [_field("x")]),
        ]
    )
    v.validate_types_batch(batch)  # no raise


def test_batch_allows_mutually_recursive_pointer_cycle() -> None:
    # A has `B *next`, B has `A *prev` (pointer_levels >= 1) → NO edge → pointer cycle ALLOWED.
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("next", "B", pointer_levels=1)]),
            _spec("struct", "B", [_named_field("prev", "A", pointer_levels=1)]),
        ]
    )
    v.validate_types_batch(batch)  # no raise


@pytest.mark.critical
def test_batch_allows_reference_to_existing_non_batch_named() -> None:
    # A member naming a type NOT in the batch creates no edge (the worker's not-found concern).
    batch = _batch([_spec("struct", "A", [_named_field("e", "ExistingType", pointer_levels=0)])])
    v.validate_types_batch(batch)  # no raise (the detector ignores non-batch named refs)


# --- validate_types_batch: bounds + dup ------------------------------------------------------
@pytest.mark.critical
def test_batch_rejects_empty_type_list() -> None:
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(_batch([]))
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_batch_rejects_oversized_type_count() -> None:
    over = [_spec("struct", f"T{i}", [_field("x")]) for i in range(v.MAX_TYPES_PER_BATCH + 1)]
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(_batch(over))
    assert exc.value.envelope.type is ErrorType.LIMIT_EXCEEDED


@pytest.mark.critical
def test_batch_rejects_duplicate_type_names() -> None:
    batch = _batch([_spec("struct", "T", [_field("x")]), _spec("union", "T", [_field("y")])])
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(batch)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_batch_propagates_per_type_validation_failure() -> None:
    # A per-type failure (bad member name) surfaces via the reused validate_composite.
    bad = _spec(
        "struct", "A", [s.FieldSpec.model_construct(name="../evil", type=_ref(), offset=None)]
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(_batch([bad]))
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_types_batch: the by-value cycle detector (the load-bearing control) ------------
@pytest.mark.critical
def test_batch_rejects_self_by_value_cycle() -> None:
    # A struct embedding itself by value — caught per-type AND by the detector's self-edge.
    batch = _batch([_spec("struct", "A", [_named_field("self", "A")])])
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(batch)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_batch_rejects_array_of_self_by_value_cycle() -> None:
    # array-of-self (pointer_levels == 0, array_len set) is a by-value embed → cycle → REJECT.
    batch = _batch([_spec("struct", "A", [_named_field("kids", "A", array_len=4)])])
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(batch)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_batch_rejects_two_node_by_value_cycle() -> None:
    # A embeds B by value, B embeds A by value → A↔B cycle → REJECT.
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("b", "B")]),
            _spec("struct", "B", [_named_field("a", "A")]),
        ]
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(batch)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_batch_rejects_three_node_by_value_cycle() -> None:
    # A→B→C→A (all by value) → cycle → REJECT (exercises the multi-hop DFS back-edge).
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("b", "B")]),
            _spec("struct", "B", [_named_field("c", "C")]),
            _spec("struct", "C", [_named_field("a", "A")]),
        ]
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(batch)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_batch_rejects_array_of_other_batch_member_cycle() -> None:
    # An array-of-B (by value) closing a cycle B→A, A→B[] → REJECT (array element type makes edge).
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("bs", "B", array_len=2)]),
            _spec("struct", "B", [_named_field("a", "A")]),
        ]
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(batch)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_batch_cycle_detail_never_echoes_type_name() -> None:
    # The reject detail names the condition, never the (attacker-influenced) type name.
    batch = _batch(
        [
            _spec("struct", "SecretName", [_named_field("b", "OtherName")]),
            _spec("struct", "OtherName", [_named_field("a", "SecretName")]),
        ]
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_types_batch(batch)
    assert "SecretName" not in exc.value.envelope.detail
    assert "OtherName" not in exc.value.envelope.detail


# --- CompositeSpec schema model validators (the duplicate barrier at construction) -----------
def test_composite_spec_schema_rejects_by_value_self_embed_at_construction() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        s.CompositeSpec(
            kind="struct", name="A", fields=[s.FieldSpec(name="self", type=s.TypeRef(named="A"))]
        )


def test_composite_spec_schema_rejects_union_member_offset_at_construction() -> None:
    # The CompositeSpec union variant rejects a per-member offset at construction (schemas.py §D1).
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        s.CompositeSpec(
            kind="union",
            name="U",
            fields=[s.FieldSpec(name="a", type=s.TypeRef(base="int"), offset=0)],
        )


def test_composite_spec_struct_allows_member_offset_at_construction() -> None:
    # A struct member offset is allowed (the union branch must NOT fire for a struct).
    spec = s.CompositeSpec(
        kind="struct",
        name="S",
        fields=[s.FieldSpec(name="a", type=s.TypeRef(base="int"), offset=8)],
    )
    assert spec.kind == "struct"


def test_composite_spec_union_with_offsetless_members_constructs() -> None:
    # A valid union (every member offset None) iterates the union loop without raising (the
    # offset-is-None branch of the model validator — covers the loop-continue path).
    spec = s.CompositeSpec(
        kind="union",
        name="U",
        fields=[
            s.FieldSpec(name="i", type=s.TypeRef(base="int")),
            s.FieldSpec(name="f", type=s.TypeRef(base="float")),
        ],
    )
    assert spec.kind == "union" and len(spec.fields) == 2


@pytest.mark.critical
def test_batch_with_shared_target_visited_twice_is_acyclic() -> None:
    # B is reachable from A both directly and via C; the detector must not false-positive (the
    # already-BLACK / already-GREY skip branches). A→B, A→C, C→B, B leaf → acyclic.
    batch = _batch(
        [
            _spec("struct", "A", [_named_field("b", "B"), _named_field("c", "C")]),
            _spec("struct", "C", [_named_field("b", "B")]),
            _spec("struct", "B", [_field("x")]),
        ]
    )
    v.validate_types_batch(batch)  # no raise (B finalized once; the second visit is skipped)


# --- property/fuzz: the by-value cycle detector vs an independent oracle (gap round-4 Q7) --------
# The by-value cycle detector (_detect_by_value_cycle, via validate_types_batch) is graph-traversal
# logic guarding an infinite-size-type DoS (CWE-400). Build random by-value/pointer edge graphs over
# a small fixed node set and assert the validator rejects a batch IFF an independent oracle finds a
# by-value cycle — a missed cycle would be an infinite composite.
_PROFILE = settings(max_examples=300, deadline=None, derandomize=True)
_N_NODES = 4


_WHITE, _GREY, _BLACK = 0, 1, 2  # DFS visit colours for the cycle oracle


def _has_by_value_cycle(adjacency: dict[int, list[int]]) -> bool:
    """Independent 3-colour DFS cycle oracle over the by-value adjacency (self-loop counts)."""
    colour = dict.fromkeys(adjacency, _WHITE)

    def visit(node: int) -> bool:
        colour[node] = _GREY
        for nxt in adjacency[node]:
            if colour[nxt] == _GREY:  # back-edge (incl. a self-loop) → cycle
                return True
            if colour[nxt] == _WHITE and visit(nxt):
                return True
        colour[node] = _BLACK
        return False

    return any(colour[n] == _WHITE and visit(n) for n in adjacency)


@_PROFILE
@given(
    edges=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=_N_NODES - 1),
            st.integers(min_value=0, max_value=_N_NODES - 1),
            st.booleans(),  # True → by-value (pointer_levels=0, makes an edge); False → pointer
        ),
        max_size=10,
    )
)
def test_cycle_detector_matches_an_independent_oracle(edges: list[tuple[int, int, bool]]) -> None:
    """validate_types_batch rejects (VALIDATION) IFF the by-value edge graph has a cycle.

    Every generated batch is valid in every OTHER respect (unique names ``T0..``, unique + valid
    field names, in-batch refs, ≥1 field/type, all structs) so the ONLY reason it can raise is a
    by-value cycle — pointer edges (pointer_levels≥1) create NO edge (mutually-recursive pointers
    are allowed). The independent oracle is the ground truth the detector must match exactly.
    """
    node_fields: dict[int, list[s.FieldSpec]] = {i: [] for i in range(_N_NODES)}
    adjacency: dict[int, list[int]] = {i: [] for i in range(_N_NODES)}
    for idx, (src, dst, by_value) in enumerate(edges):
        node_fields[src].append(
            _named_field(f"e{idx}", f"T{dst}", pointer_levels=0 if by_value else 1)
        )
        if by_value:
            adjacency[src].append(dst)
    specs = [_spec("struct", f"T{i}", node_fields[i] or [_field("pad")]) for i in range(_N_NODES)]
    batch = _batch(specs)

    if _has_by_value_cycle(adjacency):
        with pytest.raises(GhidraMcpError) as ei:
            v.validate_types_batch(batch)
        assert ei.value.envelope.type is ErrorType.VALIDATION
    else:
        v.validate_types_batch(batch)  # acyclic (or pointer-only cycles) → accepted, no raise
