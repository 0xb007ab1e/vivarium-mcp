"""Unit tests for the ADR-032 ``define_types`` annotation round-trip (interdependent graphs).

ADR-032 closes the gap where **mutually-recursive pointer composites cannot round-trip** through
annotation export/import. The fix is purely additive: export emits ALL session-authored composites
as ONE ``define_types`` batch entry (schema v2), and import replays that one batch through the
existing gated ``define_types`` handler — whose pre-registration resolves any interdependency
(pointer cycles, acyclic chains, set-order non-determinism) as one atomic transaction.

These tests prove, hermetically (no JVM, no real worker — ADR-001), that:

- ``DefineTypesEntry`` / ``ExportedDefineTypesEntry`` discriminate correctly in their unions;
- ``validate_entry`` re-validates a batch via ``validate_types_batch`` (a by-value cycle / duplicate
  name fails closed ``VALIDATION``);
- ``validate_annotation_document`` accepts a v2 doc with a ``define_types`` entry AND a v1 doc with
  the legacy ``define_struct``/``define_union`` entries (backward-compat — D3), rejects a v3 doc;
- ``define_types`` is a structural kind → import requires ``allow_structural`` consent (denied
  without it), mirroring the live tool's human-in-the-loop gate (LLM08);
- import replays a ``DefineTypesEntry`` via ``_handle_define_types`` (the port's ``define_types`` is
  called with the batch);
- ``rpc_client._build_exported_entry`` builds an ``ExportedDefineTypesEntry`` with every composite +
  field name ``Untrusted``-wrapped (DataOrigin.BINARY — ADR-005);
- **the headline**: an exported document carrying a batch of TWO mutually-recursive pointer
  composites (A→B*, B→A*) rebuilds into a bare import document that validates AND imports/replays
  as one ``define_types`` entry — proving the interdependent graph round-trips as one atomic batch.
"""

from __future__ import annotations

from typing import Literal, cast

import pytest

# Reuse the persistence test's import-path fakes (one disjoint source of truth for the fake
# SessionManager/Port + ToolContext wiring — no duplication, no drift).
from tests.unit.test_annotation_persistence import (
    _SHA,
    _SID,
    FakePort,
    FakeSessionManager,
    _ctx,
    _port,
)
from vivarium.core import validation as v
from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra.port import GhidraPort
from vivarium.ghidra.rpc_client import _build_exported_entry
from vivarium.sessions.manager import SessionManager
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s

# --------------------------------------------------------------------------------------------------
# Builders — bare (import) and exported composite specs
# --------------------------------------------------------------------------------------------------


def _field(name: str, named: str | None = None, pointer_levels: int = 0) -> s.FieldSpec:
    """A bare member: an int by default, or a (pointer) reference to ``named``."""
    ref = (
        s.TypeRef(named=named, pointer_levels=pointer_levels)
        if named is not None
        else s.TypeRef(base="int")
    )
    return s.FieldSpec(name=name, type=ref)


def _composite(
    name: str, fields: list[s.FieldSpec], kind: Literal["struct", "union"] = "struct"
) -> s.CompositeSpec:
    """A bare ``CompositeSpec`` (defaults to a struct)."""
    return s.CompositeSpec(kind=kind, name=name, fields=fields)


def _define_types_entry(*types: s.CompositeSpec) -> s.DefineTypesEntry:
    """A ``DefineTypesEntry`` carrying the given composites."""
    return s.DefineTypesEntry(kind="define_types", types=list(types))


def _doc(*entries: s.Entry, sha: str = _SHA, version: int = 2) -> s.AnnotationDocument:
    """Build an annotation document (defaults to schema v2 — ADR-032)."""
    return s.AnnotationDocument(
        schema_version=version, binary=s.AnnotationBinaryRef(sha256=sha), entries=list(entries)
    )


# A→B* and B→A* — the mutually-recursive POINTER composites (the headline round-trip case). Pointer
# edges create no by-value cycle, so the batch validates; only the batch's pre-registration can
# resolve them on import (no single-entry replay order exists).
def _mutually_recursive_pointer_batch() -> s.DefineTypesEntry:
    """Build the ADR-032 headline batch: A has a ``B*`` field, B has an ``A*`` field."""
    return _define_types_entry(
        _composite("node_a", [_field("to_b", named="node_b", pointer_levels=1)]),
        _composite("node_b", [_field("to_a", named="node_a", pointer_levels=1)]),
    )


# --------------------------------------------------------------------------------------------------
# Discrimination — the entry unions select the define_types variant by ``kind``
# --------------------------------------------------------------------------------------------------
@pytest.mark.critical
def test_define_types_entry_discriminates_in_entry_union() -> None:
    # A document carrying a ``define_types`` entry constructs (the discriminated Entry union selects
    # DefineTypesEntry by the kind literal), and the entry's batch is preserved.
    doc = _doc(_mutually_recursive_pointer_batch())
    assert len(doc.entries) == 1
    entry = doc.entries[0]
    assert isinstance(entry, s.DefineTypesEntry)
    assert entry.kind == "define_types"
    assert [t.name for t in entry.types] == ["node_a", "node_b"]


@pytest.mark.critical
def test_exported_define_types_entry_discriminates_in_exported_union() -> None:
    # The exported view discriminates symmetrically: an ExportedDefineTypesEntry constructs in the
    # ExportedEntry union (names Untrusted-wrapped — ADR-005).
    doc = s.ExportedAnnotationDocument(
        schema_version=s.ANNOTATION_SCHEMA_VERSION,
        binary=s.ExportedBinaryRef(sha256=_SHA),
        entries=[
            s.ExportedDefineTypesEntry(
                kind="define_types",
                types=[
                    s.ExportedCompositeSpec(
                        kind="struct",
                        name=Untrusted(value="t", origin=DataOrigin.BINARY),
                        fields=[
                            s.ExportedFieldSpec(
                                name=Untrusted(value="m", origin=DataOrigin.BINARY),
                                type=s.ExportedTypeRef(base="int"),
                            )
                        ],
                    )
                ],
            )
        ],
    )
    entry = doc.entries[0]
    assert isinstance(entry, s.ExportedDefineTypesEntry)
    assert entry.kind == "define_types"


# --------------------------------------------------------------------------------------------------
# validate_entry — a DefineTypesEntry is re-validated via validate_types_batch
# --------------------------------------------------------------------------------------------------
@pytest.mark.critical
def test_validate_entry_accepts_valid_define_types_batch() -> None:
    # The mutually-recursive POINTER batch is valid (pointer edges → no by-value cycle).
    v.validate_entry(_mutually_recursive_pointer_batch())  # must not raise


def _mc_field(name: str, named: str | None, pointer_levels: int) -> s.FieldSpec:
    """A model_construct'd FieldSpec (bypasses the schema validators to reach the pure batch
    validator's reject branches with a known-bad shape)."""
    base = "int" if named is None else None
    ref = s.TypeRef.model_construct(
        base=base, named=named, pointer_levels=pointer_levels, array_len=None
    )
    return s.FieldSpec.model_construct(name=name, type=ref, offset=None)


def _mc_composite(name: str, field: s.FieldSpec, kind: str = "struct") -> s.CompositeSpec:
    """A model_construct'd CompositeSpec (one field)."""
    return s.CompositeSpec.model_construct(kind=kind, name=name, fields=[field], packed=False)


@pytest.mark.critical
def test_validate_entry_rejects_by_value_cycle_batch() -> None:
    # A by-value cycle (A embeds B by value, B embeds A by value — pointer_levels 0) is the
    # forbidden infinite-size graph. validate_entry routes through validate_types_batch's by-value
    # cycle detector → fail closed VALIDATION. model_construct bypasses the schema model validators
    # so the pure batch validator's reject branch is reached with the known-bad shape.
    a = _mc_composite("A", _mc_field("b", "B", 0))
    b = _mc_composite("B", _mc_field("a", "A", 0))
    entry = s.DefineTypesEntry.model_construct(kind="define_types", types=[a, b])
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_entry(entry)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_validate_entry_rejects_duplicate_name_batch() -> None:
    # Two composites with the SAME name in one batch is the intra-batch dup-name reject (the worker
    # owns the collision-with-existing check; the boundary owns intra-batch uniqueness).
    a1 = _mc_composite("dup", _mc_field("x", None, 0), kind="struct")
    a2 = _mc_composite("dup", _mc_field("y", None, 0), kind="union")
    entry = s.DefineTypesEntry.model_construct(kind="define_types", types=[a1, a2])
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_entry(entry)
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --------------------------------------------------------------------------------------------------
# validate_annotation_document — version acceptance window (D3) + define_types entry
# --------------------------------------------------------------------------------------------------
@pytest.mark.critical
def test_v2_document_with_define_types_validates() -> None:
    # A v2 document whose only entry is a (valid) define_types batch validates end-to-end.
    v.validate_annotation_document(_doc(_mutually_recursive_pointer_batch(), version=2))


@pytest.mark.critical
def test_v1_document_with_legacy_composite_entries_still_validates() -> None:
    # Backward-compat (D3): a v1 document carrying the legacy define_struct + define_union entry
    # kinds STILL validates — a v2 importer understands v1 documents (those kinds remain in the
    # union + replayable). Old exports keep importing.
    legacy = _doc(
        s.DefineStructEntry(
            kind="define_struct",
            name="cfg_t",
            fields=[s.FieldSpec(name="flags", type=s.TypeRef(base="int"))],
        ),
        s.DefineUnionEntry(
            kind="define_union",
            name="u_t",
            fields=[s.FieldSpec(name="m", type=s.TypeRef(base="int"))],
        ),
        version=1,
    )
    v.validate_annotation_document(legacy)  # must not raise


@pytest.mark.critical
def test_v3_document_rejected_unsupported_version() -> None:
    # A version OUTSIDE the supported {1, 2} window fails closed VALIDATION (forward-compat is
    # opt-in, never silent — D3).
    doc = s.AnnotationDocument.model_construct(
        schema_version=3,
        binary=s.AnnotationBinaryRef(sha256=_SHA),
        entries=[_mutually_recursive_pointer_batch()],
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(doc)
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --------------------------------------------------------------------------------------------------
# Structural-consent gate — define_types ∈ STRUCTURAL_ENTRY_KINDS (LLM08, not bypassed by import)
# --------------------------------------------------------------------------------------------------
@pytest.mark.critical
def test_define_types_is_a_structural_entry_kind() -> None:
    # Single source of truth: define_types is structural (its live handler calls
    # require_write_consent(structural=True)), so the up-front import gate treats it as structural.
    assert "define_types" in s.STRUCTURAL_ENTRY_KINDS


@pytest.mark.critical
def test_import_define_types_without_allow_structural_denied() -> None:
    # A define_types-only document on a write-enabled-but-NOT-allow_structural session is denied UP
    # FRONT by the structural-consent gate (the human-in-the-loop gate is not bypassed by import).
    # NO batch write reaches the port.
    ctx = _ctx()
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)  # write consent, but NOT structural
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](
            session_id=_SID, document=_doc(_mutually_recursive_pointer_batch()).model_dump()
        )
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []  # denied before any replay


# --------------------------------------------------------------------------------------------------
# Replay — _replay_entry / import handler routes a DefineTypesEntry to _handle_define_types
# --------------------------------------------------------------------------------------------------
class _DefineTypesRecordingPort(FakePort):
    """A :class:`FakePort` that also records the ``define_types`` batch it replays."""

    def __init__(self) -> None:
        super().__init__()
        self.batches: list[list[tuple[str, str]]] = []  # list of [(name, kind), ...] per batch

    def define_types(self, sid: str, a: s.DefineTypesIn) -> s.DefineTypesResult:
        self.calls.append(("define_types", sid))
        self.batches.append([(t.name, t.kind) for t in a.types])
        return s.DefineTypesResult(
            types=[
                s.DefinedType(name=t.name, kind=t.kind, size=8, field_count=len(t.fields))
                for t in a.types
            ],
            applied=True,
        )


def _ctx_with_recording_port() -> tuple[reg.ToolContext, _DefineTypesRecordingPort]:
    """A ToolContext whose port records replayed define_types batches."""
    port = _DefineTypesRecordingPort()
    ctx = reg.ToolContext(
        config=_ctx().config,
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, port),
    )
    return ctx, port


@pytest.mark.critical
def test_import_replays_define_types_via_handler() -> None:
    # A define_types entry is replayed via _handle_define_types — the port's define_types is called
    # with the FULL batch (one transaction), not N individual define_struct calls.
    ctx, port = _ctx_with_recording_port()
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID, allow_structural=True)
    out = handlers["session_import_annotations"](
        session_id=_SID, document=_doc(_mutually_recursive_pointer_batch()).model_dump()
    )
    assert out.total == 1
    assert out.applied == 1
    assert out.rejected == 0
    # Exactly ONE define_types replay (the batch) — no per-composite define_struct/define_union.
    assert ("define_types", _SID) in port.calls
    assert ("define_struct", _SID) not in port.calls
    assert ("define_union", _SID) not in port.calls
    assert port.batches == [[("node_a", "struct"), ("node_b", "struct")]]


# --------------------------------------------------------------------------------------------------
# rpc_client._build_exported_entry — a worker define_types dict → ExportedDefineTypesEntry
# --------------------------------------------------------------------------------------------------
@pytest.mark.critical
def test_build_exported_entry_wraps_define_types_names_untrusted() -> None:
    # A plain worker dict builds an ExportedDefineTypesEntry whose composite + field names are
    # Untrusted-wrapped (DataOrigin.BINARY — ADR-005), with the closed-vocab base / scalar modifiers
    # bare. Mirrors how _build_exported_entry is the rpc_client chokepoint for hostile-origin names.
    worker_dict = {
        "kind": "define_types",
        "types": [
            {
                "kind": "struct",
                "name": "node_a",
                "fields": [
                    {
                        "name": "to_b",
                        "type": {
                            "base": None,
                            "named": "node_b",
                            "pointer_levels": 1,
                            "array_len": None,
                        },
                    }
                ],
            }
        ],
    }
    entry = _build_exported_entry(worker_dict)
    assert isinstance(entry, s.ExportedDefineTypesEntry)
    composite = entry.types[0]
    assert isinstance(composite, s.ExportedCompositeSpec)
    assert isinstance(composite.name, Untrusted)
    assert composite.name.origin is DataOrigin.BINARY
    assert composite.name.value == "node_a"
    field = composite.fields[0]
    assert isinstance(field.name, Untrusted)
    assert field.name.origin is DataOrigin.BINARY
    assert field.name.value == "to_b"
    assert isinstance(field.type.named, Untrusted)  # the peer composite name → binary-derived
    assert field.type.named.origin is DataOrigin.BINARY
    assert field.type.named.value == "node_b"
    assert field.type.base is None  # closed vocab — bare
    assert field.type.pointer_levels == 1  # server-safe scalar — bare


# --------------------------------------------------------------------------------------------------
# THE HEADLINE — full export → rebuild bare → validate → import/replay round-trip (one batch)
# --------------------------------------------------------------------------------------------------
def _bare_type_ref(exported: s.ExportedTypeRef) -> s.TypeRef:
    """Rebuild a bare ``TypeRef`` from an exported one (extract ``named.value`` — ADR-005)."""
    return s.TypeRef(
        base=exported.base,
        named=exported.named.value if exported.named is not None else None,
        pointer_levels=exported.pointer_levels,
        array_len=exported.array_len,
    )


def _bare_field(exported: s.ExportedFieldSpec) -> s.FieldSpec:
    """Rebuild a bare ``FieldSpec`` (extract ``name.value``)."""
    return s.FieldSpec(
        name=exported.name.value, type=_bare_type_ref(exported.type), offset=exported.offset
    )


def _bare_composite(exported: s.ExportedCompositeSpec) -> s.CompositeSpec:
    """Rebuild a bare ``CompositeSpec`` (extract every name from its Untrusted wrapper)."""
    return s.CompositeSpec(
        kind=exported.kind,
        name=exported.name.value,
        fields=[_bare_field(f) for f in exported.fields],
        packed=exported.packed,
    )


def _bare_document_from_export(exported: s.ExportedAnnotationDocument) -> s.AnnotationDocument:
    """Rebuild a bare import ``AnnotationDocument`` from an exported document (define_types-only).

    Mirrors the client's job: persist the inert exported artifact, then extract ``.value`` from each
    Untrusted wrapper to reconstruct a bare import document for round-trip. Scoped to the
    ``define_types`` entry kind (the only kind this round-trip exercises).
    """
    entries: list[s.Entry] = []
    for e in exported.entries:
        assert isinstance(e, s.ExportedDefineTypesEntry)  # this round-trip is define_types-only
        entries.append(
            s.DefineTypesEntry(kind="define_types", types=[_bare_composite(c) for c in e.types])
        )
    return s.AnnotationDocument(
        schema_version=exported.schema_version,
        binary=s.AnnotationBinaryRef(sha256=exported.binary.sha256),
        entries=entries,
    )


@pytest.mark.critical
def test_mutually_recursive_pointer_graph_round_trips_as_one_batch() -> None:
    # THE headline ADR-032 test. Build an EXPORTED document carrying a define_types batch of TWO
    # mutually-recursive pointer composites (A→B*, B→A*), rebuild a bare import document from it
    # (extracting .value from the Untrusted wrappers), then assert it (a) validates and (b)
    # imports/replays as ONE define_types batch against the recording fake port. This proves the
    # interdependent graph round-trips as a single atomic entry — the whole point of ADR-032.
    exported = s.ExportedAnnotationDocument(
        schema_version=s.ANNOTATION_SCHEMA_VERSION,  # v2
        binary=s.ExportedBinaryRef(sha256=_SHA),
        entries=[
            s.ExportedDefineTypesEntry(
                kind="define_types",
                types=[
                    s.ExportedCompositeSpec(
                        kind="struct",
                        name=Untrusted(value="node_a", origin=DataOrigin.BINARY),
                        fields=[
                            s.ExportedFieldSpec(
                                name=Untrusted(value="to_b", origin=DataOrigin.BINARY),
                                type=s.ExportedTypeRef(
                                    named=Untrusted(value="node_b", origin=DataOrigin.BINARY),
                                    pointer_levels=1,
                                ),
                            )
                        ],
                    ),
                    s.ExportedCompositeSpec(
                        kind="struct",
                        name=Untrusted(value="node_b", origin=DataOrigin.BINARY),
                        fields=[
                            s.ExportedFieldSpec(
                                name=Untrusted(value="to_a", origin=DataOrigin.BINARY),
                                type=s.ExportedTypeRef(
                                    named=Untrusted(value="node_a", origin=DataOrigin.BINARY),
                                    pointer_levels=1,
                                ),
                            )
                        ],
                    ),
                ],
            )
        ],
    )

    # Rebuild the bare import document (the client extracts .value from each Untrusted wrapper).
    bare = _bare_document_from_export(exported)
    assert bare.schema_version == 2
    assert len(bare.entries) == 1
    only = bare.entries[0]
    assert isinstance(only, s.DefineTypesEntry)
    assert [t.name for t in only.types] == ["node_a", "node_b"]
    # The pointer edges survived as a bare named pointer-ref (the interdependency is intact).
    assert only.types[0].fields[0].type.named == "node_b"
    assert only.types[0].fields[0].type.pointer_levels == 1
    assert only.types[1].fields[0].type.named == "node_a"

    # (a) The rebuilt bare document validates (the pointer cycle is allowed; one batch).
    v.validate_annotation_document(bare)

    # (b) It imports/replays via the define_types handler — ONE batch against the fake port.
    ctx, port = _ctx_with_recording_port()
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID, allow_structural=True)
    out = handlers["session_import_annotations"](session_id=_SID, document=bare.model_dump())
    assert out.total == 1
    assert out.applied == 1
    assert out.rejected == 0
    # The interdependent graph replayed as ONE define_types batch (pre-registration resolves the
    # mutually-recursive pointers) — not as two failing individual define_struct entries.
    assert port.calls.count(("define_types", _SID)) == 1
    assert port.batches == [[("node_a", "struct"), ("node_b", "struct")]]
