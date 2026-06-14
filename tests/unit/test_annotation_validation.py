"""Unit tests for annotation-document validation (ADR-018) — critical-path gate (100%).

``validate_annotation_document`` is the load-bearing first gate of the TB8 import path: the
document is fully untrusted. These tests drive every branch of the document-level validator and the
per-entry dispatcher (:func:`validate_entry`), proving each control HOLDS with deterministic,
synthetic, value-free fixtures (master §5). They assert:

- the positive case (a well-formed multi-kind document) validates;
- an unsupported ``schema_version`` is rejected (``VALIDATION``);
- a malformed/missing ``binary.sha256`` binding is rejected (``VALIDATION``);
- an over-count document is ``LIMIT_EXCEEDED``;
- an injection-bearing name / comment / type ref in an entry is rejected by the LIVE validators;
- every entry kind dispatches to its matching live validator (no new write-validation logic).
"""

from __future__ import annotations

import pytest

from ghidra_mcp.core import validation as v
from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.tools import schemas as s

_SHA = "a" * 64


def _doc(*entries: s.Entry, sha: str = _SHA, version: int = 1) -> s.AnnotationDocument:
    """Build an annotation document with the given entries (test helper)."""
    return s.AnnotationDocument(
        schema_version=version,
        binary=s.AnnotationBinaryRef(sha256=sha),
        entries=list(entries),
    )


# --- positive case: a well-formed, multi-kind, dependency-ordered document validates -----------
@pytest.mark.critical
def test_well_formed_document_validates() -> None:
    doc = _doc(
        s.DefineStructEntry(
            kind="define_struct",
            name="cfg_t",
            fields=[s.FieldSpec(name="flags", type=s.TypeRef(base="int"))],
        ),
        s.SetFunctionSignatureEntry(
            kind="set_function_signature",
            function="0x401000",
            return_type=s.TypeRef(named="cfg_t", pointer_levels=1),
            parameters=[s.ParamSpec(name="arg0", type=s.TypeRef(base="int"))],
        ),
        s.RenameFunctionEntry(kind="rename_function", function="0x401000", new_name="parse_cfg"),
        s.SetCommentEntry(
            kind="set_comment", address="0x401000", comment_type="PLATE", text="entry"
        ),
    )
    v.validate_annotation_document(doc)  # must not raise


# --- schema_version: only the supported version is accepted (fail closed) ----------------------
@pytest.mark.critical
def test_unsupported_schema_version_rejected() -> None:
    doc = _doc(version=2)
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(doc)
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- binary hash binding: presence + well-formedness (defense in depth over the schema) --------
@pytest.mark.critical
def test_malformed_hash_binding_rejected() -> None:
    # The pydantic field pattern already constrains it; construct a valid-shaped doc then mutate to
    # an under-length hash to drive the validator's own well-formedness re-assert (defense depth).
    doc = _doc()
    bad = doc.model_copy(
        update={"binary": doc.binary.model_construct(sha256="abc", name=None, size=None)}
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(bad)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_non_hex_hash_binding_rejected() -> None:
    doc = _doc()
    bad = doc.model_copy(
        update={"binary": doc.binary.model_construct(sha256="z" * 64, name=None, size=None)}
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(bad)
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- bounded entry count (DoS — CWE-400) -------------------------------------------------------
@pytest.mark.critical
def test_over_count_document_is_limit_exceeded() -> None:
    doc = _doc()
    # model_construct bypasses the pydantic max_length so the validator's own count cap is exercised
    # (a real over-count would also be rejected by the schema; this proves the value-level guard).
    oversized = doc.model_construct(
        schema_version=1,
        binary=doc.binary,
        entries=[
            s.RenameFunctionEntry(kind="rename_function", function="f", new_name="n")
            for _ in range(v.MAX_ANNOTATION_ENTRIES + 1)
        ],
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(oversized)
    assert exc.value.envelope.type is ErrorType.LIMIT_EXCEEDED


# --- per-entry re-validation through the LIVE validators (injection rejected) ------------------
@pytest.mark.critical
@pytest.mark.parametrize(
    "malicious", ["<b>evil</b>", "../escape", "zero​width", "rtl‮name", "ctrl\x01"]
)
def test_injection_in_rename_name_rejected(malicious: str) -> None:
    doc = _doc(s.RenameFunctionEntry(kind="rename_function", function="f", new_name=malicious))
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(doc)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_over_length_comment_is_limit_exceeded() -> None:
    # A comment is re-normalized by validate_comment_text; an over-length payload is LIMIT_EXCEEDED.
    # model_construct bypasses the pydantic field bound so the validator's own length cap is driven.
    entry = s.SetCommentEntry.model_construct(
        kind="set_comment",
        address="0x401000",
        comment_type="EOL",
        text="a" * (v.MAX_COMMENT_LEN + 1),
    )
    doc = s.AnnotationDocument.model_construct(
        schema_version=1, binary=s.AnnotationBinaryRef(sha256=_SHA), entries=[entry]
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(doc)
    assert exc.value.envelope.type is ErrorType.LIMIT_EXCEEDED


@pytest.mark.critical
def test_injection_in_comment_text_is_normalized_not_rejected() -> None:
    # A bidi/zero-width payload in a comment is NEUTRALIZED (validate_comment_text), not rejected —
    # so a clean-but-camouflaged comment entry validates (the worker receives the inert form).
    doc = _doc(
        s.SetCommentEntry(kind="set_comment", address="0x401000", comment_type="EOL", text="note‮ x")
    )
    v.validate_annotation_document(doc)  # must not raise


@pytest.mark.critical
def test_typeref_injection_in_entry_rejected() -> None:
    # A FieldSpec.type.named carrying C-declaration syntax is rejected by validate_type_ref.
    doc = _doc(
        s.ApplyDataTypeEntry(
            kind="apply_data_type",
            address="0x401000",
            type=s.TypeRef(named="struct{int x;}"),
        )
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(doc)
    assert exc.value.envelope.type is ErrorType.VALIDATION


@pytest.mark.critical
def test_bad_address_in_entry_rejected() -> None:
    doc = _doc(
        s.SetCommentEntry(kind="set_comment", address="NOTHEX", comment_type="EOL", text="note")
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_annotation_document(doc)
    assert exc.value.envelope.type is ErrorType.VALIDATION


# --- validate_entry dispatches every kind to its matching live validator -----------------------
@pytest.mark.critical
def test_validate_entry_accepts_every_clean_kind() -> None:
    clean: list[s.Entry] = [
        s.RenameFunctionEntry(kind="rename_function", function="0x401000", new_name="ok"),
        s.RenameSymbolEntry(kind="rename_symbol", identifier="0x402000", new_name="ok2"),
        s.RenameLocalVariableEntry(
            kind="rename_local_variable", function="f", variable="local_8", new_name="ok3"
        ),
        s.RenameParameterEntry(
            kind="rename_parameter", function="f", parameter="param_1", new_name="ok4"
        ),
        s.SetCommentEntry(kind="set_comment", address="0x401000", comment_type="EOL", text="c"),
        s.SetCommentEntry(kind="set_comment", address="0x401000", comment_type="EOL", text=None),
        s.SetFunctionSignatureEntry(
            kind="set_function_signature",
            function="f",
            return_type=s.TypeRef(base="void"),
            parameters=[],
        ),
        s.ApplyDataTypeEntry(
            kind="apply_data_type", address="0x401000", type=s.TypeRef(base="int")
        ),
        s.DefineStructEntry(
            kind="define_struct",
            name="st",
            fields=[s.FieldSpec(name="m", type=s.TypeRef(base="int"))],
        ),
        s.DefineUnionEntry(
            kind="define_union",
            name="un",
            fields=[s.FieldSpec(name="m", type=s.TypeRef(base="int"))],
        ),
    ]
    for entry in clean:
        v.validate_entry(entry)  # must not raise


# --- entry model validators (self-embed / union-offset) re-assert ADR-015 invariants ----------
@pytest.mark.critical
def test_define_union_entry_rejects_member_offset() -> None:
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        s.DefineUnionEntry(
            kind="define_union",
            name="u",
            fields=[s.FieldSpec(name="m", type=s.TypeRef(base="int"), offset=4)],
        )


@pytest.mark.critical
def test_define_struct_entry_rejects_by_value_self_embed() -> None:
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        s.DefineStructEntry(
            kind="define_struct",
            name="node",
            fields=[s.FieldSpec(name="self", type=s.TypeRef(named="node"))],  # by-value self embed
        )


@pytest.mark.critical
def test_validate_entry_rejects_malicious_local_selector() -> None:
    # The local selector goes through validate_target_ref (control-free); a control char rejects.
    bad = s.RenameLocalVariableEntry(
        kind="rename_local_variable", function="f", variable="local\x01", new_name="ok"
    )
    with pytest.raises(GhidraMcpError) as exc:
        v.validate_entry(bad)
    assert exc.value.envelope.type is ErrorType.VALIDATION
