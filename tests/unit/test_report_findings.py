"""Unit tests for ADR-078 Tier-0 finding composition (``vivarium.report.findings``)."""

from __future__ import annotations

from vivarium.core.envelope import DataOrigin, wrap
from vivarium.report.findings import compose_findings
from vivarium.tools import schemas as s


def _u(value: str) -> object:
    return wrap(value, origin=DataOrigin.BINARY)


def _typeref(name: str | None = "mytype") -> s.ExportedTypeRef:
    return s.ExportedTypeRef(base=None, named=_u(name) if name is not None else None)


def _doc(entries: list[object], sha: str = "a" * 64) -> s.ExportedAnnotationDocument:
    return s.ExportedAnnotationDocument(
        schema_version=1,
        binary=s.ExportedBinaryRef(sha256=sha),
        entries=entries,
    )


def _all_kinds() -> list[object]:
    return [
        s.ExportedRenameFunctionEntry(
            kind="rename_function", function="0x401000", new_name=_u("decrypt")
        ),
        s.ExportedRenameSymbolEntry(
            kind="rename_symbol", identifier="0x401100", new_name=_u("g_key")
        ),
        s.ExportedRenameLocalVariableEntry(
            kind="rename_local_variable",
            function="0x401000",
            variable=_u("uVar1"),
            new_name=_u("len"),
        ),
        s.ExportedRenameParameterEntry(
            kind="rename_parameter",
            function="0x401000",
            parameter=_u("param_1"),
            new_name=_u("buf"),
        ),
        s.ExportedSetCommentEntry(
            kind="set_comment", address="0x401008", comment_type="EOL", text=_u("xor loop")
        ),
        s.ExportedSetFunctionSignatureEntry(
            kind="set_function_signature",
            function="0x401000",
            return_type=_typeref("int"),
            parameters=[s.ExportedParamSpec(name=_u("p0"), type=_typeref("char"))],
            calling_convention="cdecl",
        ),
        s.ExportedApplyDataTypeEntry(
            kind="apply_data_type", address="0x402000", type=_typeref("header_t")
        ),
        s.ExportedDefineStructEntry(
            kind="define_struct",
            name=_u("header_t"),
            fields=[s.ExportedFieldSpec(name=_u("magic"), type=_typeref("uint"))],
        ),
        s.ExportedDefineUnionEntry(
            kind="define_union",
            name=_u("variant_t"),
            fields=[s.ExportedFieldSpec(name=_u("a"), type=_typeref("int"))],
        ),
        s.ExportedDefineTypesEntry(
            kind="define_types",
            types=[
                s.ExportedCompositeSpec(
                    kind="struct",
                    name=_u("node_t"),
                    fields=[s.ExportedFieldSpec(name=_u("next"), type=_typeref("void"))],
                )
            ],
        ),
    ]


def test_every_entry_kind_yields_a_finding() -> None:
    findings, truncated = compose_findings(_doc(_all_kinds()), max_findings=100)
    assert truncated is False
    kinds = {f.kind for f in findings}
    assert kinds == {
        "rename_function",
        "rename_symbol",
        "rename_local_variable",
        "rename_parameter",
        "set_comment",
        "set_function_signature",
        "apply_data_type",
        "define_struct",
        "define_union",
        "define_types",
    }
    assert all(f.confidence == "inferred" for f in findings)


def test_inference_and_observation_projected() -> None:
    doc = _doc(
        [
            s.ExportedRenameFunctionEntry(
                kind="rename_function", function="0x401000", new_name=_u("decrypt")
            )
        ]
    )
    (f,) = compose_findings(doc, max_findings=100)[0]
    assert f.subject == "0x401000"
    assert f.inference == "decrypt"
    assert f.observation == ["function renamed in session"]


def test_scope_filters_by_projected_subject() -> None:
    doc = _doc(_all_kinds())
    findings, _ = compose_findings(doc, scope=["0x401100"], max_findings=100)
    assert {f.subject for f in findings} == {"0x401100"}


def test_empty_scope_keeps_all() -> None:
    findings, _ = compose_findings(_doc(_all_kinds()), scope=[], max_findings=100)
    assert len(findings) == 10


def test_cap_truncates() -> None:
    findings, truncated = compose_findings(_doc(_all_kinds()), max_findings=3)
    assert truncated is True
    assert len(findings) == 3


def test_no_entries_yields_no_findings() -> None:
    findings, truncated = compose_findings(_doc([]), max_findings=100)
    assert findings == []
    assert truncated is False
