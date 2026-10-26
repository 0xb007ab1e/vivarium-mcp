r"""Finding-record composition (ADR-078 Tier-0, TB10) — model (B) data over (C)-projected leaves.

Composes the session's exported annotation document (from ``session_export_annotations`` — no new
worker capability, ADR-078) into ADR-shaped :class:`~vivarium.tools.schemas.FindingRecord`\ s. Each
in-session USER_DEFINED annotation is the analyst's/agent's reasoning captured as an *inference*;
its structural facts are the *observations*; the provenance manifest is the *evidence*.

Every binary-derived leaf (a read-out name / comment text — each arriving ``Untrusted``-wrapped in
the export document) is unwrapped and **(C)-allow-list-projected** here, so the records are inert in
any consumer (:mod:`vivarium.report.projection`). This runs server-side at the output edge,
never in the worker (ADR-001), and is never a write primitive.
"""

from __future__ import annotations

from vivarium.core.envelope import DataOrigin, Untrusted, wrap
from vivarium.core.secretscan import scan_secrets
from vivarium.report.projection import project_identifier, project_string
from vivarium.tools.schemas import (
    ExportedAnnotationDocument,
    ExportedApplyDataTypeEntry,
    ExportedDefineStructEntry,
    ExportedDefineTypesEntry,
    ExportedDefineUnionEntry,
    ExportedRenameFunctionEntry,
    ExportedRenameLocalVariableEntry,
    ExportedRenameParameterEntry,
    ExportedRenameSymbolEntry,
    ExportedSetCommentEntry,
    ExportedSetFunctionSignatureEntry,
    FindingRecord,
)

__all__ = ["compose_findings"]


def _ident(raw: str) -> str:
    """Project a selector/name that should be identifier-shaped (addresses, symbol names)."""
    return project_identifier(raw)


def _text(raw: str) -> str:
    """Project free-text (comment text) to an inert rendering, redacting any secret (TB10 #4).

    A generated report travels off-box, so a secret an analyst pasted into a comment must not go out
    verbatim (master §5 / ADR-072). The value is first run through the deterministic secret scanner;
    on any hit the whole value is replaced by a non-disclosing marker (closed-vocab category +
    salted hash — never the raw secret, never its ``*``-masked preview, which carries markup bytes).
    Otherwise it is (C)-allow-list-projected to its escaped preview. The marker uses only safe bytes
    (alnum, space, hyphen) so it too is inert in any consumer.
    """
    hits = scan_secrets([(None, raw)])
    if hits:
        category = hits[0].category.replace("_", "-")
        return f"redacted-secret {category} {hits[0].preview_hash}"
    return project_string(raw).preview


def _w(value: str) -> Untrusted[str]:
    """Tag an already-(C)-projected leaf ``Untrusted`` (ADR-005 uniform envelope; origin GHIDRA).

    The value is inert by projection; the envelope keeps the "all binary-derived output is tagged"
    invariant uniform and auditable (defense in depth). Server-composed phrases that embed a
    projected value are conservatively over-tagged too (consistent with the export chokepoint).
    """
    return wrap(value, origin=DataOrigin.GHIDRA)


def _match_scope(subject: str, scope: frozenset[str]) -> bool:
    """Keep a finding when no scope is given, or its subject matches a projected scope selector."""
    return not scope or subject in scope


def compose_findings(
    document: ExportedAnnotationDocument,
    *,
    scope: list[str] | None = None,
    max_findings: int,
) -> tuple[list[FindingRecord], bool]:
    """Compose finding records from an exported annotation document (ADR-078 Tier-0).

    Args:
        document: The exported, ``Untrusted``-wrapped annotation document to compose from.
        scope: Optional selectors to filter findings to (matched by projected identity). Empty/None
            keeps every entry (still hard-capped by ``max_findings``).
        max_findings: Hard cap on the number of records produced (DoS guard — CWE-400). Excess is
            dropped and the ``truncated`` flag returned True.

    Returns:
        ``(findings, truncated)`` — the projected records and whether the cap was hit.
    """
    scope_set = frozenset(_ident(s) for s in (scope or []))
    out: list[FindingRecord] = []
    truncated = False

    for entry in document.entries:
        record = _compose_entry(entry)
        if record is None or not _match_scope(record.subject.value, scope_set):
            continue
        if len(out) >= max_findings:
            truncated = True
            break
        out.append(record)

    return out, truncated


def _compose_entry(entry: object) -> FindingRecord | None:  # noqa: C901 — flat per-kind dispatch
    """Map one exported entry to a projected :class:`FindingRecord` (``None`` if unrecognized)."""
    if isinstance(entry, ExportedRenameFunctionEntry):
        return FindingRecord(
            subject=_w(_ident(entry.function)),
            kind="rename_function",
            confidence="inferred",
            observation=[_w("function renamed in session")],
            inference=_w(_ident(entry.new_name.value)),
        )
    if isinstance(entry, ExportedRenameSymbolEntry):
        return FindingRecord(
            subject=_w(_ident(entry.identifier)),
            kind="rename_symbol",
            confidence="inferred",
            observation=[_w("symbol renamed in session")],
            inference=_w(_ident(entry.new_name.value)),
        )
    if isinstance(entry, ExportedRenameLocalVariableEntry):
        return FindingRecord(
            subject=_w(_ident(entry.function)),
            kind="rename_local_variable",
            confidence="inferred",
            observation=[_w(f"local variable {_ident(entry.variable.value)} renamed")],
            inference=_w(_ident(entry.new_name.value)),
        )
    if isinstance(entry, ExportedRenameParameterEntry):
        return FindingRecord(
            subject=_w(_ident(entry.function)),
            kind="rename_parameter",
            confidence="inferred",
            observation=[_w(f"parameter {_ident(entry.parameter.value)} renamed")],
            inference=_w(_ident(entry.new_name.value)),
        )
    if isinstance(entry, ExportedSetCommentEntry):
        return FindingRecord(
            subject=_w(_ident(entry.address)),
            kind="set_comment",
            confidence="inferred",
            observation=[_w(f"comment slot {_ident(entry.comment_type)}")],
            inference=_w(_text(entry.text.value)),
        )
    if isinstance(entry, ExportedSetFunctionSignatureEntry):
        obs = [_w(f"{len(entry.parameters)} parameter(s)")]
        if entry.calling_convention:
            obs.append(_w(f"calling convention {_ident(entry.calling_convention)}"))
        ret = entry.return_type.named
        return FindingRecord(
            subject=_w(_ident(entry.function)),
            kind="set_function_signature",
            confidence="inferred",
            observation=obs,
            inference=_w(_ident(ret.value)) if ret is not None else None,
        )
    if isinstance(entry, ExportedApplyDataTypeEntry):
        named = entry.type.named
        return FindingRecord(
            subject=_w(_ident(entry.address)),
            kind="apply_data_type",
            confidence="inferred",
            observation=[_w("data type applied")],
            inference=_w(_ident(named.value)) if named is not None else None,
        )
    if isinstance(entry, ExportedDefineStructEntry):
        return FindingRecord(
            subject=_w(_ident(entry.name.value)),
            kind="define_struct",
            confidence="inferred",
            observation=[_w(f"struct, {len(entry.fields)} field(s)"), _w(f"packed={entry.packed}")],
            inference=None,
        )
    if isinstance(entry, ExportedDefineUnionEntry):
        return FindingRecord(
            subject=_w(_ident(entry.name.value)),
            kind="define_union",
            confidence="inferred",
            observation=[_w(f"union, {len(entry.fields)} field(s)")],
            inference=None,
        )
    if isinstance(entry, ExportedDefineTypesEntry):
        # A batch summarizes as one finding over its composites (each name projected).
        names = ", ".join(_ident(c.name.value) for c in entry.types[:16])
        return FindingRecord(
            subject=_w(f"define_types[{len(entry.types)}]"),
            kind="define_types",
            confidence="inferred",
            observation=[_w(f"composite batch, {len(entry.types)} type(s)")],
            inference=_w(names) if names else None,
        )
    return None
