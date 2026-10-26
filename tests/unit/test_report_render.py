"""Unit tests for ADR-078 Tier-0 HTML rendering (``vivarium.report.render``)."""

from __future__ import annotations

from vivarium.core.envelope import DataOrigin, Untrusted, wrap
from vivarium.report.render import REPORT_CSP, render_report_html
from vivarium.tools import schemas as s


def _u(value: str) -> Untrusted[str]:
    return wrap(value, origin=DataOrigin.GHIDRA)


def _manifest(n: int = 1, truncated: bool = False) -> s.ReportManifest:
    return s.ReportManifest(
        program_sha256="b" * 64,
        session_id="sess-1",
        tool_revision="tier0.1",
        generated_from=["session_export_annotations"],
        finding_count=n,
        truncated=truncated,
    )


def _finding(inference: str | None = "decrypt") -> s.FindingRecord:
    return s.FindingRecord(
        subject=_u("0x401000"),
        kind="rename_function",
        confidence="inferred",
        observation=[_u("function renamed in session")],
        inference=_u(inference) if inference is not None else None,
    )


def test_csp_starts_default_src_none() -> None:
    # F2: default-src 'none' must lead so every unlisted fetch directive fails closed.
    assert REPORT_CSP.startswith("default-src 'none'")
    for directive in (
        "script-src 'none'",
        "connect-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ):
        assert directive in REPORT_CSP


def test_rendered_doc_embeds_csp_and_has_no_script() -> None:
    html = render_report_html(title="t", manifest=_manifest(), findings=[_finding()])
    assert html.startswith("<!doctype html>")
    assert f'content="{REPORT_CSP}"' in html
    assert "<script" not in html.lower()
    assert "0x401000" in html
    assert "decrypt" in html


def test_dynamic_values_are_html_escaped() -> None:
    # Even though values are (C)-projected upstream, the renderer escapes defensively (B).
    f = s.FindingRecord(
        subject=_u("s"),
        kind="set_comment",
        confidence="inferred",
        observation=[_u('a<b&"c')],
        inference=_u("x<y"),
    )
    html = render_report_html(title="<b>T</b>", manifest=_manifest(), findings=[f])
    assert "<b>T</b>" not in html
    assert "&lt;b&gt;T&lt;/b&gt;" in html
    assert "a&lt;b&amp;&quot;c" in html
    assert "x&lt;y" in html


def _atlas() -> s.AtlasData:
    return s.AtlasData(
        summary=s.AtlasSummary(
            program_sha256="b" * 64,
            format="ELF",
            architecture="x86:LE:64:default",
            endianness="little",
            size_bytes=1024,
            entry_point="0x401000",
            compiler=_u("gcc"),
            function_count=2,
            import_count=1,
            export_count=0,
            string_count=3,
            leaf_count=1,
        ),
        nodes=[s.AtlasNode(address="0x401000", name=_u("decrypt"))],
        edges=[s.AtlasEdge(from_address="0x401000", to_address="0x401100")],
        functions=[s.AtlasFunction(address="0x401000", name=_u("decrypt"), size=16)],
        xrefs=[
            s.AtlasXref(from_address="0x401200", to_address="0x401000", ref_type="CALL"),
        ],
    )


def test_atlas_sections_rendered_scriptless() -> None:
    html = render_report_html(
        title="t", manifest=_manifest(), findings=[_finding()], atlas=_atlas()
    )
    assert "<script" not in html.lower()
    assert f'content="{REPORT_CSP}"' in html
    for heading in (">Program<", ">Call graph<", ">Functions<", ">Cross-references<"):
        assert heading in html
    assert "0x401000" in html and "0x401100" in html
    assert "0x401200" in html and "CALL" in html
    assert "decrypt" in html
    assert '<nav aria-label="Contents">' in html
    assert 'href="#atlas-xrefs"' in html


def test_atlas_no_xrefs_shows_empty_message() -> None:
    atlas = _atlas().model_copy(update={"xrefs": []})
    html = render_report_html(title="t", manifest=_manifest(), findings=[], atlas=atlas)
    assert ">Cross-references<" in html
    assert "No cross-references in scope." in html


def test_atlas_hostile_node_name_is_escaped() -> None:
    atlas = _atlas().model_copy(
        update={"nodes": [s.AtlasNode(address="0x401000", name=_u("a<b>c"))]}
    )
    html = render_report_html(title="t", manifest=_manifest(), findings=[], atlas=atlas)
    assert "a<b>c" not in html
    assert "a&lt;b&gt;c" in html


def test_no_atlas_section_without_atlas() -> None:
    html = render_report_html(title="t", manifest=_manifest(), findings=[_finding()])
    assert ">Call graph<" not in html


def test_empty_findings_message() -> None:
    html = render_report_html(title="t", manifest=_manifest(0), findings=[])
    assert "No findings in scope." in html


def test_truncated_manifest_surfaced() -> None:
    html = render_report_html(
        title="t", manifest=_manifest(3, truncated=True), findings=[_finding()]
    )
    assert "truncated" in html
