"""Unit tests for ADR-078 Tier-0 HTML rendering (``vivarium.report.render``)."""

from __future__ import annotations

from vivarium.core.envelope import DataOrigin, wrap
from vivarium.report.render import REPORT_CSP, render_report_html
from vivarium.tools import schemas as s


def _u(value: str) -> object:
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


def test_empty_findings_message() -> None:
    html = render_report_html(title="t", manifest=_manifest(0), findings=[])
    assert "No findings in scope." in html


def test_truncated_manifest_surfaced() -> None:
    html = render_report_html(
        title="t", manifest=_manifest(3, truncated=True), findings=[_finding()]
    )
    assert "truncated" in html
