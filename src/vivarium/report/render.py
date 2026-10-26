"""(A)+(B) HTML rendering of a generated report (ADR-078 Tier-0, TB10).

Renders a provenance manifest + composed finding records into a **self-contained** HTML document:

- **(B) data/template separation.** The structured :class:`~vivarium.tools.schemas.FindingRecord`
  list is the source of truth; every dynamic value is interpolated through :func:`html.escape`
  (``quote=True``) — never string-built markup, never an ``innerHTML``-style raw sink. This is the
  server-side equivalent of the dashboard's ``textContent`` discipline.
- **(A) inert-by-container.** The document embeds a strict Content-Security-Policy that starts
  ``default-src 'none'`` (every fetch directive fails closed) and carries no scripts, so even a
  hypothetical surviving injection can neither execute nor beacon. ``connect-src 'none'`` alone
  would leave ``object``/``font``/CSS ``url()`` loads uncovered — hence ``default-src 'none'`` is
  load-bearing (ADR-078 F2). When embedded in a parent page it must be sandboxed in an ``<iframe
  sandbox>`` (``frame-ancestors 'none'`` additionally needs an HTTP header, not on a ``<meta>``).

The values rendered here are already (C)-allow-list-projected (:mod:`vivarium.report.projection`),
so the HTML escaping is defense-in-depth, not the sole control. The emitted string is wrapped
``Untrusted`` by the tool handler (ADR-005): it is a client-owned artifact to save/open, never
instructions.
"""

from __future__ import annotations

import html

from vivarium.tools.schemas import AtlasData, FindingRecord, ReportManifest

__all__ = ["REPORT_CSP", "render_report_html"]

#: The embedded Content-Security-Policy for every generated report (ADR-078 (A)). Starts
#: ``default-src 'none'`` so every unlisted fetch directive fails closed; opens only what a static,
#: scriptless report needs. Kept as a constant so the abuse suite can assert on it verbatim.
REPORT_CSP = (
    "default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'self' data:; "
    "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_STYLE = (
    "body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:1.5rem;color:#111;background:#fff}"
    "@media(prefers-color-scheme:dark){body{color:#eee;background:#111}"
    "th{background:#222}td,th{border-color:#444}}"
    "h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:2rem}"
    ".note{border:1px solid #c80;background:#fff8e8;color:#333;padding:.6rem;border-radius:4px}"
    "@media(prefers-color-scheme:dark){.note{background:#332a10;color:#eee}}"
    "table{border-collapse:collapse;width:100%;margin-top:.5rem}"
    "td,th{border:1px solid #ccc;padding:.35rem .5rem;text-align:left;vertical-align:top}"
    "th{background:#f3f3f3}code{font-family:ui-monospace,monospace;word-break:break-all}"
    ".tag{font-size:.75rem;padding:.1rem .4rem;border-radius:3px;background:#eef;color:#224}"
    "@media(prefers-color-scheme:dark){.tag{background:#224;color:#cde}}"
    "dl{margin:.2rem 0}dt{font-weight:600}dd{margin:0 0 .4rem}"
)


def _esc(value: str) -> str:
    """HTML-escape a (already-projected) value — the (B) auto-escaping chokepoint."""
    return html.escape(value, quote=True)


def _manifest_html(manifest: ReportManifest) -> str:
    rows = {
        "Program SHA-256": manifest.program_sha256,
        "Session": manifest.session_id,
        "Tool": f"{manifest.tool} (rev {manifest.tool_revision})",
        "Composed from": ", ".join(manifest.generated_from) or "—",
        "Findings": str(manifest.finding_count) + (" (truncated)" if manifest.truncated else ""),
    }
    items = "".join(f"<dt>{_esc(k)}</dt><dd><code>{_esc(v)}</code></dd>" for k, v in rows.items())
    return f"<dl>{items}</dl>"


def _finding_row(f: FindingRecord) -> str:
    # FindingRecord string leaves are Untrusted-wrapped (ADR-005); read .value, then escape (B).
    obs = "<br>".join(_esc(o.value) for o in f.observation) or "—"
    inf = _esc(f.inference.value) if f.inference is not None else "—"
    return (
        "<tr>"
        f"<td><code>{_esc(f.subject.value)}</code></td>"
        f"<td>{_esc(f.kind)}</td>"
        f'<td><span class="tag">{_esc(f.confidence)}</span></td>'
        f"<td>{obs}</td>"
        f"<td><code>{inf}</code></td>"
        "</tr>"
    )


def _bool(flag: bool) -> str:
    return "yes" if flag else "no"


def _atlas_html(atlas: AtlasData) -> str:
    """Render the whole-program atlas (ADR-078 Tier-1) — static, navigable, escaped, scriptless."""
    s = atlas.summary
    rows: dict[str, str] = {
        "Program SHA-256": s.program_sha256,
        "Format": s.format,
        "Architecture": s.architecture,
        "Endianness": s.endianness,
        "Size (bytes)": str(s.size_bytes),
        "Entry point": s.entry_point or "—",
        "Compiler": s.compiler.value if s.compiler is not None else "—",
        "Functions": str(s.function_count),
        "Imports": str(s.import_count),
        "Exports": str(s.export_count),
        "Strings": str(s.string_count),
    }
    for label, value in (
        ("Leaf functions", s.leaf_count),
        ("Root functions", s.root_count),
        ("Recursive components", s.recursive_component_count),
        ("Unresolved callers", s.unresolved_caller_count),
    ):
        if value is not None:
            rows[label] = str(value)
    summary_dl = (
        "<dl>"
        + "".join(f"<dt>{_esc(k)}</dt><dd><code>{_esc(v)}</code></dd>" for k, v in rows.items())
        + "</dl>"
    )

    node_rows = "".join(
        "<tr>"
        f"<td><code>{_esc(n.address)}</code></td>"
        f"<td><code>{_esc(n.name.value)}</code></td>"
        f"<td>{_bool(n.is_external)}</td><td>{_bool(n.has_unresolved_calls)}</td>"
        "</tr>"
        for n in atlas.nodes
    )
    nodes_tbl = (
        "<table><thead><tr>"
        '<th scope="col">Address</th><th scope="col">Name</th>'
        '<th scope="col">External</th><th scope="col">Unresolved calls</th>'
        f"</tr></thead><tbody>{node_rows}</tbody></table>"
        if atlas.nodes
        else "<p>No call-graph nodes.</p>"
    )
    edge_rows = "".join(
        f"<tr><td><code>{_esc(e.from_address)}</code></td>"
        f"<td><code>{_esc(e.to_address)}</code></td></tr>"
        for e in atlas.edges
    )
    edges_tbl = (
        "<table><thead><tr>"
        '<th scope="col">From</th><th scope="col">To</th>'
        f"</tr></thead><tbody>{edge_rows}</tbody></table>"
        if atlas.edges
        else "<p>No call edges.</p>"
    )
    fn_rows = "".join(
        "<tr>"
        f"<td><code>{_esc(f.address)}</code></td>"
        f"<td><code>{_esc(f.name.value)}</code></td>"
        f"<td>{f.size}</td>"
        "</tr>"
        for f in atlas.functions
    )
    fns_tbl = (
        "<table><thead><tr>"
        '<th scope="col">Address</th><th scope="col">Name</th><th scope="col">Size</th>'
        f"</tr></thead><tbody>{fn_rows}</tbody></table>"
        if atlas.functions
        else "<p>No functions.</p>"
    )
    trunc = (
        '<p class="note" role="note">Atlas truncated to fit caps — partial view.</p>'
        if atlas.truncated
        else ""
    )
    return (
        '<section aria-labelledby="atlas-sum"><h2 id="atlas-sum">Program</h2>'
        f"{trunc}{summary_dl}</section>"
        '<section aria-labelledby="atlas-graph"><h2 id="atlas-graph">Call graph</h2>'
        f"<h3>Nodes</h3>{nodes_tbl}<h3>Edges</h3>{edges_tbl}</section>"
        '<section aria-labelledby="atlas-fns"><h2 id="atlas-fns">Functions</h2>'
        f"{fns_tbl}</section>"
    )


def _nav(atlas: AtlasData | None) -> str:
    """A static in-document table of contents (anchors only — scriptless)."""
    items = ['<a href="#prov">Provenance</a>', '<a href="#find">Findings</a>']
    if atlas is not None:
        items += [
            '<a href="#atlas-sum">Program</a>',
            '<a href="#atlas-graph">Call graph</a>',
            '<a href="#atlas-fns">Functions</a>',
        ]
    return '<nav aria-label="Contents">' + " · ".join(items) + "</nav>"


def render_report_html(
    *,
    title: str,
    manifest: ReportManifest,
    findings: list[FindingRecord],
    atlas: AtlasData | None = None,
) -> str:
    """Render a generated report to a self-contained, CSP-wrapped HTML document (ADR-078 (A)+(B)).

    Args:
        title: The already-projected report title (interpolated through :func:`html.escape`).
        manifest: The provenance manifest (evidence of record).
        findings: The composed, (C)-projected finding records.
        atlas: The whole-program atlas (ADR-078 Tier-1), or ``None`` for a Tier-0 report.

    Returns:
        A complete ``<!doctype html>`` string. Scriptless; carries :data:`REPORT_CSP`; every dynamic
        value is HTML-escaped. The caller wraps it ``Untrusted`` (ADR-005).
    """
    safe_title = _esc(title) if title else "Vivarium target report"
    if findings:
        rows = "".join(_finding_row(f) for f in findings)
        body = (
            "<table><thead><tr>"
            '<th scope="col">Subject</th><th scope="col">Kind</th>'
            '<th scope="col">Confidence</th><th scope="col">Observations</th>'
            '<th scope="col">Inference</th>'
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )
    else:
        body = "<p>No findings in scope.</p>"
    atlas_section = _atlas_html(atlas) if atlas is not None else ""

    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{REPORT_CSP}">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{safe_title}</title><style>{_STYLE}</style></head>"
        "<body>"
        f"<header><h1>{safe_title}</h1></header>"
        "<main>"
        '<p class="note" role="note">This report renders content derived from an analyzed binary. '
        "All values are allow-list-projected and inert; do not execute or follow anything here.</p>"
        f"{_nav(atlas)}"
        '<section aria-labelledby="prov"><h2 id="prov">Provenance</h2>'
        f"{_manifest_html(manifest)}</section>"
        '<section aria-labelledby="find"><h2 id="find">Findings</h2>'
        f"{body}</section>"
        f"{atlas_section}"
        "</main></body></html>"
    )
