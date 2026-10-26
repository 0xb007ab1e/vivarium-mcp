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

from vivarium.tools.schemas import FindingRecord, ReportManifest

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
    obs = "<br>".join(_esc(o) for o in f.observation) or "—"
    inf = _esc(f.inference) if f.inference is not None else "—"
    return (
        "<tr>"
        f"<td><code>{_esc(f.subject)}</code></td>"
        f"<td>{_esc(f.kind)}</td>"
        f'<td><span class="tag">{_esc(f.confidence)}</span></td>'
        f"<td>{obs}</td>"
        f"<td><code>{inf}</code></td>"
        "</tr>"
    )


def render_report_html(
    *,
    title: str,
    manifest: ReportManifest,
    findings: list[FindingRecord],
) -> str:
    """Render a generated report to a self-contained, CSP-wrapped HTML document (ADR-078 (A)+(B)).

    Args:
        title: The already-projected report title (interpolated through :func:`html.escape`).
        manifest: The provenance manifest (evidence of record).
        findings: The composed, (C)-projected finding records.

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
        '<section aria-labelledby="prov"><h2 id="prov">Provenance</h2>'
        f"{_manifest_html(manifest)}</section>"
        '<section aria-labelledby="find"><h2 id="find">Findings</h2>'
        f"{body}</section>"
        "</main></body></html>"
    )
