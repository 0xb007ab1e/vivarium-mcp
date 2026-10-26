"""Generated target documentation — output-edge report composition (ADR-078, TB10).

This package is the **output edge** for ADR-078 Tier-0: it composes already-``Untrusted``-wrapped
read-only tool outputs plus the ``session_export_annotations`` document into a bounded, navigable
report (ADR-shaped finding records + a self-contained HTML view) for a single session.

It runs **server-side only** — never in the Ghidra worker (ADR-001) — and is **never a write
primitive**. All binary-derived content it touches is hostile-origin (project data-classification);
the rendering-safety model is the tier-invariant **A+B+C** of ADR-078 / threat-model §22:

- **(C)** allow-list projection (:mod:`vivarium.report.projection`) — the only control that holds in
  a renderer we do not own (raw Markdown, an LLM reader): every binary-derived value is projected so
  no raw hostile byte can be active markup in *any* consumer.
- **(B)** data/template separation — a structured findings/graph model is rendered by a trusted
  auto-escaping emitter (never string-built markup, never ``innerHTML``).
- **(A)** inert-by-container — the emitted HTML is self-contained and wrapped in a strict CSP
  starting ``default-src 'none'`` plus ``<iframe sandbox>``, so a surviving injection can neither
  execute nor beacon.

Retention (ADR-078 amended): the report + finding records are held **in-memory, per-session**, and
discarded on session evict via the manager's evict callback — realizing ADR-002's ephemeral /
wipe-on-evict guarantee without any server-side on-disk store (production runs ``store_root=None``;
the only on-disk store is the worker's in-container tmpfs, off-limits to the output edge). This
mirrors the ADR-040 streaming-job retention model.
"""

from __future__ import annotations
