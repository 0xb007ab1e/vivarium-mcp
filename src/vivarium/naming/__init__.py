"""Semantic-naming reference client + eval (v1.1 — ADR-010).

A **pure, client-side** consumer of the read-only semantic-naming tools (ADR-007): it walks the
call graph **leaf-first** (sinks first, via ``analysis_order``), lets an injected *namer* infer a
semantic name + renamed pseudo-C per function, carries assigned names forward to callers, and
assembles a renamed translation unit — then **measures** the result (name coverage, and, behind a
sandboxed runner, compilability / behavioral equivalence — best-effort, NOT guaranteed; decision 3).

This package is a **tool consumer, not server runtime**: it never loads the JVM (ADR-001 — it only
consumes tool *outputs*), the server never imports it, and the real ``Namer`` is the client LLM
(locked decision #1 — no server-side LLM). All binary-derived input stays ``Untrusted`` (ADR-005);
nothing here executes it — the eval's compile/run step is a separate, sandboxed, gated increment
(ADR-010 §Security).
"""
