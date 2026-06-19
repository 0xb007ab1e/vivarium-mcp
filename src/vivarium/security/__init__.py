"""Security hardening: DoS bounds and injection defenses (WS4 home).

This package centralizes the controls that turn the threat model into code: the resource bounds
enforced BEFORE the worker (size/time/count caps — PLAN §3 F7) and the defensive normalization of
untrusted, binary-derived content (indirect prompt injection — std-owasp-llm LLM01/02). Critical
path: limit enforcement targets 100% coverage.
"""
