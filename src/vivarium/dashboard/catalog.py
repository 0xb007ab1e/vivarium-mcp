"""Static workflow + operation catalog for the dashboard (read-only, Phase 1).

The dashboard is an author + visualize surface (Phase 1): it does NOT drive the MCP server. This
module supplies the *catalog* the UI renders — the reverse-engineering operations vivarium exposes
(grouped for an op palette) and the prebuilt RE workflows (ordered steps). It is entirely static,
safe metadata (closed-vocabulary tool names + human descriptions) — no binary-derived content — and
is served read-only at ``/api/catalog``.

A workflow is an ordered list of steps; each step names an ``op`` (a vivarium tool) with a short
label. Steps whose op writes to the program (rename/comment/type) are marked ``gated`` — those run
only via the agent under the existing write-consent + human approval (never from the browser). The
custom step-list builder (a later increment) composes new workflows from these ops.
"""

from __future__ import annotations

from typing import Any

# Operation palette — grouped, closed-vocabulary vivarium tool names + descriptions. `gated=True`
# marks an operation that computes/costs or WRITES (analyze / annotate / type edits) and therefore
# runs only via the agent under write-consent + human approval, never autonomously from the UI.
_OP_GROUPS: list[dict[str, Any]] = [
    {
        "group": "Session",
        "ops": [
            {"op": "session_create", "desc": "Create an analysis session"},
            {
                "op": "session_import",
                "desc": "Load a binary (path under the import root)",
                "gated": True,
            },
            {"op": "session_analyze", "desc": "Run Ghidra auto-analysis", "gated": True},
            {"op": "session_status", "desc": "Session state / TTL"},
            {"op": "session_close", "desc": "Close + verified store wipe", "gated": True},
        ],
    },
    {
        "group": "Listing",
        "ops": [
            {"op": "list_functions", "desc": "Functions in the program"},
            {"op": "list_imports", "desc": "Imported symbols"},
            {"op": "list_exports", "desc": "Exported symbols"},
            {"op": "list_strings", "desc": "Defined strings"},
            {"op": "list_symbols", "desc": "Symbol table"},
            {"op": "list_data", "desc": "Defined data"},
            {"op": "program_metadata", "desc": "Format / arch / entry / compiler"},
        ],
    },
    {
        "group": "Code",
        "ops": [
            {"op": "decompile_function", "desc": "Decompile to C"},
            {"op": "disassemble", "desc": "Disassembly listing"},
            {"op": "get_pcode", "desc": "Raw p-code (IR)"},
            {"op": "get_high_pcode", "desc": "High (SSA) p-code"},
            {"op": "data_flow_slice", "desc": "Def-use slice from a seed"},
            {"op": "stack_frame", "desc": "Recovered locals / params"},
        ],
    },
    {
        "group": "Graph / xrefs",
        "ops": [
            {"op": "callers", "desc": "Direct callers (parents)"},
            {"op": "callees", "desc": "Direct callees (children)"},
            {"op": "call_graph", "desc": "Call graph (bounded)"},
            {"op": "xrefs_to", "desc": "References to an address"},
            {"op": "xrefs_from", "desc": "References from an address"},
            {"op": "function_context", "desc": "Callers+callees+xrefs+vars for a function"},
        ],
    },
    {
        "group": "Scans",
        "ops": [
            {"op": "ioc_scan", "desc": "Indicators of compromise"},
            {"op": "secret_scan", "desc": "Embedded secrets"},
            {"op": "crypto_detect", "desc": "Crypto (imports / consts / instructions)"},
            {"op": "capability_scan", "desc": "Capabilities / behaviors"},
            {"op": "deobfuscate_strings", "desc": "Recover hidden strings"},
        ],
    },
    {
        "group": "Similarity",
        "ops": [
            {"op": "function_hash", "desc": "Per-function hashes"},
            {"op": "bsim_similarity", "desc": "BSim similarity"},
            {"op": "binary_diff", "desc": "Diff two programs"},
            {"op": "family_match", "desc": "Known-family match"},
            {"op": "find_similar_functions", "desc": "Similar functions"},
        ],
    },
    {
        "group": "Annotate (write — gated)",
        "ops": [
            {"op": "rename_function", "desc": "Rename a function", "gated": True},
            {"op": "rename_local_variable", "desc": "Rename a local", "gated": True},
            {"op": "rename_parameter", "desc": "Rename a parameter", "gated": True},
            {"op": "set_comment", "desc": "Set a comment", "gated": True},
            {"op": "set_function_signature", "desc": "Set a signature", "gated": True},
            {
                "op": "ai_annotate",
                "desc": "AI propose renames/comments (propose-first)",
                "gated": True,
            },
        ],
    },
]


def _step(op: str, label: str, gated: bool = False) -> dict[str, Any]:
    """One workflow step: an op + a short human label; ``gated`` for compute/write ops."""
    return {"op": op, "label": label, "gated": gated}


# Prebuilt RE workflows — ordered steps. Read-only descriptions in Phase 1 (the agent executes).
_WORKFLOWS: list[dict[str, Any]] = [
    {
        "id": "triage",
        "name": "Triage / overview",
        "desc": "One-click 'what is this binary': load, analyze, and scan for a first verdict.",
        "steps": [
            _step("session_import", "open binary", gated=True),
            _step("session_analyze", "analyze", gated=True),
            _step("program_metadata", "binary format"),
            _step("list_strings", "strings"),
            _step("list_imports", "imports"),
            _step("ioc_scan", "IOC scan"),
            _step("crypto_detect", "crypto"),
            _step("capability_scan", "capabilities"),
            _step("ai_annotate", "verdict summary", gated=True),
        ],
    },
    {
        "id": "call-tree",
        "name": "Call-tree exploration",
        "desc": "Walk parents/children from a function recursively; feeds graph + function views.",
        "steps": [
            _step("function_context", "focus function"),
            _step("callers", "list parents (callers)"),
            _step("callees", "list children (callees)"),
            _step("call_graph", "recurse (bounded depth)"),
            _step("decompile_function", "decompile focus"),
        ],
    },
    {
        "id": "ai-annotation",
        "name": "AI annotation pass",
        "desc": "AI-assisted rename/comment from decompiled evidence — proposed first, applied "
        "only with human approval (write-consent); reversible via session_undo.",
        "steps": [
            _step("decompile_function", "decompile"),
            _step("ai_annotate", "AI propose names + comments", gated=True),
            _step("rename_function", "apply renames (approve)", gated=True),
            _step("set_comment", "apply comments (approve)", gated=True),
        ],
    },
    {
        "id": "scans-similarity",
        "name": "Scans & similarity",
        "desc": "Signal scans plus similarity/known-family matching for classification.",
        "steps": [
            _step("list_strings", "strings"),
            _step("secret_scan", "secrets"),
            _step("crypto_detect", "crypto"),
            _step("capability_scan", "capabilities"),
            _step("ioc_scan", "IOCs"),
            _step("function_hash", "function hashes"),
            _step("bsim_similarity", "BSim similarity"),
            _step("family_match", "family match"),
        ],
    },
]


def catalog() -> dict[str, Any]:
    """Return the full static catalog (op groups + prebuilt workflows) for ``/api/catalog``."""
    return {"op_groups": _OP_GROUPS, "workflows": _WORKFLOWS}
