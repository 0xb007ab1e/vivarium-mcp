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
def _op(op: str, desc: str, gated: bool = False, write: bool = False) -> dict[str, Any]:
    """One palette op entry.

    ``gated`` marks a compute/write op (never auto-run from the UI). ``write`` further marks an op
    that MUTATES the program (rename/comment/type/consent/undo/ai_annotate) — a write is always
    gated, and even a worker-backed executor refuses it (writes go only through the human-approved
    write-consent path). A ``gated`` op that is not a ``write`` is **compute** (import/analyze) — a
    worker-backed executor may run it once interactive is enabled.
    """
    entry: dict[str, Any] = {"op": op, "desc": desc}
    if gated or write:
        entry["gated"] = True
    if write:
        entry["write"] = True
    return entry


# Full vivarium tool surface, grouped. Read-only by default; ``gated=True`` = compute/write (import/
# analyze/session-control/type+annotation writes/AI) — agent + write-consent only, never auto from
# the UI. Kept in sync with the Tier-1 catalog (docs/contracts/tool-catalog.md).
_OP_GROUPS: list[dict[str, Any]] = [
    {
        "group": "Session",
        "ops": [
            _op("session_create", "Create an analysis session"),
            _op("session_import", "Load a binary (path under the import root)", gated=True),
            _op("session_analyze", "Run Ghidra auto-analysis", gated=True),
            _op("session_status", "Session state / TTL"),
            _op("session_close", "Close + verified store wipe", write=True),
            _op("session_enable_writes", "Enable write consent for the session", write=True),
            _op("session_disable_writes", "Disable write consent", write=True),
            _op("session_undo", "Undo the last write", write=True),
            _op("session_export_annotations", "Export annotations (names/comments/types)"),
            _op("session_import_annotations", "Import + replay an annotation document", write=True),
        ],
    },
    {
        "group": "Program / listing",
        "ops": [
            _op("program_metadata", "Format / arch / entry / compiler"),
            _op("program_summary", "High-level program summary"),
            _op("program_fingerprint", "Structure + import fingerprint"),
            _op("memory_map", "Memory blocks / segments"),
            _op("list_functions", "Functions in the program"),
            _op("list_imports", "Imported symbols"),
            _op("list_exports", "Exported symbols"),
            _op("list_strings", "Defined strings"),
            _op("list_symbols", "Symbol table"),
            _op("list_data", "Defined data"),
            _op("list_data_types", "Data types"),
            _op("get_symbol", "Resolve a symbol"),
            _op("get_data_type", "Resolve a data type"),
            _op("get_comments", "Comments at an address"),
        ],
    },
    {
        "group": "Code",
        "ops": [
            _op("decompile_function", "Decompile to C"),
            _op("disassemble", "Disassembly listing"),
            _op("basic_blocks", "Basic-block listing"),
            _op("get_pcode", "Raw p-code (IR)"),
            _op("get_high_pcode", "High (SSA) p-code"),
            _op("data_flow_slice", "Def-use slice from a seed"),
            _op("stack_frame", "Recovered locals / params"),
            _op("emulate", "Sandboxed p-code emulation (read-only)"),
            _op("start_decompile_stream", "Bulk decompile stream (job)"),
            _op("fetch_job_results", "Drain a streaming job"),
            _op("job_status", "Streaming job status"),
            _op("cancel_job", "Cancel a streaming job"),
        ],
    },
    {
        "group": "Graph / xrefs",
        "ops": [
            _op("callers", "Direct callers (parents)"),
            _op("callees", "Direct callees (children)"),
            _op("call_graph", "Call graph (bounded, recursive)"),
            _op("call_graph_metrics", "Call-graph metrics"),
            _op("xrefs_to", "References to an address"),
            _op("xrefs_from", "References from an address"),
            _op("function_context", "Callers+callees+xrefs+vars for a function"),
            _op("cyclomatic_complexity", "Per-function complexity"),
            _op("coverage", "Analysis coverage"),
            _op("identify_functions", "Function ID (library match)"),
        ],
    },
    {
        "group": "Scans",
        "ops": [
            _op("ioc_scan", "Indicators of compromise"),
            _op("secret_scan", "Embedded secrets (redacted)"),
            _op("crypto_detect", "Crypto (imports / consts / instructions)"),
            _op("crypto_constant_scan", "Crypto constants (S-boxes / IVs)"),
            _op("capability_scan", "Capabilities / behaviors"),
            _op("deobfuscate_strings", "Recover hidden strings"),
            _op("search_strings", "Search strings"),
            _op("search_bytes", "Search byte patterns"),
            _op("read_bytes", "Read bytes at an address"),
        ],
    },
    {
        "group": "Similarity",
        "ops": [
            _op("function_hash", "Per-function hashes"),
            _op("bsim_similarity", "BSim similarity"),
            _op("bsim_search_corpus", "BSim corpus search"),
            _op("binary_diff", "Diff two programs"),
            _op("family_match", "Known-family match"),
            _op("find_similar_functions", "Similar functions"),
            _op("version_track", "Version tracking (two binaries)"),
        ],
    },
    {
        "group": "Types (write — gated)",
        "ops": [
            _op("recover_struct", "Propose a struct layout (read-only)"),
            _op("define_struct", "Define a struct", write=True),
            _op("define_union", "Define a union", write=True),
            _op("define_types", "Define composite types (batch)", write=True),
            _op("apply_data_type", "Apply a data type", write=True),
            _op("apply_type_archive", "Apply a type archive", write=True),
            _op("delete_type", "Delete a type", write=True),
        ],
    },
    {
        "group": "Annotate (write — gated)",
        "ops": [
            _op("rename_function", "Rename a function", write=True),
            _op("rename_local_variable", "Rename a local", write=True),
            _op("rename_parameter", "Rename a parameter", write=True),
            _op("rename_symbol", "Rename a symbol", write=True),
            _op("set_comment", "Set a comment", write=True),
            _op("set_function_signature", "Set a signature", write=True),
            _op("ai_annotate", "AI propose renames/comments (propose-first)", write=True),
        ],
    },
    {
        "group": "Utility",
        "ops": [
            _op("demangle", "Demangle a symbol"),
            _op("analysis_order", "Analyzer order / plan"),
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
