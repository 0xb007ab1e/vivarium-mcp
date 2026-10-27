"""CLI: self-contained export of a binary's Vivarium analysis to memory-graph (ADR-079 §2.2).

``python -m vivarium.graph_export <source_ref>`` (or the ``vivarium-graph-export`` console script):
spawns a Vivarium MCP server, opens a session, imports the binary (a path under
``VIVARIUM_IMPORT_ROOT``), analyzes it, exports the whole analysis into its per-binary memory-graph
project, then closes the session. Writing to memory-graph is a gated outward action
(``workflow-gated-actions``); the operator runs this deliberately with a configured memory-graph
server. Live transport only — ``pragma: no cover``.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from vivarium.graph_export.driver import ExportOptions, export_session


def _build_parser() -> argparse.ArgumentParser:  # pragma: no cover - CLI wiring
    parser = argparse.ArgumentParser(
        prog="vivarium-graph-export",
        description="Export a binary's Vivarium RE analysis into the memory-graph knowledge graph.",
    )
    parser.add_argument(
        "source_ref",
        help="Binary to import: a path the Vivarium server resolves under VIVARIUM_IMPORT_ROOT.",
    )
    parser.add_argument(
        "--mg-command",
        default=os.environ.get("VIVARIUM_MEMGRAPH_CMD"),
        help="Command that launches the memory-graph MCP server (or env VIVARIUM_MEMGRAPH_CMD).",
    )
    parser.add_argument(
        "--mg-arg",
        action="append",
        default=None,
        dest="mg_args",
        help="An argument to the memory-graph server command (repeatable).",
    )
    parser.add_argument("--label", default=None, help="Audit label for the session.")
    parser.add_argument(
        "--profile",
        default="default",
        choices=["default", "light", "deep"],
        help="Analyzer depth preset.",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Per-function deep enrichment (signature/complexity/hash) — N calls per function.",
    )
    parser.add_argument("--expected-sha256", default=None, help="Integrity guard for the import.")
    return parser


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - live transport
    """Run the self-contained export; return a process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = _build_parser().parse_args(argv)
    if not args.mg_command:
        print("error: --mg-command (or VIVARIUM_MEMGRAPH_CMD) is required", file=sys.stderr)
        return 2

    # Imported lazily so the pure package has no hard dependency on the live MCP transport.
    from vivarium.dashboard.executor import McpToolCaller
    from vivarium.graph_export.sink import McpGraphSink

    caller = McpToolCaller()
    sink = McpGraphSink(command=args.mg_command, args=args.mg_args or [])

    info = caller.call("session_create", {"label": args.label} if args.label else {})
    session_id = info["session_id"]
    try:
        import_args: dict[str, object] = {"session_id": session_id, "source_ref": args.source_ref}
        if args.expected_sha256:
            import_args["expected_sha256"] = args.expected_sha256
        caller.call("session_import", import_args)
        caller.call("session_analyze", {"session_id": session_id, "profile": args.profile})
        stats = export_session(
            caller,
            sink,
            session_id,
            binary_label=args.source_ref,
            opts=ExportOptions(enrich_functions=args.enrich),
        )
    finally:
        caller.call("session_close", {"session_id": session_id})

    print(
        f"exported {stats.nodes_total} nodes / {stats.edges_total} edges "
        f"({stats.edges_skipped} edges skipped) into project {stats.project_name!r}"
    )
    if stats.failed_tools:
        print(
            f"note: some optional tools failed (partial graph): {sorted(set(stats.failed_tools))}"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
