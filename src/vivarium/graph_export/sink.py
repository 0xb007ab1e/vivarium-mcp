"""Live ``GraphSink`` adapter: an MCP stdio client to the ``memory-graph`` server (ADR-079).

Not exercised in unit CI (needs the live ``memory-graph`` server) — ``pragma: no cover`` like the
dashboard's ``McpToolCaller``. Enabling it is the operator's gated step (an outward write —
``workflow-gated-actions``): the exporter connects to a configured ``memory-graph`` MCP server and
upserts one per-binary project. The server command/args/env are injected (never hard-coded) so the
same adapter works against any memory-graph deployment.
"""

from __future__ import annotations

from typing import Any


class McpGraphSink:  # pragma: no cover - live transport (real memory-graph MCP server)
    """Live :class:`~vivarium.graph_export.ports.GraphSink` over an MCP stdio memory-graph server.

    The async MCP client runs on a dedicated background event loop; each method is a sync bridge
    with a bounded timeout. ``ensure_project`` resolves a project by name (``mg_list_projects``) and
    creates it (``mg_create_project``) only when absent, so re-export is idempotent.
    """

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        *,
        timeout: float = 120.0,
    ) -> None:
        """Start the background loop and connect an MCP stdio client to the memory-graph server."""
        import asyncio
        import threading

        self._command = command
        self._args = args or []
        self._env = env
        self._timeout = timeout
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._session: Any = None
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=60):
            raise RuntimeError("memory-graph MCP server did not become ready")

    def _run_loop(self) -> None:
        import asyncio

        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._connect())
        self._loop.run_forever()

    async def _connect(self) -> None:
        import os

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(
            command=self._command,
            args=self._args,
            env=self._env if self._env is not None else dict(os.environ),
        )
        self._ctx = stdio_client(params)
        read, write = await self._ctx.__aenter__()
        self._session = ClientSession(read, write)
        await self._session.__aenter__()
        await self._session.initialize()
        self._ready.set()

    def _call(self, tool: str, params: dict[str, Any]) -> Any:
        """Call an ``mg_*`` tool; return its parsed result (list/dict), bounded by the timeout."""
        import asyncio
        import json

        async def _do() -> Any:
            res = await self._session.call_tool(tool, params)
            sc = getattr(res, "structuredContent", None)
            if isinstance(sc, dict):
                # FastMCP wraps a non-dict return under "result"; unwrap it.
                return sc.get("result", sc) if set(sc.keys()) == {"result"} else sc
            content = getattr(res, "content", None) or []
            if content and getattr(content[0], "text", None):
                return json.loads(content[0].text)
            return None

        fut = asyncio.run_coroutine_threadsafe(_do(), self._loop)
        return fut.result(timeout=self._timeout)

    def ensure_project(self, name: str, description: str) -> str:
        """Resolve the project named ``name`` (create if absent); return its id. Idempotent."""
        existing = self._call("mg_list_projects", {})
        if isinstance(existing, list):
            for row in existing:
                if isinstance(row, dict) and row.get("name") == name:
                    return str(row["id"])
        created = self._call("mg_create_project", {"name": name, "description": description})
        if isinstance(created, dict) and "id" in created:
            return str(created["id"])
        raise RuntimeError(f"memory-graph did not return a project id for {name!r}")

    def upsert_nodes(self, project_id: str, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Upsert nodes via ``mg_upsert_nodes``; return the per-node result records."""
        result = self._call("mg_upsert_nodes", {"project_id": project_id, "nodes": nodes})
        return result if isinstance(result, list) else []

    def upsert_edges(self, project_id: str, edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Upsert edges via ``mg_upsert_edges``; return the per-edge result records."""
        result = self._call("mg_upsert_edges", {"project_id": project_id, "edges": edges})
        return result if isinstance(result, list) else []
