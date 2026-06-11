"""Gated naming-eval e2e: reference loop + sandboxed compile over real OSS fixtures (ADR-010).

The truest end-to-end path for the semantic-naming feature: drive the real MCP stdio server
(FastMCP → real worker) on a stripped OSS fixture, pull the leaf-first plan + per-function context
out via the read-only tools (ADR-007), run the pure orchestration loop with a deterministic stub
namer, then **measure** the assembled translation unit with the **sandboxed**
``ContainerCompileRunner`` (ADR-010 / TB5). It proves the whole machinery — tools → loop →
assemble → isolated compile →
metrics — works end to end; the real naming quality is the client LLM's job (decision #1), so the
stub here emits trivially-compilable bodies to make the pipeline assertion deterministic.

GATING (hermetic by default — never runs in the unit/coverage job): all of
``GHIDRA_MCP_INTEGRATION`` (truthy), ``GHIDRA_MCP_FIXTURES`` (built fixtures dir),
``GHIDRA_MCP_WORKER_IMAGE``, a container engine, and ``GHIDRA_MCP_COMPILER_IMAGE`` (the pinned,
verified compiler image for the sandbox) must be present; otherwise the module skips cleanly.

No real malware: the only input is a benign source-available OSS tool (master §5, PLAN §6).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from ghidra_mcp.naming.compile import ContainerCompileRunner
from ghidra_mcp.naming.loop import Namer, ProposedName, orchestrate
from ghidra_mcp.naming.metrics import score
from ghidra_mcp.tools.schemas import AnalysisOrderOut, FunctionContext

_ENV_INTEGRATION = "GHIDRA_MCP_INTEGRATION"
_ENV_FIXTURES = "GHIDRA_MCP_FIXTURES"
_ENV_WORKER_IMAGE = "GHIDRA_MCP_WORKER_IMAGE"
_ENV_ENGINE = "GHIDRA_MCP_CONTAINER_ENGINE"
_ENV_COMPILER_IMAGE = "GHIDRA_MCP_COMPILER_IMAGE"

#: Bound the functions named per run — the eval is a pipeline proof, not a full-program pass; this
#: keeps the per-function ``function_context`` round-trips + the compile fast on CI.
_MAX_FUNCS = 30


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


def _skip_reason() -> str | None:
    if not _truthy(os.environ.get(_ENV_INTEGRATION)):
        return f"{_ENV_INTEGRATION} not set (gated real-worker e2e)"
    fixtures = os.environ.get(_ENV_FIXTURES, "").strip()
    if not fixtures or not (Path(fixtures) / "index.json").is_file():
        return f"{_ENV_FIXTURES} not set or missing index.json (run build_fixtures.py)"
    if not os.environ.get(_ENV_WORKER_IMAGE, "").strip():
        return f"{_ENV_WORKER_IMAGE} not set"
    if not os.environ.get(_ENV_COMPILER_IMAGE, "").strip():
        return f"{_ENV_COMPILER_IMAGE} not set (pinned compiler image for the TB5 sandbox)"
    engine = os.environ.get(_ENV_ENGINE, "podman")
    if shutil.which(engine) is None:
        return f"container engine {engine!r} not found on PATH"
    return None


_SKIP = _skip_reason()
pytestmark = [pytest.mark.integration, pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")]


def _structured(result: object) -> dict[str, Any]:
    """Extract a tool's structured JSON output from an MCP ``CallToolResult`` (fail on error)."""
    if getattr(result, "isError", False):
        raise AssertionError(f"tool returned an error envelope: {getattr(result, 'content', None)}")
    sc = getattr(result, "structuredContent", None)
    if isinstance(sc, dict):
        return sc
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parsed: dict[str, Any] = json.loads(text)
            return parsed
    raise AssertionError("no structured content in tool result")


def _stub_namer() -> Namer:
    """A deterministic namer: a clean address-derived identifier + a trivially-compilable body.

    The real namer is the client LLM (decision #1). This stub keeps the e2e deterministic and
    the assembled TU compilable, so the assertion exercises the full pipeline + sandbox, not the
    LLM's naming quality.
    """

    def namer(ctx: FunctionContext, _callees: Mapping[str, str]) -> ProposedName:
        ident = "fn_" + "".join(c if c.isalnum() else "_" for c in ctx.address)
        return ProposedName(new_name=ident, new_c=f"int {ident}(void) {{ return 0; }}")

    return namer


async def _drive_naming_eval(fixtures_dir: Path) -> None:
    """Drive server→tools→loop→sandboxed-compile for cJSON and assert the pipeline + metrics."""
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    stripped = fixtures_dir / "cjson.stripped"
    params = StdioServerParameters(
        command="python",
        args=["-m", "ghidra_mcp"],
        env={**os.environ, "GHIDRA_MCP_IMPORT_ROOT": str(fixtures_dir)},
    )
    timeout = timedelta(seconds=int(os.environ.get("GHIDRA_MCP_E2E_TIMEOUT", "600")))

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        sid = _structured(await session.call_tool("session_create", {}))["session_id"]
        try:
            await session.call_tool(
                "session_import",
                {"session_id": sid, "source_ref": str(stripped)},
                read_timeout_seconds=timeout,
            )
            await session.call_tool(
                "session_analyze", {"session_id": sid}, read_timeout_seconds=timeout
            )

            order = AnalysisOrderOut.model_validate(
                _structured(await session.call_tool("analysis_order", {"session_id": sid}))
            )
            # Bound the work: take the first functions in leaf-first order and fetch their context.
            addresses = [m for comp in order.components for m in comp.members][:_MAX_FUNCS]
            contexts: dict[str, FunctionContext] = {}
            for addr in addresses:
                ctx = FunctionContext.model_validate(
                    _structured(
                        await session.call_tool(
                            "function_context", {"session_id": sid, "function": addr}
                        )
                    )
                )
                contexts[ctx.address] = ctx
        finally:
            await session.call_tool("session_close", {"session_id": sid})

    assert contexts, "no function contexts retrieved from the worker"

    program = orchestrate(order, contexts, _stub_namer(), max_functions=_MAX_FUNCS)
    runner = ContainerCompileRunner(
        compiler_image=os.environ[_ENV_COMPILER_IMAGE],
        runtime=os.environ.get("GHIDRA_MCP_WORKER_RUNTIME", "runsc"),
        timeout_s=int(os.environ.get("GHIDRA_MCP_E2E_TIMEOUT", "120")),
    )
    metrics = score(program, compile_runner=runner)

    # The pipeline ran end to end and produced measured metrics.
    assert metrics.total_functions > 0
    assert metrics.inferred_functions > 0
    assert 0.0 <= metrics.name_coverage <= 1.0
    # Stub names are clean identifiers → full coverage; the trivial TU compiles in the sandbox.
    assert metrics.name_coverage == 1.0
    assert metrics.compiles is True, f"sandboxed compile failed: {metrics.compile_diagnostics}"


def test_naming_eval_pipeline_over_cjson() -> None:
    """Reference loop + sandboxed compile run end-to-end over the real cJSON worker output."""
    asyncio.run(_drive_naming_eval(Path(os.environ[_ENV_FIXTURES])))
