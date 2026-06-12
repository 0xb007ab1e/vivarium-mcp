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


def _canon_addr(addr: str | int) -> str:
    """Canonical lowercase-hex form for joining Ghidra addresses ↔ DWARF ``low_pc``."""
    return f"{int(addr, 16) if isinstance(addr, str) else int(addr):x}"


def _load_ground_truth(fixtures_dir: Path) -> dict[str, str]:
    """Build an address→name map from the fixture's DWARF ground truth (the tool's own funcs)."""
    data = json.loads((fixtures_dir / "cjson.groundtruth.json").read_text())
    fns = data["functions"] if isinstance(data, dict) else data
    return {_canon_addr(f["low_pc"]): f["name"] for f in fns}


def _truth_namer(truth: Mapping[str, str]) -> Namer:
    """A namer that returns the GROUND-TRUTH name for each address (else a placeholder).

    Used only to prove the accuracy plumbing — the address join (``-no-pie`` Ghidra addrs ↔ DWARF
    ``low_pc``) and exact-match scoring — end to end against the real fixture, which the hermetic
    unit tests (synthetic addresses) cannot. NOT a quality measurement: real naming is the client's.
    """

    def namer(ctx: FunctionContext, _callees: Mapping[str, str]) -> ProposedName:
        name = truth.get(_canon_addr(ctx.address), f"FUN_{ctx.address}")
        return ProposedName(new_name=name, new_c=f"int {name}(void) {{ return 0; }}")

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
    truth = _load_ground_truth(fixtures_dir)

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
            # Bound the work, but prefer functions present in the DWARF truth (the tool's OWN
            # functions) over the CRT/runtime leaves that dominate the very start of leaf-first
            # order (_start, frame_dummy, libc thunks — absent from the truth) so naming_accuracy is
            # measured over SCORABLE functions. Fall back to the raw head if the join finds nothing.
            members = [m for comp in order.components for m in comp.members]
            truth_keys = set(truth)
            scorable = [m for m in members if _canon_addr(m) in truth_keys]
            addresses = (scorable or members)[:_MAX_FUNCS]
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
    metrics = score(program, compile_runner=runner, ground_truth=truth)

    # The pipeline ran end to end and produced measured metrics.
    assert metrics.total_functions > 0
    assert metrics.inferred_functions > 0
    assert 0.0 <= metrics.name_coverage <= 1.0
    # Stub names are clean identifiers → full coverage; the trivial TU compiles in the sandbox.
    assert metrics.name_coverage == 1.0
    assert metrics.compiles is True, f"sandboxed compile failed: {metrics.compile_diagnostics}"

    # naming_accuracy is TRACKED here: the stub's `fn_<addr>` names share no tokens with the DWARF
    # truth, so its accuracy is ~0 BY DESIGN — a meaningful number comes only from a real client
    # namer (decision #1). We assert the metric joined to real truth (scored>0) + is well-formed,
    # and report it; we do NOT gate on stub quality.
    acc = metrics.naming_accuracy
    assert acc is not None and acc.scored > 0, "naming_accuracy did not join to the DWARF truth"
    assert 0.0 <= acc.exact_match_rate <= 1.0 and 0.0 <= acc.mean_token_f1 <= 1.0
    print(
        f"naming_accuracy[stub]: scored={acc.scored} unscored={acc.unscored} "
        f"exact={acc.exact_match_rate:.3f} token_f1={acc.mean_token_f1:.3f} (stub → ~0 expected)"
    )

    # Integration check of the accuracy PLUMBING: a namer emitting the true names must score a
    # perfect exact match over the REAL Ghidra↔DWARF address join (-no-pie). This validates the
    # join + scoring against real fixture data — the hermetic unit tests use synthetic addresses.
    truth_prog = orchestrate(order, contexts, _truth_namer(truth), max_functions=_MAX_FUNCS)
    truth_acc = score(truth_prog, ground_truth=truth).naming_accuracy
    assert truth_acc is not None and truth_acc.scored > 0
    assert truth_acc.exact_match_rate == 1.0, (
        f"address join/scoring broke: only {truth_acc.exact_matches}/{truth_acc.scored} exact"
    )


def test_naming_eval_pipeline_over_cjson() -> None:
    """Reference loop + sandboxed compile run end-to-end over the real cJSON worker output."""
    asyncio.run(_drive_naming_eval(Path(os.environ[_ENV_FIXTURES])))
