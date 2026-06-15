"""Gated differential-run e2e: behavioral_equivalence over the cJSON fixture (ADR-016).

Completes ADR-010's deferred ``behavioral_equivalence`` field. It compares two BUILDS on shared
synthetic inputs and **never runs the analyzed (hostile) sample** (ADR-001 / D1):

  * **(A) reference build** — the fixture's TRUSTED known source (cJSON) compiled with the
    committed differential driver,
  * **(B) candidate build** — the recompiled renamed-decompiled-C produced by the naming loop,
    compiled with the SAME driver.

Both builds run, in-sandbox uniformly (TB5 / :class:`ContainerExecRunner`), once per synthetic input
vector (``cjson_input_vectors.json`` — benign JSON, no PII / no malware, master §5). The metric is
the fraction of vectors whose ``(exit_code, stdout)`` match byte-exactly (D2). Low/zero scores are
honest: a stub or non-recompiling candidate fails to build/link and scores ~0 — that is the point.

GATING (hermetic by default — never runs in the unit/coverage job): mirrors
``test_naming_eval_oss`` — all of ``GHIDRA_MCP_INTEGRATION`` (truthy), ``GHIDRA_MCP_FIXTURES`` (the
built fixtures dir with ``index.json``), ``GHIDRA_MCP_WORKER_IMAGE``, a container engine, and
``GHIDRA_MCP_COMPILER_IMAGE`` (the pinned, verified compiler image for the TB5 sandbox) must be
present; otherwise this module skips cleanly. The fixtures-build job must additionally emit the
cJSON **source** alongside the stripped binary (``GHIDRA_MCP_CJSON_SOURCE``) so build A/B have the
amalgamated TU + driver to compile — absent it, the test skips.
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

from ghidra_mcp.naming.compile import ContainerExecRunner
from ghidra_mcp.naming.loop import Namer, ProposedName, orchestrate
from ghidra_mcp.naming.metrics import generate_fuzz_vectors, score
from ghidra_mcp.tools.schemas import AnalysisOrderOut, FunctionContext

_ENV_INTEGRATION = "GHIDRA_MCP_INTEGRATION"
_ENV_FIXTURES = "GHIDRA_MCP_FIXTURES"
_ENV_WORKER_IMAGE = "GHIDRA_MCP_WORKER_IMAGE"
_ENV_ENGINE = "GHIDRA_MCP_CONTAINER_ENGINE"
_ENV_COMPILER_IMAGE = "GHIDRA_MCP_COMPILER_IMAGE"
#: The gated fixtures-build job emits the amalgamated cJSON source (cJSON.c text) so the e2e can
#: build the TRUSTED reference (A) from known source — never from the hostile binary (D1).
_ENV_CJSON_SOURCE = "GHIDRA_MCP_CJSON_SOURCE"

_HERE = Path(__file__).resolve().parent
_FIXTURES_OSS = _HERE.parent / "fixtures" / "oss"
_DRIVER = _FIXTURES_OSS / "differential_driver_cjson.c"
_VECTORS = _FIXTURES_OSS / "cjson_input_vectors.json"

#: Bound the functions named per run (pipeline proof, not a full-program pass) — matches the
#: naming-eval e2e so the round-trips + builds stay fast on CI.
_MAX_FUNCS = 30

#: Seeded fuzz-vector parameters (ADR-022 D2) — deterministic + bounded so the gated e2e stays
#: reproducible and fast. Fixed seed ⇒ the same broadened input set every run (hermetic).
_FUZZ_SEED = 0xC0FFEE
_FUZZ_COUNT = 16
_FUZZ_MAX_LEN = 64


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


def _skip_reason() -> str | None:
    if not _truthy(os.environ.get(_ENV_INTEGRATION)):
        return f"{_ENV_INTEGRATION} not set (gated differential-run e2e)"
    fixtures = os.environ.get(_ENV_FIXTURES, "").strip()
    if not fixtures or not (Path(fixtures) / "index.json").is_file():
        return f"{_ENV_FIXTURES} not set or missing index.json (run build_fixtures.py)"
    if not os.environ.get(_ENV_WORKER_IMAGE, "").strip():
        return f"{_ENV_WORKER_IMAGE} not set"
    if not os.environ.get(_ENV_COMPILER_IMAGE, "").strip():
        return f"{_ENV_COMPILER_IMAGE} not set (pinned compiler image for the TB5 sandbox)"
    if not os.environ.get(_ENV_CJSON_SOURCE, "").strip():
        return f"{_ENV_CJSON_SOURCE} not set (trusted cJSON source for reference build A — D1)"
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
    """A deterministic namer emitting clean identifiers + trivially-compilable bodies.

    The real namer is the client LLM (ADR-007). The stub keeps the pipeline deterministic; its
    bodies do NOT reconstruct the cJSON API, so the CANDIDATE build (B) will not link against the
    differential driver → ``behavioral_equivalence`` is ~0 BY DESIGN here (honest low score — D2).
    A real client namer that recovers the cJSON API names would link + score > 0.
    """

    def namer(ctx: FunctionContext, _callees: Mapping[str, str]) -> ProposedName:
        ident = "fn_" + "".join(c if c.isalnum() else "_" for c in ctx.address)
        return ProposedName(new_name=ident, new_c=f"int {ident}(void) {{ return 0; }}")

    return namer


def _load_vectors() -> list[bytes]:
    """Load the committed synthetic input vectors as stdin byte strings (D3)."""
    data = json.loads(_VECTORS.read_text())
    return [v["stdin"].encode("utf-8") for v in data["vectors"]]


def _reference_source() -> str:
    """Assemble build A: the TRUSTED cJSON source + the differential driver as ONE TU (D1).

    The driver calls the cJSON public API by name; concatenating the amalgamated source with the
    driver makes those symbols available in a single translation unit (no header needed). NEVER
    derived from the hostile binary — this is the fixture's own known source.
    """
    cjson_src = Path(os.environ[_ENV_CJSON_SOURCE]).read_text()
    driver = _DRIVER.read_text()
    # Drop the driver's `#include "cJSON.h"` — the API is already declared/defined in cjson_src.
    driver_body = "\n".join(
        ln for ln in driver.splitlines() if not ln.strip().startswith('#include "cJSON.h"')
    )
    return cjson_src + "\n\n" + driver_body + "\n"


def _candidate_source(translation_unit: str) -> str:
    """Assemble build B: the candidate recompiled C + the differential driver as ONE TU.

    Same driver as A. If the candidate recovered the cJSON API names this links + runs; otherwise
    it fails to build → ``ok=False`` for every vector → an honest non-match (D2).
    """
    driver = _DRIVER.read_text()
    driver_body = "\n".join(
        ln for ln in driver.splitlines() if not ln.strip().startswith('#include "cJSON.h"')
    )
    return translation_unit + "\n\n" + driver_body + "\n"


async def _collect_candidate(fixtures_dir: Path) -> str:
    """Drive server→tools→loop over the stripped cJSON fixture; return the candidate TU (B)."""
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
            members = [m for comp in order.components for m in comp.members][:_MAX_FUNCS]
            contexts: dict[str, FunctionContext] = {}
            for addr in members:
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
    return program.translation_unit


def _exec_runner() -> ContainerExecRunner:
    return ContainerExecRunner(
        compiler_image=os.environ[_ENV_COMPILER_IMAGE],
        runtime=os.environ.get("GHIDRA_MCP_WORKER_RUNTIME", "runsc"),
        timeout_s=int(os.environ.get("GHIDRA_MCP_E2E_TIMEOUT", "120")),
    )


def test_behavioral_equivalence_over_cjson() -> None:
    """A-vs-B differential run over cJSON: strict + normalized are measured + well-formed.

    Runs the fixed committed vectors **and** seeded fuzz vectors (ADR-022 D2) through the same
    sandbox, and reports both the strict byte-exact score (ADR-016 D2) and the looser normalized
    score (ADR-022 D1). The fuzz vectors are deterministic (fixed seed) so the run is reproducible.
    """
    fixtures_dir = Path(os.environ[_ENV_FIXTURES])
    # Fixed committed vectors broadened with seeded, bounded fuzz vectors (ADR-022 D2 — the SAME
    # synthetic vectors feed both builds A and B; deterministic, never attacker-controlled).
    fixed = _load_vectors()
    assert fixed, "no synthetic input vectors loaded"
    fuzz = generate_fuzz_vectors(seed=_FUZZ_SEED, count=_FUZZ_COUNT, max_len=_FUZZ_MAX_LEN)
    vectors = fixed + fuzz

    candidate_tu = asyncio.run(_collect_candidate(fixtures_dir))

    runner = _exec_runner()
    # Build A (trusted reference source) and build B (candidate) run uniformly in-sandbox; the
    # hostile binary is NEVER executed (D1) — both inputs are C sources, not the analyzed sample.
    runs_a = runner(_reference_source(), vectors)
    runs_b = runner(_candidate_source(candidate_tu), vectors)

    metrics = score(
        orchestrate(  # a throwaway program to reuse score(); equivalence is over the run lists
            AnalysisOrderOut(
                components=[], unresolved_callers=[], self_recursive=[], truncated=False
            ),
            {},
            _stub_namer(),
        ),
        behavioral_runs=(runs_a, runs_b),
    )

    # The reference build (A) must itself run cleanly on every vector — trusted known source.
    assert all(r.ok for r in runs_a), "reference build A failed to build/run (fixture/toolchain?)"
    # Both metrics are MEASURED + well-formed; we do NOT gate on the stub's (expected ~0) score.
    be = metrics.behavioral_equivalence
    be_norm = metrics.behavioral_equivalence_normalized
    assert be is not None and 0.0 <= be <= 1.0
    assert be_norm is not None and 0.0 <= be_norm <= 1.0
    # Invariant (ADR-022 D1): normalization only loosens the compare → normalized >= strict.
    assert be_norm >= be
    print(
        f"behavioral_equivalence[stub]: strict={be:.3f} normalized={be_norm:.3f} "
        f"over {len(vectors)} vectors ({len(fixed)} fixed + {len(fuzz)} fuzz; stub → ~0 expected)"
    )


def test_reference_build_runs_consistently_on_repeat() -> None:
    """Determinism check: build A's (exit_code, stdout) is stable across two runs (self-equiv).

    Compares the trusted reference build against ITSELF — must be a perfect 1.0 (the oracle + the
    sandbox are deterministic). Catches a flaky driver/toolchain before it masquerades as a
    fidelity signal.
    """
    vectors = _load_vectors()
    runner = _exec_runner()
    ref = _reference_source()
    runs1 = runner(ref, vectors)
    runs2 = runner(ref, vectors)
    metrics = score(
        orchestrate(
            AnalysisOrderOut(
                components=[], unresolved_callers=[], self_recursive=[], truncated=False
            ),
            {},
            _stub_namer(),
        ),
        behavioral_runs=(runs1, runs2),
    )
    assert metrics.behavioral_equivalence == 1.0
