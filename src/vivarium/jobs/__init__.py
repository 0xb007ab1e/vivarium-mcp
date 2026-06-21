"""Streaming-job machinery (ADR-040 — streaming partial results, server-side core).

This package holds the *server-side* model + manager for incremental, pull-based extraction jobs
(design A2 "job plus cursor", `docs/design/streaming-partial-results-and-progress.md` §4). A tool
starts an extraction **job** that produces results incrementally; the client pulls bounded batches
by cursor while extraction continues, so the calling LLM can begin inference on early results.

The machinery here is JVM-free and worker-agnostic (ADR-001): it owns the bounded buffer, the
gap-free sequence numbering, backpressure-as-pause, the terminal-error path, the one-active-job
cap, and the BOLA ownership binding. It is *fed* by a producer (an iterator of per-unit results
the adapter obtains from the worker's streaming capability); the worker side is out of scope for
this increment (a fake streaming producer drives the hermetic tests).
"""

from __future__ import annotations

from vivarium.jobs.streaming import (
    DecompileStreamIn,
    FetchJobResultsIn,
    JobHandleIn,
    JobState,
    StreamChunk,
    StreamFetchResult,
    StreamingJobManager,
    StreamJobStatus,
)

__all__ = [
    "DecompileStreamIn",
    "FetchJobResultsIn",
    "JobHandleIn",
    "JobState",
    "StreamChunk",
    "StreamFetchResult",
    "StreamJobStatus",
    "StreamingJobManager",
]
