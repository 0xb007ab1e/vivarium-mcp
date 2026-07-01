"""Integration: session lifecycle fault path against a real Ghidra worker.

The happy-path worker-backed journey (create → import → analyze → read-only tool → close with
verified store wipe) is exercised live by ``tests/e2e/test_groundtruth_oss.py`` over the real
server→worker chain (run in ``e2e-groundtruth.yml``). This file holds the fail-closed fault case:
an unrecognized input yields a safe ``ANALYSIS_FAILED`` envelope rather than a crash.

Marked ``integration`` (skipped in the unit/coverage job; runs in the dedicated integration job
once the worker image is pinned). Synthetic fixtures only — never real malware (master §5, PLAN §6).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_analyze_unrecognized_input_reports_analysis_failed(worker_image: str) -> None:
    """A format-less blob yields an ``ANALYSIS_FAILED`` envelope, not a server crash (fail closed).

    The worker must contain the failure to its fault domain and surface a safe error envelope.
    """
    pytest.skip(
        "Covered live (G4 Phase 1) by tests/e2e/test_abuse_containment_oss.py::"
        "test_malformed_loader_contained_no_rce; this finer in-process variant is deferred."
    )
