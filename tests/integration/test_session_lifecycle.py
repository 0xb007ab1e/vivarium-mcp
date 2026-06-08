"""Integration: full session lifecycle against a real Ghidra worker (WS5 scaffold).

Primary worker-backed journey (PLAN §2, ADR-002): create a session → import a synthetic benign
binary → analyze → run a read-only tool → close (evict + verified store wipe). Marked
``integration`` so it is skipped in the unit/coverage job and only runs in the dedicated
integration job once the worker image exists and is pinned by digest (WS3).

Synthetic fixtures only — never real malware (master §5, PLAN §6). When the implementation
(WS1/WS2) and the worker image land, the bodies replace the placeholder skips with real
assertions against the live worker; the structure (markers, gating, synthetic inputs) is already
correct so wiring is incremental.
"""

from __future__ import annotations

import pytest

from tests._fixtures import build_elf64

pytestmark = pytest.mark.integration


def test_create_import_analyze_close_round_trip(worker_image: str) -> None:
    """Open → import (synthetic ELF) → analyze → close against the real worker.

    Asserts (once wired): the session reaches ``ready``, ``program_metadata`` reports the ELF
    format, and ``session_close`` returns ``store_wiped=True`` (verified-wipe — ADR-002).
    """
    elf = build_elf64()
    assert elf[:4] == b"\x7fELF"  # synthetic input is well-formed before we hand it to the worker
    pytest.skip(
        "WS5 Wave-2: drive a real SessionManager + RpcGhidraAdapter through "
        "create/import/analyze/close once WS1/WS2 and the worker image (WS3) are integrated"
    )


def test_analyze_unrecognized_input_reports_analysis_failed(worker_image: str) -> None:
    """A format-less blob yields an ``ANALYSIS_FAILED`` envelope, not a server crash (fail closed).

    The worker must contain the failure to its fault domain and surface a safe error envelope.
    """
    pytest.skip("WS5 Wave-2: assert ANALYSIS_FAILED on an unrecognized input via the live worker")
