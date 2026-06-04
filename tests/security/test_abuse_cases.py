"""WS4 abuse/injection test suite — SCAFFOLD (skipped until WS4 implements the controls).

This file enumerates the REQUIRED abuse cases from the threat model (docs/security/threat-model.md
§ abuse cases). Each is a placeholder marked ``xfail``/``skip`` so the suite is green now but the
gaps are visible and tracked. WS4 (security-eng) replaces each placeholder with a real adversarial
test using BENIGN/SYNTHETIC fixtures only (never real malware — master §5, PLAN §6).
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.abuse, pytest.mark.integration]

_REASON = "WS4: implement against the real server/worker with synthetic fixtures"


@pytest.mark.skip(reason=_REASON)
def test_decompile_bomb_is_bounded_and_kills_worker() -> None:
    """A pathological function must hit the tool/analysis timeout and kill the worker, not hang."""


@pytest.mark.skip(reason=_REASON)
def test_oversized_binary_rejected_before_worker() -> None:
    """An input above max-binary-bytes is rejected before any byte reaches Ghidra."""


@pytest.mark.skip(reason=_REASON)
def test_zip_or_decompression_bomb_rejected() -> None:
    """Archive/decompression-ratio abuse is rejected by the size/ratio guard."""


@pytest.mark.skip(reason=_REASON)
def test_malformed_loader_input_contained_no_rce() -> None:
    """A malformed/crafted loader input crashes only the contained worker; server stays healthy."""


@pytest.mark.skip(reason=_REASON)
def test_indirect_prompt_injection_via_strings_is_wrapped() -> None:
    """Strings/symbols/comments containing injection payloads return wrapped Untrusted data."""


@pytest.mark.skip(reason=_REASON)
def test_session_id_guessing_and_bola_denied() -> None:
    """Foreign/guessed session ids return SESSION_INVALID without revealing other sessions."""


@pytest.mark.skip(reason=_REASON)
def test_worker_pool_starvation_backpressured() -> None:
    """Exceeding the concurrency cap yields backpressure (LIMIT_EXCEEDED), not exhaustion."""


@pytest.mark.skip(reason=_REASON)
def test_cross_session_project_store_isolation() -> None:
    """One session cannot read another's project store; eviction verified-wipes the store."""
