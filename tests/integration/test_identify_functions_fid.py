"""Real-worker end-to-end test for ``identify_functions`` FID library matching (ADR-042 Phase 1).

Placeholder pending a fixture. Verifying a true FID match needs a binary whose functions are
present in a shipped Ghidra FunctionID database — in practice a **benign, statically-linked MSVC
PE** (the standard Ghidra FID DBs cover MSVC runtime/library functions). Our current fixtures are
all ELF, which the MSVC FID DBs do not match, so a hermetic real-match assertion is not yet
possible. This file is intentionally skipped until that fixture exists (ADR-042 Phase 1 follow-up).

TODO(ADR-042 Phase 1 follow-up): add a benign static-MSVC PE fixture (built deterministically, no
real malware — master §5 / project rule) and assert that ``identify_functions`` returns at least one
match with a non-empty ``matched_name``/``library`` and a score at/above the FID default threshold,
that every match's ``matched_name``/``library`` is ``Untrusted``-wrapped, and that ``limit`` bounds
the result with an honest ``truncated`` flag.
"""

from __future__ import annotations

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skip(reason="needs a benign static-MSVC PE fixture (ADR-042 Phase 1 follow-up)"),
]


def test_identify_functions_matches_static_msvc_pe() -> None:
    """Placeholder: a static-MSVC PE should yield FID library matches (skipped — no fixture yet)."""
    raise AssertionError("unreachable — skipped pending a static-MSVC PE fixture")
