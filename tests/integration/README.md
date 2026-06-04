# Integration tests (WS5)

Tests that require a **real Ghidra worker container** (mark `@pytest.mark.integration`). They are
NOT run in the unit/coverage CI job (no network / no image pulls there); they run in a dedicated
integration job once the worker image is built and pinned by digest.

Cover: the RPC adapter round-trip (server ↔ worker), session import/analyze, each Tier-1 tool
against synthetic binaries, timeout→worker-kill, and verified store wipe on eviction.

**Fixtures: benign/synthetic binaries only — never real malware (master §5, PLAN §6).**
