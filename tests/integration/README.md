# Integration tests (WS5)

Tests that require a **real Ghidra worker container** (mark `@pytest.mark.integration`). They are
NOT run in the unit/coverage CI job (no network / no image pulls there); they run in a dedicated
integration job once the worker image is built and pinned by digest.

Cover: session import/analyze over the real chain (`test_session_lifecycle.py` — a full server ↔
worker round-trip), each Tier-1 tool against synthetic binaries, timeout→worker-kill, and verified
store wipe on eviction.

> **RPC framing / fault paths** (length-prefixed round-trip, oversized-declared-frame → kill,
> worker-crash-mid-call → `worker-unavailable` + kill) are exercised at the **unit** level against a
> real `socketpair` + a fake worker handle in `tests/unit/test_rpc_adapter.py` (plus the framing
> property test), so the adapter logic is fully covered without a container. A dedicated
> live-container round-trip file was retired (gap round-3 P8) — it only ever `pytest.skip`-ped
> (coverage theater); a container adds isolation coverage (drilled separately in
> `.github/workflows/gvisor-isolation.yml`), not framing logic.

**Fixtures: benign/synthetic binaries only — never real malware (master §5, PLAN §6).**
