# `ghidra_scripts/` — headless Ghidra / PyGhidra scripts (worker-only)

Scripts here run **only inside the worker container** (ADR-001/003) and are invoked by the JVM
bridge (`src/vivarium/ghidra/_jvm_bridge.py`). They are the sole code permitted to touch the JVM
and the hostile binary.

**v1 status:** empty. The v1 read-only Tier-1 catalog is served via the PyGhidra Python API
directly from `PyGhidraBackend` (in `_jvm_bridge.py`), so no standalone `*.java` /
`ghidra_scripts/*.py` headless scripts are required yet. This directory is the agreed location for
any such script a future operation needs (e.g. a complex analyzer pass), kept separate so the
JVM-touching surface stays auditable and worker-confined.

Anything added here MUST:

- run only in the worker (never importable by the server — ADR-001);
- treat the analyzed binary and all derived bytes as **hostile, untrusted** input;
- return **size-capped**, structured results (the server wraps them in the untrusted-data
  envelope — ADR-005); never emit a host path, stack trace, or unbounded payload.
