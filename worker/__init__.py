"""Ghidra worker package — in-container RPC server hosting the JVM bridge (WS2/WS3).

Runs ONLY inside the hardened, network-isolated worker container (ADR-001/003/004). It hosts the
length-prefixed JSON-RPC server loop and dispatches to PyGhidra/headless-Ghidra via the JVM bridge
(:mod:`ghidra_mcp.ghidra._jvm_bridge`). The pure framing/dispatch logic lives in
:mod:`worker.dispatch` (JVM-free) so it is unit-testable with a faked backend — no Ghidra needed.
"""

from __future__ import annotations
