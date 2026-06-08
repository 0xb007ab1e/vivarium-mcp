"""Integration: server ↔ worker JSON-RPC-over-UDS round trip (WS5 scaffold).

Exercises trust boundary TB2 (``docs/contracts/rpc-protocol.md``): a length-prefixed JSON-RPC 2.0
request over the per-session Unix domain socket, a valid framed response, and the framing-defense
behaviors (oversized declared frame → close socket + kill worker). Marked ``integration``; skipped
without a real worker.

Synthetic fixtures only (master §5). Wave-2 wires the real :class:`RpcGhidraAdapter` (WS2).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_uds_request_response_round_trip(worker_image: str) -> None:
    """A ``ping`` (or ``program_metadata``) RPC round-trips over the per-session UDS.

    Asserts (once wired): the response is a length-prefixed JSON-RPC 2.0 frame with a matching
    ``id``, and the socket lives at the per-session path with ``0600`` perms (no shared socket).
    """
    pytest.skip("WS5 Wave-2: round-trip a framed JSON-RPC call over the per-session UDS (WS2)")


def test_oversized_declared_frame_kills_worker(worker_image: str) -> None:
    """A declared frame length above ``max_response_bytes`` → socket closed and worker killed.

    Framing defense (rpc-protocol §3): the server must not allocate/parse an over-cap frame; it
    closes the socket, kills the worker, and surfaces ``WORKER_UNAVAILABLE`` + eviction (TB2-D/I).
    """
    pytest.skip("WS5 Wave-2: assert oversized-frame → kill+evict against the live worker (WS2)")


def test_worker_crash_mid_call_maps_to_worker_unavailable(worker_image: str) -> None:
    """A worker that closes the socket mid-call yields ``WORKER_UNAVAILABLE`` + eviction."""
    pytest.skip("WS5 Wave-2: kill the worker mid-call and assert worker-unavailable + eviction")
