"""Abuse + correctness tests for the RPC frame-read absolute deadline (gap N11).

``RpcGhidraAdapter._recv_exact`` reads a frame one ``recv`` at a time. It previously relied on a
single ``settimeout`` set once by the caller, so each ``recv`` reset its own clock — a hostile/slow
worker dribbling one byte just under that timeout could hold a frame read open indefinitely
(slow-loris, CWE-400 resource exhaustion; the worker is untrusted — TB2). The fix threads an
ABSOLUTE :func:`time.monotonic` deadline through the read so the WHOLE frame is time-bounded.

These are hermetic: a fake socket dribbles bytes and a monkeypatched monotonic clock is advanced
manually (no real sleeps, no network — topic-testing).
"""

from __future__ import annotations

import pytest

from vivarium.ghidra.rpc_client import RpcGhidraAdapter

_MONOTONIC = "vivarium.ghidra.rpc_client.time.monotonic"


class _DribbleSocket:
    """Fake socket handing back one byte per ``recv`` (a slow-loris dribble); records timeouts."""

    def __init__(self, payload: bytes) -> None:
        self._buf = bytearray(payload)
        self.timeouts: list[float] = []

    def settimeout(self, t: float) -> None:
        self.timeouts.append(t)

    def recv(self, _n: int) -> bytes:
        if not self._buf:
            return b""  # peer "closed" / no more bytes
        b = bytes(self._buf[:1])
        del self._buf[:1]
        return b


def test_recv_exact_enforces_absolute_deadline_against_a_dribbling_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A peer dribbling bytes past the deadline is cut off — the read does NOT run unbounded."""
    clock = {"t": 1000.0}
    monkeypatch.setattr(_MONOTONIC, lambda: clock["t"])
    sock = _DribbleSocket(b"ABCDEFGHIJ")  # 10 bytes available, 1 per recv

    # Each recv advances the clock 20ms; the budget is 50ms → the deadline is crossed after 3 recvs,
    # long before all 10 bytes arrive. Without the absolute deadline this would read all 10 (or, for
    # a never-ending dribble, never return).
    real_recv = sock.recv

    def ticking_recv(n: int) -> bytes:
        clock["t"] += 0.02
        return real_recv(n)

    monkeypatch.setattr(sock, "recv", ticking_recv)
    deadline = clock["t"] + 0.05

    with pytest.raises(TimeoutError, match="deadline"):
        RpcGhidraAdapter._recv_exact(sock, 10, deadline)  # type: ignore[arg-type]

    # Bounded: it gave up well before consuming all 10 bytes, and re-armed settimeout to a strictly
    # SHRINKING remaining budget before each recv (proving the deadline is threaded, not reset).
    assert len(sock.timeouts) <= 3
    assert sock.timeouts == sorted(sock.timeouts, reverse=True)
    assert all(t > 0 for t in sock.timeouts)


def test_recv_exact_returns_when_all_bytes_arrive_within_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bytes that all arrive before the deadline are returned in full (no false timeout)."""
    clock = {"t": 0.0}
    monkeypatch.setattr(_MONOTONIC, lambda: clock["t"])  # clock never advances
    sock = _DribbleSocket(b"ABCD")
    out = RpcGhidraAdapter._recv_exact(sock, 4, deadline=10.0)  # type: ignore[arg-type]
    assert out == b"ABCD"


def test_recv_exact_raises_eof_on_early_close(monkeypatch: pytest.MonkeyPatch) -> None:
    """A peer that closes before ``n`` bytes still surfaces EOF (deadline did not mask it)."""
    clock = {"t": 0.0}
    monkeypatch.setattr(_MONOTONIC, lambda: clock["t"])
    sock = _DribbleSocket(b"AB")  # only 2 bytes, then recv() returns b"" (closed)
    with pytest.raises(EOFError):
        RpcGhidraAdapter._recv_exact(sock, 4, deadline=10.0)  # type: ignore[arg-type]
