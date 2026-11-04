"""Pure (JVM-free) buffer selection + stage-chain assembly for multi-stage decode (ADR-081).

Part of the functional core (ADR-001). ADR-068's single-pass ``xor_decode`` emulates the whole
decoder function (the ADR-049 sandbox) and reads back **one** buffer (``min(write_targets)``). A
chained / multi-stage *local* decoder writes an intermediate buffer first and the final plaintext
into a **different** buffer, so the single buffer read is the wrong one and recovery fails closed.

The emulator already runs every local stage; ADR-081 only widens **readback**: read every distinct
write buffer (bounded by ``max_stages``) and pick the one whose decoded window became printable.
This module holds that selection + the ordered decode-stage-chain assembly: deterministic,
side-effect-free, hermetically testable. Recovered text/keys are binary-derived and MUST be wrapped
untrusted by the adapter (ADR-005); nothing here trusts or interprets the bytes.
"""

from __future__ import annotations


def leading_printable_run(data: bytes) -> bytes:
    """Return the leading run of printable ASCII bytes, stopping at the first non-printable byte.

    Printable is ``0x20..0x7E`` (NUL and any other control byte terminate the run). Deterministic +
    side-effect-free. An empty input (or a non-printable first byte) yields ``b""``.

    Args:
        data: The decoded buffer window (already length-bounded by ``max_bytes``).

    Returns:
        The maximal printable prefix of ``data``.
    """
    run = bytearray()
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            run.append(byte)
        else:
            break
    return bytes(run)


def best_decoded_run(
    buffers: list[tuple[int, bytes, bytes]], *, min_length: int
) -> tuple[int, bytes] | None:
    """Pick the write buffer whose decode produced the best recovered plaintext run (ADR-081 D1).

    Over every candidate buffer, take the leading printable run of its *after* (decoded) bytes and
    keep it only when it (a) meets ``min_length`` and (b) **changed** versus the buffer's *before*
    bytes — the ADR-068 D3 honesty gate: a non-decoder or an intermediate/garbage stage yields no
    qualifying run and is reported not-recovered, never guessed. Among qualifying buffers the
    longest run wins; ties break on the lowest base address (deterministic).

    Args:
        buffers: One ``(base_address, before_bytes, after_bytes)`` per distinct write-target buffer
            read back after the bounded whole-function emulation. Already bounded in count
            (``max_stages``) and per-window length (``max_bytes``) by the caller.
        min_length: Minimum recovered-run length to accept (noise floor; already server-clamped).

    Returns:
        ``(base_address, printable_run)`` for the best qualifying buffer, else ``None``.
    """
    best: tuple[int, bytes] | None = None
    for base, before, after in buffers:
        run = leading_printable_run(after)
        if len(run) < min_length:
            continue
        # Only a run the decode actually PRODUCED — reject bytes that were already plaintext.
        if run == before[: len(run)]:
            continue
        if best is None or len(run) > len(best[1]) or (len(run) == len(best[1]) and base < best[0]):
            best = (base, run)
    return best


def assemble_stage_chain(
    ops: list[tuple[str, int]], *, max_stages: int
) -> tuple[list[dict[str, str]], bool]:
    """Assemble the ordered decode-stage chain from detected constant decode ops (ADR-081 D2).

    Each input op is ``(operation, key)`` in instruction order, where ``operation`` is ``"xor"`` or
    ``"add"`` and ``key`` is the constant operand. The chain is capped at ``max_stages`` (DoS bound,
    ADR-081 D3); each key is normalised to a single byte and rendered as ``0xNN`` hex. The returned
    keys are binary-derived and MUST be wrapped untrusted by the adapter (ADR-005).

    Args:
        ops: Ordered ``(operation, key)`` pairs detected in the decoder function.
        max_stages: Hard cap on the number of stages reported (server-clamped ``[1, 64]``).

    Returns:
        ``(stages, truncated)`` — ``stages`` is the capped list of ``{"op", "key"}`` dicts in order;
        ``truncated`` is True when the cap clipped the chain.
    """
    truncated = len(ops) > max_stages
    stages: list[dict[str, str]] = [
        {"op": op, "key": hex(key & 0xFF)} for op, key in ops[:max_stages]
    ]
    return stages, truncated
