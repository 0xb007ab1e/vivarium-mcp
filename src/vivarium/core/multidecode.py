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

from collections.abc import Hashable, Sequence


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


def expand_value_feeders[K: Hashable](
    store_value_keys: set[K], link_edges: dict[K, list[K]], *, max_depth: int = 8
) -> set[K]:
    """Expand the STORE-value varnode set backward through COPY/SUBPIECE edges (#401).

    A byte written by a ``STORE`` can be produced one or more links upstream: an 8-bit decode op
    (``add al, k``) often lands in a unique temp that a ``COPY``/``SUBPIECE`` then moves into the
    sub-register that is stored. So the real decode op's **output** may not be the STORE value
    varnode itself but a source of it. ``link_edges`` maps a varnode key to the input keys of the
    ``COPY``/``SUBPIECE`` that produced it; this walks those edges backward from every stored value,
    bounded by ``max_depth``, returning the stored values plus all reachable sources.

    Deterministic + side-effect-free. Keeping this to COPY/SUBPIECE (not arithmetic) preserves the
    address/counter filter: a loop-counter or address ``INT_ADD`` output is never copied into a
    stored byte, so it stays out of the expanded set.

    Args:
        store_value_keys: Varnode identities that are a ``STORE`` value operand.
        link_edges: ``{out_key: [input_key, ...]}`` for each COPY/SUBPIECE op in the function.
        max_depth: Bound on the backward walk (DoS / cycle guard).

    Returns:
        The stored-value keys plus every COPY/SUBPIECE source reachable within ``max_depth``.
    """
    result = set(store_value_keys)
    frontier = list(store_value_keys)
    depth = 0
    while frontier and depth < max_depth:
        nxt: list[K] = []
        for key in frontier:
            for src in link_edges.get(key, ()):
                if src not in result:
                    result.add(src)
                    nxt.append(src)
        frontier = nxt
        depth += 1
    return result


def extract_changed_strings(
    before: bytes, after: bytes, *, min_length: int, max_results: int
) -> list[tuple[int, str]]:
    """Extract printable-ASCII runs in ``after`` that an unpacker PRODUCED (changed vs ``before``).

    Scans ``after`` for maximal runs of printable ASCII (``0x20..0x7E``) of at least ``min_length``,
    keeping only a run whose bytes differ from the same span of ``before`` — so only content the
    unpacker wrote into memory is reported, not plaintext that was already there (ADR-084 D2). The
    before/after change requirement is the honesty gate: a function that produced no new printable
    string yields nothing. Deterministic + side-effect-free.

    Args:
        before: The original (static file) bytes of the window.
        after: The post-emulation bytes of the same window.
        min_length: Minimum run length to report (noise floor; already server-clamped).
        max_results: Hard cap on the number of strings returned.

    Returns:
        ``(offset, text)`` pairs (offset within the window) for each changed printable run, in
        ascending offset order, bounded by ``max_results``. ``text`` is binary-derived and MUST be
        wrapped untrusted by the adapter (ADR-005).
    """
    results: list[tuple[int, str]] = []
    i, n = 0, len(after)
    while i < n and len(results) < max_results:
        if 0x20 <= after[i] <= 0x7E:
            j = i
            while j < n and 0x20 <= after[j] <= 0x7E:
                j += 1
            run = after[i:j]
            if len(run) >= min_length and run != before[i:j]:
                results.append((i, run.decode("latin1")))
            i = j
        else:
            i += 1
    return results


def select_decode_ops[K: Hashable](
    ops: Sequence[tuple[str, K, int]], store_value_keys: set[K]
) -> list[tuple[str, int]]:
    """Filter candidate constant ops down to the real decode stages (ADR-081 / #401).

    Each candidate is ``(op, out_key, const)`` in instruction order, where ``op`` is ``"xor"`` or
    ``"add"``, ``out_key`` identifies the op's **output** varnode, and ``const`` is the constant
    operand. ``store_value_keys`` is the set of varnode identities that are the VALUE written by a
    ``STORE`` in the function.

    - ``xor`` ops are **always** kept: a constant ``INT_XOR`` is rare in ordinary code (``xor
      reg,reg`` zeroing carries no constant), so the permissive rule from the ADR-068 MVP has a low
      false-positive rate.
    - ``add`` ops are kept **only** when the op's output feeds a stored value (``out_key in
      store_value_keys``): a constant ``INT_ADD`` is overwhelmingly address arithmetic (``[base +
      disp]``) or a loop counter (``inc``), so an unfiltered rule would pollute the chain with bogus
      ``add`` keys. Requiring the add to produce a stored byte isolates the genuine decode op.

    Deterministic + side-effect-free. Returns the kept ``(op, const)`` pairs in input order.

    Args:
        ops: Ordered ``(op, out_key, const)`` candidates from the function's p-code walk.
        store_value_keys: Varnode identities that are a ``STORE`` value operand in the function.

    Returns:
        The ordered ``(op, const)`` decode stages (XOR kept always; ADD kept only if value-feeding).
    """
    result: list[tuple[str, int]] = []
    for op, out_key, const in ops:
        if op == "xor" or (op == "add" and out_key in store_value_keys):
            result.append((op, const))
    return result


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
