"""Property/fuzz tests for the IOC + crypto-constant scanners (gap N14; TB3).

:mod:`vivarium.core.iocscan` runs regexes over **extracted strings**, which are binary-derived and
therefore UNTRUSTED (hostile origin — master §5). The patterns are deliberately written with
BOUNDED quantifiers to be ReDoS-safe, but that claim was untested. These generated-input properties
complement the example-based ``test_iocscan.py``:

- **Total / never-crash:** ``scan_iocs`` over arbitrary text returns a ``list[IocHit]`` and never
  raises (the scanner is heuristic — bad input is data, not an error).
- **Closed-vocabulary + dedup + ordering + bounds:** every hit's category is from the frozen
  vocabulary, no duplicate ``(category, value)`` survives, output is sorted by the documented key,
  and every value fits the scan window.
- **Determinism:** same input → identical output (pure function).
- **ReDoS resistance:** crafted catastrophic-backtracking inputs complete near-instantly (a linear
  matcher finishes in microseconds; an exponential one would take minutes — a generous wall-clock
  bound separates the two without being flaky on shared runners).
- ``scan_crypto_constants`` (pure shaping) holds the same dedup / ordering / provenance invariants.

Hermetic + deterministic (``derandomize``); no worker, no I/O.
"""

from __future__ import annotations

import time

import pytest

hypothesis = pytest.importorskip("hypothesis")  # skip cleanly if the property-test extra is absent
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from vivarium.core.iocscan import (  # noqa: E402
    CRYPTO_SIGNATURES,
    IOC_CATEGORIES,
    MAX_SCAN_LEN,
    CryptoSignature,
    scan_crypto_constants,
    scan_iocs,
)

#: Deterministic + CI-safe: bounded examples, no per-example deadline (wall-clock deadlines flake on
#: shared runners — the ReDoS bound below is a separate, generous wall-clock check), fixed sequence.
_PROFILE = settings(max_examples=200, deadline=None, derandomize=True)

#: Characters the IOC regexes key on, so generated text actually exercises matches (not just noise).
_IOC_ALPHABET = "0123456789abcdefABCDEF.:/@\\-_= \r\n\tHKLMUCRcomnetorg"

#: A scanned string value: a mix of focused (match-triggering) text and fully arbitrary unicode.
_ioc_value: st.SearchStrategy[str] = st.one_of(
    st.text(alphabet=_IOC_ALPHABET, max_size=400),
    st.text(max_size=200),
)

#: ``(source_address | None, value)`` rows, the shape ``scan_iocs`` consumes.
_ioc_rows: st.SearchStrategy[list[tuple[str | None, str]]] = st.lists(
    st.tuples(st.one_of(st.none(), st.just("0x401000"), st.just("0x10")), _ioc_value),
    max_size=20,
)


@_PROFILE
@given(rows=_ioc_rows)
def test_scan_iocs_invariants(rows: list[tuple[str | None, str]]) -> None:
    """scan_iocs is total, closed-vocabulary, deduped, sorted, bounded, and deterministic."""
    hits = scan_iocs(rows)
    categories = set(IOC_CATEGORIES)
    seen: set[tuple[str, str]] = set()
    for h in hits:
        assert h.category in categories  # closed vocabulary (safe label)
        assert h.value and len(h.value) <= MAX_SCAN_LEN  # non-empty, within the scan window
        key = (h.category, h.value)
        assert key not in seen  # de-duplicated
        seen.add(key)
    order = [(IOC_CATEGORIES.index(h.category), h.source_address or "", h.value) for h in hits]
    assert order == sorted(order)  # ordered by the documented key
    assert scan_iocs(rows) == hits  # deterministic / pure


@_PROFILE
@given(text=st.text(max_size=500))
def test_scan_iocs_total_over_arbitrary_text(text: str) -> None:
    """Over ANY unicode text the scanner returns a list and never raises (bad input is data)."""
    hits = scan_iocs([("0x1000", text)])
    assert isinstance(hits, list)
    assert all(h.category in set(IOC_CATEGORIES) for h in hits)


# Crafted inputs aimed at catastrophic backtracking for each pattern class. Each is >MAX_SCAN_LEN so
# the full scan window is exercised; bounded quantifiers should keep every match LINEAR.
_REDOS_INPUTS = [
    "a" * 5000,
    "0" * 5000,
    "1." * 3000,  # ipv4 / domain dotted runs with no valid terminator
    ":" * 5000,  # ipv6 colon run
    "ff" * 3000,  # hex-hash near-miss run
    "a@" * 3000,  # email near-miss run
    "http://" + "a" * 5000,  # url with a huge tail
    "x." * 3000 + "com",  # domain with a deep label chain
    "255." * 2000,  # ipv4 near-miss
    "\\\\" + "a" * 5000,  # unc path
    "HKLM\\" + "x" * 5000,  # registry key
    "C:\\" + "a\\" * 2000,  # windows path segment run
]


@pytest.mark.parametrize("evil", _REDOS_INPUTS)
def test_scan_iocs_no_catastrophic_backtracking(evil: str) -> None:
    """A pathological input completes well under a generous bound (no exponential backtracking)."""
    start = time.perf_counter()
    hits = scan_iocs([("0x1000", evil)])
    elapsed = time.perf_counter() - start
    # Linear regexes finish in microseconds on 4 KiB; an exponential blowup would take minutes. The
    # 2 s ceiling is enormous relative to that gap, so it flags ReDoS without flaking on slow CI.
    assert elapsed < 2.0, f"scan took {elapsed:.3f}s — possible catastrophic backtracking"
    assert all(h.category in set(IOC_CATEGORIES) for h in hits)


_crypto_rows: st.SearchStrategy[list[tuple[CryptoSignature, list[str]]]] = st.lists(
    st.tuples(
        st.sampled_from(CRYPTO_SIGNATURES),
        st.lists(st.from_regex(r"0x[0-9a-f]{1,8}", fullmatch=True), max_size=6),
    ),
    max_size=10,
)


@_PROFILE
@given(rows=_crypto_rows)
def test_scan_crypto_constants_invariants(
    rows: list[tuple[CryptoSignature, list[str]]],
) -> None:
    """scan_crypto_constants dedups, orders by (algorithm, kind, address), preserves provenance."""
    hits = scan_crypto_constants(rows)
    valid = {(sig.algorithm, sig.kind) for sig, _ in rows}
    seen: set[tuple[str, str, str]] = set()
    for h in hits:
        assert (h.algorithm, h.kind) in valid  # provenance: came from an input signature
        key = (h.algorithm, h.kind, h.address)
        assert key not in seen  # de-duplicated
        seen.add(key)
    order = [(h.algorithm, h.kind, h.address) for h in hits]
    assert order == sorted(order)  # ordered by the documented key
    assert scan_crypto_constants(rows) == hits  # deterministic / pure
