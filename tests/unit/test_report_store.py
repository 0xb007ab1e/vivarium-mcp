"""Unit tests for ADR-078 Tier-0 in-memory report store (``vivarium.report.store``)."""

from __future__ import annotations

from vivarium.report.store import ReportStore
from vivarium.tools import schemas as s


def _manifest() -> s.ReportManifest:
    return s.ReportManifest(
        program_sha256="c" * 64, session_id="sess-1", tool_revision="tier0.1", finding_count=0
    )


def _put(store: ReportStore, session: str = "sess-1", html: str | None = "<html></html>") -> str:
    return store.put(session, manifest=_manifest(), findings=[], html=html).report_id


def test_put_then_get_roundtrip() -> None:
    store = ReportStore()
    rid = _put(store)
    got = store.get("sess-1", rid)
    assert got is not None
    assert got.report_id == rid
    assert got.html == "<html></html>"
    assert store.count("sess-1") == 1


def test_get_unknown_id_returns_none() -> None:
    store = ReportStore()
    _put(store)
    assert store.get("sess-1", "nope") is None


def test_get_is_session_partitioned() -> None:
    store = ReportStore()
    rid = _put(store, session="sess-1")
    # A report id is only found under its own session partition (owner isolation key).
    assert store.get("sess-2", rid) is None


def test_discard_session_wipes_reports() -> None:
    store = ReportStore()
    _put(store, session="sess-1")
    _put(store, session="sess-2")
    store.discard_session("sess-1")
    assert store.count("sess-1") == 0
    assert store.count("sess-2") == 1


def test_discard_session_is_idempotent() -> None:
    store = ReportStore()
    store.discard_session("never-existed")  # no raise
    assert store.count("never-existed") == 0


def test_ring_buffer_drops_oldest_beyond_cap() -> None:
    store = ReportStore(max_per_session=2)
    r1 = _put(store)
    r2 = _put(store)
    r3 = _put(store)
    assert store.count("sess-1") == 2
    assert store.get("sess-1", r1) is None  # oldest dropped
    assert store.get("sess-1", r2) is not None
    assert store.get("sess-1", r3) is not None


def test_report_ids_are_unique() -> None:
    store = ReportStore()
    ids = {_put(store) for _ in range(20)}
    assert len(ids) == 20


def test_byte_budget_evicts_oldest_beyond_budget() -> None:
    # Budget fits ~2 reports of ~100-byte html; a 3rd drops the oldest (reviewer Low).
    store = ReportStore(max_bytes_per_session=250)
    big = "x" * 100
    r1 = _put(store, html=big)
    r2 = _put(store, html=big)
    r3 = _put(store, html=big)
    assert store.get("sess-1", r1) is None  # oldest dropped to fit the byte budget
    assert store.get("sess-1", r2) is not None
    assert store.get("sess-1", r3) is not None


def test_byte_budget_keeps_at_least_the_newest() -> None:
    # Even a single report larger than the whole budget is retained (keep >=1).
    store = ReportStore(max_bytes_per_session=10)
    rid = _put(store, html="x" * 1000)
    assert store.get("sess-1", rid) is not None
    assert store.count("sess-1") == 1
