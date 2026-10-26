"""In-memory, per-session report store (ADR-078 Tier-0 retention, TB10).

ADR-078 says Tier-0 is "written to the ADR-002 ephemeral session store (wipe-on-evict)". In
production there is **no server-side on-disk session store** (``store_root=None``; the only on-disk
store is the worker's in-container tmpfs, off-limits to the output edge). This module realizes that
ephemeral / wipe-on-evict guarantee the same way ADR-040 holds streaming jobs: **in memory, keyed by
session, discarded on session evict** via the manager's evict callback. No binary-derived content
outlives the session, and nothing touches disk.

The store holds already-composed, (C)-projected, CSP-wrapped reports. It performs no authorization
itself — a report is only ever put/fetched after the tool handler has run the BOLA-safe
``sessions.authorize`` (ADR-017) for the caller; the ``session_id`` partition is the isolation key.
"""

from __future__ import annotations

import secrets
import threading
import time

from pydantic import BaseModel, ConfigDict, Field

from vivarium.tools.schemas import AtlasData, FindingRecord, ReportManifest

__all__ = ["ReportStore", "StoredReport"]

_REPORT_ID_BYTES = 16  # CSPRNG report-handle entropy (opaque, unguessable)
_MAX_REPORTS_PER_SESSION = 32  # ring-buffer COUNT cap per session (bounded memory — CWE-400)
# A per-session BYTE budget on top of the count cap: a Tier-1 atlas report is far larger than a
# Tier-0 one (up to 2k nodes + 8k edges + 2k functions + the rendered HTML blob), so a fixed count
# of 32 is a large byte multiplier. Bound the actual retained bytes too (CWE-400; reviewer Low).
_MAX_REPORT_BYTES_PER_SESSION = 32 * 1024 * 1024  # 32 MiB of retained reports per session
# Rough per-row byte estimates for the structured (non-HTML) retained state.
_EST_FINDING_BYTES = 256
_EST_NODE_BYTES = 96
_EST_EDGE_BYTES = 48
_EST_FUNCTION_BYTES = 96


def _estimate_bytes(
    html: str | None, findings: list[FindingRecord], atlas: AtlasData | None
) -> int:
    """Approximate the retained byte footprint of a report (HTML blob + structured state)."""
    total = len(html or "")
    total += len(findings) * _EST_FINDING_BYTES
    if atlas is not None:
        total += len(atlas.nodes) * _EST_NODE_BYTES
        total += len(atlas.edges) * _EST_EDGE_BYTES
        total += len(atlas.functions) * _EST_FUNCTION_BYTES
    return total


class StoredReport(BaseModel):
    """One retained report (in-memory, session-scoped) — ADR-078 Tier-0.

    Attributes:
        report_id: Opaque CSPRNG handle.
        manifest: The provenance manifest.
        findings: The composed, (C)-projected finding records.
        atlas: The whole-program atlas (ADR-078 Tier-1), or ``None`` (Tier-0 report).
        html: The self-contained CSP-wrapped HTML artifact, or ``None`` if not rendered.
        created_monotonic: Creation time (monotonic) — for ordering/eviction.
        approx_bytes: Estimated retained byte footprint — drives the per-session byte budget.
    """

    model_config = ConfigDict(frozen=True)

    report_id: str
    manifest: ReportManifest
    findings: list[FindingRecord] = Field(default_factory=list)
    atlas: AtlasData | None = None
    html: str | None = None
    created_monotonic: float
    approx_bytes: int = Field(default=0, ge=0)


class ReportStore:
    """Owns generated reports across sessions, in memory, discarded on evict (ADR-078 Tier-0).

    Thread-safety: a single :class:`threading.RLock` serializes the in-memory table mutations; every
    operation is fast and performs no I/O. Mirrors the ADR-040 streaming-job retention model.
    """

    def __init__(
        self,
        *,
        max_per_session: int = _MAX_REPORTS_PER_SESSION,
        max_bytes_per_session: int = _MAX_REPORT_BYTES_PER_SESSION,
        clock: object = time.monotonic,
    ) -> None:
        """Initialize an empty store.

        Args:
            max_per_session: Ring-buffer COUNT cap per session; when exceeded the oldest report for
                that session is dropped (reports are regenerable). Bounds memory (CWE-400).
            max_bytes_per_session: BYTE budget per session; the oldest reports are dropped until the
                session's retained bytes fit (a Tier-1 atlas report is far larger than Tier-0).
            clock: Injected monotonic clock (deterministic ordering in tests).
        """
        self._max_per_session = max_per_session
        self._max_bytes_per_session = max_bytes_per_session
        self._clock = clock  # callable[[], float]
        self._by_session: dict[str, list[StoredReport]] = {}
        self._lock = threading.RLock()

    def put(
        self,
        session_id: str,
        *,
        manifest: ReportManifest,
        findings: list[FindingRecord],
        html: str | None,
        atlas: AtlasData | None = None,
    ) -> StoredReport:
        """Store a freshly composed report for an (already-authorized) session; return it.

        Args:
            session_id: The owning session (authorized by the caller BEFORE this call).
            manifest: The report's provenance manifest.
            findings: The composed finding records.
            html: The rendered HTML artifact, or ``None``.
            atlas: The whole-program atlas (ADR-078 Tier-1), or ``None``.

        Returns:
            The :class:`StoredReport` (its ``report_id`` is the opaque handle).
        """
        now = self._clock() if callable(self._clock) else time.monotonic()
        report = StoredReport(
            report_id=secrets.token_urlsafe(_REPORT_ID_BYTES),
            manifest=manifest,
            findings=findings,
            atlas=atlas,
            html=html,
            created_monotonic=now,
            approx_bytes=_estimate_bytes(html, findings, atlas),
        )
        with self._lock:
            bucket = self._by_session.setdefault(session_id, [])
            bucket.append(report)
            # Drop the oldest while the session exceeds EITHER the count cap OR the byte budget,
            # always keeping the just-added report (bounded memory — CWE-400).
            while len(bucket) > 1 and (
                len(bucket) > self._max_per_session
                or sum(r.approx_bytes for r in bucket) > self._max_bytes_per_session
            ):
                del bucket[0]
        return report

    def get(self, session_id: str, report_id: str) -> StoredReport | None:
        """Return a retained report for the session, or ``None`` if absent/evicted.

        The ``session_id`` partition is the isolation key — a ``report_id`` from another session is
        simply not found here (the caller has already been owner-authorized for ``session_id``).
        """
        with self._lock:
            for report in self._by_session.get(session_id, ()):
                if secrets.compare_digest(report.report_id, report_id):
                    return report
        return None

    def count(self, session_id: str) -> int:
        """Return the number of reports currently retained for a session."""
        with self._lock:
            return len(self._by_session.get(session_id, ()))

    def discard_session(self, session_id: str) -> None:
        """Drop all reports for a session — the evict hook (ADR-002 wipe-on-evict).

        Wired via the session manager's evict callback so a session's reports never outlive it
        (TTL/idle/close/poison/timeout). Idempotent.
        """
        with self._lock:
            self._by_session.pop(session_id, None)
