"""Handler-level tests for ADR-078 Tier-0 ``session_generate_report`` (registry integration).

Exercises ``_handle_session_generate_report`` end-to-end over purpose-built fakes (no worker/JVM):
owner-scope (TB10 #7), retention in the in-memory store, the include_html toggle, and the
store-not-wired fail-closed guard.
"""

from __future__ import annotations

from typing import cast

import pytest

from vivarium.config import Config
from vivarium.core.envelope import DataOrigin, Untrusted, wrap
from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.ghidra.port import GhidraPort
from vivarium.report.store import ReportStore
from vivarium.security.limits import Limits
from vivarium.sessions.manager import SessionManager
from vivarium.tools import registry as reg
from vivarium.tools import schemas as s


class _Info:
    binary_sha256 = "e" * 64
    binary_size = 123


class FakeSessions:
    def authorize(self, sid: str, *, caller: str) -> _Info:
        if sid == "foreign":
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.SESSION_INVALID,
                    title="Invalid session",
                    detail="unknown or not owned by caller",
                    status=404,
                )
            )
        return _Info()

    def export_targets(self, sid: str, caller: str) -> tuple[list[object], list[object]]:
        return ([], [])

    def binary_name(self, sid: str, *, caller: str) -> str | None:
        return None


class FakePort:
    def __init__(self, entries: list[object]) -> None:
        self._entries = entries

    def export_annotations(
        self, sid: str, a: s.SessionExportAnnotationsIn, *, targets: s.ExportTargets
    ) -> s.SessionExportAnnotationsOut:
        doc = s.ExportedAnnotationDocument(
            schema_version=1,
            binary=s.ExportedBinaryRef(sha256="0" * 64),  # overlaid by the export handler
            entries=self._entries,
        )
        return s.SessionExportAnnotationsOut(document=doc)


def _config() -> Config:
    return Config(
        log_level="INFO",
        log_format="json",
        session_ttl_s=3600,
        session_idle_s=900,
        limits=Limits(),
        worker_image="x",
        worker_runtime="runsc",
        worker_uid=65532,
        worker_gid=65532,
        rpc_socket_dir="/run/x",
        import_root="/work/imports",
    )


def _entries() -> list[object]:
    return [
        s.ExportedRenameFunctionEntry(
            kind="rename_function",
            function="0x401000",
            new_name=wrap("decrypt", origin=DataOrigin.BINARY),
        ),
        s.ExportedRenameSymbolEntry(
            kind="rename_symbol",
            identifier="0x401100",
            new_name=wrap("g_key", origin=DataOrigin.BINARY),
        ),
    ]


def _ctx(entries: list[object], *, store: ReportStore | None) -> reg.ToolContext:
    return reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, FakeSessions()),
        port=cast(GhidraPort, FakePort(entries)),
        report_store=store,
    )


def test_happy_path_returns_findings_html_and_retains() -> None:
    store = ReportStore()
    ctx = _ctx(_entries(), store=store)
    out = reg._handle_session_generate_report(ctx, s.SessionGenerateReportIn(session_id="s1"))
    assert out.report_id
    assert out.manifest.program_sha256 == "e" * 64  # overlaid authoritative hash
    assert out.manifest.finding_count == 2
    assert len(out.findings) == 2
    assert isinstance(out.html, Untrusted)
    assert out.html.encoding == "html"
    assert "<script" not in out.html.value.lower()
    assert store.count("s1") == 1


def test_include_html_false_omits_artifact() -> None:
    store = ReportStore()
    ctx = _ctx(_entries(), store=store)
    out = reg._handle_session_generate_report(
        ctx, s.SessionGenerateReportIn(session_id="s1", include_html=False)
    )
    assert out.html is None
    assert len(out.findings) == 2
    assert store.count("s1") == 1


def test_scope_filters_through_handler() -> None:
    ctx = _ctx(_entries(), store=ReportStore())
    out = reg._handle_session_generate_report(
        ctx, s.SessionGenerateReportIn(session_id="s1", scope=["0x401100"])
    )
    assert [f.subject.value for f in out.findings] == ["0x401100"]


def test_foreign_session_is_session_invalid_no_oracle() -> None:
    # TB10 #7: a foreign/unknown session id yields SESSION_INVALID (BOLA-safe, no oracle).
    ctx = _ctx(_entries(), store=ReportStore())
    with pytest.raises(GhidraMcpError) as ei:
        reg._handle_session_generate_report(ctx, s.SessionGenerateReportIn(session_id="foreign"))
    assert ei.value.envelope.type is ErrorType.SESSION_INVALID


def test_store_not_wired_fails_closed() -> None:
    ctx = _ctx(_entries(), store=None)
    with pytest.raises(GhidraMcpError) as ei:
        reg._handle_session_generate_report(ctx, s.SessionGenerateReportIn(session_id="s1"))
    assert ei.value.envelope.type is ErrorType.INTERNAL
