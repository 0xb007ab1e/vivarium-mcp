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
    def __init__(self, entries: list[s.ExportedEntry]) -> None:
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

    # --- Tier-1 atlas sources (reused read-only tools) ---
    def program_summary(self, sid: str, a: s.ProgramSummaryIn) -> s.ProgramSummary:
        return s.ProgramSummary(
            metadata=s.ProgramMetadata(
                sha256="e" * 64,
                size_bytes=1024,
                format="ELF",
                architecture="x86:LE:64:default",
                endianness="little",
                compiler=None,
                entry_point="0x401000",
                function_count=1,
                analysis_complete=True,
            ),
            function_count=1,
            import_count=0,
            export_count=0,
            string_count=0,
            call_graph_metrics=s.CallGraphMetricsOut(
                function_count=1,
                edge_count=1,
                leaf_count=0,
                root_count=1,
                recursive_component_count=0,
                self_recursive_count=0,
                unresolved_caller_count=0,
                top_fan_in=[
                    s.FanRanking(
                        address="0x401000",
                        name=wrap("decrypt", origin=DataOrigin.BINARY),
                        count=2,
                    )
                ],
                top_fan_out=[],
            ),
        )

    def xrefs_to(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        # Synthetic references into the requested target — all server-safe scalars.
        return s.XrefsOut(
            xrefs=[
                s.Xref(from_address="0x401200", to_address=a.target, ref_type="CALL"),
                s.Xref(from_address="0x401300", to_address=a.target, ref_type="CONDITIONAL_CALL"),
            ],
            total=2,
            truncated=False,
        )

    def call_graph(self, sid: str, a: s.CallGraphIn) -> s.CallGraphOut:
        return s.CallGraphOut(
            nodes=[
                s.CallGraphNode(
                    address="0x401000",
                    name=wrap("<img src=x onerror=alert(1)>", origin=DataOrigin.BINARY),
                    is_external=False,
                    has_unresolved_calls=False,
                )
            ],
            edges=[s.CallEdge(from_address="0x401000", to_address="0x401100")],
            unresolved_callers=[],
            truncated=False,
        )

    def list_functions(self, sid: str, a: s.ListFunctionsIn) -> s.FunctionListOut:
        return s.FunctionListOut(
            functions=[
                s.FunctionSummary(
                    address="0x401000", name=wrap("decrypt", origin=DataOrigin.BINARY), size=16
                )
            ],
            total=1,
            truncated=False,
        )


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


def _entries() -> list[s.ExportedEntry]:
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


def _ctx(entries: list[s.ExportedEntry], *, store: ReportStore | None) -> reg.ToolContext:
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


def test_atlas_mode_composes_whole_program_atlas() -> None:
    store = ReportStore()
    ctx = _ctx(_entries(), store=store)
    out = reg._handle_session_generate_report(
        ctx, s.SessionGenerateReportIn(session_id="s1", atlas=True)
    )
    assert out.atlas is not None
    assert out.atlas.summary.program_sha256 == "e" * 64
    assert set(out.manifest.generated_from) >= {
        "program_summary",
        "call_graph",
        "list_functions",
        "xrefs_to",
    }
    # the hostile call-graph node name is projected inert in the atlas + the rendered HTML
    assert "<img" not in out.atlas.nodes[0].name.value
    assert out.html is not None
    assert "<img" not in out.html.value.lower()
    # xref drill-down populated from the top-fan-in target (server-safe scalars)
    assert len(out.atlas.xrefs) == 2
    assert out.atlas.xrefs[0].to_address == "0x401000"
    assert out.atlas.xrefs[0].ref_type == "CALL"
    # nothing was dropped (1 target, page not capped) → honest complete view
    assert out.atlas.truncated is False
    assert store.get("s1", out.report_id) is not None


class _PerTargetTruncPort(FakePort):
    """A hot target whose referrers exceed the per-target page (``xrefs_to.truncated=True``)."""

    def xrefs_to(self, sid: str, a: s.XrefsIn) -> s.XrefsOut:
        return s.XrefsOut(
            xrefs=[s.Xref(from_address="0x401200", to_address=a.target, ref_type="CALL")],
            total=999,
            truncated=True,
        )


class _ManyTargetsPort(FakePort):
    """More ranked functions than ``_MAX_ATLAS_XREF_TARGETS`` → the drill-down probes only some."""

    def program_summary(self, sid: str, a: s.ProgramSummaryIn) -> s.ProgramSummary:
        base = super().program_summary(sid, a)
        metrics = base.call_graph_metrics
        assert metrics is not None
        many = [
            s.FanRanking(
                address=f"0x{0x401000 + i:x}",
                name=wrap("f", origin=DataOrigin.BINARY),
                count=1,
            )
            for i in range(s._MAX_ATLAS_XREF_TARGETS + 3)
        ]
        return base.model_copy(
            update={"call_graph_metrics": metrics.model_copy(update={"top_fan_in": many})}
        )


def _ctx_port(port: FakePort, *, store: ReportStore) -> reg.ToolContext:
    return reg.ToolContext(
        config=_config(),
        sessions=cast(SessionManager, FakeSessions()),
        port=cast(GhidraPort, port),
        report_store=store,
    )


def test_atlas_xref_per_target_overflow_flags_truncated() -> None:
    # Finding 1: a target with more referrers than its page must set atlas.truncated (honest view).
    ctx = _ctx_port(_PerTargetTruncPort(_entries()), store=ReportStore())
    out = reg._handle_session_generate_report(
        ctx, s.SessionGenerateReportIn(session_id="s1", atlas=True)
    )
    assert out.atlas is not None
    assert out.atlas.truncated is True


def test_atlas_xref_target_count_overflow_flags_truncated() -> None:
    # Finding 1: more ranked functions than _MAX_ATLAS_XREF_TARGETS → truncated (only some probed).
    ctx = _ctx_port(_ManyTargetsPort(_entries()), store=ReportStore())
    out = reg._handle_session_generate_report(
        ctx, s.SessionGenerateReportIn(session_id="s1", atlas=True)
    )
    assert out.atlas is not None
    assert out.atlas.truncated is True


def test_atlas_off_by_default() -> None:
    ctx = _ctx(_entries(), store=ReportStore())
    out = reg._handle_session_generate_report(ctx, s.SessionGenerateReportIn(session_id="s1"))
    assert out.atlas is None
    assert "program_summary" not in out.manifest.generated_from


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
