"""Unit tests for annotation export/import handlers (ADR-018; TB8) — critical-path gate (100%).

These drive the two new registry handlers through the synthesized flat-kwargs callables
(``build_handlers``) with local fakes for the session manager + :class:`GhidraPort` (no JVM, no
real worker — ADR-001). The IMPORT handler is the new trust boundary; the tests prove, in order,
that each security gate HOLDS and that import is a replay of the EXISTING gated writes (no new
write primitive):

- **export** is read-only (no consent), owner-scoped, and the server overlays the authoritative
  binary hash onto the document binding;
- **import** schema-validates → verifies the binary-hash binding → consent-gates (+ allow_structural
  for structural entries) → re-validates + replays each entry via the EXISTING write handlers →
  returns a per-entry outcome report; the server persists nothing;
- a **wrong-binary hash** fails closed before any write;
- a **structural entry without allow_structural** is denied;
- an **import without write consent** is denied with NO write;
- a **cross-owner** export/import is BOLA-safe ``SESSION_INVALID``;
- a **tampered/injection-bearing entry** is rejected (per-entry) while clean entries still apply.
"""

from __future__ import annotations

from typing import cast

import pytest

from ghidra_mcp.config import Config
from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from ghidra_mcp.ghidra.port import GhidraPort
from ghidra_mcp.security.limits import Limits
from ghidra_mcp.server.auth import Principal
from ghidra_mcp.sessions.manager import SessionManager
from ghidra_mcp.tools import registry as reg
from ghidra_mcp.tools import schemas as s

_SID = "sid1"
_OWNER = "local"
_SHA = "a" * 64
_WRONG_SHA = "b" * 64


def _u(text: str, origin: DataOrigin = DataOrigin.BINARY) -> Untrusted[str]:
    return Untrusted(value=text, origin=origin)


def _session_invalid() -> GhidraMcpError:
    return GhidraMcpError(
        ErrorEnvelope(
            type=ErrorType.SESSION_INVALID,
            title="Invalid session",
            detail="the session is unknown, expired, or no longer valid",
            status=404,
        )
    )


class FakeSessionManager:
    """Fake manager modeling owner-scoping, write consent, and the recorded program hash.

    Single owned session (``_OWNER``) with a recorded binary hash. A foreign caller is denied the
    BOLA-safe ``SESSION_INVALID`` everywhere; write consent is default-deny; structural consent is a
    separate opt-in. Records consent checks so tests can assert ordering (gate-before-write).
    """

    def __init__(self) -> None:
        self._writes = False
        self._structural = False
        self._hash: str | None = _SHA
        self.consent_checks: list[tuple[str, bool]] = []

    def _check(self, sid: str, caller: str) -> None:
        if sid != _SID or caller != _OWNER:
            raise _session_invalid()

    def _info(self) -> s.SessionInfo:
        return s.SessionInfo(
            session_id=_SID,
            state="ready",
            created_at=0,
            expires_at=10,
            binary_sha256=self._hash,
            writes_enabled=self._writes,
            allow_structural=self._structural,
        )

    def begin_call(self, session_id: str) -> None:
        """In-flight marker (ADR-025 / F4) — no-op for these dispatch tests."""

    def end_call(self, session_id: str) -> None:
        """In-flight clear (ADR-025 / F4) — no-op for these dispatch tests."""

    def authorize(self, session_id: str, *, caller: str = _OWNER) -> s.SessionInfo:
        self._check(session_id, caller)
        return self._info()

    def enable_writes(
        self, session_id: str, *, allow_structural: bool = False, caller: str = _OWNER
    ) -> s.SessionInfo:
        self._check(session_id, caller)
        self._writes = True
        self._structural = allow_structural
        return self._info()

    def require_write_consent(
        self, session_id: str, *, structural: bool = False, caller: str = _OWNER
    ) -> s.SessionInfo:
        self._check(session_id, caller)
        self.consent_checks.append((session_id, structural))
        if not self._writes:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.VALIDATION,
                    title="Invalid arguments",
                    detail="session is read-only; write consent not granted",
                    status=400,
                )
            )
        if structural and not self._structural:
            raise GhidraMcpError(
                ErrorEnvelope(
                    type=ErrorType.VALIDATION,
                    title="Invalid arguments",
                    detail="structural writes not permitted for this session",
                    status=400,
                )
            )
        return self._info()


class FakePort:
    """In-test :class:`GhidraPort` recording write replays + returning valid results."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    # --- export read-out ---
    def export_annotations(
        self, sid: str, a: s.SessionExportAnnotationsIn
    ) -> s.SessionExportAnnotationsOut:
        self.calls.append(("export_annotations", sid))
        return s.SessionExportAnnotationsOut(
            document=s.ExportedAnnotationDocument(
                schema_version=s.ANNOTATION_SCHEMA_VERSION,
                # The worker's binding is a placeholder; the server overlays the authoritative hash.
                binary=s.ExportedBinaryRef(sha256="0" * 64, name=_u("sample.bin"), size=4096),
                entries=[
                    s.ExportedRenameFunctionEntry(
                        kind="rename_function", function="0x401000", new_name=_u("parse_cfg")
                    ),
                    s.ExportedSetCommentEntry(
                        kind="set_comment",
                        address="0x401000",
                        comment_type="PLATE",
                        text=_u("entry"),
                    ),
                ],
            )
        )

    # --- the existing gated write methods import REPLAYS through ---
    def rename_function(self, sid: str, a: s.RenameFunctionIn) -> s.RenameResult:
        self.calls.append(("rename_function", sid))
        return s.RenameResult(
            address="0x401000", old_name=_u("FUN_00401000"), new_name=a.new_name, applied=True
        )

    def rename_symbol(self, sid: str, a: s.RenameSymbolIn) -> s.RenameSymbolResult:
        self.calls.append(("rename_symbol", sid))
        return s.RenameSymbolResult(
            address="0x402000", old_name=_u("DAT"), new_name=a.new_name, applied=True, kind="LABEL"
        )

    def set_comment(self, sid: str, a: s.SetCommentIn) -> s.SetCommentResult:
        self.calls.append(("set_comment", sid))
        return s.SetCommentResult(address="0x401000", comment_type=a.comment_type, applied=True)

    def define_struct(self, sid: str, a: s.DefineStructIn) -> s.DefineStructResult:
        self.calls.append(("define_struct", sid))
        return s.DefineStructResult(
            name=a.name, kind="struct", size=8, field_count=len(a.fields), applied=True
        )

    def set_function_signature(
        self, sid: str, a: s.SetFunctionSignatureIn
    ) -> s.SetFunctionSignatureResult:
        self.calls.append(("set_function_signature", sid))
        return s.SetFunctionSignatureResult(
            address="0x401000",
            function=_u("f"),
            old_signature=_u("void f(void)"),
            new_signature=_u("int f(int)"),
            applied=True,
        )

    def rename_local_variable(
        self, sid: str, a: s.RenameLocalVariableIn
    ) -> s.StructuralRenameResult:
        self.calls.append(("rename_local_variable", sid))
        return s.StructuralRenameResult(
            address="0x401000",
            function=_u("f"),
            old_name=_u("local_8"),
            new_name=a.new_name,
            applied=True,
        )

    def rename_parameter(self, sid: str, a: s.RenameParameterIn) -> s.StructuralRenameResult:
        self.calls.append(("rename_parameter", sid))
        return s.StructuralRenameResult(
            address="0x401000",
            function=_u("f"),
            old_name=_u("param_1"),
            new_name=a.new_name,
            applied=True,
        )

    def apply_data_type(self, sid: str, a: s.ApplyDataTypeIn) -> s.ApplyDataTypeResult:
        self.calls.append(("apply_data_type", sid))
        return s.ApplyDataTypeResult(address="0x401000", type_name=_u("int"), size=4, applied=True)

    def define_union(self, sid: str, a: s.DefineUnionIn) -> s.DefineUnionResult:
        self.calls.append(("define_union", sid))
        return s.DefineUnionResult(
            name=a.name, kind="union", size=4, field_count=len(a.fields), applied=True
        )


def _ctx() -> reg.ToolContext:
    config = Config(
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
    return reg.ToolContext(
        config=config,
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, FakePort()),
    )


@pytest.fixture
def ctx() -> reg.ToolContext:
    return _ctx()


def _port(ctx: reg.ToolContext) -> FakePort:
    return cast(FakePort, ctx.port)


def _sessions(ctx: reg.ToolContext) -> FakeSessionManager:
    return cast(FakeSessionManager, ctx.sessions)


def _doc(*entries: s.Entry, sha: str = _SHA) -> s.AnnotationDocument:
    return s.AnnotationDocument(
        schema_version=1, binary=s.AnnotationBinaryRef(sha256=sha), entries=list(entries)
    )


_RENAME = s.RenameFunctionEntry(kind="rename_function", function="0x401000", new_name="parse_cfg")
_COMMENT = s.SetCommentEntry(
    kind="set_comment", address="0x401000", comment_type="PLATE", text="entry"
)
_STRUCT = s.DefineStructEntry(
    kind="define_struct",
    name="cfg_t",
    fields=[s.FieldSpec(name="flags", type=s.TypeRef(base="int"))],
)


# =============================================================================================
# Export — read-only, owner-scoped, server overlays the authoritative binary hash
# =============================================================================================
@pytest.mark.critical
def test_export_is_read_only_and_overlays_authoritative_hash(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    out = handlers["session_export_annotations"](session_id=_SID)
    assert isinstance(out, s.SessionExportAnnotationsOut)
    # The server overlays the session's recorded program hash (not the worker placeholder).
    assert out.document.binary.sha256 == _SHA
    assert len(out.document.entries) == 2
    # Binary-derived strings are untrusted-wrapped (ADR-005).
    first = out.document.entries[0]
    assert isinstance(first, s.ExportedRenameFunctionEntry)
    assert isinstance(first.new_name, Untrusted)
    # Read-only: no write consent was required.
    assert _sessions(ctx).consent_checks == []
    assert ("export_annotations", _SID) in _port(ctx).calls


@pytest.mark.critical
def test_export_keeps_worker_binding_when_session_has_no_recorded_hash() -> None:
    # If the session has no recorded program hash (no binary imported), the server cannot overlay —
    # the worker-supplied binding is kept as-is (the document is then unbindable on re-import).
    ctx = _ctx()
    _sessions(ctx)._hash = None
    handlers = reg.build_handlers(ctx)
    out = handlers["session_export_annotations"](session_id=_SID)
    assert out.document.binary.sha256 == "0" * 64  # the worker placeholder, not overlaid


@pytest.mark.critical
def test_export_cross_owner_is_session_invalid(ctx: reg.ToolContext) -> None:
    # A foreign caller cannot export another principal's session (BOLA-safe).
    ctx2 = reg.ToolContext(
        config=ctx.config, sessions=ctx.sessions, port=ctx.port, principal=Principal(id="B")
    )
    handlers = reg.build_handlers(ctx2)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_export_annotations"](session_id=_SID)
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID
    assert _port(ctx).calls == []


# =============================================================================================
# Import — the TB8 path: schema → hash-bind → consent → per-entry re-validate + replay
# =============================================================================================
@pytest.mark.critical
def test_import_happy_path_replays_existing_writes(ctx: reg.ToolContext) -> None:
    # abuse case 70 — a well-formed, hash-matching, consented document replays via the
    # EXISTING gated write handlers (no new write primitive).
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)  # write consent (no structural)
    out = handlers["session_import_annotations"](
        session_id=_SID, document=_doc(_RENAME, _COMMENT).model_dump()
    )
    assert isinstance(out, s.SessionImportAnnotationsOut)
    assert out.total == 2
    assert out.applied == 2
    assert out.rejected == 0
    # Replayed via the EXISTING write handlers/port methods (no new primitive).
    assert ("rename_function", _SID) in _port(ctx).calls
    assert ("set_comment", _SID) in _port(ctx).calls
    # Every applied entry has a per-entry outcome (no values echoed — only kind/index/applied).
    assert [o.applied for o in out.outcomes] == [True, True]
    assert all(o.reason is None for o in out.outcomes)


@pytest.mark.critical
def test_import_wrong_binary_hash_fails_closed(ctx: reg.ToolContext) -> None:
    # abuse case 71-adjacent / TB8-S — a doc minted for a different binary is rejected by the
    # hash binding; fail closed before any write.
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](
            session_id=_SID, document=_doc(_RENAME, sha=_WRONG_SHA).model_dump()
        )
    assert exc.value.envelope.type is ErrorType.VALIDATION
    # Fail closed BEFORE any write reached the port.
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_import_without_consent_denied_no_write(ctx: reg.ToolContext) -> None:
    # abuse case 73 (read-only variant) — without write consent the import is denied up front.
    handlers = reg.build_handlers(ctx)  # no enable_writes → read-only
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](session_id=_SID, document=_doc(_RENAME).model_dump())
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_import_structural_entry_without_allow_structural_denied(ctx: reg.ToolContext) -> None:
    # abuse case 73 — a type-aware structural entry (define_struct) on a write-enabled-but-NOT-
    # allow_structural session is denied up front (structural consent required). No write committed.
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)  # write consent, but NOT structural
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](session_id=_SID, document=_doc(_STRUCT).model_dump())
    assert exc.value.envelope.type is ErrorType.VALIDATION
    # No structural write committed (the structural-consent gate ran before any replay).
    assert _port(ctx).calls == []


@pytest.mark.critical
@pytest.mark.parametrize(
    "entry",
    [
        s.RenameLocalVariableEntry(
            kind="rename_local_variable", function="0x401000", variable="local_8", new_name="ctx"
        ),
        s.RenameParameterEntry(
            kind="rename_parameter", function="0x401000", parameter="param_1", new_name="arg"
        ),
    ],
    ids=["rename_local_variable", "rename_parameter"],
)
def test_import_phase_a_structural_rename_without_allow_structural_denied(
    ctx: reg.ToolContext, entry: s.Entry
) -> None:
    # abuse case 73 — the Phase-A name-only structural renames (rename_local_variable /
    # rename_parameter) ARE structural kinds (their live handlers call require_write_consent(
    # structural=True)). A local/param-only document imported into a write-enabled-but-NOT-
    # allow_structural session must be denied UP FRONT (structural consent required) — the up-front
    # import gate (STRUCTURAL_ENTRY_KINDS) is single-sourced with the handlers. NO write occurs.
    assert entry.kind in s.STRUCTURAL_ENTRY_KINDS  # single source of truth includes Phase-A renames
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)  # write consent, but NOT structural
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](session_id=_SID, document=_doc(entry).model_dump())
    assert exc.value.envelope.type is ErrorType.VALIDATION
    # Denied up front by the structural-consent gate — no local/param write reached the port.
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_import_structural_entry_with_allow_structural_applies(ctx: reg.ToolContext) -> None:
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID, allow_structural=True)
    out = handlers["session_import_annotations"](
        session_id=_SID, document=_doc(_STRUCT).model_dump()
    )
    assert out.applied == 1
    assert ("define_struct", _SID) in _port(ctx).calls
    # Both consent checks ran: write consent, then structural consent.
    assert (_SID, False) in _sessions(ctx).consent_checks
    assert (_SID, True) in _sessions(ctx).consent_checks


@pytest.mark.critical
def test_import_cross_owner_is_session_invalid(ctx: reg.ToolContext) -> None:
    # abuse case 74 — principal B importing into A's session is BOLA-safe SESSION_INVALID.
    ctx2 = reg.ToolContext(
        config=ctx.config, sessions=ctx.sessions, port=ctx.port, principal=Principal(id="B")
    )
    handlers = reg.build_handlers(ctx2)
    handlers_owner = reg.build_handlers(ctx)
    handlers_owner["session_enable_writes"](session_id=_SID)  # owner grants; B still cannot import
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](session_id=_SID, document=_doc(_RENAME).model_dump())
    assert exc.value.envelope.type is ErrorType.SESSION_INVALID
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_import_tampered_entry_rejected_before_any_write(ctx: reg.ToolContext) -> None:
    # abuse case 71 — an injection-bearing new_name is rejected by the live validators; no write.
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)
    # A tampered entry (injection-bearing new_name) makes the WHOLE-document schema validation fail
    # closed (validate_annotation_document re-validates every entry up front) — nothing is written.
    tampered = _doc(
        s.RenameFunctionEntry(kind="rename_function", function="f", new_name="<b>evil</b>")
    )
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](session_id=_SID, document=tampered.model_dump())
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_import_unknown_kind_rejected(ctx: reg.ToolContext) -> None:
    # abuse case 75 — an unknown kind is rejected at document construction (closed union); no write.
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)
    # An unknown discriminator is rejected at document construction (the discriminated union admits
    # no other kind) — surfaces as a (pydantic) validation failure; nothing is written.
    bad_doc = {
        "schema_version": 1,
        "binary": {"sha256": _SHA},
        "entries": [{"kind": "delete_everything", "target": "x"}],
    }
    with pytest.raises((GhidraMcpError, Exception)):
        handlers["session_import_annotations"](session_id=_SID, document=bad_doc)
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_import_unknown_schema_version_rejected(ctx: reg.ToolContext) -> None:
    # abuse case 75 — an unsupported schema_version is rejected VALIDATION (opt-in forward-compat).
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)
    doc = _doc(_RENAME).model_dump()
    doc["schema_version"] = 999
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](session_id=_SID, document=doc)
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []


@pytest.mark.critical
def test_import_replays_every_entry_kind_via_existing_writes(ctx: reg.ToolContext) -> None:
    # A full-kinds document (dependency-ordered) replays through EVERY existing write handler —
    # proving import adds NO new write primitive (it dispatches to the existing gated writes).
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID, allow_structural=True)
    full = _doc(
        s.DefineStructEntry(
            kind="define_struct",
            name="cfg_t",
            fields=[s.FieldSpec(name="flags", type=s.TypeRef(base="int"))],
        ),
        s.DefineUnionEntry(
            kind="define_union",
            name="u_t",
            fields=[s.FieldSpec(name="m", type=s.TypeRef(base="int"))],
        ),
        s.SetFunctionSignatureEntry(
            kind="set_function_signature",
            function="0x401000",
            return_type=s.TypeRef(base="int"),
            parameters=[s.ParamSpec(name="arg0", type=s.TypeRef(base="int"))],
        ),
        s.ApplyDataTypeEntry(
            kind="apply_data_type", address="0x401000", type=s.TypeRef(base="int")
        ),
        s.RenameFunctionEntry(kind="rename_function", function="0x401000", new_name="parse_cfg"),
        s.RenameSymbolEntry(kind="rename_symbol", identifier="0x402000", new_name="g_key"),
        s.RenameLocalVariableEntry(
            kind="rename_local_variable", function="f", variable="local_8", new_name="ctx"
        ),
        s.RenameParameterEntry(
            kind="rename_parameter", function="f", parameter="param_1", new_name="arg"
        ),
        s.SetCommentEntry(kind="set_comment", address="0x401000", comment_type="PLATE", text="x"),
    )
    out = handlers["session_import_annotations"](session_id=_SID, document=full.model_dump())
    assert out.total == 9
    assert out.applied == 9
    replayed = {m for m, _ in _port(ctx).calls}
    assert replayed == {
        "define_struct",
        "define_union",
        "set_function_signature",
        "apply_data_type",
        "rename_function",
        "rename_symbol",
        "rename_local_variable",
        "rename_parameter",
        "set_comment",
    }


@pytest.mark.critical
def test_empty_document_imports_with_no_writes(ctx: reg.ToolContext) -> None:
    # An empty (zero-entry) document is valid: consent is still gated, but nothing is written.
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)
    out = handlers["session_import_annotations"](session_id=_SID, document=_doc().model_dump())
    assert out.total == 0
    assert out.applied == 0
    assert out.outcomes == []
    # No structural consent needed (no structural entries), and no port write reached.
    assert _port(ctx).calls == []


class _PartialFailPort(FakePort):
    """Port whose ``rename_function`` replay fails NOT_FOUND, the rest succeed (partial import)."""

    def rename_function(self, sid: str, a: s.RenameFunctionIn) -> s.RenameResult:
        self.calls.append(("rename_function", sid))
        raise GhidraMcpError(
            ErrorEnvelope(
                type=ErrorType.NOT_FOUND,
                title="Not found",
                detail="the function does not resolve",
                status=404,
            )
        )


@pytest.mark.critical
def test_import_partial_application_reports_per_entry_outcomes() -> None:
    # abuse case 76 — a validation-clean entry whose write cannot apply is recorded rejected;
    # the other clean entries still apply (best-effort, per-entry transaction).
    # A validation-clean entry whose WRITE cannot apply (worker not-found) is recorded as rejected
    # with a safe reason; the other clean entries still apply (best-effort per the txn model).
    ctx = reg.ToolContext(
        config=_ctx().config,
        sessions=cast(SessionManager, FakeSessionManager()),
        port=cast(GhidraPort, _PartialFailPort()),
    )
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)
    out = handlers["session_import_annotations"](
        session_id=_SID, document=_doc(_RENAME, _COMMENT).model_dump()
    )
    assert out.total == 2
    assert out.applied == 1
    assert out.rejected == 1
    rejected = [o for o in out.outcomes if not o.applied]
    assert len(rejected) == 1
    assert rejected[0].kind == "rename_function"
    assert rejected[0].reason == ErrorType.NOT_FOUND.value
    # The clean comment still applied.
    assert ("set_comment", _SID) in _port(ctx).calls


@pytest.mark.critical
def test_import_into_session_with_no_recorded_hash_fails_closed() -> None:
    # A session that never imported a binary has no recorded hash → no document can bind → reject.
    ctx = _ctx()
    _sessions(ctx)._hash = None
    handlers = reg.build_handlers(ctx)
    handlers["session_enable_writes"](session_id=_SID)
    with pytest.raises(GhidraMcpError) as exc:
        handlers["session_import_annotations"](session_id=_SID, document=_doc(_RENAME).model_dump())
    assert exc.value.envelope.type is ErrorType.VALIDATION
    assert _port(ctx).calls == []
