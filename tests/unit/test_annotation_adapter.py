"""Unit tests for the annotation-export RPC adapter builder (ADR-018) — TB2/TB4.

Mirrors ``test_mutation_adapter.py``: a real connected UDS pair (``socket.socketpair``) plays the
worker and a fake worker handle records kills. No real Ghidra, no JVM, no network. Covers the
``export_annotations`` adapter method + its ``_build_exported_annotation_document`` /
``_build_exported_entry`` builders. Asserts:

- a plain worker export result round-trips into the typed ``ExportedAnnotationDocument`` with every
  binary-derived value field ``Untrusted``-wrapped (ADR-005) and structured refs/addresses bare;
- every entry ``kind`` shapes into its matching exported variant — incl. the ADR-032
  ``define_types`` batch (schema v2): the session-authored composites arrive as ONE batch entry
  whose per-composite name + field names are ``Untrusted``-wrapped (vs. legacy define_struct/union);
- a structurally-malformed / unknown-kind worker result fails closed as ``WORKER_UNAVAILABLE`` (the
  ``_fail_closed`` builder), never surfacing the raw shaping error.
"""

from __future__ import annotations

import socket
import threading

import pytest
from worker import dispatch

from vivarium.core.envelope import DataOrigin, Untrusted
from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra import rpc_framing
from vivarium.ghidra.rpc_client import RpcGhidraAdapter
from vivarium.tools import schemas as s

_CAP = 4 * 1024 * 1024


class _FakeWorker:
    """A fake worker process handle recording whether it was killed."""

    def __init__(self) -> None:
        self.killed = 0
        self._alive = True

    def kill(self) -> None:
        self.killed += 1
        self._alive = False

    def is_alive(self) -> bool:
        return self._alive


class _ConnectedAdapter(RpcGhidraAdapter):
    """Adapter whose ``_ensure_connected`` returns a pre-wired socketpair end."""

    def __init__(self, *, server_sock: socket.socket, **kw: object) -> None:
        super().__init__(**kw)  # type: ignore[arg-type]
        self._wired = server_sock

    def _ensure_connected(self, sess: object, *, deadline: float = 0.0) -> socket.socket:
        sess.sock = self._wired  # type: ignore[attr-defined]
        return self._wired


def _make_adapter(server_sock: socket.socket, worker: _FakeWorker) -> _ConnectedAdapter:
    adapter = _ConnectedAdapter(
        server_sock=server_sock,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/vivarium-test",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=0.5,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    adapter.start_worker("s")
    return adapter


def _serve_one(worker_sock: socket.socket, response: dict[str, object]) -> None:
    obj = dispatch.read_frame(worker_sock, max_frame_bytes=_CAP)
    response = {**response, "id": obj["id"]}
    worker_sock.sendall(rpc_framing.encode_frame(response, max_frame_bytes=_CAP))


def _run_export(result: dict[str, object]) -> tuple[s.SessionExportAnnotationsOut, _FakeWorker]:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    try:
        out = adapter.export_annotations(
            "s", s.SessionExportAnnotationsIn(session_id="s"), targets=s.ExportTargets()
        )
    finally:
        t.join(timeout=2)
        wrk.close()
    return out, worker


# ADR-032 (schema v2): the worker emits ALL session-authored composites as ONE ``define_types``
# batch entry (emitted FIRST), not N individual ``define_struct``/``define_union`` entries. Here the
# batch carries one struct + one union to exercise both composite kinds through the batch builder.
_FULL_RESULT: dict[str, object] = {
    "schema_version": 2,
    "binary": {"sha256": "a" * 64, "name": "sample.bin", "size": 4096},
    "entries": [
        {
            "kind": "define_types",
            "types": [
                {
                    "kind": "struct",
                    "name": "cfg_t",
                    "fields": [
                        {
                            "name": "flags",
                            "type": {
                                "base": "int",
                                "named": None,
                                "pointer_levels": 0,
                                "array_len": None,
                            },
                            "offset": 0,
                        }
                    ],
                    "packed": False,
                },
                {
                    "kind": "union",
                    "name": "u_t",
                    "fields": [
                        {
                            "name": "m",
                            "type": {
                                "base": "int",
                                "named": None,
                                "pointer_levels": 0,
                                "array_len": None,
                            },
                            "offset": None,
                        }
                    ],
                },
            ],
        },
        {
            "kind": "set_function_signature",
            "function": "0x401000",
            "return_type": {"base": "int", "named": None, "pointer_levels": 0, "array_len": None},
            "parameters": [
                {
                    "name": "arg0",
                    "type": {"base": "int", "named": None, "pointer_levels": 0, "array_len": None},
                }
            ],
            "calling_convention": None,
        },
        {
            "kind": "apply_data_type",
            "address": "0x401000",
            "type": {"base": "int", "named": None, "pointer_levels": 1, "array_len": None},
            "clear_existing": False,
        },
        {"kind": "rename_function", "function": "0x401000", "new_name": "parse_cfg"},
        {"kind": "rename_symbol", "identifier": "0x402000", "new_name": "g_key"},
        {
            "kind": "rename_local_variable",
            "function": "0x401000",
            "variable": "local_8",
            "new_name": "ctx",
        },
        {
            "kind": "rename_parameter",
            "function": "0x401000",
            "parameter": "param_1",
            "new_name": "arg",
        },
        {"kind": "set_comment", "address": "0x401000", "comment_type": "PLATE", "text": "entry"},
    ],
}


def test_export_round_trips_every_kind_with_untrusted_wrapping() -> None:
    # abuse case 70 (export analog) — every entry kind round-trips through the typed exported view.
    # ADR-032 (v2): the composites arrive as ONE ``define_types`` batch (first), not N entries.
    out, worker = _run_export(_FULL_RESULT)
    doc = out.document
    assert doc.schema_version == 2  # ADR-032 — new exports are v2
    assert doc.binary.sha256 == "a" * 64  # server-relevant digest of input — bare/safe
    assert isinstance(doc.binary.name, Untrusted)  # advisory original name → binary-derived
    assert len(doc.entries) == 8  # the two composites collapsed into one define_types batch
    kinds = [e.kind for e in doc.entries]
    assert kinds == [
        "define_types",
        "set_function_signature",
        "apply_data_type",
        "rename_function",
        "rename_symbol",
        "rename_local_variable",
        "rename_parameter",
        "set_comment",
    ]
    # Binary-derived value fields are Untrusted-wrapped (ADR-005); structured refs/addresses bare.
    rename_fn = doc.entries[3]
    assert isinstance(rename_fn, s.ExportedRenameFunctionEntry)
    assert isinstance(rename_fn.new_name, Untrusted)
    assert rename_fn.new_name.origin is DataOrigin.BINARY
    assert rename_fn.function == "0x401000"  # address — server-safe, bare
    comment = doc.entries[7]
    assert isinstance(comment, s.ExportedSetCommentEntry)
    assert isinstance(comment.text, Untrusted)
    assert comment.comment_type == "PLATE"  # closed vocab — bare
    local = doc.entries[5]
    assert isinstance(local, s.ExportedRenameLocalVariableEntry)
    assert isinstance(local.variable, Untrusted)  # decompiler selector — binary-derived
    assert worker.killed == 0


def test_export_wraps_composite_and_member_and_typeref_names() -> None:
    # abuse case 71 (export analog) — a composite name, a member/param name, and a TypeRef.named
    # are all read OUT of the hostile program (USER_DEFINED identifiers an injection-steered prior
    # write may control), so they MUST come back Untrusted-wrapped (ADR-005 / CWE-200), not bare.
    # ADR-032: the composites live inside the single ``define_types`` batch entry now.
    out, _ = _run_export(_FULL_RESULT)
    doc = out.document

    batch = doc.entries[0]
    assert isinstance(batch, s.ExportedDefineTypesEntry)
    assert [t.kind for t in batch.types] == ["struct", "union"]

    struct = batch.types[0]
    assert isinstance(struct, s.ExportedCompositeSpec)
    # composite name: Untrusted-wrapped, not a bare str.
    assert isinstance(struct.name, Untrusted)
    assert struct.name.origin is DataOrigin.BINARY
    # member name: Untrusted-wrapped.
    assert isinstance(struct.fields[0].name, Untrusted)
    assert struct.fields[0].name.origin is DataOrigin.BINARY

    union = batch.types[1]
    assert isinstance(union, s.ExportedCompositeSpec)
    assert isinstance(union.name, Untrusted)
    assert isinstance(union.fields[0].name, Untrusted)

    sig = doc.entries[1]
    assert isinstance(sig, s.ExportedSetFunctionSignatureEntry)
    # parameter name: Untrusted-wrapped (binary-derived on export).
    assert isinstance(sig.parameters[0].name, Untrusted)
    assert sig.parameters[0].name.origin is DataOrigin.BINARY


def test_export_wraps_typeref_named_leaf() -> None:
    # abuse case 71 (export analog) — a TypeRef.named (an existing program type name read out) is
    # binary-derived and must be Untrusted-wrapped; the closed-vocab `base` and bounded modifiers
    # stay bare/safe. A planted/injection-steered type name cannot ride out unwrapped.
    result = {
        "schema_version": 1,
        "binary": {"sha256": "a" * 64},
        "entries": [
            {
                "kind": "apply_data_type",
                "address": "0x401000",
                "type": {
                    "base": None,
                    "named": "evil_t",
                    "pointer_levels": 1,
                    "array_len": None,
                },
                "clear_existing": False,
            }
        ],
    }
    out, _ = _run_export(result)
    entry = out.document.entries[0]
    assert isinstance(entry, s.ExportedApplyDataTypeEntry)
    assert isinstance(entry.type, s.ExportedTypeRef)
    assert isinstance(entry.type.named, Untrusted)
    assert entry.type.named.origin is DataOrigin.BINARY
    assert entry.type.named.value == "evil_t"
    assert entry.type.base is None  # closed vocab — bare
    assert entry.type.pointer_levels == 1  # server-safe scalar — bare


def test_export_define_types_batch_wraps_every_composite_and_field_name() -> None:
    # ADR-032 — a plain worker ``define_types`` dict (TWO mutually-recursive pointer composites)
    # builds an ``ExportedDefineTypesEntry`` whose every composite name + field name is read OUT of
    # the hostile program → Untrusted-wrapped (ADR-005). The pointer modifier + closed-vocab base
    # stay bare/safe. This is the headline interdependent-graph carrier coming back out.
    result = {
        "schema_version": 2,
        "binary": {"sha256": "a" * 64},
        "entries": [
            {
                "kind": "define_types",
                "types": [
                    {
                        "kind": "struct",
                        "name": "node_a",
                        "fields": [
                            {
                                "name": "to_b",
                                "type": {
                                    "base": None,
                                    "named": "node_b",
                                    "pointer_levels": 1,
                                    "array_len": None,
                                },
                                "offset": None,
                            }
                        ],
                    },
                    {
                        "kind": "struct",
                        "name": "node_b",
                        "fields": [
                            {
                                "name": "to_a",
                                "type": {
                                    "base": None,
                                    "named": "node_a",
                                    "pointer_levels": 1,
                                    "array_len": None,
                                },
                                "offset": None,
                            }
                        ],
                    },
                ],
            }
        ],
    }
    out, _ = _run_export(result)
    entry = out.document.entries[0]
    assert isinstance(entry, s.ExportedDefineTypesEntry)
    assert len(entry.types) == 2
    for composite, expected_name in zip(entry.types, ("node_a", "node_b"), strict=True):
        assert isinstance(composite, s.ExportedCompositeSpec)
        assert isinstance(composite.name, Untrusted)  # composite name → binary-derived
        assert composite.name.origin is DataOrigin.BINARY
        assert composite.name.value == expected_name
        field = composite.fields[0]
        assert isinstance(field.name, Untrusted)  # member name → binary-derived
        assert field.name.origin is DataOrigin.BINARY
        # The TypeRef.named (the peer composite name read out) is Untrusted-wrapped; modifiers bare.
        assert isinstance(field.type.named, Untrusted)
        assert field.type.named.origin is DataOrigin.BINARY
        assert field.type.pointer_levels == 1  # server-safe scalar — bare


def test_export_neutralizes_injection_in_read_out_name() -> None:
    # abuse case 71 (export analog) — a hostile read-out name (bidi camouflage) is neutralized
    # when wrapped out (ADR-005).
    result = {
        "schema_version": 1,
        "binary": {"sha256": "a" * 64},
        "entries": [{"kind": "rename_function", "function": "0x1", "new_name": "evil‮name"}],
    }
    out, _ = _run_export(result)
    entry = out.document.entries[0]
    assert isinstance(entry, s.ExportedRenameFunctionEntry)
    assert "‮" not in entry.new_name.value
    assert "<U+202E>" in entry.new_name.value
    assert entry.new_name.notes  # the neutralized class is annotated for the client


def test_export_malformed_result_fails_closed() -> None:
    # A missing required key in an entry → builder KeyError → _fail_closed → WORKER_UNAVAILABLE.
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    bad = {
        "jsonrpc": "2.0",
        "result": {
            "schema_version": 1,
            "binary": {"sha256": "a" * 64},
            "entries": [{"kind": "rename_function", "function": "0x1"}],  # missing new_name
        },
    }
    t = threading.Thread(target=_serve_one, args=(wrk, bad), daemon=True)
    t.start()
    try:
        with pytest.raises(GhidraMcpError) as ei:
            adapter.export_annotations(
                "s", s.SessionExportAnnotationsIn(session_id="s"), targets=s.ExportTargets()
            )
    finally:
        t.join(timeout=2)
        wrk.close()
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_export_unknown_entry_kind_fails_closed() -> None:
    # An unknown kind from the worker → builder ValueError → _fail_closed → WORKER_UNAVAILABLE.
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    bad = {
        "jsonrpc": "2.0",
        "result": {
            "schema_version": 1,
            "binary": {"sha256": "a" * 64},
            "entries": [{"kind": "delete_everything"}],
        },
    }
    t = threading.Thread(target=_serve_one, args=(wrk, bad), daemon=True)
    t.start()
    try:
        with pytest.raises(GhidraMcpError) as ei:
            adapter.export_annotations(
                "s", s.SessionExportAnnotationsIn(session_id="s"), targets=s.ExportTargets()
            )
    finally:
        t.join(timeout=2)
        wrk.close()
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


# --- ADR-027: the pure change-log → RPC params shaper (_export_annotations_params) -------------
def test_export_annotations_params_shapes_targets() -> None:
    from vivarium.ghidra.rpc_client import _export_annotations_params

    targets = s.ExportTargets(
        comments=[
            s.ExportCommentTarget(address="0x401000", comment_type="PLATE"),
            s.ExportCommentTarget(address="0x401004", comment_type="EOL"),
        ],
        composites=["cfg_t", "widget_t"],
    )
    params = _export_annotations_params(targets)
    assert params == {
        "targets": {
            "comments": [
                {"address": "0x401000", "comment_type": "PLATE"},
                {"address": "0x401004", "comment_type": "EOL"},
            ],
            "composites": ["cfg_t", "widget_t"],
        }
    }


def test_export_annotations_params_empty_is_empty_lists() -> None:
    from vivarium.ghidra.rpc_client import _export_annotations_params

    params = _export_annotations_params(s.ExportTargets())
    assert params == {"targets": {"comments": [], "composites": []}}


def test_export_annotations_params_emits_only_identity_keys_no_values() -> None:
    # The shaper must NEVER carry a comment text / field value — only addresses, slots, names.
    from vivarium.ghidra.rpc_client import _export_annotations_params

    params = _export_annotations_params(
        s.ExportTargets(
            comments=[s.ExportCommentTarget(address="0xabc", comment_type="PRE")],
            composites=["t"],
        )
    )
    comment = params["targets"]["comments"][0]
    assert set(comment.keys()) == {"address", "comment_type"}  # no "text" / value field
