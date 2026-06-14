"""Unit tests for the annotation-export RPC adapter builder (ADR-018) — TB2/TB4.

Mirrors ``test_mutation_adapter.py``: a real connected UDS pair (``socket.socketpair``) plays the
worker and a fake worker handle records kills. No real Ghidra, no JVM, no network. Covers the
``export_annotations`` adapter method + its ``_build_exported_annotation_document`` /
``_build_exported_entry`` builders. Asserts:

- a plain worker export result round-trips into the typed ``ExportedAnnotationDocument`` with every
  binary-derived value field ``Untrusted``-wrapped (ADR-005) and structured refs/addresses bare;
- every entry ``kind`` shapes into its matching exported variant;
- a structurally-malformed / unknown-kind worker result fails closed as ``WORKER_UNAVAILABLE`` (the
  ``_fail_closed`` builder), never surfacing the raw shaping error.
"""

from __future__ import annotations

import socket
import threading

import pytest
from worker import dispatch

from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.ghidra import rpc_framing
from ghidra_mcp.ghidra.rpc_client import RpcGhidraAdapter
from ghidra_mcp.tools import schemas as s

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

    def _ensure_connected(self, sess: object) -> socket.socket:
        sess.sock = self._wired  # type: ignore[attr-defined]
        return self._wired


def _make_adapter(server_sock: socket.socket, worker: _FakeWorker) -> _ConnectedAdapter:
    adapter = _ConnectedAdapter(
        server_sock=server_sock,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/ghidra-mcp-test",  # noqa: S108  # test-only path; no real socket bound
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
        out = adapter.export_annotations("s", s.SessionExportAnnotationsIn(session_id="s"))
    finally:
        t.join(timeout=2)
        wrk.close()
    return out, worker


_FULL_RESULT: dict[str, object] = {
    "schema_version": 1,
    "binary": {"sha256": "a" * 64, "name": "sample.bin", "size": 4096},
    "entries": [
        {
            "kind": "define_struct",
            "name": "cfg_t",
            "fields": [
                {
                    "name": "flags",
                    "type": {"base": "int", "named": None, "pointer_levels": 0, "array_len": None},
                    "offset": 0,
                }
            ],
            "packed": False,
        },
        {
            "kind": "define_union",
            "name": "u_t",
            "fields": [
                {
                    "name": "m",
                    "type": {"base": "int", "named": None, "pointer_levels": 0, "array_len": None},
                    "offset": None,
                }
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
    out, worker = _run_export(_FULL_RESULT)
    doc = out.document
    assert doc.schema_version == 1
    assert doc.binary.sha256 == "a" * 64  # server-relevant digest of input — bare/safe
    assert isinstance(doc.binary.name, Untrusted)  # advisory original name → binary-derived
    assert len(doc.entries) == 9
    kinds = [e.kind for e in doc.entries]
    assert kinds == [
        "define_struct",
        "define_union",
        "set_function_signature",
        "apply_data_type",
        "rename_function",
        "rename_symbol",
        "rename_local_variable",
        "rename_parameter",
        "set_comment",
    ]
    # Binary-derived value fields are Untrusted-wrapped (ADR-005); structured refs/addresses bare.
    rename_fn = doc.entries[4]
    assert isinstance(rename_fn, s.ExportedRenameFunctionEntry)
    assert isinstance(rename_fn.new_name, Untrusted)
    assert rename_fn.new_name.origin is DataOrigin.BINARY
    assert rename_fn.function == "0x401000"  # address — server-safe, bare
    comment = doc.entries[8]
    assert isinstance(comment, s.ExportedSetCommentEntry)
    assert isinstance(comment.text, Untrusted)
    assert comment.comment_type == "PLATE"  # closed vocab — bare
    local = doc.entries[6]
    assert isinstance(local, s.ExportedRenameLocalVariableEntry)
    assert isinstance(local.variable, Untrusted)  # decompiler selector — binary-derived
    assert worker.killed == 0


def test_export_neutralizes_injection_in_read_out_name() -> None:
    # A hostile read-out name (bidi camouflage) is neutralized when wrapped out (ADR-005).
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
            adapter.export_annotations("s", s.SessionExportAnnotationsIn(session_id="s"))
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
            adapter.export_annotations("s", s.SessionExportAnnotationsIn(session_id="s"))
    finally:
        t.join(timeout=2)
        wrk.close()
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
