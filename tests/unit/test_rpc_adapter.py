"""Unit tests for the worker RPC adapter, framing codec, and JVM-free worker dispatch (WS2).

These cover trust boundary 2 (server ↔ worker) without a real Ghidra worker: a real connected UDS
pair (``socket.socketpair``) plays the worker, and a fake :class:`worker.dispatch.GhidraBackend`
exercises the dispatch/framing path. Assertions:

- length-prefixed JSON-RPC round-trip (encode → decode → parse);
- oversized declared frame → ``FramingError`` and adapter kills the worker;
- per-call timeout → adapter SIGKILLs the worker, ``timeout`` envelope;
- worker crash / closed socket mid-call → ``worker-unavailable`` + kill;
- worker JSON-RPC error response → mapped to the public error type (worker NOT killed);
- worker method allow-list + safe-error mapping in the dispatcher.

No real worker, no Ghidra, no network.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from worker import dispatch

from ghidra_mcp.core.envelope import DataOrigin, Untrusted
from ghidra_mcp.core.errors import ErrorType, GhidraMcpError
from ghidra_mcp.ghidra import rpc_framing
from ghidra_mcp.ghidra.rpc_client import RpcGhidraAdapter
from ghidra_mcp.security.limits import Limits
from ghidra_mcp.tools import schemas as s

_CAP = 4 * 1024 * 1024


class _FakeWorker:
    """A fake worker process handle that records whether it was killed."""

    def __init__(self) -> None:
        """Initialize a live, un-killed fake worker."""
        self.killed = 0
        self._alive = True

    def kill(self) -> None:
        """Record a kill and mark dead."""
        self.killed += 1
        self._alive = False

    def is_alive(self) -> bool:
        """Whether the fake worker is still alive."""
        return self._alive


class _ConnectedAdapter(RpcGhidraAdapter):
    """Adapter whose ``_ensure_connected`` returns a pre-wired socket (a socketpair end)."""

    def __init__(self, *, server_sock: socket.socket, **kw: object) -> None:
        """Initialize with the server-side end of a connected socket pair.

        Args:
            server_sock: The socket the adapter should use as if connected to the worker.
            **kw: Forwarded to :class:`RpcGhidraAdapter`.
        """
        super().__init__(**kw)  # type: ignore[arg-type]
        self._wired = server_sock

    def _ensure_connected(self, sess: object) -> socket.socket:
        """Return the pre-wired socket instead of dialing a real UDS.

        Args:
            sess: The per-session state (unused).

        Returns:
            The pre-wired socket.
        """
        sess.sock = self._wired  # type: ignore[attr-defined]
        return self._wired


def _make_adapter(server_sock: socket.socket, worker: _FakeWorker) -> _ConnectedAdapter:
    """Build an adapter wired to ``server_sock`` with a fake worker registered for ``sid="s"``.

    Args:
        server_sock: The adapter's end of the connected pair.
        worker: The fake worker handle to register.

    Returns:
        A ready adapter with a live session ``"s"``.
    """
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


# --- framing codec ----------------------------------------------------------------------------
def test_framing_round_trip() -> None:
    req = rpc_framing.build_request("id1", "ping", {})
    frame = rpc_framing.encode_frame(req, max_frame_bytes=_CAP)
    assert len(frame) >= rpc_framing.LENGTH_PREFIX_BYTES
    prefix, body = frame[:4], frame[4:]
    n = rpc_framing.decode_length_prefix(prefix, max_frame_bytes=_CAP)
    assert n == len(body)
    obj = rpc_framing.decode_body(body)
    assert obj["method"] == "ping" and obj["id"] == "id1"


def test_decode_length_prefix_rejects_oversized() -> None:
    import struct

    prefix = struct.pack(">I", _CAP + 1)
    with pytest.raises(rpc_framing.FramingError):
        rpc_framing.decode_length_prefix(prefix, max_frame_bytes=_CAP)


def test_decode_length_prefix_rejects_short_prefix() -> None:
    with pytest.raises(rpc_framing.FramingError):
        rpc_framing.decode_length_prefix(b"\x00\x00", max_frame_bytes=_CAP)


def test_encode_frame_rejects_oversized_body() -> None:
    with pytest.raises(rpc_framing.FramingError):
        rpc_framing.encode_frame({"x": "y" * 100}, max_frame_bytes=4)


def test_decode_body_rejects_malformed_json() -> None:
    with pytest.raises(rpc_framing.RpcProtocolError):
        rpc_framing.decode_body(b"{not json")


def test_decode_body_rejects_non_object() -> None:
    with pytest.raises(rpc_framing.RpcProtocolError):
        rpc_framing.decode_body(b"[1,2,3]")


def test_parse_response_id_mismatch() -> None:
    obj = {"jsonrpc": "2.0", "id": "other", "result": {}}
    with pytest.raises(rpc_framing.RpcProtocolError):
        rpc_framing.parse_response(obj, expected_id="mine")


def test_parse_response_both_result_and_error() -> None:
    obj = {"jsonrpc": "2.0", "id": "x", "result": {}, "error": {"code": -1, "message": "m"}}
    with pytest.raises(rpc_framing.RpcProtocolError):
        rpc_framing.parse_response(obj, expected_id="x")


def test_parse_response_error_carries_slug() -> None:
    obj = {
        "jsonrpc": "2.0",
        "id": "x",
        "error": {"code": -32004, "message": "nope", "data": {"type": "not-found"}},
    }
    with pytest.raises(rpc_framing.RpcCallError) as ei:
        rpc_framing.parse_response(obj, expected_id="x")
    assert ei.value.error.type_slug == "not-found"


# --- adapter call semantics -------------------------------------------------------------------
def _serve_one(worker_sock: socket.socket, response: dict[str, object]) -> None:
    """Read one framed request and reply with ``response`` (echoing the request id)."""
    obj = dispatch.read_frame(worker_sock, max_frame_bytes=_CAP)
    response = {**response, "id": obj["id"]}
    worker_sock.sendall(rpc_framing.encode_frame(response, max_frame_bytes=_CAP))


def test_call_success_round_trip() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    result = {
        "session_id": "s",
        "state": "ready",
        "created_at": 1,
        "expires_at": 2,
        "binary_sha256": None,
    }
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    info = adapter.analyze("s", s.SessionAnalyzeIn(session_id="s", timeout_seconds=1))
    t.join(timeout=2)
    assert info.state == "ready"
    assert worker.killed == 0  # success never kills
    wrk.close()


def test_worker_error_response_maps_and_does_not_kill() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    err = {
        "jsonrpc": "2.0",
        "error": {"code": -32004, "message": "no fn", "data": {"type": "not-found"}},
    }
    t = threading.Thread(target=_serve_one, args=(wrk, err), daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.NOT_FOUND
    assert worker.killed == 0  # a healthy worker returning a method error is NOT killed
    wrk.close()


def test_timeout_kills_worker() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    # No thread answers → the recv times out (tool_timeout_s=0.5).
    with pytest.raises(GhidraMcpError) as ei:
        adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    assert ei.value.envelope.type is ErrorType.TIMEOUT
    assert ei.value.envelope.retryable is True
    assert worker.killed == 1  # SIGKILL on deadline expiry (no graceful wait)
    wrk.close()


def test_oversized_declared_frame_kills_worker() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    # Small-but-usable cap: requests fit, but the worker declares a far-larger inbound frame.
    cap = 1024
    adapter = _ConnectedAdapter(
        server_sock=srv,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/x",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=cap,
    )
    adapter.start_worker("s")

    def _serve_oversized() -> None:
        import struct

        dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        # Declare a body far above the adapter's cap; the adapter must reject BEFORE allocating.
        wrk.sendall(struct.pack(">I", cap + 1_000_000) + b"{")

    t = threading.Thread(target=_serve_oversized, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.read_bytes("s", s.ReadBytesIn(session_id="s", address="0x1000", length=16))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1
    wrk.close()


def test_worker_crash_mid_call_is_unavailable_and_kills() -> None:
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)

    def _crash() -> None:
        dispatch.read_frame(wrk, max_frame_bytes=_CAP)
        wrk.close()  # close mid-call → EOF on the adapter's read

    t = threading.Thread(target=_crash, daemon=True)
    t.start()
    with pytest.raises(GhidraMcpError) as ei:
        adapter.list_functions("s", s.ListFunctionsIn(session_id="s"))
    t.join(timeout=2)
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE
    assert worker.killed == 1


def test_call_without_worker_is_unavailable() -> None:
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/tmp/x",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    with pytest.raises(GhidraMcpError) as ei:
        adapter.memory_map("ghost", s.MemoryMapIn(session_id="ghost"))
    assert ei.value.envelope.type is ErrorType.WORKER_UNAVAILABLE


def test_kill_worker_is_idempotent() -> None:
    worker = _FakeWorker()
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/x",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    adapter.start_worker("s")
    adapter.start_worker("s")  # idempotent spawn
    adapter.kill_worker("s")
    adapter.kill_worker("s")  # idempotent kill (no error, no double-kill of a dropped session)
    assert worker.killed == 1


def test_socket_path_uses_session_id() -> None:
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/run/ghidra-mcp/",
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
    )
    assert adapter._socket_path("abc") == "/run/ghidra-mcp/abc/abc.sock"


# --- #9: untrusted-data wrap chokepoint (ADR-005) ---------------------------------------------
def _run_with_result(method: str, args: object, result: dict[str, object]) -> object:
    """Drive ``adapter.<method>("s", args)`` against a fake worker returning ``result``.

    Args:
        method: The adapter method name to call.
        args: The input model to pass.
        result: The PLAIN (un-wrapped) result dict the fake worker replies with.

    Returns:
        The adapter's typed, wrapped output model.
    """
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    adapter = _make_adapter(srv, worker)
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    try:
        out = getattr(adapter, method)("s", args)
    finally:
        t.join(timeout=2)
        wrk.close()
    assert worker.killed == 0  # a successful wrap never kills the worker
    return out


def test_decompile_wraps_name_binary_code_ghidra() -> None:
    """Decompiler output is GHIDRA-origin; the symbol name is BINARY-origin — both untrusted."""
    out = _run_with_result(
        "decompile_function",
        s.DecompileFunctionIn(session_id="s", function="main"),
        {
            "address": "0x1000",
            "name": "main",
            "c_code": "int main(){return 0;}",
            "signature": "int main(void)",
        },
    )
    assert isinstance(out, s.DecompiledFunction)
    assert isinstance(out.name, Untrusted) and out.name.origin is DataOrigin.BINARY
    assert out.c_code.origin is DataOrigin.GHIDRA
    assert out.signature.origin is DataOrigin.GHIDRA
    assert out.c_code.value == "int main(){return 0;}"
    assert out.address == "0x1000"  # server-normalized address stays bare (safe)


def test_decompile_normalizes_bidi_injection_in_code() -> None:
    """A Trojan-Source bidi override in decompiled C is neutralized + annotated when wrapped."""
    out = _run_with_result(
        "decompile_function",
        s.DecompileFunctionIn(session_id="s", function="f"),
        {"address": "0x1", "name": "f", "c_code": "a‮b", "signature": "void f()"},
    )
    assert isinstance(out, s.DecompiledFunction)
    assert "‮" not in out.c_code.value  # neutralized to an inert <U+202E> token
    assert "<U+202E>" in out.c_code.value
    assert out.c_code.notes  # the bidi class is annotated for the client


def test_strings_wrap_binary_with_utf8_replace_encoding() -> None:
    out = _run_with_result(
        "list_strings",
        s.ListStringsIn(session_id="s"),
        {
            "strings": [{"address": "0x2000", "value": "hello", "length": 5}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.StringListOut)
    item = out.strings[0]
    assert item.value.origin is DataOrigin.BINARY
    assert item.value.encoding == "utf-8-replace"
    assert item.value.value == "hello"


def test_read_bytes_wraps_hex_binary() -> None:
    out = _run_with_result(
        "read_bytes",
        s.ReadBytesIn(session_id="s", address="0x3000", length=4),
        {"address": "0x3000", "data": "deadbeef", "length": 4, "truncated": False},
    )
    assert isinstance(out, s.ReadBytesOut)
    assert out.data.origin is DataOrigin.BINARY
    assert out.data.encoding == "hex"


def test_search_bytes_wraps_context_hex_binary() -> None:
    out = _run_with_result(
        "search_bytes",
        s.SearchBytesIn(session_id="s", pattern_hex="90"),
        {"matches": [{"address": "0x10", "context_hex": "9090"}], "total": 1, "truncated": False},
    )
    assert isinstance(out, s.SearchBytesOut)
    assert out.matches[0].context_hex.origin is DataOrigin.BINARY
    assert out.matches[0].context_hex.encoding == "hex"


def test_disassemble_wraps_mnemonic_ghidra_bytes_binary() -> None:
    out = _run_with_result(
        "disassemble",
        s.DisassembleIn(session_id="s", start="0x40"),
        {
            "instructions": [
                {"address": "0x40", "mnemonic": "MOV", "operands": "EAX, 1", "bytes_hex": "b801"}
            ],
            "truncated": True,
        },
    )
    assert isinstance(out, s.DisassembleOut)
    insn = out.instructions[0]
    assert insn.mnemonic.origin is DataOrigin.GHIDRA
    assert insn.operands.origin is DataOrigin.GHIDRA
    assert insn.bytes_hex.origin is DataOrigin.BINARY and insn.bytes_hex.encoding == "hex"
    assert out.truncated is True


def test_function_list_wraps_name_binary() -> None:
    out = _run_with_result(
        "list_functions",
        s.ListFunctionsIn(session_id="s"),
        {
            "functions": [{"address": "0x1", "name": "f", "size": 10}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.FunctionListOut)
    assert out.functions[0].name.origin is DataOrigin.BINARY
    assert out.functions[0].size == 10


def test_get_function_wraps_optional_calling_convention() -> None:
    out = _run_with_result(
        "get_function",
        s.GetFunctionIn(session_id="s", function="f"),
        {
            "address": "0x1",
            "name": "f",
            "signature": "void f()",
            "size": 4,
            "is_thunk": False,
            "calling_convention": "__cdecl",
        },
    )
    assert isinstance(out, s.FunctionDetail)
    assert out.name.origin is DataOrigin.BINARY
    assert out.signature.origin is DataOrigin.GHIDRA
    assert out.calling_convention is not None
    assert out.calling_convention.origin is DataOrigin.GHIDRA


def test_get_function_optional_calling_convention_absent_is_none() -> None:
    out = _run_with_result(
        "get_function",
        s.GetFunctionIn(session_id="s", function="f"),
        {"address": "0x1", "name": "f", "signature": "void f()", "size": 4, "is_thunk": True},
    )
    assert isinstance(out, s.FunctionDetail)
    assert out.calling_convention is None  # optional GHIDRA field passes None through unwrapped


def test_symbol_list_wraps_name_and_namespace_binary() -> None:
    out = _run_with_result(
        "list_symbols",
        s.ListSymbolsIn(session_id="s"),
        {
            "symbols": [
                {"address": "0x1", "name": "sym", "kind": "LABEL", "namespace": "ns"},
                {"address": "0x2", "name": "sym2", "kind": "IMPORT"},
            ],
            "total": 2,
            "truncated": False,
        },
    )
    assert isinstance(out, s.SymbolListOut)
    assert out.symbols[0].name.origin is DataOrigin.BINARY
    assert out.symbols[0].namespace is not None
    assert out.symbols[0].namespace.origin is DataOrigin.BINARY
    assert out.symbols[1].namespace is None  # optional absent → None


def test_get_symbol_wraps_single() -> None:
    out = _run_with_result(
        "get_symbol",
        s.GetSymbolIn(session_id="s", identifier="sym"),
        {"address": "0x1", "name": "sym", "kind": "FUNCTION", "namespace": None},
    )
    assert isinstance(out, s.Symbol)
    assert out.name.origin is DataOrigin.BINARY


def test_data_list_wraps_type_ghidra_value_binary() -> None:
    out = _run_with_result(
        "list_data",
        s.ListDataIn(session_id="s"),
        {
            "data": [
                {"address": "0x1", "data_type": "char[4]", "value_repr": '"abc"', "length": 4}
            ],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.DataListOut)
    assert out.data[0].data_type.origin is DataOrigin.GHIDRA
    assert out.data[0].value_repr.origin is DataOrigin.BINARY


def test_get_data_type_wraps_ghidra() -> None:
    out = _run_with_result(
        "get_data_type",
        s.GetDataTypeIn(session_id="s", name="my_struct"),
        {"name": "my_struct", "kind": "struct", "size": 8, "definition": "struct {int a;}"},
    )
    assert isinstance(out, s.DataType)
    assert out.name.origin is DataOrigin.GHIDRA
    assert out.definition.origin is DataOrigin.GHIDRA


def test_comments_wrap_text_binary() -> None:
    out = _run_with_result(
        "get_comments",
        s.GetCommentsIn(session_id="s"),
        {
            "comments": [{"address": "0x1", "comment_type": "EOL", "text": "planted"}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.CommentListOut)
    assert out.comments[0].text.origin is DataOrigin.BINARY


def test_memory_map_wraps_block_name_binary() -> None:
    out = _run_with_result(
        "memory_map",
        s.MemoryMapIn(session_id="s"),
        {
            "blocks": [
                {
                    "name": ".text",
                    "start": "0x1000",
                    "end": "0x2000",
                    "size": 4096,
                    "permissions": "r-x",
                    "initialized": True,
                }
            ]
        },
    )
    assert isinstance(out, s.MemoryMapOut)
    assert out.blocks[0].name.origin is DataOrigin.BINARY
    assert out.blocks[0].permissions == "r-x"  # derived flags stay bare


def test_xrefs_have_no_untrusted_fields() -> None:
    out = _run_with_result(
        "xrefs_to",
        s.XrefsIn(session_id="s", target="0x1"),
        {
            "xrefs": [{"from_address": "0x1", "to_address": "0x2", "ref_type": "CALL"}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.XrefsOut)
    assert out.xrefs[0].ref_type == "CALL"  # all-safe; no wrap needed


def test_xrefs_from_round_trip() -> None:
    out = _run_with_result(
        "xrefs_from",
        s.XrefsIn(session_id="s", target="0x1"),
        {
            "xrefs": [{"from_address": "0x1", "to_address": "0x3", "ref_type": "DATA"}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.XrefsOut)
    assert out.xrefs[0].ref_type == "DATA"


def test_search_strings_wraps_like_list_strings() -> None:
    out = _run_with_result(
        "search_strings",
        s.SearchStringsIn(session_id="s", query="pw"),
        {
            "strings": [{"address": "0x9", "value": "password", "length": 8}],
            "total": 1,
            "truncated": False,
        },
    )
    assert isinstance(out, s.SearchStringsOut)
    assert out.strings[0].value.origin is DataOrigin.BINARY
    assert out.strings[0].value.encoding == "utf-8-replace"


def test_program_metadata_wraps_compiler_binary_rest_bare() -> None:
    out = _run_with_result(
        "program_metadata",
        s.ProgramMetadataIn(session_id="s"),
        {
            "sha256": "a" * 64,
            "size_bytes": 100,
            "format": "ELF",
            "architecture": "x86:LE:64",
            "endianness": "little",
            "compiler": "gcc",
            "entry_point": "0x1040",
            "function_count": 3,
            "analysis_complete": True,
        },
    )
    assert isinstance(out, s.ProgramMetadata)
    assert out.compiler is not None and out.compiler.origin is DataOrigin.BINARY
    assert out.format == "ELF"  # Ghidra-classified, safe
    assert out.entry_point == "0x1040"


def test_program_metadata_optional_fields_none() -> None:
    out = _run_with_result(
        "program_metadata",
        s.ProgramMetadataIn(session_id="s"),
        {
            "sha256": "a" * 64,
            "size_bytes": 100,
            "format": "ELF",
            "architecture": "x86:LE:64",
            "endianness": "little",
            "compiler": None,
            "entry_point": None,
            "function_count": 0,
            "analysis_complete": False,
        },
    )
    assert isinstance(out, s.ProgramMetadata)
    assert out.compiler is None
    assert out.entry_point is None


# --- #9: pre-Ghidra binary-size cap in import_binary ------------------------------------------
def _import_adapter(
    server_sock: socket.socket,
    worker: _FakeWorker,
    *,
    limits: Limits,
    resolver: Callable[[str], int],
) -> _ConnectedAdapter:
    """Build an adapter with injected ``limits`` + ``source_resolver`` for import tests."""
    adapter = _ConnectedAdapter(
        server_sock=server_sock,
        launcher=lambda sid, path: worker,
        socket_dir="/tmp/ghidra-mcp-test",  # noqa: S108  # test-only path; no real socket bound
        tool_timeout_s=1.0,
        analysis_timeout_s=1.0,
        max_response_bytes=_CAP,
        limits=limits,
        source_resolver=resolver,
    )
    adapter.start_worker("s")
    return adapter


def test_import_rejects_oversize_binary_before_worker() -> None:
    """An over-cap binary is rejected pre-Ghidra: no RPC is sent and the worker is never fed."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    limits = Limits(max_binary_bytes=1024)
    adapter = _import_adapter(srv, worker, limits=limits, resolver=lambda ref: 1025)
    with pytest.raises(GhidraMcpError) as ei:
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="big"))
    assert ei.value.envelope.type is ErrorType.LIMIT_EXCEEDED
    assert worker.killed == 0  # pre-flight rejection: worker untouched
    srv.close()
    wrk.close()


def test_import_unresolvable_source_is_validation_error() -> None:
    """A ``source_ref`` the resolver cannot stat fails closed as VALIDATION (no leak, no worker)."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()

    def _boom(ref: str) -> int:
        raise FileNotFoundError("/secret/host/path")  # detail must NOT cross the boundary

    adapter = _import_adapter(srv, worker, limits=Limits(), resolver=_boom)
    with pytest.raises(GhidraMcpError) as ei:
        adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="missing"))
    assert ei.value.envelope.type is ErrorType.VALIDATION
    assert "secret" not in ei.value.envelope.detail
    srv.close()
    wrk.close()


def test_import_within_cap_feeds_worker() -> None:
    """A within-cap binary passes the check and the import RPC reaches the worker."""
    srv, wrk = socket.socketpair(socket.AF_UNIX)
    worker = _FakeWorker()
    limits = Limits(max_binary_bytes=4096)
    adapter = _import_adapter(srv, worker, limits=limits, resolver=lambda ref: 4096)
    result = {
        "session_id": "s",
        "state": "importing",
        "created_at": 1,
        "expires_at": 2,
        "binary_sha256": "b" * 64,
    }
    t = threading.Thread(
        target=_serve_one, args=(wrk, {"jsonrpc": "2.0", "result": result}), daemon=True
    )
    t.start()
    info = adapter.import_binary("s", s.SessionImportIn(session_id="s", source_ref="ok"))
    t.join(timeout=2)
    assert info.state == "importing"
    assert worker.killed == 0
    wrk.close()


def test_default_source_resolver_stats_a_real_file(tmp_path: Path) -> None:
    """The built-in resolver returns the on-disk size (used when no confined resolver is wired)."""
    from ghidra_mcp.ghidra.rpc_client import _default_source_size

    f = tmp_path / "blob.bin"
    f.write_bytes(b"abcd")
    assert _default_source_size(str(f)) == 4


def test_ensure_connected_dials_real_uds(tmp_path: Path) -> None:
    """The real ``_ensure_connected`` connects to the per-session UDS and round-trips a call.

    Uses a genuinely bound listening UDS (no socketpair, no subclass override) so the adapter's
    own connect path is exercised — then a within-process 'worker' thread accepts and replies.
    """
    sock_dir = str(tmp_path)
    worker = _FakeWorker()
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: worker,
        socket_dir=sock_dir,
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
    )
    adapter.start_worker("s")
    sock_path = adapter._socket_path("s")
    Path(sock_path).parent.mkdir(parents=True, exist_ok=True)  # per-session subdir (ADR-009)

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(1)

    _resp = {
        "jsonrpc": "2.0",
        "result": {"address": "0x1", "name": "main", "c_code": "x", "signature": "void main()"},
    }

    def _serve() -> None:
        conn, _ = listener.accept()
        try:
            _serve_one(conn, dict(_resp))  # first call: fresh connect
            _serve_one(conn, dict(_resp))  # second call: reuses the cached socket
        finally:
            conn.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    out1 = adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    # Second call on the same session reuses the cached socket (covers the cached-socket branch).
    out2 = adapter.decompile_function("s", s.DecompileFunctionIn(session_id="s", function="main"))
    t.join(timeout=3)
    assert out1.name.value == "main"
    assert out2.name.value == "main"
    assert worker.killed == 0
    adapter.kill_worker("s")  # closes the connected socket
    listener.close()


def test_ensure_connected_retries_until_worker_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The connect retries past the worker-bind race (ENOENT/ECONNREFUSED), not one-shot.

    The spawn (`podman run --detach`) returns before the worker binds its UDS; a single connect
    would lose the race and fail closed as worker-unavailable. Here connect fails twice (not bound
    yet) then succeeds — the adapter must keep trying within the connect budget.
    """
    from ghidra_mcp.ghidra import rpc_client as rc

    # String targets (not rc.time/rc.socket attribute access) so --strict mypy doesn't flag the
    # imported modules as non-reexported attributes; monkeypatch resolves them on the module.
    monkeypatch.setattr("ghidra_mcp.ghidra.rpc_client.time.sleep", lambda *_: None)
    attempts = {"n": 0}

    class _FlakySock:
        def settimeout(self, *_: object) -> None: ...

        def connect(self, path: str) -> None:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise FileNotFoundError(path)  # socket not bound yet

        def close(self) -> None: ...

    monkeypatch.setattr("ghidra_mcp.ghidra.rpc_client.socket.socket", lambda *a, **k: _FlakySock())
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/run/x",
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
        connect_timeout_s=5.0,
    )
    sess = rc._Session(_FakeWorker(), "/run/x/s/s.sock")
    got = adapter._ensure_connected(sess)
    assert attempts["n"] == 3
    assert got is sess.sock


def test_ensure_connected_gives_up_after_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that never binds within the budget makes connect raise (→ worker-unavailable)."""
    from ghidra_mcp.ghidra import rpc_client as rc

    monkeypatch.setattr("ghidra_mcp.ghidra.rpc_client.time.sleep", lambda *_: None)
    clock = iter([0.0, 100.0])  # start, then a check already past the connect budget
    monkeypatch.setattr("ghidra_mcp.ghidra.rpc_client.time.monotonic", lambda: next(clock))

    class _DeadSock:
        def settimeout(self, *_: object) -> None: ...

        def connect(self, path: str) -> None:
            raise ConnectionRefusedError(path)  # bound but never accepting

        def close(self) -> None: ...

    monkeypatch.setattr("ghidra_mcp.ghidra.rpc_client.socket.socket", lambda *a, **k: _DeadSock())
    adapter = RpcGhidraAdapter(
        launcher=lambda sid, path: _FakeWorker(),
        socket_dir="/run/x",
        tool_timeout_s=2.0,
        analysis_timeout_s=2.0,
        max_response_bytes=_CAP,
        connect_timeout_s=5.0,
    )
    sess = rc._Session(_FakeWorker(), "/run/x/s/s.sock")
    with pytest.raises(ConnectionRefusedError):
        adapter._ensure_connected(sess)


# --- worker dispatcher (JVM-free) -------------------------------------------------------------
class _FakeBackend:
    """A fake :class:`worker.dispatch.GhidraBackend` recording calls and returning canned dicts."""

    def __init__(self) -> None:
        """Initialize with no recorded calls."""
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __getattr__(self, name: str) -> Callable[[dict[str, object]], dict[str, object]]:
        """Return a handler that records the call and echoes the method name."""

        def handler(params: dict[str, object]) -> dict[str, object]:
            self.calls.append((name, params))
            return {"method": name}

        return handler


def test_dispatch_ping_and_shutdown_bypass_backend() -> None:
    be = _FakeBackend()
    assert dispatch.dispatch(be, "ping", {}) == {"ok": True}
    assert dispatch.dispatch(be, "shutdown", {}) == {"ok": True}
    assert be.calls == []  # neither touched the backend


def test_handle_request_unknown_method() -> None:
    resp = dispatch.handle_request(_FakeBackend(), {"jsonrpc": "2.0", "id": "1", "method": "nope"})
    assert (
        resp["error"]["data"]["type"] == "internal-error"
        or resp["error"]["code"] == dispatch.CODE_METHOD_NOT_FOUND
    )


def test_handle_request_bad_envelope() -> None:
    resp = dispatch.handle_request(_FakeBackend(), {"id": "1", "method": "ping"})
    assert resp["error"]["code"] == dispatch.CODE_INVALID_REQUEST


def test_handle_request_non_dict_params() -> None:
    resp = dispatch.handle_request(
        _FakeBackend(), {"jsonrpc": "2.0", "id": "1", "method": "ping", "params": [1]}
    )
    assert resp["error"]["code"] == dispatch.CODE_INVALID_PARAMS


def test_handle_request_backend_worker_error_maps_slug() -> None:
    class _Boom:
        def list_strings(self, params: dict[str, object]) -> dict[str, object]:
            raise dispatch.WorkerError(dispatch.CODE_NOT_FOUND, "missing")

    resp = dispatch.handle_request(
        cast("dispatch.GhidraBackend", _Boom()),
        {"jsonrpc": "2.0", "id": "1", "method": "list_strings", "params": {}},
    )
    assert resp["error"]["data"]["type"] == "not-found"


def test_handle_request_unexpected_exception_is_internal_only() -> None:
    class _Boom:
        def memory_map(self, params: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("/secret/host/path leaked")  # must NOT cross the boundary

    resp = dispatch.handle_request(
        cast("dispatch.GhidraBackend", _Boom()),
        {"jsonrpc": "2.0", "id": "1", "method": "memory_map", "params": {}},
    )
    assert resp["error"]["code"] == dispatch.CODE_INTERNAL
    assert "secret" not in resp["error"]["message"]  # no host detail leaked


def test_handle_request_success() -> None:
    be = _FakeBackend()
    resp = dispatch.handle_request(
        be, {"jsonrpc": "2.0", "id": "9", "method": "program_metadata", "params": {}}
    )
    assert resp["result"] == {"method": "program_metadata"}
    assert resp["id"] == "9"


def test_serve_connection_round_trip_then_shutdown() -> None:
    a, b = socket.socketpair(socket.AF_UNIX)
    be = _FakeBackend()
    server_thread = threading.Thread(
        target=dispatch.serve_connection,
        args=(a,),
        kwargs={"backend": be, "max_frame_bytes": _CAP},
        daemon=True,
    )
    server_thread.start()
    # client: send a list_functions request, read the reply, then shutdown.
    b.sendall(
        rpc_framing.encode_frame(
            rpc_framing.build_request("r1", "list_functions", {"offset": 0}),
            max_frame_bytes=_CAP,
        )
    )
    reply = dispatch.read_frame(b, max_frame_bytes=_CAP)
    assert rpc_framing.parse_response(reply, expected_id="r1") == {"method": "list_functions"}
    b.sendall(
        rpc_framing.encode_frame(
            rpc_framing.build_request("r2", "shutdown", {}), max_frame_bytes=_CAP
        )
    )
    dispatch.read_frame(b, max_frame_bytes=_CAP)  # shutdown ack
    server_thread.join(timeout=2)
    assert not server_thread.is_alive()
    a.close()
    b.close()


def test_serve_connection_protocol_violation_closes() -> None:
    a, b = socket.socketpair(socket.AF_UNIX)
    be = _FakeBackend()
    server_thread = threading.Thread(
        target=dispatch.serve_connection,
        args=(a,),
        kwargs={"backend": be, "max_frame_bytes": 8},
        daemon=True,
    )
    server_thread.start()
    import struct

    b.sendall(struct.pack(">I", 1_000_000) + b"x")  # declared length over the 8-byte cap
    server_thread.join(timeout=2)
    assert not server_thread.is_alive()  # loop returned on FramingError
    a.close()
    b.close()
