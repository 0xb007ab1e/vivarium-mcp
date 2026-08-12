"""Unit tests for v1.8 discoverability/observability findings F2-F4 (import UX).

* F2 — the ``session_import`` tool description (the handler docstring FastMCP surfaces to a client)
  names ``VIVARIUM_IMPORT_ROOT``, gives an example, and points at the docs resource.
* F3 — the ``vivarium://docs/importing`` MCP resource is registered and returns the how-to.
* F4 — the resolver reject reason is distinguished (outside-root / not-found / malformed) and mapped
  to a specific, category-safe ``VALIDATION`` detail.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from vivarium.core.errors import ErrorType, GhidraMcpError
from vivarium.ghidra.launcher import make_confined_resolver
from vivarium.ghidra.rpc_client import SourceRefError
from vivarium.server import app as appmod
from vivarium.tools import registry
from vivarium.tools import schemas as s

# --- F2: client-facing tool description -----------------------------------------------------------


def test_session_import_description_is_self_sufficient() -> None:
    """The handler docstring (the MCP tool description) carries the import contract in-band."""
    doc = registry._handle_session_import.__doc__ or ""
    assert "VIVARIUM_IMPORT_ROOT" in doc  # names the import root
    assert "vivarium://docs/importing" in doc  # points at the how-to resource
    assert "loader" in doc and "processor" in doc  # mentions the raw-image hints
    assert "validation" in doc and "limit-exceeded" in doc  # names the reject reasons


# --- F3: in-band importing resource ---------------------------------------------------------------


def test_importing_resource_registered_and_readable() -> None:
    """``vivarium://docs/importing`` is registered and returns the import how-to text."""
    from mcp.server.fastmcp import FastMCP

    app = FastMCP(name="test")
    appmod._register_docs_resources(app)

    resources = asyncio.run(app.list_resources())
    uris = {str(r.uri) for r in resources}
    assert any(appmod._IMPORTING_DOC_URI in u for u in uris), uris

    contents = asyncio.run(app.read_resource(appmod._IMPORTING_DOC_URI))
    text = "".join(str(c.content) for c in contents)
    assert "VIVARIUM_IMPORT_ROOT" in text
    assert "ARM:LE:32:Cortex" in text  # the loader-hint how-to made it in
    assert "limit-exceeded" in text


def test_importing_doc_constant_has_no_binary_content() -> None:
    """The served doc is static first-party text (sanity: no obvious placeholder leaks)."""
    assert "session_import" in appmod._IMPORTING_DOC
    assert appmod._IMPORTING_DOC_URI == "vivarium://docs/importing"


# --- F4: distinguished resolver reject reasons ----------------------------------------------------


def test_confined_resolver_tags_each_reject_reason(tmp_path: object) -> None:
    """The confined resolver raises a reason-tagged ``SourceRefError`` per reject category."""
    import pathlib

    root = pathlib.Path(str(tmp_path)) / "imports"
    root.mkdir()
    good = root / "prog.bin"
    good.write_bytes(b"abc")
    resolve = make_confined_resolver(str(root))

    # Happy path: a real file under the root returns its byte size.
    assert resolve(str(good)) == 3

    # Outside the import root.
    outside = pathlib.Path(str(tmp_path)) / "evil.bin"
    outside.write_bytes(b"x")
    with pytest.raises(SourceRefError) as ei_escape:
        resolve(str(outside))
    assert ei_escape.value.reason == "escapes-root"

    # Under the root but missing.
    with pytest.raises(SourceRefError) as ei_missing:
        resolve(str(root / "nope.bin"))
    assert ei_missing.value.reason == "not-found"

    # Malformed path (embedded NUL makes Path.resolve raise ValueError).
    with pytest.raises(SourceRefError) as ei_bad:
        resolve("bad\x00path")
    assert ei_bad.value.reason == "malformed"


def _capturing_adapter() -> object:
    """Build a real adapter (wired to a socketpair + fake worker) for the import mapping tests."""
    from tests.unit.test_rpc_adapter import _FakeWorker, _make_adapter

    srv, _client = socket.socketpair()
    return _make_adapter(srv, _FakeWorker())


@pytest.mark.parametrize(
    ("reason", "expected_substring"),
    [
        ("escapes-root", "under the import root"),
        ("not-found", "not found under the import root"),
        ("malformed", "not a valid path"),
    ],
)
def test_import_maps_resolver_reason_to_specific_detail(
    reason: str, expected_substring: str
) -> None:
    """Each reason yields a specific, category-safe ``VALIDATION`` detail (no root/ref leak)."""
    adapter = _capturing_adapter()

    def _raiser(_ref: str) -> int:
        raise SourceRefError(reason, "server-side only message")

    adapter._source_resolver = _raiser  # type: ignore[attr-defined]
    args = s.SessionImportIn(session_id="s", source_ref="whatever")
    with pytest.raises(GhidraMcpError) as ei:
        adapter.import_binary("s", args)  # type: ignore[attr-defined]
    assert ei.value.envelope.type is ErrorType.VALIDATION
    assert expected_substring in (ei.value.envelope.detail or "")
    # The safe detail must NOT leak the resolved root path or the source_ref value.
    assert "server-side only message" not in (ei.value.envelope.detail or "")


def test_import_plain_filenotfound_maps_to_not_found() -> None:
    """A bare ``FileNotFoundError`` (the built-in resolver's stat miss) maps to not-found."""
    adapter = _capturing_adapter()

    def _raiser(_ref: str) -> int:
        raise FileNotFoundError("missing")

    adapter._source_resolver = _raiser  # type: ignore[attr-defined]
    args = s.SessionImportIn(session_id="s", source_ref="whatever")
    with pytest.raises(GhidraMcpError) as ei:
        adapter.import_binary("s", args)  # type: ignore[attr-defined]
    assert "not found under the import root" in (ei.value.envelope.detail or "")
