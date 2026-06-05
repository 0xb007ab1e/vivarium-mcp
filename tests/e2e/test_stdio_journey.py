"""E2E: primary MCP stdio journey with a FakeGhidraPort injected (WS5 scaffold).

Drives the server as an MCP client would over the **stdio** transport (PLAN §3, ADR-006), with
the in-process :class:`tests.conftest.FakeGhidraPort` substituted for the real Ghidra adapter at
the composition root — so the full server shell (tool registry, validation, session manager,
untrusted/error envelope mapping) is exercised end-to-end **without** a real worker or gated image
pull.

Primary journey: ``session_create`` → ``session_import`` (synthetic ELF) → ``session_analyze`` →
``decompile_function`` / ``list_strings`` / ``search_strings`` → ``session_close``, asserting at
each step that binary-derived fields arrive wrapped in the untrusted-data envelope and failures
arrive as a leak-free error envelope.

Skipped by ``tests/e2e/conftest.py`` until the WS1 server shell is implemented; activates
automatically in Wave-2. Synthetic fixtures only — never real malware (master §5, PLAN §6).
"""

from __future__ import annotations

import pytest

from tests._fixtures import build_elf64


def test_full_read_only_journey_over_stdio(fake_port: object) -> None:
    """Open → import → analyze → read-only tools → close over stdio with the fake adapter.

    Asserts (once wired): each tool result validates against its frozen output schema, every
    binary-derived field is an ``Untrusted`` wrapper (TB4), and ``session_close`` reports
    ``store_wiped=True``.
    """
    elf = build_elf64()
    assert elf[:4] == b"\x7fELF"
    pytest.skip(
        "WS5 Wave-2: build_app(config, session_manager, port=fake_port) and drive the stdio "
        "client through the journey once WS1 wires the FastMCP app + tool registry"
    )


def test_unknown_session_id_is_bola_safe_over_stdio(fake_port: object) -> None:
    """A tool call with a foreign/unknown ``session_id`` returns ``SESSION_INVALID`` (BOLA-safe).

    The error must be identical whether or not other sessions exist (no existence oracle) and must
    not leak internals (assert via ``assert_error_envelope``).
    """
    pytest.skip("WS5 Wave-2: drive an unknown session_id over stdio and assert BOLA-safe envelope")


def test_oversize_argument_rejected_at_boundary_over_stdio(fake_port: object) -> None:
    """An over-cap tool argument is rejected with a ``VALIDATION`` envelope before the port.

    Confirms the server validates at TB1 (the fake port should never be called for a rejected arg).
    """
    pytest.skip("WS5 Wave-2: send an over-cap argument and assert VALIDATION before port dispatch")
