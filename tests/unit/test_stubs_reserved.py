"""Guard tests: WS1-WS5 stubs are reserved (raise NotImplementedError) with frozen signatures.

These lock the interface the build workstreams implement against, exercise the stub bodies for
coverage, and will turn red the moment a stub is implemented — prompting the implementer to
replace the guard with real behavior tests (a deliberate, visible TODO in the suite).

They also assert module-level constants that are part of the frozen contract.
"""

from __future__ import annotations

import pytest

from ghidra_mcp.core import validation as v


def test_validation_constants_frozen() -> None:
    assert v.MAX_NAME_LEN == 1024
    assert v.MAX_QUERY_LEN == 4096
    assert v.MAX_READ_BYTES == 1_048_576
    assert v.MAX_RESULT_COUNT == 10_000


@pytest.mark.critical
def test_validation_stubs_reserved() -> None:
    with pytest.raises(NotImplementedError):
        v.parse_address("0x1000")
    with pytest.raises(NotImplementedError):
        v.validate_name("main")
    with pytest.raises(NotImplementedError):
        v.validate_byte_range(0, 16)


def test_limits_defaults_and_clamps_present() -> None:
    from ghidra_mcp.security import limits as lim

    assert lim.DEFAULT_MAX_BINARY_BYTES == 128 * 1024 * 1024
    assert lim.HARD_MAX_BINARY_BYTES == 1024 * 1024 * 1024
    # Default dataclass is constructible with safe defaults.
    defaults = lim.Limits()
    assert defaults.max_sessions == lim.DEFAULT_MAX_SESSIONS


@pytest.mark.critical
def test_limits_stubs_reserved() -> None:
    from ghidra_mcp.security import limits as lim

    with pytest.raises(NotImplementedError):
        lim.resolve_limits({"max_sessions": 2})
    with pytest.raises(NotImplementedError):
        lim.check_binary_size(10, lim.Limits())


def test_session_manager_stubs_reserved() -> None:
    from ghidra_mcp.sessions.manager import SessionManager

    mgr = SessionManager()
    with pytest.raises(NotImplementedError):
        mgr.create()
    with pytest.raises(NotImplementedError):
        mgr.authorize("sid")
    with pytest.raises(NotImplementedError):
        mgr.evict("sid", reason="close")
    with pytest.raises(NotImplementedError):
        mgr.reap_expired()
    with pytest.raises(NotImplementedError):
        mgr.shutdown()


def test_config_and_logging_stubs_reserved() -> None:
    from ghidra_mcp import config, logging as glog

    with pytest.raises(NotImplementedError):
        config.load_config()
    with pytest.raises(NotImplementedError):
        glog.configure_logging()
    # get_logger is real (thin wrapper) — must return a logger, not raise.
    assert glog.get_logger("test").name == "test"


def test_server_stubs_reserved() -> None:
    from ghidra_mcp.server import app

    with pytest.raises(NotImplementedError):
        app.build_app(None, session_manager=None)
    with pytest.raises(NotImplementedError):
        app.run_stdio(None)


def test_tools_registry_stub_reserved() -> None:
    from ghidra_mcp.tools.registry import register_tools

    with pytest.raises(NotImplementedError):
        register_tools()


def test_ghidra_adapter_and_envelope_wrap_stubs_reserved() -> None:
    from ghidra_mcp.core.envelope import wrap
    from ghidra_mcp.ghidra.rpc_client import RpcGhidraAdapter

    with pytest.raises(NotImplementedError):
        RpcGhidraAdapter()
    with pytest.raises(NotImplementedError):
        wrap("x")


def test_main_entrypoint_stub_reserved() -> None:
    from ghidra_mcp.__main__ import main

    with pytest.raises(NotImplementedError):
        main()
