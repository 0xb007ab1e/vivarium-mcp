"""Unit tests for HTTP-transport config + fail-closed startup validation (v1.1 — ADR-011 / TB6).

Hermetic: ``load_config`` reads an injected ``env`` mapping, never the real environment. Covers the
secure-by-default rules — a misconfigured network bind must refuse to boot (master §2).
"""

from __future__ import annotations

import pytest

from ghidra_mcp.config import load_config
from ghidra_mcp.core.errors import GhidraMcpError

_WORKER = {"GHIDRA_MCP_WORKER_IMAGE": "ghcr.io/x/worker@sha256:" + "a" * 64}
_TOKEN = "s" * 24  # >= _MIN_BEARER_TOKEN_LEN


def _env(**extra: str) -> dict[str, str]:
    return {**_WORKER, **extra}


def test_default_transport_is_stdio_no_http_config() -> None:
    cfg = load_config(_env())
    assert cfg.transport == "stdio"
    assert cfg.http is None


def test_http_loopback_default_is_plaintext_unauthenticated() -> None:
    cfg = load_config(_env(GHIDRA_MCP_TRANSPORT="http"))
    assert cfg.transport == "http" and cfg.http is not None
    h = cfg.http
    assert h.bind == "127.0.0.1:8765"
    assert h.is_network is False and h.is_unix_socket is False
    assert h.auth_mode == "none" and h.bearer_token is None and h.tls_cert is None
    assert h.rate_per_second == 10 and h.rate_burst == 20 and h.max_body_bytes == 1_048_576


def test_unix_socket_bind_is_not_network() -> None:
    cfg = load_config(_env(GHIDRA_MCP_TRANSPORT="http", GHIDRA_MCP_HTTP_BIND="unix:/run/gmcp.sock"))
    assert cfg.http is not None
    assert cfg.http.is_unix_socket is True and cfg.http.is_network is False
    assert cfg.http.auth_mode == "none"


def test_network_bind_without_tls_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="requires TLS"):
        load_config(_env(GHIDRA_MCP_TRANSPORT="http", GHIDRA_MCP_HTTP_BIND="0.0.0.0:8765"))


def test_network_bind_with_tls_but_no_auth_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="requires an authenticator"):
        load_config(
            _env(
                GHIDRA_MCP_TRANSPORT="http",
                GHIDRA_MCP_HTTP_BIND="0.0.0.0:8765",
                GHIDRA_MCP_HTTP_TLS_CERT="/c.pem",
                GHIDRA_MCP_HTTP_TLS_KEY="/k.pem",
                GHIDRA_MCP_HTTP_AUTH="none",
            )
        )


def test_network_bind_with_tls_and_bearer_is_valid() -> None:
    cfg = load_config(
        _env(
            GHIDRA_MCP_TRANSPORT="http",
            GHIDRA_MCP_HTTP_BIND="0.0.0.0:8765",
            GHIDRA_MCP_HTTP_TLS_CERT="/c.pem",
            GHIDRA_MCP_HTTP_TLS_KEY="/k.pem",
            GHIDRA_MCP_HTTP_BEARER_TOKEN=_TOKEN,
        )
    )
    assert cfg.http is not None
    h = cfg.http
    assert h.is_network is True and h.auth_mode == "bearer" and h.bearer_token == _TOKEN
    assert h.tls_cert == "/c.pem" and h.tls_key == "/k.pem"


@pytest.mark.parametrize("token", ["", "short", "x" * 15])
def test_bearer_auth_requires_long_token(token: str) -> None:
    env = _env(GHIDRA_MCP_TRANSPORT="http", GHIDRA_MCP_HTTP_AUTH="bearer")
    if token:
        env["GHIDRA_MCP_HTTP_BEARER_TOKEN"] = token
    with pytest.raises(GhidraMcpError, match="bearer auth requires a token"):
        load_config(env)


def test_tls_cert_without_key_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="both be set or both unset"):
        load_config(_env(GHIDRA_MCP_TRANSPORT="http", GHIDRA_MCP_HTTP_TLS_CERT="/c.pem"))


def test_wildcard_cors_rejected() -> None:
    with pytest.raises(GhidraMcpError, match="CORS origins must be explicit"):
        load_config(_env(GHIDRA_MCP_TRANSPORT="http", GHIDRA_MCP_HTTP_CORS_ORIGINS="*"))


def test_cors_origins_parsed_comma_separated() -> None:
    cfg = load_config(
        _env(
            GHIDRA_MCP_TRANSPORT="http",
            GHIDRA_MCP_HTTP_CORS_ORIGINS="https://a.example, https://b.example",
        )
    )
    assert cfg.http is not None
    assert cfg.http.cors_origins == ("https://a.example", "https://b.example")


@pytest.mark.parametrize("bind", ["nope", "host:notaport", "host:0", "host:99999", "unix:"])
def test_malformed_bind_fails_closed(bind: str) -> None:
    with pytest.raises(GhidraMcpError):
        load_config(_env(GHIDRA_MCP_TRANSPORT="http", GHIDRA_MCP_HTTP_BIND=bind))


def test_ipv6_loopback_bind_is_not_network() -> None:
    cfg = load_config(_env(GHIDRA_MCP_TRANSPORT="http", GHIDRA_MCP_HTTP_BIND="[::1]:8765"))
    assert cfg.http is not None and cfg.http.is_network is False


def test_bearer_token_excluded_from_repr() -> None:
    cfg = load_config(
        _env(
            GHIDRA_MCP_TRANSPORT="http",
            GHIDRA_MCP_HTTP_BIND="127.0.0.1:8765",
            GHIDRA_MCP_HTTP_AUTH="bearer",
            GHIDRA_MCP_HTTP_BEARER_TOKEN=_TOKEN,
        )
    )
    assert cfg.http is not None
    assert _TOKEN not in repr(cfg.http)  # secret must not leak via repr/logs


def test_invalid_transport_and_auth_rejected() -> None:
    with pytest.raises(GhidraMcpError):
        load_config(_env(GHIDRA_MCP_TRANSPORT="grpc"))
    with pytest.raises(GhidraMcpError):
        load_config(_env(GHIDRA_MCP_TRANSPORT="http", GHIDRA_MCP_HTTP_AUTH="kerberos"))
