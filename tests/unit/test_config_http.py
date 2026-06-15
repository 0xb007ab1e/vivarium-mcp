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
    # ADR-017: an absent token fails "requires at least one token"; a present-but-short one fails
    # the per-token length floor in the multi-token loader ("token is too short"). Both fail closed
    # at startup as VALIDATION; the 16-char floor is mentioned in either path.
    with pytest.raises(GhidraMcpError, match="16 characters"):
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


# ==============================================================================================
# Multi-principal bearer token map (ADR-017): {token: principal-id} from the env, fail-closed.
# ==============================================================================================
_TOKEN_A = "a" * 24  # test fixture, not a real secret
_TOKEN_B = "b" * 24  # test fixture, not a real secret


def _bearer_env(**extra: str) -> dict[str, str]:
    return _env(
        GHIDRA_MCP_TRANSPORT="http",
        GHIDRA_MCP_HTTP_BIND="127.0.0.1:8765",
        GHIDRA_MCP_HTTP_AUTH="bearer",
        **extra,
    )


def test_single_token_back_compat_maps_to_bearer_principal() -> None:
    cfg = load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKEN=_TOKEN))
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN: "bearer"}


def test_multi_token_map_parsed_from_pairs() -> None:
    cfg = load_config(
        _bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}, bob:{_TOKEN_B}")
    )
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN_A: "alice", _TOKEN_B: "bob"}


def test_multi_token_map_combines_with_single_token() -> None:
    cfg = load_config(
        _bearer_env(
            GHIDRA_MCP_HTTP_BEARER_TOKEN=_TOKEN,
            GHIDRA_MCP_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}",
        )
    )
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN_A: "alice", _TOKEN: "bearer"}


def test_multi_token_secrets_excluded_from_repr() -> None:
    cfg = load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}"))
    assert cfg.http is not None
    assert _TOKEN_A not in repr(cfg.http)  # the token KEYS are secrets — not in repr


def test_multi_token_short_token_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="too short"):
        load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS="alice:short"))


def test_multi_token_missing_separator_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="id:token"):
        load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=_TOKEN_A))  # no "id:" prefix


def test_multi_token_empty_id_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="empty id"):
        load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=f":{_TOKEN_A}"))


@pytest.mark.parametrize("bad_id", ["has space", "rtl‮id", "a/b", "x" * 65])
def test_multi_token_bad_principal_id_fails_closed(bad_id: str) -> None:
    with pytest.raises(GhidraMcpError):
        load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=f"{bad_id}:{_TOKEN_A}"))


def test_multi_token_ambiguous_token_two_principals_fails_closed() -> None:
    """One token mapping to two principals makes ownership non-deterministic → refuse to boot."""
    with pytest.raises(GhidraMcpError, match="one token to two principals"):
        load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}\nbob:{_TOKEN_A}"))


def test_multi_token_newline_separated_pairs() -> None:
    cfg = load_config(
        _bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}\nbob:{_TOKEN_B}")
    )
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN_A: "alice", _TOKEN_B: "bob"}


def test_multi_token_ignores_blank_items_from_trailing_separators() -> None:
    """Empty items (trailing/extra commas or blank lines) are skipped, not errors."""
    cfg = load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}, ,\n"))
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN_A: "alice"}


def test_multi_token_value_too_long_fails_closed() -> None:
    """An oversized token-map value is rejected at startup (bounds startup input — CWE-400)."""
    huge = ",".join(f"p{i}:{'x' * 24}" for i in range(1000))
    with pytest.raises(GhidraMcpError, match="is too long"):
        load_config(_bearer_env(GHIDRA_MCP_HTTP_BEARER_TOKENS=huge))


# ==============================================================================================
# mTLS config (ADR-019 increment A): client-CA bundle (required for mtls) + principal-field
# selector (validated allow-list). The CA path / field are NOT secrets. Fail-closed startup.
# ==============================================================================================
def _mtls_env(**extra: str) -> dict[str, str]:
    """A loopback HTTP env with auth=mtls + server TLS (mTLS requires server TLS — ADR-019)."""
    return _env(
        GHIDRA_MCP_TRANSPORT="http",
        GHIDRA_MCP_HTTP_BIND="127.0.0.1:8765",
        GHIDRA_MCP_HTTP_AUTH="mtls",
        GHIDRA_MCP_HTTP_TLS_CERT="/c.pem",
        GHIDRA_MCP_HTTP_TLS_KEY="/k.pem",
        **extra,
    )


def test_mtls_without_server_tls_fails_closed() -> None:
    """auth=mtls with no server cert is refused — the client-cert handshake needs a TLS listener."""
    with pytest.raises(GhidraMcpError, match="requires server TLS"):
        load_config(
            _env(
                GHIDRA_MCP_TRANSPORT="http",
                GHIDRA_MCP_HTTP_BIND="127.0.0.1:8765",
                GHIDRA_MCP_HTTP_AUTH="mtls",
                GHIDRA_MCP_HTTP_TLS_CLIENT_CA="/ca.pem",
            )
        )


def test_mtls_with_client_ca_defaults_to_cn_field() -> None:
    cfg = load_config(_mtls_env(GHIDRA_MCP_HTTP_TLS_CLIENT_CA="/etc/ca/clients.pem"))
    assert cfg.http is not None
    assert cfg.http.auth_mode == "mtls"
    assert cfg.http.tls_client_ca == "/etc/ca/clients.pem"
    assert cfg.http.mtls_principal_field == "cn"  # secure default


def test_mtls_without_client_ca_fails_closed() -> None:
    """mTLS needs the CA bundle for the handshake verify gate — refuse to boot without it."""
    with pytest.raises(GhidraMcpError, match="mTLS auth requires a client-CA bundle"):
        load_config(_mtls_env())


@pytest.mark.parametrize("field_name", ["cn", "san-dns", "san-uri", "san-email", "dn"])
def test_mtls_principal_field_accepts_each_valid_choice(field_name: str) -> None:
    cfg = load_config(
        _mtls_env(
            GHIDRA_MCP_HTTP_TLS_CLIENT_CA="/ca.pem",
            GHIDRA_MCP_HTTP_MTLS_PRINCIPAL_FIELD=field_name,
        )
    )
    assert cfg.http is not None
    assert cfg.http.mtls_principal_field == field_name


def test_mtls_principal_field_rejects_unknown_choice() -> None:
    with pytest.raises(GhidraMcpError, match="unsupported value"):
        load_config(
            _mtls_env(
                GHIDRA_MCP_HTTP_TLS_CLIENT_CA="/ca.pem",
                GHIDRA_MCP_HTTP_MTLS_PRINCIPAL_FIELD="serial",
            )
        )


def test_mtls_over_network_bind_requires_server_tls_too() -> None:
    """A network mtls bind still needs the server TLS cert/key (defense in depth, existing rule)."""
    with pytest.raises(GhidraMcpError, match="requires TLS"):
        load_config(
            _env(
                GHIDRA_MCP_TRANSPORT="http",
                GHIDRA_MCP_HTTP_BIND="0.0.0.0:8765",
                GHIDRA_MCP_HTTP_AUTH="mtls",
                GHIDRA_MCP_HTTP_TLS_CLIENT_CA="/ca.pem",
            )
        )


def test_mtls_network_bind_full_valid_config() -> None:
    cfg = load_config(
        _env(
            GHIDRA_MCP_TRANSPORT="http",
            GHIDRA_MCP_HTTP_BIND="0.0.0.0:8765",
            GHIDRA_MCP_HTTP_AUTH="mtls",
            GHIDRA_MCP_HTTP_TLS_CERT="/c.pem",
            GHIDRA_MCP_HTTP_TLS_KEY="/k.pem",
            GHIDRA_MCP_HTTP_TLS_CLIENT_CA="/ca.pem",
            GHIDRA_MCP_HTTP_MTLS_PRINCIPAL_FIELD="san-uri",
        )
    )
    assert cfg.http is not None
    h = cfg.http
    assert h.is_network is True and h.auth_mode == "mtls"
    assert h.tls_client_ca == "/ca.pem" and h.mtls_principal_field == "san-uri"


def test_non_mtls_config_leaves_client_ca_none() -> None:
    """The client CA is read but irrelevant for non-mtls modes; bearer leaves it None by default."""
    cfg = load_config(
        _env(
            GHIDRA_MCP_TRANSPORT="http",
            GHIDRA_MCP_HTTP_BIND="127.0.0.1:8765",
            GHIDRA_MCP_HTTP_AUTH="bearer",
            GHIDRA_MCP_HTTP_BEARER_TOKEN=_TOKEN,
        )
    )
    assert cfg.http is not None
    assert cfg.http.tls_client_ca is None
    assert cfg.http.mtls_principal_field == "cn"  # default, harmless for bearer


# ==============================================================================================
# OAuth config (ADR-019 increment B): issuer/audience/JWKS URI (required for oauth) + principal
# claim / PINNED algorithm allow-list / leeway. None is a secret (the access token is per-request).
# Fail-closed startup: oauth without iss/aud/jwks, or an unsafe algorithm, must refuse to boot.
# ==============================================================================================
_ISS = "https://idp.example/realm"
_AUD = "ghidra-mcp"
_JWKS = "https://idp.example/realm/jwks"


def _oauth_env(**extra: str) -> dict[str, str]:
    """A loopback HTTP env with auth=oauth (no server TLS needed on loopback — like bearer)."""
    return _env(
        GHIDRA_MCP_TRANSPORT="http",
        GHIDRA_MCP_HTTP_BIND="127.0.0.1:8765",
        GHIDRA_MCP_HTTP_AUTH="oauth",
        **extra,
    )


def test_oauth_full_valid_config_defaults() -> None:
    cfg = load_config(
        _oauth_env(
            GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
            GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
            GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
        )
    )
    assert cfg.http is not None
    h = cfg.http
    assert h.auth_mode == "oauth"
    assert h.oauth_issuer == _ISS and h.oauth_audience == _AUD and h.oauth_jwks_uri == _JWKS
    assert h.oauth_principal_claim == "sub"  # secure default
    assert h.oauth_algorithms == ("RS256", "ES256")  # secure default (asymmetric)
    assert h.oauth_leeway_s == 30  # small default


def test_oauth_without_issuer_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="oauth auth requires an issuer"):
        load_config(
            _oauth_env(
                GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
                GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
            )
        )


def test_oauth_without_audience_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="oauth auth requires an issuer"):
        load_config(
            _oauth_env(
                GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
                GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
            )
        )


def test_oauth_without_jwks_uri_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="oauth auth requires an issuer"):
        load_config(
            _oauth_env(
                GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
                GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
            )
        )


def test_oauth_principal_claim_configurable() -> None:
    cfg = load_config(
        _oauth_env(
            GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
            GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
            GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
            GHIDRA_MCP_HTTP_OAUTH_PRINCIPAL_CLAIM="email",
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_principal_claim == "email"


def test_oauth_algorithms_parsed_and_deduped() -> None:
    cfg = load_config(
        _oauth_env(
            GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
            GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
            GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
            GHIDRA_MCP_HTTP_OAUTH_ALGORITHMS="ES256, RS256 , ES256",  # dup + spaces
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_algorithms == ("ES256", "RS256")  # order-preserving, de-duped


@pytest.mark.parametrize("bad", ["none", "HS256", "HS512", "made-up", "none,RS256", "RS256,HS256"])
def test_oauth_unsafe_algorithm_fails_closed(bad: str) -> None:
    """``none`` and symmetric ``HS*`` (and unknown) algs are rejected at startup (fail closed)."""
    with pytest.raises(GhidraMcpError, match="unsupported algorithm"):
        load_config(
            _oauth_env(
                GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
                GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
                GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
                GHIDRA_MCP_HTTP_OAUTH_ALGORITHMS=bad,
            )
        )


def test_oauth_empty_algorithm_list_after_parse_fails_closed() -> None:
    """A set-but-content-free list (only separators) is rejected — not a silent fall-back."""
    with pytest.raises(GhidraMcpError, match="at least one algorithm"):
        load_config(
            _oauth_env(
                GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
                GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
                GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
                GHIDRA_MCP_HTTP_OAUTH_ALGORITHMS=" , ,",
            )
        )


def test_oauth_leeway_configurable() -> None:
    cfg = load_config(
        _oauth_env(
            GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
            GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
            GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
            GHIDRA_MCP_HTTP_OAUTH_LEEWAY_SECONDS="5",
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_leeway_s == 5


def test_oauth_leeway_non_positive_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="positive integer"):
        load_config(
            _oauth_env(
                GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
                GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
                GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
                GHIDRA_MCP_HTTP_OAUTH_LEEWAY_SECONDS="0",
            )
        )


def test_oauth_principal_claim_too_long_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="too long"):
        load_config(
            _oauth_env(
                GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
                GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
                GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
                GHIDRA_MCP_HTTP_OAUTH_PRINCIPAL_CLAIM="c" * 65,
            )
        )


def test_oauth_over_network_bind_requires_server_tls() -> None:
    """A network oauth bind still needs server TLS (the generic is_network rule)."""
    with pytest.raises(GhidraMcpError, match="requires TLS"):
        load_config(
            _env(
                GHIDRA_MCP_TRANSPORT="http",
                GHIDRA_MCP_HTTP_BIND="0.0.0.0:8765",
                GHIDRA_MCP_HTTP_AUTH="oauth",
                GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
                GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
                GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
            )
        )


def test_oauth_network_bind_full_valid_config() -> None:
    cfg = load_config(
        _env(
            GHIDRA_MCP_TRANSPORT="http",
            GHIDRA_MCP_HTTP_BIND="0.0.0.0:8765",
            GHIDRA_MCP_HTTP_AUTH="oauth",
            GHIDRA_MCP_HTTP_TLS_CERT="/c.pem",
            GHIDRA_MCP_HTTP_TLS_KEY="/k.pem",
            GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
            GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
            GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
        )
    )
    assert cfg.http is not None
    h = cfg.http
    assert h.is_network is True and h.auth_mode == "oauth"
    assert h.oauth_issuer == _ISS and h.oauth_jwks_uri == _JWKS


def test_non_oauth_config_leaves_oauth_fields_default() -> None:
    """For bearer, the OAuth fields keep their (harmless) defaults — None issuer, default algs."""
    cfg = load_config(
        _env(
            GHIDRA_MCP_TRANSPORT="http",
            GHIDRA_MCP_HTTP_BIND="127.0.0.1:8765",
            GHIDRA_MCP_HTTP_AUTH="bearer",
            GHIDRA_MCP_HTTP_BEARER_TOKEN=_TOKEN,
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_issuer is None
    assert cfg.http.oauth_algorithms == ("RS256", "ES256")
    assert cfg.http.oauth_principal_claim == "sub"


def test_oauth_token_not_present_in_repr() -> None:
    """OAuth config is non-secret (no stored token) — but the repr must still be benign/loggable."""
    cfg = load_config(
        _oauth_env(
            GHIDRA_MCP_HTTP_OAUTH_ISSUER=_ISS,
            GHIDRA_MCP_HTTP_OAUTH_AUDIENCE=_AUD,
            GHIDRA_MCP_HTTP_OAUTH_JWKS_URI=_JWKS,
        )
    )
    assert cfg.http is not None
    # issuer/audience/jwks are non-secret config and MAY appear (they are loggable); no token here.
    assert _ISS in repr(cfg.http)
