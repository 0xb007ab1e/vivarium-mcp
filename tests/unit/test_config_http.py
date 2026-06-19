"""Unit tests for HTTP-transport config + fail-closed startup validation (v1.1 — ADR-011 / TB6).

Hermetic: ``load_config`` reads an injected ``env`` mapping, never the real environment. Covers the
secure-by-default rules — a misconfigured network bind must refuse to boot (master §2).
"""

from __future__ import annotations

import pytest

from vivarium.config import load_config
from vivarium.core.errors import GhidraMcpError
from vivarium.server.auth import (
    PROXY_IDENTITY_HEADER_DEFAULT,
    PROXY_SECRET_HEADER_DEFAULT,
)

_WORKER = {"VIVARIUM_WORKER_IMAGE": "ghcr.io/x/worker@sha256:" + "a" * 64}
_TOKEN = "s" * 24  # >= _MIN_BEARER_TOKEN_LEN


def _env(**extra: str) -> dict[str, str]:
    return {**_WORKER, **extra}


def test_default_transport_is_stdio_no_http_config() -> None:
    cfg = load_config(_env())
    assert cfg.transport == "stdio"
    assert cfg.http is None


def test_http_loopback_default_is_plaintext_unauthenticated() -> None:
    cfg = load_config(_env(VIVARIUM_TRANSPORT="http"))
    assert cfg.transport == "http" and cfg.http is not None
    h = cfg.http
    assert h.bind == "127.0.0.1:8765"
    assert h.is_network is False and h.is_unix_socket is False
    assert h.auth_mode == "none" and h.bearer_token is None and h.tls_cert is None
    assert h.rate_per_second == 10 and h.rate_burst == 20 and h.max_body_bytes == 1_048_576


def test_unix_socket_bind_is_not_network() -> None:
    cfg = load_config(_env(VIVARIUM_TRANSPORT="http", VIVARIUM_HTTP_BIND="unix:/run/gmcp.sock"))
    assert cfg.http is not None
    assert cfg.http.is_unix_socket is True and cfg.http.is_network is False
    assert cfg.http.auth_mode == "none"


def test_network_bind_without_tls_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="requires TLS"):
        load_config(_env(VIVARIUM_TRANSPORT="http", VIVARIUM_HTTP_BIND="0.0.0.0:8765"))


def test_network_bind_with_tls_but_no_auth_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="requires an authenticator"):
        load_config(
            _env(
                VIVARIUM_TRANSPORT="http",
                VIVARIUM_HTTP_BIND="0.0.0.0:8765",
                VIVARIUM_HTTP_TLS_CERT="/c.pem",
                VIVARIUM_HTTP_TLS_KEY="/k.pem",
                VIVARIUM_HTTP_AUTH="none",
            )
        )


def test_network_bind_with_tls_and_bearer_is_valid() -> None:
    cfg = load_config(
        _env(
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="0.0.0.0:8765",
            VIVARIUM_HTTP_TLS_CERT="/c.pem",
            VIVARIUM_HTTP_TLS_KEY="/k.pem",
            VIVARIUM_HTTP_BEARER_TOKEN=_TOKEN,
        )
    )
    assert cfg.http is not None
    h = cfg.http
    assert h.is_network is True and h.auth_mode == "bearer" and h.bearer_token == _TOKEN
    assert h.tls_cert == "/c.pem" and h.tls_key == "/k.pem"


@pytest.mark.parametrize("token", ["", "short", "x" * 15])
def test_bearer_auth_requires_long_token(token: str) -> None:
    env = _env(VIVARIUM_TRANSPORT="http", VIVARIUM_HTTP_AUTH="bearer")
    if token:
        env["VIVARIUM_HTTP_BEARER_TOKEN"] = token
    # ADR-017: an absent token fails "requires at least one token"; a present-but-short one fails
    # the per-token length floor in the multi-token loader ("token is too short"). Both fail closed
    # at startup as VALIDATION; the 16-char floor is mentioned in either path.
    with pytest.raises(GhidraMcpError, match="16 characters"):
        load_config(env)


def test_tls_cert_without_key_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="both be set or both unset"):
        load_config(_env(VIVARIUM_TRANSPORT="http", VIVARIUM_HTTP_TLS_CERT="/c.pem"))


def test_wildcard_cors_rejected() -> None:
    with pytest.raises(GhidraMcpError, match="CORS origins must be explicit"):
        load_config(_env(VIVARIUM_TRANSPORT="http", VIVARIUM_HTTP_CORS_ORIGINS="*"))


def test_cors_origins_parsed_comma_separated() -> None:
    cfg = load_config(
        _env(
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_CORS_ORIGINS="https://a.example, https://b.example",
        )
    )
    assert cfg.http is not None
    assert cfg.http.cors_origins == ("https://a.example", "https://b.example")


@pytest.mark.parametrize("bind", ["nope", "host:notaport", "host:0", "host:99999", "unix:"])
def test_malformed_bind_fails_closed(bind: str) -> None:
    with pytest.raises(GhidraMcpError):
        load_config(_env(VIVARIUM_TRANSPORT="http", VIVARIUM_HTTP_BIND=bind))


def test_ipv6_loopback_bind_is_not_network() -> None:
    cfg = load_config(_env(VIVARIUM_TRANSPORT="http", VIVARIUM_HTTP_BIND="[::1]:8765"))
    assert cfg.http is not None and cfg.http.is_network is False


def test_bearer_token_excluded_from_repr() -> None:
    cfg = load_config(
        _env(
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="127.0.0.1:8765",
            VIVARIUM_HTTP_AUTH="bearer",
            VIVARIUM_HTTP_BEARER_TOKEN=_TOKEN,
        )
    )
    assert cfg.http is not None
    assert _TOKEN not in repr(cfg.http)  # secret must not leak via repr/logs


def test_invalid_transport_and_auth_rejected() -> None:
    with pytest.raises(GhidraMcpError):
        load_config(_env(VIVARIUM_TRANSPORT="grpc"))
    with pytest.raises(GhidraMcpError):
        load_config(_env(VIVARIUM_TRANSPORT="http", VIVARIUM_HTTP_AUTH="kerberos"))


# ==============================================================================================
# Multi-principal bearer token map (ADR-017): {token: principal-id} from the env, fail-closed.
# ==============================================================================================
_TOKEN_A = "a" * 24  # test fixture, not a real secret
_TOKEN_B = "b" * 24  # test fixture, not a real secret


def _bearer_env(**extra: str) -> dict[str, str]:
    return _env(
        VIVARIUM_TRANSPORT="http",
        VIVARIUM_HTTP_BIND="127.0.0.1:8765",
        VIVARIUM_HTTP_AUTH="bearer",
        **extra,
    )


def test_single_token_back_compat_maps_to_bearer_principal() -> None:
    cfg = load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKEN=_TOKEN))
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN: "bearer"}


def test_multi_token_map_parsed_from_pairs() -> None:
    cfg = load_config(
        _bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}, bob:{_TOKEN_B}")
    )
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN_A: "alice", _TOKEN_B: "bob"}


def test_multi_token_map_combines_with_single_token() -> None:
    cfg = load_config(
        _bearer_env(
            VIVARIUM_HTTP_BEARER_TOKEN=_TOKEN,
            VIVARIUM_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}",
        )
    )
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN_A: "alice", _TOKEN: "bearer"}


def test_multi_token_secrets_excluded_from_repr() -> None:
    cfg = load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}"))
    assert cfg.http is not None
    assert _TOKEN_A not in repr(cfg.http)  # the token KEYS are secrets — not in repr


def test_multi_token_short_token_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="too short"):
        load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKENS="alice:short"))


def test_multi_token_missing_separator_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="id:token"):
        load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=_TOKEN_A))  # no "id:" prefix


def test_multi_token_empty_id_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="empty id"):
        load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=f":{_TOKEN_A}"))


@pytest.mark.parametrize("bad_id", ["has space", "rtl‮id", "a/b", "x" * 65])
def test_multi_token_bad_principal_id_fails_closed(bad_id: str) -> None:
    with pytest.raises(GhidraMcpError):
        load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=f"{bad_id}:{_TOKEN_A}"))


def test_multi_token_ambiguous_token_two_principals_fails_closed() -> None:
    """One token mapping to two principals makes ownership non-deterministic → refuse to boot."""
    with pytest.raises(GhidraMcpError, match="one token to two principals"):
        load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}\nbob:{_TOKEN_A}"))


def test_multi_token_newline_separated_pairs() -> None:
    cfg = load_config(
        _bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}\nbob:{_TOKEN_B}")
    )
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN_A: "alice", _TOKEN_B: "bob"}


def test_multi_token_ignores_blank_items_from_trailing_separators() -> None:
    """Empty items (trailing/extra commas or blank lines) are skipped, not errors."""
    cfg = load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=f"alice:{_TOKEN_A}, ,\n"))
    assert cfg.http is not None
    assert cfg.http.bearer_tokens == {_TOKEN_A: "alice"}


def test_multi_token_value_too_long_fails_closed() -> None:
    """An oversized token-map value is rejected at startup (bounds startup input — CWE-400)."""
    huge = ",".join(f"p{i}:{'x' * 24}" for i in range(1000))
    with pytest.raises(GhidraMcpError, match="is too long"):
        load_config(_bearer_env(VIVARIUM_HTTP_BEARER_TOKENS=huge))


# ==============================================================================================
# mTLS config (ADR-019 increment A): client-CA bundle (required for mtls) + principal-field
# selector (validated allow-list). The CA path / field are NOT secrets. Fail-closed startup.
# ==============================================================================================
def _mtls_env(**extra: str) -> dict[str, str]:
    """A loopback HTTP env with auth=mtls + server TLS (mTLS requires server TLS — ADR-019)."""
    return _env(
        VIVARIUM_TRANSPORT="http",
        VIVARIUM_HTTP_BIND="127.0.0.1:8765",
        VIVARIUM_HTTP_AUTH="mtls",
        VIVARIUM_HTTP_TLS_CERT="/c.pem",
        VIVARIUM_HTTP_TLS_KEY="/k.pem",
        **extra,
    )


def test_mtls_without_server_tls_fails_closed() -> None:
    """auth=mtls with no server cert is refused — the client-cert handshake needs a TLS listener."""
    with pytest.raises(GhidraMcpError, match="requires server TLS"):
        load_config(
            _env(
                VIVARIUM_TRANSPORT="http",
                VIVARIUM_HTTP_BIND="127.0.0.1:8765",
                VIVARIUM_HTTP_AUTH="mtls",
                VIVARIUM_HTTP_TLS_CLIENT_CA="/ca.pem",
            )
        )


def test_mtls_with_client_ca_defaults_to_cn_field() -> None:
    cfg = load_config(_mtls_env(VIVARIUM_HTTP_TLS_CLIENT_CA="/etc/ca/clients.pem"))
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
            VIVARIUM_HTTP_TLS_CLIENT_CA="/ca.pem",
            VIVARIUM_HTTP_MTLS_PRINCIPAL_FIELD=field_name,
        )
    )
    assert cfg.http is not None
    assert cfg.http.mtls_principal_field == field_name


def test_mtls_principal_field_rejects_unknown_choice() -> None:
    with pytest.raises(GhidraMcpError, match="unsupported value"):
        load_config(
            _mtls_env(
                VIVARIUM_HTTP_TLS_CLIENT_CA="/ca.pem",
                VIVARIUM_HTTP_MTLS_PRINCIPAL_FIELD="serial",
            )
        )


def test_mtls_over_network_bind_requires_server_tls_too() -> None:
    """A network mtls bind still needs the server TLS cert/key (defense in depth, existing rule)."""
    with pytest.raises(GhidraMcpError, match="requires TLS"):
        load_config(
            _env(
                VIVARIUM_TRANSPORT="http",
                VIVARIUM_HTTP_BIND="0.0.0.0:8765",
                VIVARIUM_HTTP_AUTH="mtls",
                VIVARIUM_HTTP_TLS_CLIENT_CA="/ca.pem",
            )
        )


def test_mtls_network_bind_full_valid_config() -> None:
    cfg = load_config(
        _env(
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="0.0.0.0:8765",
            VIVARIUM_HTTP_AUTH="mtls",
            VIVARIUM_HTTP_TLS_CERT="/c.pem",
            VIVARIUM_HTTP_TLS_KEY="/k.pem",
            VIVARIUM_HTTP_TLS_CLIENT_CA="/ca.pem",
            VIVARIUM_HTTP_MTLS_PRINCIPAL_FIELD="san-uri",
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
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="127.0.0.1:8765",
            VIVARIUM_HTTP_AUTH="bearer",
            VIVARIUM_HTTP_BEARER_TOKEN=_TOKEN,
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
_AUD = "vivarium"
_JWKS = "https://idp.example/realm/jwks"


def _oauth_env(**extra: str) -> dict[str, str]:
    """A loopback HTTP env with auth=oauth (no server TLS needed on loopback — like bearer)."""
    return _env(
        VIVARIUM_TRANSPORT="http",
        VIVARIUM_HTTP_BIND="127.0.0.1:8765",
        VIVARIUM_HTTP_AUTH="oauth",
        **extra,
    )


def test_oauth_full_valid_config_defaults() -> None:
    cfg = load_config(
        _oauth_env(
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
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
                VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
                VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
            )
        )


def test_oauth_without_audience_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="oauth auth requires an issuer"):
        load_config(
            _oauth_env(
                VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
                VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
            )
        )


def test_oauth_without_jwks_uri_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="oauth auth requires an issuer"):
        load_config(
            _oauth_env(
                VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
                VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            )
        )


def test_oauth_principal_claim_configurable() -> None:
    cfg = load_config(
        _oauth_env(
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
            VIVARIUM_HTTP_OAUTH_PRINCIPAL_CLAIM="email",
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_principal_claim == "email"


def test_oauth_algorithms_parsed_and_deduped() -> None:
    cfg = load_config(
        _oauth_env(
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
            VIVARIUM_HTTP_OAUTH_ALGORITHMS="ES256, RS256 , ES256",  # dup + spaces
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
                VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
                VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
                VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
                VIVARIUM_HTTP_OAUTH_ALGORITHMS=bad,
            )
        )


def test_oauth_empty_algorithm_list_after_parse_fails_closed() -> None:
    """A set-but-content-free list (only separators) is rejected — not a silent fall-back."""
    with pytest.raises(GhidraMcpError, match="at least one algorithm"):
        load_config(
            _oauth_env(
                VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
                VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
                VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
                VIVARIUM_HTTP_OAUTH_ALGORITHMS=" , ,",
            )
        )


def test_oauth_leeway_configurable() -> None:
    cfg = load_config(
        _oauth_env(
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
            VIVARIUM_HTTP_OAUTH_LEEWAY_SECONDS="5",
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_leeway_s == 5


def test_oauth_leeway_non_positive_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="positive integer"):
        load_config(
            _oauth_env(
                VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
                VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
                VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
                VIVARIUM_HTTP_OAUTH_LEEWAY_SECONDS="0",
            )
        )


def test_oauth_principal_claim_too_long_fails_closed() -> None:
    with pytest.raises(GhidraMcpError, match="too long"):
        load_config(
            _oauth_env(
                VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
                VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
                VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
                VIVARIUM_HTTP_OAUTH_PRINCIPAL_CLAIM="c" * 65,
            )
        )


def test_oauth_over_network_bind_requires_server_tls() -> None:
    """A network oauth bind still needs server TLS (the generic is_network rule)."""
    with pytest.raises(GhidraMcpError, match="requires TLS"):
        load_config(
            _env(
                VIVARIUM_TRANSPORT="http",
                VIVARIUM_HTTP_BIND="0.0.0.0:8765",
                VIVARIUM_HTTP_AUTH="oauth",
                VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
                VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
                VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
            )
        )


def test_oauth_network_bind_full_valid_config() -> None:
    cfg = load_config(
        _env(
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="0.0.0.0:8765",
            VIVARIUM_HTTP_AUTH="oauth",
            VIVARIUM_HTTP_TLS_CERT="/c.pem",
            VIVARIUM_HTTP_TLS_KEY="/k.pem",
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
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
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="127.0.0.1:8765",
            VIVARIUM_HTTP_AUTH="bearer",
            VIVARIUM_HTTP_BEARER_TOKEN=_TOKEN,
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
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
        )
    )
    assert cfg.http is not None
    # issuer/audience/jwks are non-secret config and MAY appear (they are loggable); no token here.
    assert _ISS in repr(cfg.http)


# ==============================================================================================
# ADR-033 — OAuth write-scope config (opt-in per-tool authZ). ``VIVARIUM_HTTP_OAUTH_WRITE_SCOPE``
# is OPTIONAL and non-secret: unset ⇒ None (scope-gating off, identity-only — pre-ADR-033); set ⇒
# the scope that grants the ``write`` capability. Over-length is rejected at startup like the
# principal-claim (fail closed, same _MAX_OAUTH_CLAIM_LEN bound).
# ==============================================================================================
def test_oauth_write_scope_set_is_parsed() -> None:
    cfg = load_config(
        _oauth_env(
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
            VIVARIUM_HTTP_OAUTH_WRITE_SCOPE="ghidra:write",
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_write_scope == "ghidra:write"


def test_oauth_write_scope_unset_defaults_none() -> None:
    """Omitting the write-scope leaves gating OFF (``None``) — backward-compatible default."""
    cfg = load_config(
        _oauth_env(
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_write_scope is None


def test_oauth_write_scope_too_long_fails_closed() -> None:
    """An over-64-char write-scope is rejected at startup (mirrors the principal-claim bound)."""
    with pytest.raises(GhidraMcpError, match="too long"):
        load_config(
            _oauth_env(
                VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
                VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
                VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
                VIVARIUM_HTTP_OAUTH_WRITE_SCOPE="w" * 65,
            )
        )


def test_oauth_write_scope_at_max_len_accepted() -> None:
    """A boundary write-scope (exactly 64 chars) is accepted (off-by-one guard)."""
    cfg = load_config(
        _oauth_env(
            VIVARIUM_HTTP_OAUTH_ISSUER=_ISS,
            VIVARIUM_HTTP_OAUTH_AUDIENCE=_AUD,
            VIVARIUM_HTTP_OAUTH_JWKS_URI=_JWKS,
            VIVARIUM_HTTP_OAUTH_WRITE_SCOPE="w" * 64,
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_write_scope == "w" * 64


def test_non_oauth_config_leaves_write_scope_none() -> None:
    """For bearer, the write-scope field keeps its harmless default (None)."""
    cfg = load_config(
        _env(
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="127.0.0.1:8765",
            VIVARIUM_HTTP_AUTH="bearer",
            VIVARIUM_HTTP_BEARER_TOKEN=_TOKEN,
        )
    )
    assert cfg.http is not None
    assert cfg.http.oauth_write_scope is None


# ==============================================================================================
# Reverse-proxy mTLS config (ADR-034 — auth_mode "mtls-proxy"). The shared secret IS a secret (the
# trust anchor): REQUIRED for the mode, length-floored (>=16, like the bearer token), excluded from
# repr. The header names are non-secret NAMES, lowercased. Fail-closed startup: the mode cannot boot
# without a sufficiently long secret. Hermetic — ``load_config`` reads an injected env mapping.
# ==============================================================================================
_PROXY_SECRET = "p" * 24  # >= _MIN_BEARER_TOKEN_LEN; synthetic, not a real secret
# Custom header NAMES for the lowercasing test (mixed case input). NAMES, not secrets.
_CUSTOM_SECRET_HEADER_IN = "X-My-Proxy-Secret"  # noqa: S105  # a header NAME, not a secret value
_CUSTOM_SECRET_HEADER_LC = "x-my-proxy-secret"  # noqa: S105  # a header NAME, not a secret value
_CUSTOM_IDENTITY_HEADER_IN = "X-My-Client-ID"
_CUSTOM_IDENTITY_HEADER_LC = "x-my-client-id"


def _proxy_env(**extra: str) -> dict[str, str]:
    """A loopback HTTP env with auth=mtls-proxy (TLS is terminated at the proxy, not here)."""
    return _env(
        VIVARIUM_TRANSPORT="http",
        VIVARIUM_HTTP_BIND="127.0.0.1:8765",
        VIVARIUM_HTTP_AUTH="mtls-proxy",
        **extra,
    )


def test_mtls_proxy_is_an_accepted_auth_mode() -> None:
    """``mtls-proxy`` passes the auth-mode allow-list (no 'unsupported value' error)."""
    cfg = load_config(_proxy_env(VIVARIUM_HTTP_PROXY_SHARED_SECRET=_PROXY_SECRET))
    assert cfg.http is not None
    assert cfg.http.auth_mode == "mtls-proxy"


def test_mtls_proxy_full_valid_config_defaults() -> None:
    cfg = load_config(_proxy_env(VIVARIUM_HTTP_PROXY_SHARED_SECRET=_PROXY_SECRET))
    assert cfg.http is not None
    h = cfg.http
    assert h.auth_mode == "mtls-proxy"
    assert h.proxy_shared_secret == _PROXY_SECRET
    assert h.proxy_secret_header == PROXY_SECRET_HEADER_DEFAULT  # secure default
    assert h.proxy_identity_header == PROXY_IDENTITY_HEADER_DEFAULT  # secure default


def test_mtls_proxy_without_secret_fails_closed() -> None:
    """The mode cannot boot without the trust anchor (a direct attacker could forge identity)."""
    with pytest.raises(GhidraMcpError, match="requires a shared secret"):
        load_config(_proxy_env())


@pytest.mark.parametrize("secret", ["short", "x" * 15])
def test_mtls_proxy_short_secret_fails_closed(secret: str) -> None:
    """A present-but-too-short secret (<16) is refused at startup (length floor)."""
    with pytest.raises(GhidraMcpError, match="requires a shared secret"):
        load_config(_proxy_env(VIVARIUM_HTTP_PROXY_SHARED_SECRET=secret))


def test_mtls_proxy_secret_at_min_len_accepted() -> None:
    """A boundary secret (exactly 16 chars) is accepted (off-by-one guard)."""
    cfg = load_config(_proxy_env(VIVARIUM_HTTP_PROXY_SHARED_SECRET="x" * 16))
    assert cfg.http is not None
    assert cfg.http.proxy_shared_secret == "x" * 16


def test_mtls_proxy_secret_excluded_from_repr() -> None:
    """The shared secret is the credential — it must not leak via repr/logs (workflow-secrets)."""
    cfg = load_config(_proxy_env(VIVARIUM_HTTP_PROXY_SHARED_SECRET=_PROXY_SECRET))
    assert cfg.http is not None
    assert _PROXY_SECRET not in repr(cfg.http)


def test_mtls_proxy_custom_header_names_lowercased() -> None:
    """The header-name envs are honored and lowercased (HTTP headers are case-insensitive)."""
    cfg = load_config(
        _proxy_env(
            **{
                "VIVARIUM_HTTP_PROXY_SHARED_SECRET": _PROXY_SECRET,
                "VIVARIUM_HTTP_PROXY_SECRET_HEADER": _CUSTOM_SECRET_HEADER_IN,
                "VIVARIUM_HTTP_PROXY_IDENTITY_HEADER": _CUSTOM_IDENTITY_HEADER_IN,
            }
        )
    )
    assert cfg.http is not None
    assert cfg.http.proxy_secret_header == _CUSTOM_SECRET_HEADER_LC
    assert cfg.http.proxy_identity_header == _CUSTOM_IDENTITY_HEADER_LC


def test_mtls_proxy_unset_header_names_default_lowercased() -> None:
    """Unset header-name envs fall back to the lowercased defaults."""
    cfg = load_config(_proxy_env(VIVARIUM_HTTP_PROXY_SHARED_SECRET=_PROXY_SECRET))
    assert cfg.http is not None
    assert cfg.http.proxy_secret_header == PROXY_SECRET_HEADER_DEFAULT
    assert cfg.http.proxy_identity_header == PROXY_IDENTITY_HEADER_DEFAULT


def test_mtls_proxy_network_bind_full_valid_config() -> None:
    """A network mtls-proxy bind needs server TLS too (generic is_network rule) + the secret."""
    cfg = load_config(
        _env(
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="0.0.0.0:8765",
            VIVARIUM_HTTP_AUTH="mtls-proxy",
            VIVARIUM_HTTP_TLS_CERT="/c.pem",
            VIVARIUM_HTTP_TLS_KEY="/k.pem",
            VIVARIUM_HTTP_PROXY_SHARED_SECRET=_PROXY_SECRET,
        )
    )
    assert cfg.http is not None
    h = cfg.http
    assert h.is_network is True and h.auth_mode == "mtls-proxy"
    assert h.proxy_shared_secret == _PROXY_SECRET


def test_non_proxy_config_leaves_proxy_fields_default() -> None:
    """For bearer, the proxy fields keep their harmless defaults — None secret, default headers."""
    cfg = load_config(
        _env(
            VIVARIUM_TRANSPORT="http",
            VIVARIUM_HTTP_BIND="127.0.0.1:8765",
            VIVARIUM_HTTP_AUTH="bearer",
            VIVARIUM_HTTP_BEARER_TOKEN=_TOKEN,
        )
    )
    assert cfg.http is not None
    assert cfg.http.proxy_shared_secret is None
    assert cfg.http.proxy_secret_header == PROXY_SECRET_HEADER_DEFAULT
    assert cfg.http.proxy_identity_header == PROXY_IDENTITY_HEADER_DEFAULT
