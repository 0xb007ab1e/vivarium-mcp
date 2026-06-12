"""Unit tests for the HTTP authentication strategies (v1.1 — ADR-011 / TB6).

Hermetic + framework-agnostic: strategies operate on :class:`AuthContext`, so no web server is
needed. Asserts default-deny, the generic (oracle-free) bearer reject, and the port-ready stubs.
"""

from __future__ import annotations

import pytest

from ghidra_mcp.server.auth import (
    AuthContext,
    Authenticator,
    BearerAuthenticator,
    MtlsAuthenticator,
    NullAuthenticator,
    OAuthResourceAuthenticator,
    Principal,
    build_authenticator,
)

_TOKEN = "s3cret-token-of-sufficient-length"  # noqa: S105  # test fixture, not a real secret


def test_bearer_accepts_valid_token() -> None:
    auth = BearerAuthenticator(expected_token=_TOKEN)
    p = auth.authenticate(AuthContext(authorization=f"Bearer {_TOKEN}"))
    assert p == Principal(id="bearer")


def test_bearer_scheme_is_case_insensitive() -> None:
    auth = BearerAuthenticator(expected_token=_TOKEN)
    assert auth.authenticate(AuthContext(authorization=f"bearer {_TOKEN}")) == Principal(
        id="bearer"
    )


@pytest.mark.parametrize(
    "header",
    [
        None,  # missing
        "",  # empty
        "Bearer wrong-token-but-long-enough-xxxx",  # wrong token
        f"Basic {_TOKEN}",  # wrong scheme
        _TOKEN,  # no scheme
        "Bearer ",  # empty token
    ],
)
def test_bearer_rejects_generically(header: str | None) -> None:
    """A missing/malformed/wrong credential all fail identically (no oracle) → None."""
    auth = BearerAuthenticator(expected_token=_TOKEN)
    assert auth.authenticate(AuthContext(authorization=header)) is None


def test_bearer_rejects_short_token_at_construction() -> None:
    with pytest.raises(ValueError, match="too short"):
        BearerAuthenticator(expected_token="short")  # noqa: S106  # test fixture, not a real secret


def test_bearer_token_not_in_repr() -> None:
    assert _TOKEN not in repr(BearerAuthenticator(expected_token=_TOKEN))


def test_null_authenticator_accepts_everything_as_local() -> None:
    auth = NullAuthenticator()
    assert auth.authenticate(AuthContext()) == Principal(id="local")
    assert auth.authenticate(AuthContext(authorization="anything")) == Principal(id="local")


@pytest.mark.parametrize("cls", [MtlsAuthenticator, OAuthResourceAuthenticator])
def test_port_ready_stubs_raise_until_built(cls: type) -> None:
    with pytest.raises(NotImplementedError):
        cls().authenticate(AuthContext())


@pytest.mark.parametrize(
    "cls", [BearerAuthenticator, NullAuthenticator, MtlsAuthenticator, OAuthResourceAuthenticator]
)
def test_all_strategies_satisfy_the_protocol(cls: type) -> None:
    inst = cls(expected_token=_TOKEN) if cls is BearerAuthenticator else cls()
    assert isinstance(inst, Authenticator)  # runtime_checkable structural check


def test_build_authenticator_maps_modes() -> None:
    assert isinstance(build_authenticator("none", bearer_token=None), NullAuthenticator)
    assert isinstance(build_authenticator("bearer", bearer_token=_TOKEN), BearerAuthenticator)
    assert isinstance(build_authenticator("mtls", bearer_token=None), MtlsAuthenticator)
    assert isinstance(build_authenticator("oauth", bearer_token=None), OAuthResourceAuthenticator)


def test_build_authenticator_bearer_without_token_fails() -> None:
    with pytest.raises(ValueError, match="requires a token"):
        build_authenticator("bearer", bearer_token=None)


def test_build_authenticator_unknown_mode_fails() -> None:
    with pytest.raises(ValueError, match="unknown auth mode"):
        build_authenticator("kerberos", bearer_token=None)
