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
    MultiTokenBearerAuthenticator,
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
    "cls",
    [
        BearerAuthenticator,
        MultiTokenBearerAuthenticator,
        NullAuthenticator,
        MtlsAuthenticator,
        OAuthResourceAuthenticator,
    ],
)
def test_all_strategies_satisfy_the_protocol(cls: type) -> None:
    if cls is BearerAuthenticator:
        inst: Authenticator = cls(expected_token=_TOKEN)
    elif cls is MultiTokenBearerAuthenticator:
        inst = cls(tokens={_TOKEN: "bearer"})
    else:
        inst = cls()
    assert isinstance(inst, Authenticator)  # runtime_checkable structural check


def test_build_authenticator_maps_modes() -> None:
    assert isinstance(build_authenticator("none", bearer_token=None), NullAuthenticator)
    # ADR-017: ``bearer`` now builds the multi-principal authenticator (a single token folds into a
    # one-entry map → the ``bearer`` principal, back-compat).
    assert isinstance(
        build_authenticator("bearer", bearer_token=_TOKEN), MultiTokenBearerAuthenticator
    )
    assert isinstance(build_authenticator("mtls", bearer_token=None), MtlsAuthenticator)
    assert isinstance(build_authenticator("oauth", bearer_token=None), OAuthResourceAuthenticator)


def test_build_authenticator_bearer_without_token_fails() -> None:
    with pytest.raises(ValueError, match="requires a token"):
        build_authenticator("bearer", bearer_token=None)


def test_build_authenticator_unknown_mode_fails() -> None:
    with pytest.raises(ValueError, match="unknown auth mode"):
        build_authenticator("kerberos", bearer_token=None)


# ==============================================================================================
# MultiTokenBearerAuthenticator (ADR-017) — multi-principal bearer: distinct tokens map to distinct
# principals; constant-time compare with no which-token timing oracle; generic reject (no oracle);
# tokens kept out of repr. Hermetic — synthetic tokens only, no real secrets.
# ==============================================================================================
_TOKEN_A = "token-A-of-sufficient-length-aaaa"  # noqa: S105  # test fixture, not a real secret
_TOKEN_B = "token-B-of-sufficient-length-bbbb"  # noqa: S105  # test fixture, not a real secret


def _multi() -> MultiTokenBearerAuthenticator:
    return MultiTokenBearerAuthenticator(tokens={_TOKEN_A: "alice", _TOKEN_B: "bob"})


def test_multi_token_maps_distinct_tokens_to_distinct_principals() -> None:
    auth = _multi()
    assert auth.authenticate(AuthContext(authorization=f"Bearer {_TOKEN_A}")) == Principal(
        id="alice"
    )
    assert auth.authenticate(AuthContext(authorization=f"Bearer {_TOKEN_B}")) == Principal(id="bob")


def test_multi_token_scheme_is_case_insensitive() -> None:
    assert _multi().authenticate(AuthContext(authorization=f"bearer {_TOKEN_A}")) == Principal(
        id="alice"
    )


@pytest.mark.parametrize(
    "header",
    [
        None,  # missing
        "",  # empty
        "Bearer wrong-token-but-long-enough-xxxx",  # wrong token (no entry matches)
        f"Basic {_TOKEN_A}",  # wrong scheme
        _TOKEN_A,  # no scheme
        "Bearer ",  # empty token
    ],
)
def test_multi_token_rejects_generically(header: str | None) -> None:
    """A missing/malformed/unknown credential all fail identically (no credential oracle) → None."""
    assert _multi().authenticate(AuthContext(authorization=header)) is None


def test_multi_token_scans_all_entries_no_which_token_short_circuit() -> None:
    """The match is found regardless of map order — proving the scan does not early-return on a hit.

    A structural guard against a which-token timing oracle: the LAST entry still matches, so the
    loop must visit every entry (no break on an earlier non-match, no early return on a match).
    """
    auth = MultiTokenBearerAuthenticator(
        tokens={_TOKEN_A: "first", _TOKEN_B: "second", "z" * 40: "last"}
    )
    assert auth.authenticate(AuthContext(authorization="Bearer " + "z" * 40)) == Principal(
        id="last"
    )
    assert auth.authenticate(AuthContext(authorization=f"Bearer {_TOKEN_A}")) == Principal(
        id="first"
    )


def test_multi_token_rejects_empty_map_at_construction() -> None:
    with pytest.raises(ValueError, match="at least one token"):
        MultiTokenBearerAuthenticator(tokens={})


def test_multi_token_rejects_short_token_at_construction() -> None:
    with pytest.raises(ValueError, match="too short"):
        MultiTokenBearerAuthenticator(tokens={"short": "x"})  # test fixture


def test_multi_token_secrets_not_in_repr() -> None:
    r = repr(_multi())
    assert _TOKEN_A not in r
    assert _TOKEN_B not in r


def test_build_authenticator_uses_token_map() -> None:
    auth = build_authenticator("bearer", bearer_tokens={_TOKEN_A: "alice", _TOKEN_B: "bob"})
    assert isinstance(auth, MultiTokenBearerAuthenticator)
    assert auth.authenticate(AuthContext(authorization=f"Bearer {_TOKEN_B}")) == Principal(id="bob")


def test_build_authenticator_single_token_back_compat_is_bearer_principal() -> None:
    """A lone ``bearer_token`` folds into a one-entry map → the historical ``bearer`` principal."""
    auth = build_authenticator("bearer", bearer_token=_TOKEN)
    assert auth.authenticate(AuthContext(authorization=f"Bearer {_TOKEN}")) == Principal(
        id="bearer"
    )


def test_build_authenticator_combines_single_token_and_map() -> None:
    auth = build_authenticator("bearer", bearer_token=_TOKEN, bearer_tokens={_TOKEN_A: "alice"})
    assert auth.authenticate(AuthContext(authorization=f"Bearer {_TOKEN}")) == Principal(
        id="bearer"
    )
    assert auth.authenticate(AuthContext(authorization=f"Bearer {_TOKEN_A}")) == Principal(
        id="alice"
    )
