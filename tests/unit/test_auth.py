"""Unit tests for the HTTP authentication strategies (v1.1 — ADR-011 / TB6).

Hermetic + framework-agnostic: strategies operate on :class:`AuthContext`, so no web server is
needed. Asserts default-deny, the generic (oracle-free) bearer reject, and the port-ready stubs.
"""

from __future__ import annotations

import pytest

from ghidra_mcp.server.auth import (
    MTLS_PRINCIPAL_FIELD_DEFAULT,
    MTLS_PRINCIPAL_FIELDS,
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


def test_oauth_stub_raises_until_built() -> None:
    """OAuth is the remaining port-ready stub (increment B); mTLS is now BUILT (increment A)."""
    with pytest.raises(NotImplementedError):
        OAuthResourceAuthenticator().authenticate(AuthContext())


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


def test_build_authenticator_mtls_uses_configured_field() -> None:
    """``build_authenticator`` threads the principal field into the mTLS authenticator."""
    auth = build_authenticator("mtls", mtls_principal_field="san-dns")
    assert isinstance(auth, MtlsAuthenticator)
    assert auth.principal_field == "san-dns"


def test_build_authenticator_mtls_default_field_is_cn() -> None:
    auth = build_authenticator("mtls")
    assert isinstance(auth, MtlsAuthenticator)
    assert auth.principal_field == MTLS_PRINCIPAL_FIELD_DEFAULT == "cn"


def test_build_authenticator_mtls_bad_field_fails() -> None:
    with pytest.raises(ValueError, match="unknown mTLS principal field"):
        build_authenticator("mtls", mtls_principal_field="serial")


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


# ==============================================================================================
# MtlsAuthenticator (ADR-019 increment A) — server-terminated, in-app mTLS: the VERIFIED peer cert
# (the handshake already chain-verified it to the configured CA) maps via a configured field →
# Principal; fail closed (generic None) on absent cert / empty field; no oracle. Hermetic — driven
# with SYNTHETIC parsed-cert dicts in the exact shape ``ssl.getpeercert()`` returns; NO real keys
# (the live uvicorn mTLS handshake is integration-gated, like other live edges).
# ==============================================================================================


def _cert(
    *,
    subject: tuple[object, ...] | None = ((("commonName", "alice"),),),
    san: tuple[object, ...] | None = None,
) -> dict[str, object]:
    """Build a synthetic ``getpeercert()``-shaped dict (subject RDNs + optional subjectAltName)."""
    cert: dict[str, object] = {}
    if subject is not None:
        cert["subject"] = subject
    if san is not None:
        cert["subjectAltName"] = san
    return cert


def test_mtls_default_field_is_cn() -> None:
    assert MtlsAuthenticator().principal_field == "cn"


def test_mtls_rejects_unknown_field_at_construction() -> None:
    with pytest.raises(ValueError, match="unknown mTLS principal field"):
        MtlsAuthenticator(principal_field="serial")


def test_mtls_maps_subject_cn_to_principal() -> None:
    auth = MtlsAuthenticator()  # default cn
    assert auth.authenticate(AuthContext(peer_certificate=_cert())) == Principal(id="alice")


def test_mtls_cn_picks_first_common_name_skipping_other_rdns() -> None:
    """A multi-RDN subject: non-CN attributes are skipped; the first commonName wins."""
    subject = ((("organizationName", "acme"),), (("commonName", "bob"),))
    auth = MtlsAuthenticator(principal_field="cn")
    assert auth.authenticate(AuthContext(peer_certificate=_cert(subject=subject))) == Principal(
        id="bob"
    )


def test_mtls_dn_renders_full_subject() -> None:
    subject = ((("organizationName", "acme"),), (("commonName", "carol"),))
    auth = MtlsAuthenticator(principal_field="dn")
    assert auth.authenticate(AuthContext(peer_certificate=_cert(subject=subject))) == Principal(
        id="organizationName=acme,commonName=carol"
    )


@pytest.mark.parametrize(
    ("field_name", "tag"),
    [("san-dns", "DNS"), ("san-uri", "URI"), ("san-email", "email")],
)
def test_mtls_maps_san_field(field_name: str, tag: str) -> None:
    """Each SAN selector reads the first matching SAN entry of the right tag."""
    san = (("othername", "ignored"), (tag, "svc.example.test"))
    auth = MtlsAuthenticator(principal_field=field_name)
    assert auth.authenticate(AuthContext(peer_certificate=_cert(san=san))) == Principal(
        id="svc.example.test"
    )


def test_mtls_san_first_matching_entry_wins() -> None:
    san = (("DNS", "first.example"), ("DNS", "second.example"))
    auth = MtlsAuthenticator(principal_field="san-dns")
    assert auth.authenticate(AuthContext(peer_certificate=_cert(san=san))) == Principal(
        id="first.example"
    )


# --- Fail-closed (generic None, no oracle) ----------------------------------------------------
def test_mtls_no_peer_cert_is_rejected() -> None:
    """No verified peer cert (None) → fail closed (defense in depth atop the handshake gate)."""
    assert MtlsAuthenticator().authenticate(AuthContext(peer_certificate=None)) is None
    assert MtlsAuthenticator().authenticate(AuthContext()) is None  # default None


@pytest.mark.parametrize(
    "cert",
    [
        "not-a-dict",  # unexpected shape (non-mapping) → fail closed
        b"\x00bytes",  # DER bytes, not the parsed dict → fail closed
        12345,  # nonsense
    ],
)
def test_mtls_non_mapping_cert_is_rejected(cert: object) -> None:
    assert MtlsAuthenticator().authenticate(AuthContext(peer_certificate=cert)) is None


def test_mtls_cn_missing_subject_is_rejected() -> None:
    ctx = AuthContext(peer_certificate=_cert(subject=None))
    assert MtlsAuthenticator().authenticate(ctx) is None


def test_mtls_cn_no_common_name_in_subject_is_rejected() -> None:
    subject = ((("organizationName", "acme"),),)  # only O=, no CN
    assert (
        MtlsAuthenticator().authenticate(AuthContext(peer_certificate=_cert(subject=subject)))
        is None
    )


def test_mtls_empty_cn_value_is_rejected() -> None:
    """An empty mapped field → fail closed (no empty/anonymous principal id)."""
    subject = ((("commonName", ""),),)
    assert (
        MtlsAuthenticator().authenticate(AuthContext(peer_certificate=_cert(subject=subject)))
        is None
    )


def test_mtls_dn_empty_subject_is_rejected() -> None:
    assert (
        MtlsAuthenticator(principal_field="dn").authenticate(
            AuthContext(peer_certificate=_cert(subject=()))
        )
        is None
    )


def test_mtls_dn_only_malformed_rdns_is_rejected() -> None:
    """A subject whose RDNs are all malformed yields no parts → None (fail closed)."""
    subject = ("not-an-rdn", (("commonName", 123),))  # wrong types → skipped
    assert (
        MtlsAuthenticator(principal_field="dn").authenticate(
            AuthContext(peer_certificate=_cert(subject=subject))
        )
        is None
    )


def test_mtls_san_field_missing_san_is_rejected() -> None:
    assert (
        MtlsAuthenticator(principal_field="san-dns").authenticate(
            AuthContext(peer_certificate=_cert(san=None))
        )
        is None
    )


def test_mtls_san_field_wrong_tag_is_rejected() -> None:
    """san-dns must not fall back to an email/URI SAN — only its tag counts."""
    san = (("email", "x@example.test"), ("URI", "spiffe://x"))
    assert (
        MtlsAuthenticator(principal_field="san-dns").authenticate(
            AuthContext(peer_certificate=_cert(san=san))
        )
        is None
    )


@pytest.mark.parametrize(
    "subject",
    [
        "not-a-tuple",  # subject is not a sequence
        ("malformed-rdn",),  # rdn is not a sequence
        ((("commonName",),),),  # pair has wrong arity
        (((123, "alice"),),),  # attr name not a str (dn skips it)
        ((("commonName", 999),),),  # CN value not a str
    ],
)
def test_mtls_cn_tolerates_malformed_shapes_failing_closed(subject: object) -> None:
    """Hostile/odd cert shapes never raise — every extractor returns None (fail closed)."""
    assert (
        MtlsAuthenticator().authenticate(AuthContext(peer_certificate=_cert(subject=subject)))  # type: ignore[arg-type]
        is None
    )


def test_mtls_san_tolerates_malformed_shapes_failing_closed() -> None:
    san: tuple[object, ...] = ("not-a-pair", ("DNS",), ("DNS", 123))  # arity/type junk
    assert (
        MtlsAuthenticator(principal_field="san-dns").authenticate(
            AuthContext(peer_certificate=_cert(san=san))
        )
        is None
    )


def test_mtls_san_non_sequence_is_rejected() -> None:
    assert (
        MtlsAuthenticator(principal_field="san-dns").authenticate(
            AuthContext(peer_certificate={"subjectAltName": "not-a-tuple"})
        )
        is None
    )


def test_mtls_two_distinct_certs_yield_two_distinct_principals() -> None:
    """Distinct certs → distinct principals → distinct owner-scoped sessions (composes ADR-017)."""
    auth = MtlsAuthenticator()
    alice = auth.authenticate(AuthContext(peer_certificate=_cert()))  # default CN = "alice"
    bob = auth.authenticate(
        AuthContext(peer_certificate=_cert(subject=((("commonName", "bob"),),)))
    )
    assert alice == Principal(id="alice")
    assert bob == Principal(id="bob")
    assert alice != bob


def test_mtls_authenticator_satisfies_protocol() -> None:
    assert isinstance(MtlsAuthenticator(), Authenticator)


def test_mtls_principal_field_set_matches_default_membership() -> None:
    assert MTLS_PRINCIPAL_FIELD_DEFAULT in MTLS_PRINCIPAL_FIELDS
    assert frozenset({"cn", "san-dns", "san-uri", "san-email", "dn"}) == MTLS_PRINCIPAL_FIELDS
