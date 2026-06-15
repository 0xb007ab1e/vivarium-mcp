"""Unit tests for the HTTP authentication strategies (v1.1 — ADR-011 / TB6).

Hermetic + framework-agnostic: strategies operate on :class:`AuthContext`, so no web server is
needed. Asserts default-deny, the generic (oracle-free) bearer reject, and the port-ready stubs.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ghidra_mcp.server.auth import (
    MTLS_PRINCIPAL_FIELD_DEFAULT,
    MTLS_PRINCIPAL_FIELDS,
    OAUTH_ALLOWED_ALGORITHMS,
    OAUTH_DEFAULT_ALGORITHMS,
    OAUTH_PRINCIPAL_CLAIM_DEFAULT,
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


def test_oauth_is_built_not_a_stub() -> None:
    """OAuth is now BUILT (ADR-019 increment B) — it no longer raises NotImplementedError.

    A missing/wrong-scheme header is rejected generically (``None``) before any crypto/JWKS work,
    so this needs no key material (the full JWT path is covered in the OAuth block below).
    """
    auth = OAuthResourceAuthenticator(
        issuer="https://idp.example", audience="gmcp", jwks_uri="https://idp.example/jwks"
    )
    assert auth.authenticate(AuthContext(authorization=None)) is None
    assert auth.authenticate(AuthContext(authorization="Basic xyz")) is None


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
    elif cls is OAuthResourceAuthenticator:
        inst = cls(issuer="https://idp", audience="gmcp", jwks_uri="https://idp/jwks")
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
    # ADR-019 B: oauth builds the resource-server authenticator from the configured issuer/aud/JWKS.
    assert isinstance(
        build_authenticator(
            "oauth",
            oauth_issuer="https://idp",
            oauth_audience="gmcp",
            oauth_jwks_uri="https://idp/jwks",
        ),
        OAuthResourceAuthenticator,
    )


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


# ==============================================================================================
# OAuthResourceAuthenticator (ADR-019 increment B) — a Bearer JWT validated LOCALLY via JWKS.
# HERMETIC: an in-test RSA (+ EC) keypair mints JWTs with PyJWT; the JWKS fetch is MOCKED by
# monkeypatching the authenticator's cached client so ``get_signing_key_from_jwt`` returns our
# public key (or raises, for the unknown-kid / fetch-failure paths). NO live IdP / network / real
# secrets. The pinned-alg allow-list makes ``alg:none`` and RS/HS confusion impossible by
# construction; iss/aud/exp/nbf are all validated; sub → Principal; any failure → generic None.
# ==============================================================================================
_ISS = "https://idp.example/realm"
_AUD = "ghidra-mcp"
_JWKS = "https://idp.example/realm/jwks"


class _FakeSigningKey:
    """A stand-in for PyJWT's ``PyJWK`` — only the ``.key`` attribute is used by ``jwt.decode``."""

    def __init__(self, key: object) -> None:
        self.key = key


class _FakeJWKClient:
    """A fake :class:`jwt.PyJWKClient`: returns a fixed signing key, or raises to simulate failure.

    Mocks the ONLY network touch (JWKS fetch) so the JWT-validation path is fully hermetic. With
    ``raises`` set it simulates an unknown ``kid`` / JWKS-fetch error (the authenticator must fail
    closed). ``calls`` counts invocations so a test can assert the client is reused (cached), not
    rebuilt per request (TB6-D — no per-request IdP round-trip).
    """

    def __init__(self, key: object, *, raises: Exception | None = None) -> None:
        self._key = key
        self._raises = raises
        self.calls = 0

    def get_signing_key_from_jwt(self, token: str) -> _FakeSigningKey:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return _FakeSigningKey(self._key)


def _rsa_keypair() -> rsa.RSAPrivateKey:
    """A deterministic-enough in-test RSA keypair (2048-bit). Synthetic — never a real secret."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ec_keypair() -> ec.EllipticCurvePrivateKey:
    """An in-test EC (P-256) keypair for the ES256 path. Synthetic — never a real secret."""
    return ec.generate_private_key(ec.SECP256R1())


def _mint(
    private_key: Any,  # an RSA/EC private key from cryptography (PyJWT's accepted signing key)
    *,
    alg: str,
    sub: str | None = "alice",
    iss: str | None = _ISS,
    aud: str | None = _AUD,
    exp_delta: int = 300,
    nbf_delta: int | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Mint a signed JWT with PyJWT (hermetic). Claims default to a valid, currently-valid token."""
    now = int(time.time())
    payload: dict[str, Any] = {"exp": now + exp_delta}
    if sub is not None:
        payload["sub"] = sub
    if iss is not None:
        payload["iss"] = iss
    if aud is not None:
        payload["aud"] = aud
    if nbf_delta is not None:
        payload["nbf"] = now + nbf_delta
    if extra:
        payload.update(extra)
    return jwt.encode(payload, private_key, algorithm=alg, headers={"kid": "test-key-1"})


def _oauth(
    monkeypatch: pytest.MonkeyPatch,
    *,
    public_key: object,
    raises: Exception | None = None,
    **kw: Any,
) -> tuple[OAuthResourceAuthenticator, _FakeJWKClient]:
    """Build an authenticator whose JWKS client is the fake (no network). Returns (auth, client).

    The authenticator caches its JWKS client in a mutable ``_jwks_client`` list (a frozen-dataclass-
    friendly lazy cache). We **pre-seed** that list with the fake so ``_client()`` finds it and
    never constructs a real :class:`jwt.PyJWKClient` — fully hermetic, no network. ``monkeypatch``
    is accepted for symmetry with the test signatures (and used by callers for ``caplog``).
    """
    _ = monkeypatch  # kept for signature symmetry; the cache is seeded directly below
    auth = OAuthResourceAuthenticator(issuer=_ISS, audience=_AUD, jwks_uri=_JWKS, **kw)
    fake = _FakeJWKClient(public_key, raises=raises)
    # Seed the lazy cache → _client() returns the fake (no network). The fake is duck-typed to
    # PyJWKClient.get_signing_key_from_jwt; mypy can't see the match on a concrete list.
    auth._jwks_client.append(fake)  # type: ignore[arg-type]
    return auth, fake


def test_oauth_valid_rs256_token_maps_sub_to_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="RS256", sub="alice")
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) == Principal(id="alice")


def test_oauth_valid_es256_token_maps_sub_to_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The EC (ES256) signature path is in the default allow-list and verifies hermetically."""
    key = _ec_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="ES256", sub="svc-account")
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) == Principal(
        id="svc-account"
    )


def test_oauth_scheme_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="RS256")
    assert auth.authenticate(AuthContext(authorization=f"bearer {token}")) == Principal(id="alice")


@pytest.mark.parametrize(
    "header",
    [None, "", "Basic abc", "Bearer ", "abc.def.ghi"],  # missing/empty/wrong-scheme/no-scheme
)
def test_oauth_missing_or_wrong_scheme_rejected_before_crypto(
    monkeypatch: pytest.MonkeyPatch, header: str | None
) -> None:
    """A missing/malformed scheme is rejected with NO JWKS call (no crypto on an absent token)."""
    key = _rsa_keypair()
    auth, fake = _oauth(monkeypatch, public_key=key.public_key())
    assert auth.authenticate(AuthContext(authorization=header)) is None
    assert fake.calls == 0  # short-circuited before any key fetch / verify


def test_oauth_principal_claim_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key(), principal_claim="email")
    token = _mint(key, alg="RS256", extra={"email": "alice@example.test"})
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) == Principal(
        id="alice@example.test"
    )


def test_oauth_jwks_client_is_cached_not_per_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """One JWKS client is reused across requests (no per-request IdP round-trip — TB6-D)."""
    key = _rsa_keypair()
    auth, fake = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="RS256")
    for _ in range(3):
        assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) == Principal(
            id="alice"
        )
    assert fake.calls == 3  # 3 lookups on ONE reused client (the client itself caches keys)


def test_oauth_real_client_built_lazily_and_cached() -> None:
    """Without monkeypatching, ``_client()`` constructs a real PyJWKClient ONCE and reuses it.

    This exercises the lazy-build/cache branch (no network: PyJWKClient does not fetch on
    construction — the fetch happens on ``get_signing_key_from_jwt``, which we never call here).
    """
    auth = OAuthResourceAuthenticator(issuer=_ISS, audience=_AUD, jwks_uri=_JWKS)
    first = auth._client()
    second = auth._client()
    assert first is second  # cached — same instance, not rebuilt


# --- Fail-closed: every failure → generic None, no oracle, token never logged -----------------
def test_oauth_alg_none_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A token with ``alg:none`` (unsigned) is rejected — the pinned allow-list forbids it."""
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    # PyJWT refuses to encode alg=none without allow_unsecured; craft the unsigned token directly.
    unsigned = jwt.encode({"sub": "mallory", "iss": _ISS, "aud": _AUD}, key=None, algorithm="none")  # type: ignore[arg-type]
    assert auth.authenticate(AuthContext(authorization=f"Bearer {unsigned}")) is None


def test_oauth_alg_confusion_hs256_when_rs256_expected_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An HS256 token (symmetric) is rejected when only RS256/ES256 are allowed (RS/HS confusion).

    The classic RS↔HS confusion attack signs an HS256 token (which the verifier might be tricked
    into checking with the RSA *public* key as the HMAC secret). With a pinned **asymmetric-only**
    allow-list, PyJWT is never asked to try HS256, so the forged token is rejected regardless of the
    HMAC secret. We mint the attacker token with the vetted ``jwt.encode`` (a raw shared-secret —
    PyJWT, not hand-rolled crypto).
    """
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())  # verifier given the RSA public key
    forged = jwt.encode(
        {"sub": "mallory", "iss": _ISS, "aud": _AUD},
        b"attacker-chosen-hmac-secret-32bytes!!",  # synthetic attacker secret, not real
        algorithm="HS256",
        headers={"kid": "test-key-1"},
    )
    assert auth.authenticate(AuthContext(authorization=f"Bearer {forged}")) is None


def test_oauth_wrong_issuer_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="RS256", iss="https://evil.example")
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_wrong_audience_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="RS256", aud="some-other-api")
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_expired_token_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key(), leeway_s=0)
    token = _mint(key, alg="RS256", exp_delta=-60)  # expired a minute ago
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_not_yet_valid_nbf_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key(), leeway_s=0)
    token = _mint(key, alg="RS256", nbf_delta=300)  # nbf 5 min in the future
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_bad_signature_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A token signed by a DIFFERENT key fails signature verification → reject."""
    signing = _rsa_keypair()
    other = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=other.public_key())  # verifier has the WRONG key
    token = _mint(signing, alg="RS256")
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_unknown_kid_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unknown ``kid`` (JWKS has no matching key) → the client raises → fail closed."""
    key = _rsa_keypair()
    auth, _ = _oauth(
        monkeypatch,
        public_key=key.public_key(),
        raises=jwt.exceptions.PyJWKClientError("no key for kid"),
    )
    token = _mint(key, alg="RS256")
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_jwks_fetch_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A JWKS fetch error (network/timeout) → generic reject, bounded (no fail-open)."""
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key(), raises=OSError("jwks unreachable"))
    token = _mint(key, alg="RS256")
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_missing_sub_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A validly-signed token with no ``sub`` claim → reject (no anonymous principal)."""
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="RS256", sub=None)
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_empty_sub_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="RS256", sub="")
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_non_string_sub_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-string subject (e.g. a number) → reject (the principal id must be a safe string)."""
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key(), principal_claim="uid")
    token = _mint(key, alg="RS256", extra={"uid": 12345})
    assert auth.authenticate(AuthContext(authorization=f"Bearer {token}")) is None


def test_oauth_malformed_token_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    assert auth.authenticate(AuthContext(authorization="Bearer not-a-jwt")) is None


def test_oauth_two_distinct_subjects_yield_two_distinct_principals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct ``sub`` → distinct principals → distinct owner-scoped sessions (ADR-017)."""
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    tok_a = _mint(key, alg="RS256", sub="alice")
    tok_b = _mint(key, alg="RS256", sub="bob")
    alice = auth.authenticate(AuthContext(authorization=f"Bearer {tok_a}"))
    bob = auth.authenticate(AuthContext(authorization=f"Bearer {tok_b}"))
    assert alice == Principal(id="alice")
    assert bob == Principal(id="bob")
    assert alice != bob


def test_oauth_rejects_empty_algorithm_list_at_construction() -> None:
    with pytest.raises(ValueError, match="at least one allowed algorithm"):
        OAuthResourceAuthenticator(issuer=_ISS, audience=_AUD, jwks_uri=_JWKS, algorithms=())


@pytest.mark.parametrize("bad", ["none", "HS256", "HS512", "rs256", "made-up"])
def test_oauth_rejects_unsafe_algorithm_at_construction(bad: str) -> None:
    """``alg:none`` and symmetric ``HS*`` (and unknown) algs cannot be configured (fail closed)."""
    with pytest.raises(ValueError, match="unsupported OAuth algorithm"):
        OAuthResourceAuthenticator(
            issuer=_ISS, audience=_AUD, jwks_uri=_JWKS, algorithms=("RS256", bad)
        )


def test_oauth_token_never_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Validating a token must emit NO log record containing the token (TB6-I/R)."""
    key = _rsa_keypair()
    auth, _ = _oauth(monkeypatch, public_key=key.public_key())
    token = _mint(key, alg="RS256", sub="alice")
    with caplog.at_level("DEBUG"):
        principal = auth.authenticate(AuthContext(authorization=f"Bearer {token}"))
    assert principal == Principal(id="alice")
    assert all(token not in rec.getMessage() for rec in caplog.records)
    # AuthContext keeps no secret in repr either (authorization carries the token, but it is the
    # per-request credential — defense in depth: assert the authenticator object never repr's it).
    assert token not in repr(auth)


def test_oauth_allow_list_excludes_symmetric_and_none() -> None:
    """Structural guard: the pinned allow-list is asymmetric-only — no ``none`` / ``HS*``."""
    assert "none" not in OAUTH_ALLOWED_ALGORITHMS
    assert not any(a.startswith("HS") for a in OAUTH_ALLOWED_ALGORITHMS)
    assert set(OAUTH_DEFAULT_ALGORITHMS) <= OAUTH_ALLOWED_ALGORITHMS
    assert OAUTH_PRINCIPAL_CLAIM_DEFAULT == "sub"


def test_oauth_authenticator_satisfies_protocol() -> None:
    assert isinstance(
        OAuthResourceAuthenticator(issuer=_ISS, audience=_AUD, jwks_uri=_JWKS), Authenticator
    )


def test_build_authenticator_oauth_threads_config() -> None:
    """``build_authenticator`` threads issuer/aud/JWKS/claim/algs/leeway into the OAuth strategy."""
    auth = build_authenticator(
        "oauth",
        oauth_issuer=_ISS,
        oauth_audience=_AUD,
        oauth_jwks_uri=_JWKS,
        oauth_principal_claim="email",
        oauth_algorithms=("ES256",),
        oauth_leeway_s=5,
    )
    assert isinstance(auth, OAuthResourceAuthenticator)
    assert auth.issuer == _ISS
    assert auth.audience == _AUD
    assert auth.jwks_uri == _JWKS
    assert auth.principal_claim == "email"
    assert auth.algorithms == ("ES256",)
    assert auth.leeway_s == 5


def test_build_authenticator_oauth_without_required_config_fails() -> None:
    with pytest.raises(ValueError, match="requires issuer, audience, and a JWKS URI"):
        build_authenticator("oauth", oauth_issuer=_ISS, oauth_audience=_AUD)  # missing jwks_uri
