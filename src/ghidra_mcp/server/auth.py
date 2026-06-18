"""HTTP authentication strategies (v1.1 — ADR-011 / threat-model TB6).

The **imperative shell's** auth seam. Authentication is a small **strategy port**
(:class:`Authenticator`) so the three mechanisms ADR-011 names compose behind one interface,
**default-deny** (a rejected request yields ``None`` → the shell returns a generic ``401``):

- :class:`BearerAuthenticator` — BUILT now. Constant-time compare of the ``Authorization: Bearer``
  token vs the configured secret; never reveals *why* a request failed (no user/credential oracle).
- :class:`MultiTokenBearerAuthenticator` — BUILT now (ADR-017). The multi-principal generalization:
  a ``{token: principal-id}`` map; a presented token is compared **constant-time against every
  entry with no early return** (no which-token timing oracle) and, on a match, the request is
  authenticated as that token's mapped :class:`Principal`. Distinct tokens → distinct principals, so
  each principal owns only the sessions it creates (BOLA / ``std-owasp-api`` API1). The map keys are
  secrets — kept out of ``repr``/logs (workflow-secrets).
- :class:`NullAuthenticator` — loopback/UDS only (single trusted host); explicit, never the default
  on a network bind (config fails closed there — `ghidra_mcp.config`).
- :class:`MtlsAuthenticator` — BUILT now (ADR-019 increment A). Server-terminated, in-app mTLS:
  uvicorn verifies the client cert chain to a configured CA at the TLS handshake (the transport
  gate — `config`/`app`), and the **verified** peer cert is surfaced to
  :attr:`AuthContext.peer_certificate` by the HTTP shell. This authenticator maps a configured cert
  field (subject CN — default — / a SAN / the full subject DN) → :class:`Principal`, **failing
  closed** (generic reject, no oracle) on an absent peer cert or an empty mapped field, as
  defense-in-depth on top of the handshake gate (`std-zero-trust`, `topic-authn-authz`).
- :class:`OAuthResourceAuthenticator` — BUILT now (ADR-019 increment B). OAuth resource server:
  validates a ``Bearer`` **JWT** access token LOCALLY via the issuer's **JWKS** (fetched + cached,
  no per-request IdP round-trip) with a **pinned** algorithm allow-list (no ``alg:none`` / RS-HS
  confusion) and the registered claims (``iss``/``aud``/``exp``/``nbf``); the configured claim
  (default ``sub``) → :class:`Principal`. Fails closed (generic reject, no oracle) on any failure;
  the token is never logged (`std-zero-trust`, `topic-authn-authz`, `std-owasp-api`).

Framework-agnostic by design: strategies operate on a minimal :class:`AuthContext` (the bits an
authenticator needs), not on a web request object — so this module is pure and 100%-unit-testable,
and the HTTP shell (a later slice) adapts its request to :class:`AuthContext`.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import jwt
from jwt import PyJWKClient

_BEARER_PREFIX = "bearer "  # scheme is case-insensitive (RFC 7235); compared lowercased

#: Defense-in-depth floor on the bearer token length. The AUTHORITATIVE startup gate is
#: `config._load_http_config` (same value); this re-check guards a too-short token reaching here.
_MIN_BEARER_TOKEN_LEN = 16

#: mTLS principal-field selectors (ADR-019 D2). Which field of the **verified** peer cert maps to
#: the principal id: ``cn`` = subject CN (default); ``san-dns`` / ``san-uri`` / ``san-email`` = the
#: first matching subjectAltName entry; ``dn`` = the full subject distinguished name (RFC 4514-ish
#: ``k=v`` join, stable + collision-resistant). Validated by config against the same set.
MTLS_PRINCIPAL_FIELDS = frozenset({"cn", "san-dns", "san-uri", "san-email", "dn"})
#: The default principal field when none is configured (subject CN — ADR-019 D2). Public so config
#: shares the same default (no drift).
MTLS_PRINCIPAL_FIELD_DEFAULT = "cn"
_DEFAULT_MTLS_PRINCIPAL_FIELD = MTLS_PRINCIPAL_FIELD_DEFAULT
#: Map a ``san-*`` selector to the SAN entry tag :func:`ssl.getpeercert` uses (case as returned).
_SAN_FIELD_TAGS = {"san-dns": "DNS", "san-uri": "URI", "san-email": "email"}

#: Reverse-proxy mTLS defaults (ADR-034). Header names are lowercased (HTTP headers are
#: case-insensitive; the middleware lowercases). Public so config shares the same defaults.
PROXY_SECRET_HEADER_DEFAULT = "x-proxy-auth"  # noqa: S105  # nosec B105 - a header NAME, not a secret
PROXY_IDENTITY_HEADER_DEFAULT = "x-client-cert-subject"
_DEFAULT_PROXY_SECRET_HEADER = PROXY_SECRET_HEADER_DEFAULT
_DEFAULT_PROXY_IDENTITY_HEADER = PROXY_IDENTITY_HEADER_DEFAULT
#: Upper bound on a forwarded identity (a subject CN/DN). Bounds the principal-id length the proxy
#: can assert (it becomes the session-owner key — ADR-017); a longer value fails closed.
_MAX_PROXY_IDENTITY_LEN = 256


def _valid_proxy_identity(value: str) -> bool:
    """Return whether a proxy-forwarded identity is a safe principal id (ADR-034; fail closed).

    Non-empty, ``<= _MAX_PROXY_IDENTITY_LEN`` chars, and free of control/newline characters (it is
    attacker-influenced if the proxy is compromised, and becomes the session-owner key — bound it).
    A subject DN's ``=,/ .`` etc. are allowed; only control characters are rejected.

    Args:
        value: The raw identity-header value (already confirmed non-``None`` by the caller).

    Returns:
        ``True`` iff the value is a usable, bounded, control-char-free principal id.
    """
    if not value or len(value) > _MAX_PROXY_IDENTITY_LEN:
        return False
    return not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


#: OAuth (ADR-019 D3). The PINNED algorithm allow-list — only **asymmetric** JWS algorithms whose
#: verification key is a *public* key (so a leaked/guessed JWKS key cannot be used to MINT tokens).
#: ``alg:none`` and every symmetric (``HS*``) algorithm are excluded by construction, defeating the
#: classic RS↔HS key-confusion attack (a server that accepted ``HS256`` could be tricked into
#: verifying an attacker-forged token with the *public* key as the HMAC secret). Config validates
#: any configured allow-list against this set, so an operator can never widen it to an unsafe alg.
OAUTH_ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
)
#: The default algorithm allow-list when none is configured (the two most common OIDC asymmetric
#: algs — ADR-019 D3). Public so config shares the same default (no drift). Ordered for a stable
#: repr; the set above is the validation gate.
OAUTH_DEFAULT_ALGORITHMS = ("RS256", "ES256")
#: The default JWT claim mapped to the principal id (subject — ADR-019 D3). Public so config shares
#: the same default.
OAUTH_PRINCIPAL_CLAIM_DEFAULT = "sub"
#: Default leeway (seconds) for ``exp``/``nbf`` clock-skew tolerance — small, per ADR-019 D3.
OAUTH_DEFAULT_LEEWAY_S = 30

#: The two per-tool capabilities (ADR-033). ``write`` is required by the mutation tools; ``read`` by
#: everything else (read/query tools, session lifecycle, the read-only annotation export).
CAP_READ = "read"
CAP_WRITE = "write"
#: Full capability — the default for every principal. Only the OAuth authenticator, AND only when a
#: write-scope is configured (ADR-033 D2), ever narrows a principal below this (to read-only).
ALL_CAPABILITIES: frozenset[str] = frozenset({CAP_READ, CAP_WRITE})


def _token_scopes(claims: dict[str, object]) -> frozenset[str]:
    """Extract the granted OAuth scopes from a token's claims (ADR-033; fail closed/empty).

    Accepts both the standard ``scope`` (a single space-delimited string — RFC 6749 §3.3 / RFC 8693)
    and the common ``scp`` variant (a list of strings, or a space-delimited string). Anything of an
    unexpected shape yields the empty set (fail closed — an unparsable scopes claim grants nothing).

    Args:
        claims: The verified JWT claims.

    Returns:
        The set of scope strings present on the token (possibly empty).
    """
    out: set[str] = set()
    raw_scope = claims.get("scope")
    if isinstance(raw_scope, str):
        out.update(raw_scope.split())
    raw_scp = claims.get("scp")
    if isinstance(raw_scp, str):
        out.update(raw_scp.split())
    elif isinstance(raw_scp, (list, tuple)):
        out.update(str(s) for s in raw_scp if isinstance(s, str))
    return frozenset(out)


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated identity. Owns the sessions it creates (TB6-I / BOLA — `std-owasp-api`).

    ``capabilities`` (ADR-033) is the principal's per-tool authorization set — ``read`` and/or
    ``write``. It defaults to **full** (``ALL_CAPABILITIES``): stdio (the local operator), bearer,
    and mTLS principals are full-capability (they have no scope concept — ADR-019). Only an OAuth
    token,
    and only when the deployment configures a write-scope, is narrowed (to read-only when the token
    lacks that scope). The dispatch chokepoint denies a tool whose required capability is absent.
    """

    id: str
    capabilities: frozenset[str] = ALL_CAPABILITIES


@dataclass(frozen=True, slots=True)
class AuthContext:
    """The minimal, transport-agnostic inputs an authenticator may use.

    Attributes:
        authorization: The ``Authorization`` header value, or ``None`` if absent.
        peer_certificate: The **verified** client certificate for mTLS as the parsed mapping
            :func:`ssl.SSLSocket.getpeercert` returns (``{"subject": ..., "subjectAltName": ...}``),
            or ``None`` when the request carried no verified peer cert. Populated by the HTTP shell
            (the auth middleware) from the ASGI scope; unused by bearer. ``None``/empty ⇒ the mTLS
            authenticator fails closed.
        headers: The request headers as a lowercased-name → first-value mapping (ADR-034). Populated
            by the auth middleware. Read only by the reverse-proxy authenticator (its configured
            secret + identity headers); bearer/mTLS/OAuth ignore it. Empty for non-HTTP/test calls.
    """

    authorization: str | None = None
    peer_certificate: object | None = field(default=None, repr=False)
    headers: Mapping[str, str] = field(default_factory=dict)


@runtime_checkable
class Authenticator(Protocol):
    """Strategy port: map an :class:`AuthContext` to a :class:`Principal`, or ``None`` to reject."""

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Map ``ctx`` to a :class:`Principal`, or ``None`` to reject (default-deny)."""
        ...


@dataclass(frozen=True, slots=True)
class BearerAuthenticator:
    """Static bearer-token authenticator: constant-time compare, generic reject (no oracle).

    The expected token is a secret (env/secret-manager — `workflow-secrets`); kept out of ``repr``.
    """

    expected_token: str = field(repr=False)

    def __post_init__(self) -> None:
        """Reject a too-short/empty token at construction (defense in depth; config also checks)."""
        if len(self.expected_token) < _MIN_BEARER_TOKEN_LEN:
            raise ValueError("bearer token too short")

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Return a :class:`Principal` iff a valid ``Bearer`` token is presented, else ``None``.

        Constant-time comparison (`hmac.compare_digest`) avoids a timing oracle; a missing header,
        wrong scheme, or wrong token all fail identically (no distinguishing signal to the caller).
        """
        header = ctx.authorization
        if header is None or header[: len(_BEARER_PREFIX)].lower() != _BEARER_PREFIX:
            return None
        presented = header[len(_BEARER_PREFIX) :].strip()
        # A non-ASCII value can never equal the ASCII configured token; reject it BEFORE
        # compare_digest (which raises TypeError on non-ASCII) — fail closed, no oracle, no raise.
        if not presented.isascii() or not hmac.compare_digest(presented, self.expected_token):
            return None
        return Principal(id="bearer")


@dataclass(frozen=True, slots=True)
class MultiTokenBearerAuthenticator:
    """Multi-principal bearer authenticator (ADR-017): ``{token: principal-id}``, no timing oracle.

    Generalizes :class:`BearerAuthenticator` to several distinct principals, each identified by a
    distinct secret token. A presented token is compared **constant-time against every configured
    entry with no early return** on the timing-sensitive path, so the response time does not reveal
    *which* token matched (or how far a near-miss got) — no which-token oracle. On a match the
    request is authenticated as that token's mapped :class:`Principal`; any miss is a generic reject
    (``None`` → ``401``), identical to an absent/malformed header (no credential oracle).

    The map keys are secrets (env/secret-manager — `workflow-secrets`); the whole map is kept out of
    ``repr``. Distinct tokens yield distinct principals, so a session created by one token's
    principal is not accessible to another (the per-principal ownership check lives in the manager).
    """

    #: ``{token: principal-id}``. Excluded from ``repr`` — the KEYS are secrets.
    tokens: dict[str, str] = field(repr=False)

    def __post_init__(self) -> None:
        """Reject an empty map or any too-short token at construction (defense in depth)."""
        if not self.tokens:
            raise ValueError("bearer auth requires at least one token")
        if any(len(token) < _MIN_BEARER_TOKEN_LEN for token in self.tokens):
            raise ValueError("bearer token too short")

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Return the matched token's :class:`Principal`, else ``None`` (generic, oracle-free).

        Scans **all** entries with :func:`hmac.compare_digest` and **no early return**, recording
        the matched principal id without branching on the comparison outcome — so neither *whether*
        a token matched nor *which* one is observable via timing. A missing/malformed header
        short-circuits before the constant-time scan (no secret is involved in that case).
        """
        header = ctx.authorization
        if header is None or header[: len(_BEARER_PREFIX)].lower() != _BEARER_PREFIX:
            return None
        presented = header[len(_BEARER_PREFIX) :].strip()
        if not presented.isascii():
            return None  # non-ASCII can't match an ASCII token + would raise in compare_digest
        matched_id: str | None = None
        # Compare against EVERY entry; do not break on a hit — the loop's work is independent of
        # which (if any) token matched, so there is no which-token timing oracle (ADR-017 STRIDE-S).
        for token, principal_id in self.tokens.items():
            if hmac.compare_digest(presented, token):
                matched_id = principal_id
        if matched_id is None:
            return None
        return Principal(id=matched_id)


@dataclass(frozen=True, slots=True)
class NullAuthenticator:
    """No-auth strategy for loopback/UDS (single trusted host); never the default on a net bind."""

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Accept every request as the local operator (the bind itself is the trust boundary)."""
        return Principal(id="local")


def _cn_from_subject(subject: object) -> str | None:
    """Extract the subject **commonName** from a parsed ``getpeercert()`` subject, or ``None``.

    The subject is a tuple of RDNs, each a tuple of ``(attr, value)`` pairs, e.g.
    ``((("commonName", "alice"),), (("organizationName", "acme"),))``. The first ``commonName``
    found is returned. Malformed/missing shapes yield ``None`` (fail closed — never raise on a
    hostile/odd cert structure).
    """
    if not isinstance(subject, (tuple, list)):
        return None
    for rdn in subject:
        if not isinstance(rdn, (tuple, list)):
            continue
        for pair in rdn:
            if (
                isinstance(pair, (tuple, list))
                and len(pair) == 2
                and pair[0] == "commonName"
                and isinstance(pair[1], str)
            ):
                return pair[1]
    return None


def _dn_from_subject(subject: object) -> str | None:
    """Render the full subject DN as a stable ``attr=value`` join (RFC 4514-ish), or ``None``.

    Joins every RDN attribute as ``attr=value`` with ``,`` so the whole distinguished name (not just
    the CN) identifies the principal — useful when CNs are not unique but the issuing CA guarantees
    unique full subjects. Returns ``None`` for an empty/malformed subject (fail closed).
    """
    if not isinstance(subject, (tuple, list)) or not subject:
        return None
    parts: list[str] = []
    for rdn in subject:
        if not isinstance(rdn, (tuple, list)):
            continue
        for pair in rdn:
            if (
                isinstance(pair, (tuple, list))
                and len(pair) == 2
                and isinstance(pair[0], str)
                and isinstance(pair[1], str)
            ):
                parts.append(f"{pair[0]}={pair[1]}")
    return ",".join(parts) if parts else None


def _first_san(san: object, tag: str) -> str | None:
    """Return the first subjectAltName value whose tag equals ``tag`` (e.g. ``DNS``), or ``None``.

    ``san`` is a tuple of ``(tag, value)`` pairs, e.g. ``(("DNS", "alice.example"), ...)``.
    Malformed/missing shapes yield ``None`` (fail closed).
    """
    if not isinstance(san, (tuple, list)):
        return None
    for pair in san:
        if (
            isinstance(pair, (tuple, list))
            and len(pair) == 2
            and pair[0] == tag
            and isinstance(pair[1], str)
        ):
            return pair[1]
    return None


@dataclass(frozen=True, slots=True)
class MtlsAuthenticator:
    """mTLS authenticator (ADR-019 D2): verified peer cert field → principal, fail closed.

    The TLS handshake (uvicorn ``ssl_cert_reqs=CERT_REQUIRED`` + a configured client-CA bundle) is
    the first gate — no client without a CA-signed cert reaches the app. This authenticator is the
    in-app second gate (defense in depth): it reads the **verified** peer cert from
    :attr:`AuthContext.peer_certificate` (the parsed :func:`ssl.getpeercert` mapping the HTTP shell
    surfaces) and maps the configured field to a :class:`Principal`.

    ``principal_field`` selects which cert field is the identity (validated against
    :data:`MTLS_PRINCIPAL_FIELDS` at config time): ``cn`` (subject CN, default), ``san-dns`` /
    ``san-uri`` / ``san-email`` (the first matching SAN), or ``dn`` (the full subject DN).

    **Fail closed, no oracle:** an absent peer cert, an unparseable cert mapping, or an
    empty/missing mapped field all return ``None`` → the shell's generic ``401`` — identical to
    every other reject, so nothing about *why* a request failed is observable. The CA path / field
    selector are config, not secrets; ``principal_field`` is loggable (not a secret), kept in
    ``repr``.
    """

    principal_field: str = _DEFAULT_MTLS_PRINCIPAL_FIELD

    def __post_init__(self) -> None:
        """Reject an unknown ``principal_field`` at construction (defense in depth; config too)."""
        if self.principal_field not in MTLS_PRINCIPAL_FIELDS:
            raise ValueError("unknown mTLS principal field")

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Map the verified peer cert's configured field to a :class:`Principal`, else ``None``.

        Fails closed (``None``) on a missing peer cert, a non-mapping cert object, or an empty
        mapped field — a uniform reject with no oracle. Never raises on a hostile/odd cert: every
        extractor returns ``None`` rather than throwing.
        """
        cert = ctx.peer_certificate
        if not isinstance(cert, dict):
            return None  # no verified peer cert (or an unexpected shape) → fail closed
        value: str | None
        if self.principal_field == "cn":
            value = _cn_from_subject(cert.get("subject"))
        elif self.principal_field == "dn":
            value = _dn_from_subject(cert.get("subject"))
        else:  # san-dns / san-uri / san-email — validated, so the tag lookup always hits
            value = _first_san(cert.get("subjectAltName"), _SAN_FIELD_TAGS[self.principal_field])
        if not value:  # missing or empty mapped field → fail closed (no anonymous principal)
            return None
        return Principal(id=value)


@dataclass(frozen=True, slots=True)
class ReverseProxyMtlsAuthenticator:
    """Trust a TLS-terminating proxy's forwarded client identity, gated on a secret (ADR-034).

    The opt-in reverse-proxy mTLS mode. The proxy terminates TLS, **verifies the client cert
    chain**, and forwards the verified identity (subject CN/DN) in :attr:`identity_header`. Because
    the server has no direct TLS to the client, it trusts that header **only** when the request also
    carries the correct pre-shared secret in :attr:`secret_header` — the code-enforced trust anchor
    against the header-spoofing footgun ADR-019 named (a direct attacker cannot forge identity
    without the secret). The mode is also subject to a mandatory network-isolation deployment
    constraint (only the proxy may reach the server — see the threat model / deploy docs).

    Fail closed, no oracle: a missing/wrong secret, or a missing/malformed identity, returns a
    uniform ``None`` (→ the shell's generic ``401``). The secret is never logged (excluded from
    ``repr``); the identity is never logged verbatim.

    Attributes:
        shared_secret: The pre-shared secret the proxy must present (the trust anchor). Excluded
            from ``repr`` (it is the credential).
        secret_header: The (lowercased) header carrying the shared secret. Default ``x-proxy-auth``.
        identity_header: The (lowercased) header carrying the proxy-verified client identity.
            Default ``x-client-cert-subject``.
    """

    shared_secret: str = field(repr=False)
    secret_header: str = _DEFAULT_PROXY_SECRET_HEADER
    identity_header: str = _DEFAULT_PROXY_IDENTITY_HEADER

    def __post_init__(self) -> None:
        """Re-assert the secret length floor (defense in depth over the config gate)."""
        if len(self.shared_secret) < _MIN_BEARER_TOKEN_LEN:
            raise ValueError("reverse-proxy shared secret too short")

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Map the proxy-forwarded identity to a principal IFF the shared secret matches (ADR-034).

        Order (fail closed): verify the secret header **first** (constant-time, no early-return
        oracle) — a missing/wrong secret never even consults the identity header; then read +
        validate the identity header and map it to a :class:`Principal`. Any failure → ``None``.
        """
        presented = ctx.headers.get(self.secret_header)
        # Constant-time compare; reject before touching the identity header (the secret is the
        # anchor — without it the forwarded identity is meaningless). A non-ASCII value can't equal
        # the ASCII secret and would raise in compare_digest, so reject it first. No oracle.
        if (
            presented is None
            or not presented.isascii()
            or not hmac.compare_digest(presented, self.shared_secret)
        ):
            return None
        identity = ctx.headers.get(self.identity_header)
        if identity is None or not _valid_proxy_identity(identity):
            return None  # missing/empty/over-long/control-char identity → fail closed
        return Principal(id=identity)


@dataclass(frozen=True, slots=True)
class OAuthResourceAuthenticator:
    """OAuth resource-server authenticator (ADR-019 D3): a Bearer **JWT** validated via JWKS.

    The server acts as an OAuth 2.x **resource server**: it validates a ``Bearer`` access token
    that is a **JWT** without a per-request IdP round-trip. The issuer's signing keys are fetched
    from the configured **JWKS** endpoint and **cached** (PyJWT's :class:`~jwt.PyJWKClient`, stdlib
    ``urllib`` under the hood — no new HTTP dependency; the worker stays no-network —
    `std-zero-trust` TB6-D). Validation, in order, mirrors `topic-authn-authz`:

    1. Extract the ``Bearer`` token from :attr:`AuthContext.authorization`; a missing header or a
       wrong scheme returns ``None`` **before any crypto** (no work on an absent credential).
    2. Resolve the JWS **signing key** for the token's ``kid`` from the JWKS (an unknown ``kid`` or
       a JWKS-fetch failure → fail closed; bounded — no unbounded retry/egress).
    3. Verify the signature with a **PINNED algorithm allow-list**
       (:data:`OAUTH_ALLOWED_ALGORITHMS`, narrowed by ``algorithms``): the token's own ``alg`` is
       **never trusted** — ``alg:none`` and any symmetric/confusion alg are impossible by
       construction.
    4. Enforce the **registered claims**: ``iss`` == configured issuer, ``aud`` == configured
       audience, and ``exp``/``nbf`` (with a small ``leeway``); ``exp``/``iss``/``aud`` are
       **required** (a token missing one is rejected, not silently accepted).
    5. Map the configured ``principal_claim`` (default ``sub``) to :class:`Principal`; an
       empty/missing/non-string value → ``None``.

    **Fail closed, no oracle:** *any* failure — bad signature, wrong ``iss``/``aud``, expired or
    not-yet-valid, unknown ``kid``, ``alg:none``, missing ``sub``, malformed token, or a JWKS-fetch
    error — returns a generic ``None`` → the shell's uniform ``401``. The token is **never** logged
    or echoed and the failure reason is not surfaced to the caller (TB6-I/R —
    `topic-logging-observability`). Construction validates the allow-list (defense in depth; config
    also checks).

    All fields are **non-secret** config (issuer / audience / JWKS URI / claim / algs / leeway), so
    the dataclass stays in ``repr`` — there is no secret to hide (the bearer token is per-request,
    never stored here).
    """

    issuer: str
    audience: str
    jwks_uri: str
    principal_claim: str = OAUTH_PRINCIPAL_CLAIM_DEFAULT
    algorithms: tuple[str, ...] = OAUTH_DEFAULT_ALGORITHMS
    leeway_s: int = OAUTH_DEFAULT_LEEWAY_S
    #: The scope (ADR-033) granting the ``write`` capability. ``None`` (default) ⇒ scope-gating OFF:
    #: every valid token is full-capability (identity-only, the pre-ADR-033 behavior). When set, a
    #: token gets ``write`` iff its ``scope``/``scp`` claim contains this string (else read-only).
    write_scope: str | None = None
    #: The JWKS client (key fetch + cache). Excluded from ``repr`` (not a secret, but noisy) and
    #: from equality (an internal cache handle, not identity). Built lazily on first use so the
    #: dataclass stays cheap to build and the network-touching client is made only on first request.
    _jwks_client: list[PyJWKClient] = field(
        default_factory=list, repr=False, compare=False, hash=False
    )

    def __post_init__(self) -> None:
        """Reject an empty or non-allow-listed algorithm list at construction (fail closed).

        Defense in depth on top of the config gate: the only algorithms ever passed to PyJWT are
        asymmetric, public-key-verified ones — ``alg:none``/``HS*`` can never reach the verifier.
        """
        if not self.algorithms:
            raise ValueError("OAuth requires at least one allowed algorithm")
        for alg in self.algorithms:
            if alg not in OAUTH_ALLOWED_ALGORITHMS:
                raise ValueError("unsupported OAuth algorithm")

    def _client(self) -> PyJWKClient:
        """Return the cached :class:`~jwt.PyJWKClient`, building it on first use (fetch + cache)."""
        if not self._jwks_client:
            # PyJWKClient caches fetched keys (lifespan-bounded); one instance is reused so the JWKS
            # endpoint is hit at most on a cache miss, not per request (TB6-D, `std-zero-trust`).
            self._jwks_client.append(PyJWKClient(self.jwks_uri))
        return self._jwks_client[0]

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Validate the Bearer JWT (sig via JWKS + iss/aud/exp/nbf), map ``sub`` to a principal.

        Returns a :class:`Principal` only for a token that passes **every** check; any failure is a
        uniform ``None`` (generic reject, no oracle). Never raises on a hostile/malformed token and
        never logs the token (defense in depth — the shell turns ``None`` into a generic ``401``).
        """
        header = ctx.authorization
        if header is None or header[: len(_BEARER_PREFIX)].lower() != _BEARER_PREFIX:
            return None  # missing/wrong scheme — reject before any crypto (no token to verify)
        token = header[len(_BEARER_PREFIX) :].strip()
        if not token:
            return None
        try:
            signing_key = self._client().get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                # PINNED allow-list — the token's own ``alg`` is never trusted (no alg:none / HS
                # confusion); PyJWT rejects a token whose alg is not in this list.
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_s,
                # Require the security-relevant registered claims to be PRESENT (a token lacking
                # exp/iss/aud is rejected, not silently accepted) and verified.
                options={
                    "require": ["exp", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except Exception:  # fail closed on ANY error (incl. JWKS fetch/network) — never re-raise
            # Any validation/parse/JWKS-fetch error → generic reject. We deliberately catch broadly
            # (a JWKS fetch may raise PyJWTError OR a network OSError/URLError) and discard the
            # detail: the failure reason must NOT become a caller-visible oracle, and the token /
            # exception text is never logged here (TB6-I/R, fail closed — `topic-error-handling`).
            return None
        principal_id = claims.get(self.principal_claim)
        if not isinstance(principal_id, str) or not principal_id:
            return None  # missing/empty/non-string subject → no anonymous principal (fail closed)
        return Principal(id=principal_id, capabilities=self._capabilities_from_claims(claims))

    def _capabilities_from_claims(self, claims: dict[str, object]) -> frozenset[str]:
        """Derive the principal's capabilities from the token scopes (ADR-033 D2; fail closed).

        With no ``write_scope`` configured, scope-gating is OFF → full capability (identity-only,
        the pre-ADR-033 behavior). With it set, a valid token always gets ``read``; it gets
        ``write`` ONLY if its ``scope`` (space-delimited string — RFC 6749/8693) or ``scp`` (array —
        a common IdP variant) claim contains the configured ``write_scope``.

        Args:
            claims: The verified JWT claims.

        Returns:
            The capability set granted to this token.
        """
        if self.write_scope is None:
            return ALL_CAPABILITIES
        scopes = _token_scopes(claims)
        return ALL_CAPABILITIES if self.write_scope in scopes else frozenset({CAP_READ})


def build_authenticator(
    auth_mode: str,
    *,
    bearer_token: str | None = None,
    bearer_tokens: dict[str, str] | None = None,
    mtls_principal_field: str = _DEFAULT_MTLS_PRINCIPAL_FIELD,
    oauth_issuer: str | None = None,
    oauth_audience: str | None = None,
    oauth_jwks_uri: str | None = None,
    oauth_principal_claim: str = OAUTH_PRINCIPAL_CLAIM_DEFAULT,
    oauth_algorithms: tuple[str, ...] = OAUTH_DEFAULT_ALGORITHMS,
    oauth_leeway_s: int = OAUTH_DEFAULT_LEEWAY_S,
    oauth_write_scope: str | None = None,
    proxy_shared_secret: str | None = None,
    proxy_secret_header: str = _DEFAULT_PROXY_SECRET_HEADER,
    proxy_identity_header: str = _DEFAULT_PROXY_IDENTITY_HEADER,
) -> Authenticator:
    """Construct the :class:`Authenticator` for a validated ``auth_mode`` (the wiring seam).

    For ``bearer`` the multi-principal :class:`MultiTokenBearerAuthenticator` is built from
    ``bearer_tokens`` (the ``{token: principal-id}`` map from config — ADR-017). A lone
    ``bearer_token`` (back-compat / tests) is folded into a one-entry map → the ``bearer``
    principal, so a single configured token keeps working unchanged. For ``mtls`` (ADR-019 A) the
    :class:`MtlsAuthenticator` is built with the configured ``mtls_principal_field`` (the verified
    peer-cert field → principal id); the client-CA bundle that backs the handshake gate is wired in
    the HTTP runner, not here. For ``oauth`` (ADR-019 B) the :class:`OAuthResourceAuthenticator` is
    built with the configured issuer / audience / JWKS URI / principal-claim / alg allow-list /
    leeway (config guarantees the three required values are present for ``auth_mode == "oauth"``).

    Args:
        auth_mode: One of ``"none"`` / ``"bearer"`` / ``"mtls"`` / ``"oauth"`` (already validated by
            config).
        bearer_token: A single back-compat bearer secret (→ the ``bearer`` principal). Optional.
        bearer_tokens: The multi-principal ``{token: principal-id}`` map. Optional; combined with
            ``bearer_token`` when both are given.
        mtls_principal_field: The verified peer-cert field that maps to the principal id for
            ``mtls`` (one of :data:`MTLS_PRINCIPAL_FIELDS`; default subject CN). Ignored for other
            modes.
        oauth_issuer: The expected JWT ``iss`` for ``oauth`` (required for that mode).
        oauth_audience: The expected JWT ``aud`` for ``oauth`` (required for that mode).
        oauth_jwks_uri: The issuer's JWKS endpoint for ``oauth`` (required for that mode).
        oauth_principal_claim: The JWT claim mapped to the principal id (default ``sub``).
        oauth_algorithms: The pinned algorithm allow-list (subset of
            :data:`OAUTH_ALLOWED_ALGORITHMS`; default :data:`OAUTH_DEFAULT_ALGORITHMS`).
        oauth_leeway_s: Clock-skew leeway in seconds for ``exp``/``nbf``.
        oauth_write_scope: The scope granting the ``write`` capability (ADR-033); ``None`` ⇒
            scope-gating off (every valid token is full-capability — identity-only).
        proxy_shared_secret: The pre-shared secret for ``mtls-proxy`` (ADR-034); REQUIRED for that
            mode (the trust anchor) — absent ⇒ ``ValueError``.
        proxy_secret_header: The header carrying the shared secret (default ``x-proxy-auth``).
        proxy_identity_header: The header carrying the proxy-verified client identity (default
            ``x-client-cert-subject``).

    Returns:
        The matching authenticator.

    Raises:
        ValueError: if ``auth_mode`` is unknown, ``bearer`` without any token, ``mtls`` with an
            unknown principal field, or ``oauth`` without issuer/audience/JWKS URI or with an
            unsupported algorithm (fail closed).
    """
    if auth_mode == "none":
        return NullAuthenticator()
    if auth_mode == "bearer":
        tokens: dict[str, str] = dict(bearer_tokens) if bearer_tokens else {}
        if bearer_token is not None:
            tokens.setdefault(bearer_token, "bearer")
        if not tokens:
            raise ValueError("bearer auth requires a token")
        return MultiTokenBearerAuthenticator(tokens=tokens)
    if auth_mode == "mtls":
        return MtlsAuthenticator(principal_field=mtls_principal_field)
    if auth_mode == "mtls-proxy":
        if not proxy_shared_secret:
            raise ValueError("mtls-proxy auth requires a shared secret")
        return ReverseProxyMtlsAuthenticator(
            shared_secret=proxy_shared_secret,
            secret_header=proxy_secret_header,
            identity_header=proxy_identity_header,
        )
    if auth_mode == "oauth":
        if oauth_issuer is None or oauth_audience is None or oauth_jwks_uri is None:
            # Config guarantees these for auth_mode=oauth; re-checked here so a programmatic caller
            # cannot build a half-configured OAuth authenticator (fail closed — defense in depth).
            raise ValueError("oauth auth requires issuer, audience, and a JWKS URI")
        return OAuthResourceAuthenticator(
            issuer=oauth_issuer,
            audience=oauth_audience,
            jwks_uri=oauth_jwks_uri,
            principal_claim=oauth_principal_claim,
            algorithms=oauth_algorithms,
            leeway_s=oauth_leeway_s,
            write_scope=oauth_write_scope,
        )
    raise ValueError(f"unknown auth mode: {auth_mode}")
