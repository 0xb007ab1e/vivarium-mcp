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
- :class:`OAuthResourceAuthenticator` — **port-ready stub** (ADR-019 increment B, not built here):
  satisfies the :class:`Authenticator` protocol so the shell + factory are complete, and raises on
  use until built (OAuth 2.1 per the MCP remote-auth profile).

Framework-agnostic by design: strategies operate on a minimal :class:`AuthContext` (the bits an
authenticator needs), not on a web request object — so this module is pure and 100%-unit-testable,
and the HTTP shell (a later slice) adapts its request to :class:`AuthContext`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

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


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated identity. Owns the sessions it creates (TB6-I / BOLA — `std-owasp-api`)."""

    id: str


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
    """

    authorization: str | None = None
    peer_certificate: object | None = field(default=None, repr=False)


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
        if hmac.compare_digest(presented, self.expected_token):
            return Principal(id="bearer")
        return None


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
class OAuthResourceAuthenticator:
    """Port-ready OAuth 2.1 resource-server stub; satisfies the port, raises until built."""

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Not yet implemented — `auth=oauth` is a port; build before enabling."""
        raise NotImplementedError(
            "OAuth authentication is not implemented yet (ADR-011 port-ready)"
        )


def build_authenticator(
    auth_mode: str,
    *,
    bearer_token: str | None = None,
    bearer_tokens: dict[str, str] | None = None,
    mtls_principal_field: str = _DEFAULT_MTLS_PRINCIPAL_FIELD,
) -> Authenticator:
    """Construct the :class:`Authenticator` for a validated ``auth_mode`` (the wiring seam).

    For ``bearer`` the multi-principal :class:`MultiTokenBearerAuthenticator` is built from
    ``bearer_tokens`` (the ``{token: principal-id}`` map from config — ADR-017). A lone
    ``bearer_token`` (back-compat / tests) is folded into a one-entry map → the ``bearer``
    principal, so a single configured token keeps working unchanged. For ``mtls`` (ADR-019 A) the
    :class:`MtlsAuthenticator` is built with the configured ``mtls_principal_field`` (the verified
    peer-cert field → principal id); the client-CA bundle that backs the handshake gate is wired in
    the HTTP runner, not here.

    Args:
        auth_mode: One of ``"none"`` / ``"bearer"`` / ``"mtls"`` / ``"oauth"`` (already validated by
            config).
        bearer_token: A single back-compat bearer secret (→ the ``bearer`` principal). Optional.
        bearer_tokens: The multi-principal ``{token: principal-id}`` map. Optional; combined with
            ``bearer_token`` when both are given.
        mtls_principal_field: The verified peer-cert field that maps to the principal id for
            ``mtls`` (one of :data:`MTLS_PRINCIPAL_FIELDS`; default subject CN). Ignored for other
            modes.

    Returns:
        The matching authenticator (OAuth returns a port-ready stub).

    Raises:
        ValueError: if ``auth_mode`` is unknown, ``bearer`` without any token, or ``mtls`` with an
            unknown principal field (fail closed).
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
    if auth_mode == "oauth":
        return OAuthResourceAuthenticator()
    raise ValueError(f"unknown auth mode: {auth_mode}")
