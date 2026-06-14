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
- :class:`MtlsAuthenticator` / :class:`OAuthResourceAuthenticator` — **port-ready stubs**: they
  satisfy the :class:`Authenticator` protocol so the shell + factory are complete, and raise on use
  until built (mTLS per `std-zero-trust`; OAuth 2.1 per the MCP remote-auth profile).

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


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated identity. Owns the sessions it creates (TB6-I / BOLA — `std-owasp-api`)."""

    id: str


@dataclass(frozen=True, slots=True)
class AuthContext:
    """The minimal, transport-agnostic inputs an authenticator may use.

    Attributes:
        authorization: The ``Authorization`` header value, or ``None`` if absent.
        peer_certificate: The verified client certificate for mTLS, or ``None`` (set by the TLS
            terminator in a later slice; unused by bearer).
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


@dataclass(frozen=True, slots=True)
class MtlsAuthenticator:
    """Port-ready mTLS stub (`std-zero-trust`); satisfies the port, raises until built."""

    def authenticate(self, ctx: AuthContext) -> Principal | None:
        """Not yet implemented — `auth=mtls` is a port; build before enabling."""
        raise NotImplementedError("mTLS authentication is not implemented yet (ADR-011 port-ready)")


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
) -> Authenticator:
    """Construct the :class:`Authenticator` for a validated ``auth_mode`` (the wiring seam).

    For ``bearer`` the multi-principal :class:`MultiTokenBearerAuthenticator` is built from
    ``bearer_tokens`` (the ``{token: principal-id}`` map from config — ADR-017). A lone
    ``bearer_token`` (back-compat / tests) is folded into a one-entry map → the ``bearer``
    principal, so a single configured token keeps working unchanged.

    Args:
        auth_mode: One of ``"none"`` / ``"bearer"`` / ``"mtls"`` / ``"oauth"`` (already validated by
            config).
        bearer_token: A single back-compat bearer secret (→ the ``bearer`` principal). Optional.
        bearer_tokens: The multi-principal ``{token: principal-id}`` map. Optional; combined with
            ``bearer_token`` when both are given.

    Returns:
        The matching authenticator (mTLS/OAuth return port-ready stubs).

    Raises:
        ValueError: if ``auth_mode`` is unknown, or ``bearer`` without any token (fail closed).
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
        return MtlsAuthenticator()
    if auth_mode == "oauth":
        return OAuthResourceAuthenticator()
    raise ValueError(f"unknown auth mode: {auth_mode}")
