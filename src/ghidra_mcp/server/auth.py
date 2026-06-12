"""HTTP authentication strategies (v1.1 — ADR-011 / threat-model TB6).

The **imperative shell's** auth seam. Authentication is a small **strategy port**
(:class:`Authenticator`) so the three mechanisms ADR-011 names compose behind one interface,
**default-deny** (a rejected request yields ``None`` → the shell returns a generic ``401``):

- :class:`BearerAuthenticator` — BUILT now. Constant-time compare of the ``Authorization: Bearer``
  token vs the configured secret; never reveals *why* a request failed (no user/credential oracle).
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


def build_authenticator(auth_mode: str, *, bearer_token: str | None) -> Authenticator:
    """Construct the :class:`Authenticator` for a validated ``auth_mode`` (the slice-3 wiring seam).

    Args:
        auth_mode: One of ``"none"`` / ``"bearer"`` / ``"mtls"`` / ``"oauth"`` (already validated by
            config).
        bearer_token: Required when ``auth_mode == "bearer"``.

    Returns:
        The matching authenticator (mTLS/OAuth return port-ready stubs).

    Raises:
        ValueError: if ``auth_mode`` is unknown, or ``bearer`` without a token (fail closed).
    """
    if auth_mode == "none":
        return NullAuthenticator()
    if auth_mode == "bearer":
        if bearer_token is None:
            raise ValueError("bearer auth requires a token")
        return BearerAuthenticator(expected_token=bearer_token)
    if auth_mode == "mtls":
        return MtlsAuthenticator()
    if auth_mode == "oauth":
        return OAuthResourceAuthenticator()
    raise ValueError(f"unknown auth mode: {auth_mode}")
