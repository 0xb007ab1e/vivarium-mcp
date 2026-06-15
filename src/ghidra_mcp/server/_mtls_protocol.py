"""mTLS peer-cert → ASGI scope bridge (ADR-020, Option A — custom uvicorn HTTP protocol).

ADR-019 increment A shipped the mTLS *handshake* gate (uvicorn ``ssl_cert_reqs=CERT_REQUIRED`` +
the client-CA bundle) and the in-app :class:`~ghidra_mcp.server.auth.MtlsAuthenticator`, but left
one seam unwired: **uvicorn 0.49 does not surface the verified peer certificate into the ASGI
scope** (it builds no ``scope["extensions"]`` and never exposes the SSL object to the app). So the
verified cert never reached the authenticator and ``auth_mode=mtls`` was fail-closed but
*non-functional* (every request rejected; the handshake gate still blocked uncertified clients).

This module wires that delivery, exactly per ADR-020:

- :func:`build_tls_scope_extension` — the **pure, unit-testable** extractor/shaper: given a TLS
  ``ssl_object`` it returns ``{"peercert": <getpeercert()>}`` when a verified peer cert is present,
  else ``None``. No I/O; the only place 100% coverage is asserted.
- :class:`MtlsAwareProtocol` — a thin subclass of uvicorn's h11 HTTP protocol that, **at scope
  construction**, injects ``scope["extensions"]["tls"]`` from the connection's verified
  ``ssl_object`` — the exact key/shape the ``AuthenticationMiddleware``
  (:mod:`ghidra_mcp.server.http_middleware`) reads into
  :attr:`~ghidra_mcp.server.auth.AuthContext.peer_certificate`. The cert is sourced
  **only** from the verified TLS object — never a client-supplied header (no spoofing).

Fail-closed is preserved: a connection only reaches the ASGI app *after* the ``CERT_REQUIRED``
handshake verified a CA-signed client cert, so ``getpeercert()`` is populated; if it is ever
empty/``None`` the helper yields no ``peercert`` → :class:`MtlsAuthenticator` rejects (generic
``401``). No fail-open path is introduced (`std-zero-trust`, `topic-authn-authz`).

The subclass + its wiring stay ``# pragma: no cover`` (a real TLS socket cannot be exercised in the
unit run) — they are covered by the gated real-TLS integration test
(``tests/integration/test_mtls_bridge.py``). The pure helper carries the logic and is unit-tested.

Version dependency (ADR-020 "bounded fragility"): :class:`MtlsAwareProtocol` overrides uvicorn's
internal scope-construction surface (``H11Protocol`` assigns ``self.scope`` per request inside
``handle_events``; the property setter below hooks that assignment). uvicorn is **pinned**
(0.49.0, lockfile); a major bump must re-verify this seam — the integration test fails loudly if
the scope-construction surface changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

# uvicorn's resolved default HTTP protocol. We deliberately pin to the h11 implementation (rather
# than the "auto"/httptools path) so the override surface is a single, stable class — ADR-020 allows
# forcing ``http="h11"`` for the mtls path when that is the clean base. h11 is always available
# (it is a hard uvicorn dependency); httptools is the optional speedup. For the single-principal
# mTLS control endpoint, h11 is more than sufficient and far easier to reason about/verify.
from uvicorn.protocols.http.h11_impl import H11Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
    import ssl


def build_tls_scope_extension(ssl_object: ssl.SSLObject | None) -> dict[str, Any] | None:
    """Build the ASGI ``tls`` scope extension from a verified TLS object, or ``None``.

    Pure (no I/O): reads the **verified** peer certificate from ``ssl_object.getpeercert()`` and
    shapes it into the single key the auth middleware consumes —
    ``{"peercert": <parsed getpeercert() dict>}``. The value is exactly the parsed mapping
    :func:`ssl.SSLSocket.getpeercert` returns (``{"subject": ..., "subjectAltName": ...}``), which
    is the shape :class:`~ghidra_mcp.server.auth.MtlsAuthenticator` expects.

    Returns ``None`` (no extension injected → the authenticator fails closed) when there is no
    verified peer cert to surface:

    - ``ssl_object`` is ``None`` (a plaintext connection — should not occur on the mTLS path, but
      handled defensively), or
    - ``getpeercert()`` returns ``None`` or an empty mapping (no client cert was presented/verified
      — under ``CERT_REQUIRED`` the handshake would already have rejected such a client, so this is
      a fail-closed backstop, never a fail-open).

    The cert is read **only** from the verified TLS object — never from a client-supplied header —
    so the identity is server-derived and cannot be spoofed (ADR-020 security invariant).

    Args:
        ssl_object: The connection's verified TLS object (from
            ``transport.get_extra_info("ssl_object")``), or ``None``.

    Returns:
        ``{"peercert": <dict>}`` when a verified peer cert is present, else ``None``.
    """
    if ssl_object is None:
        return None
    peercert = ssl_object.getpeercert()
    # ``getpeercert()`` returns None (no cert / not yet handshaken) or {} (cert present but no
    # parsed fields requested) — neither yields a usable identity, so inject nothing (fail closed).
    if not peercert:
        return None
    return {"peercert": peercert}


class MtlsAwareProtocol(H11Protocol):  # pragma: no cover - real TLS socket; covered by integration
    """uvicorn h11 protocol that injects the verified peer cert into ``scope["extensions"]["tls"]``.

    Used **only** when ``auth_mode == "mtls"`` (wired in :func:`ghidra_mcp.server.app.run_http`);
    every other transport/auth path uses uvicorn's default protocol, byte-for-byte unchanged.

    Mechanism (minimal, version-bounded): :class:`~uvicorn.protocols.http.h11_impl.H11Protocol`
    builds the per-request ASGI scope by assigning ``self.scope = {...}`` inside ``handle_events``,
    with ``self.transport`` available. We expose ``scope`` as a property whose **setter** injects
    the TLS extension at that exact assignment — so the injected key matches what
    :func:`ghidra_mcp.server.http_middleware._peer_certificate` reads, with no copy of uvicorn's
    request-handling body. The extension is only added when
    :func:`build_tls_scope_extension` returns non-``None`` (a verified peer cert is present), so a
    missing cert leaves the scope untouched and the authenticator fails closed.

    The cert is sourced from ``self.transport.get_extra_info("ssl_object")`` — the verified TLS
    object — never a header (no spoofing). This subclass is ``# pragma: no cover`` (it requires a
    real TLS socket); the gated real-TLS integration test exercises it end-to-end.
    """

    @property
    def scope(self) -> Any:
        """Return the current per-request ASGI scope (uvicorn's instance attribute)."""
        return getattr(self, "_mtls_scope", None)

    @scope.setter
    def scope(self, value: Any) -> None:
        """Store the scope; on the per-request scope, inject the verified-peer-cert TLS extension.

        uvicorn assigns ``self.scope`` twice: once to ``None`` in ``__init__`` (no transport yet),
        and once per request to the built scope dict (transport available). We only inject on the
        per-request ``dict`` assignment, reading the verified cert from the live TLS object.
        """
        if isinstance(value, dict):
            transport = getattr(self, "transport", None)
            ssl_object = transport.get_extra_info("ssl_object") if transport is not None else None
            extension = build_tls_scope_extension(cast("Any", ssl_object))
            if extension is not None:
                value.setdefault("extensions", {})["tls"] = extension
        self._mtls_scope = value
