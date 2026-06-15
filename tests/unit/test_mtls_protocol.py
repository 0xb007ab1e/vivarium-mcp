"""Unit tests for the mTLS peer-cert → ASGI scope bridge helper (ADR-020, Option A).

Only the **pure** helper :func:`ghidra_mcp.server._mtls_protocol.build_tls_scope_extension` is
unit-tested here — and it is the one piece ADR-020 requires at **100%**. The uvicorn subclass
(:class:`MtlsAwareProtocol`) and its ``run_http`` wiring require a real TLS socket and are
``# pragma: no cover``; the gated real-TLS integration test
(``tests/integration/test_mtls_bridge.py``) exercises them end-to-end.

The helper is driven with a tiny fake ``ssl_object`` (only ``getpeercert()`` matters) — no live
TLS — so these tests are hermetic and deterministic (`topic-testing`).
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ghidra_mcp.server._mtls_protocol import build_tls_scope_extension


class _FakeSslObject:
    """Minimal stand-in for ``ssl.SSLObject`` exposing only ``getpeercert()`` (the bit used)."""

    def __init__(self, peercert: Any) -> None:
        self._peercert = peercert

    def getpeercert(self, binary_form: bool = False) -> Any:
        """Return the configured parsed peer-cert mapping (the shape the helper consumes)."""
        return self._peercert


def _build(fake: _FakeSslObject) -> dict[str, Any] | None:
    """Call the helper with the duck-typed fake (cast to the ``ssl.SSLObject`` param type)."""
    return build_tls_scope_extension(cast("Any", fake))


def test_verified_cert_is_shaped_into_the_peercert_extension() -> None:
    """A populated verified cert → ``{"peercert": <getpeercert() dict>}`` (the exact scope key).

    The shape must match what ``http_middleware._peer_certificate`` reads
    (``scope["extensions"]["tls"]["peercert"]``) and what ``MtlsAuthenticator`` parses.
    """
    cert = {"subject": ((("commonName", "alice"),),), "subjectAltName": (("DNS", "alice.example"),)}
    ext = _build(_FakeSslObject(cert))
    assert ext == {"peercert": cert}
    # The cert dict is passed through unchanged (same object) — no copy/mutation of the parsed cert.
    assert ext is not None and ext["peercert"] is cert


def test_no_ssl_object_yields_none() -> None:
    """``ssl_object is None`` (plaintext connection) → no extension (fail closed, defensive)."""
    assert build_tls_scope_extension(None) is None


def test_getpeercert_none_yields_none() -> None:
    """A TLS object with no presented cert (``getpeercert()`` → ``None``) → no extension."""
    assert _build(_FakeSslObject(None)) is None


def test_getpeercert_empty_mapping_yields_none() -> None:
    """A TLS object whose ``getpeercert()`` is an empty ``{}`` → no extension (fail closed).

    Empty parsed fields carry no usable identity, so the helper injects nothing → the authenticator
    fails closed (no fail-open from a contentless cert).
    """
    assert _build(_FakeSslObject({})) is None


@pytest.mark.critical
def test_cert_is_never_sourced_from_a_header_only_from_the_tls_object() -> None:
    """Sanity: the helper's *only* input is the TLS object — there is no header/string path.

    Documents the no-spoofing invariant (ADR-020): a string/header value is not a TLS object and
    has no ``getpeercert()``, so it cannot be coerced into a peer cert. We assert the helper raises
    on a non-TLS object rather than silently trusting it (it never treats arbitrary input as a
    cert).
    """
    with pytest.raises(AttributeError):
        build_tls_scope_extension("Authorization: a-forged-header")  # type: ignore[arg-type]
