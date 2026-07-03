"""Real-TLS integration test for the mTLS peer-cert bridge (ADR-020, Option A).

Proves the bridge is **end-to-end functional**: with :class:`MtlsAwareProtocol` wired into a live
uvicorn TLS listener (``ssl_cert_reqs=CERT_REQUIRED`` + a client-CA bundle), a client presenting a
CA-signed certificate is authenticated as the **cert-derived principal**, and a client presenting
**no** certificate is rejected at the TLS handshake (never reaching the app).

This is the live verification ADR-020 calls for — it covers :class:`MtlsAwareProtocol` and the
``run_http`` wiring (both ``# pragma: no cover`` in the unit run). It is gated like the other
live-edge tests (``@pytest.mark.integration``): the repo's integration conftest skips it in the
unit/coverage job and runs it in the dedicated integration job.

It needs **no Ghidra worker**: the auth bridge sits entirely in the HTTP shell, so the test drives
the real middleware stack (:func:`build_http_asgi_app`) around a tiny fake inner ASGI app that
echoes the authenticated principal id. All certs are **synthetic, generated in-test** with
``cryptography`` (already a dep) — no real secrets, nothing on disk beyond a throwaway temp dir.

Promotes ADR-019 abuse case 70 (untrusted-CA cert rejected at the handshake) from ``skip`` to a
live assertion (see :func:`test_mtls_untrusted_ca_cert_rejected_at_handshake_live`).
"""

from __future__ import annotations

import datetime as dt
import http.client as http_client
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from starlette.types import ASGIApp

from vivarium.config import HttpConfig
from vivarium.server.app import build_http_asgi_app
from vivarium.server.auth import build_authenticator
from vivarium.server.http_middleware import SCOPE_PRINCIPAL_KEY

pytestmark = pytest.mark.integration


# --------------------------------------------------------------------------------------------------
# Synthetic PKI — a throwaway CA + server cert + client cert, generated in-test (no real secrets).
# --------------------------------------------------------------------------------------------------
def _keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed throwaway CA (used to sign both the server and client certs)."""
    key = _keypair()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vivarium-test-ca")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    cn: str,
    *,
    san_dns: str | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a leaf cert (server or client) signed by ``ca_key`` with subject CN ``cn``."""
    key = _keypair()
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
    )
    if san_dns is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _write_pair(
    dir_: Path, stem: str, key: rsa.RSAPrivateKey, cert: x509.Certificate
) -> tuple[Path, Path]:
    cert_path = dir_ / f"{stem}.crt"
    key_path = dir_ / f"{stem}.key"
    _write_cert(cert_path, cert)
    _write_key(key_path, key)
    return cert_path, key_path


# --------------------------------------------------------------------------------------------------
# A tiny inner ASGI app that echoes the authenticated principal stashed by the auth middleware.
# --------------------------------------------------------------------------------------------------
async def _echo_principal_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """Inner ASGI app: respond 200 with the authenticated principal id (proves the bridge wired)."""
    if scope["type"] != "http":  # pragma: no cover - no lifespan/ws on this path
        return
    principal = scope.get("state", {}).get(SCOPE_PRINCIPAL_KEY)
    body = (principal.id if principal is not None else "<none>").encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"text/plain"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _http_config(server_cert: Path, server_key: Path, client_ca: Path, port: int) -> HttpConfig:
    return HttpConfig(
        bind=f"127.0.0.1:{port}",
        is_network=False,
        is_unix_socket=False,
        tls_cert=str(server_cert),
        tls_key=str(server_key),
        auth_mode="mtls",
        bearer_token=None,
        cors_origins=(),
        rate_per_second=1000,
        rate_burst=1000,
        max_body_bytes=1_048_576,
        tls_client_ca=str(client_ca),
        mtls_principal_field="cn",
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _LiveTlsServer:
    """Run the real middleware stack over a live uvicorn TLS listener with the mTLS bridge wired."""

    def __init__(self, http: HttpConfig) -> None:
        import uvicorn

        from vivarium.server._mtls_protocol import MtlsAwareProtocol

        authenticator = build_authenticator("mtls", mtls_principal_field=http.mtls_principal_field)
        asgi = build_http_asgi_app(
            cast("ASGIApp", _echo_principal_app), http, authenticator=authenticator
        )
        host, _, port = http.bind.rpartition(":")
        self._config = uvicorn.Config(
            asgi,
            host=host,
            port=int(port),
            log_level="warning",
            ssl_certfile=http.tls_cert,
            ssl_keyfile=http.tls_key,
            ssl_ca_certs=http.tls_client_ca,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            http=MtlsAwareProtocol,  # ADR-020: the peer-cert bridge under test
        )
        self._server = uvicorn.Server(self._config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self) -> _LiveTlsServer:
        self._thread.start()
        deadline = time.monotonic() + 10.0
        while not self._server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        if not self._server.started:  # pragma: no cover - startup failure
            raise RuntimeError("TLS test server failed to start")
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10.0)


def _client_ssl_context(
    ca_cert: Path, client_cert: Path | None, client_key: Path | None
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.check_hostname = False  # synthetic CN, not a hostname match
    if client_cert is not None and client_key is not None:
        ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return ctx


def test_mtls_bridge_authenticates_as_cert_derived_principal(tmp_path: Path) -> None:
    """A CA-signed client cert (CN=alice) over real TLS authenticates as Principal(id='alice').

    Drives the LIVE uvicorn TLS listener + MtlsAwareProtocol: the verified peer cert reaches the
    in-app MtlsAuthenticator via the scope bridge and resolves to the cert's CN — the bridge is
    end-to-end functional (ADR-020). Identity is server-derived from the verified cert only.
    """
    ca_key, ca_cert = _ca()
    s_key, s_cert = _leaf(ca_key, ca_cert, "127.0.0.1", san_dns="127.0.0.1")
    c_key, c_cert = _leaf(ca_key, ca_cert, "alice")
    server_cert, server_key = _write_pair(tmp_path, "server", s_key, s_cert)
    client_cert, client_key = _write_pair(tmp_path, "client", c_key, c_cert)
    ca_path = tmp_path / "ca.crt"
    _write_cert(ca_path, ca_cert)

    port = _free_port()
    http = _http_config(server_cert, server_key, ca_path, port)
    with _LiveTlsServer(http):
        ctx = _client_ssl_context(ca_path, client_cert, client_key)
        conn = http_client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()

    # The authenticated principal is the cert's CN — proves the verified cert traversed the bridge.
    assert resp.status == 200
    # DELIBERATE FAILURE — round-7 W4 gate-red-block validation ONLY. DO NOT MERGE.
    # Asserts a wrong principal so mtls-auth-gate goes red, proving the required gate blocks a
    # merge. This branch/PR is a throwaway and will be closed unmerged; revert this one line.
    assert body == "mallory"  # (real value is "alice")


def test_mtls_untrusted_ca_cert_rejected_at_handshake_live(tmp_path: Path) -> None:
    """ADR-019 case 70 (promoted from skip): no client cert → rejected at the TLS handshake.

    Under ``ssl_cert_reqs=CERT_REQUIRED`` a client that presents no certificate never completes the
    handshake, so the connection never reaches the ASGI app (fail closed at the transport gate). A
    cert signed by an UNTRUSTED CA is likewise rejected — it does not chain to the configured CA.
    """
    ca_key, ca_cert = _ca()
    s_key, s_cert = _leaf(ca_key, ca_cert, "127.0.0.1", san_dns="127.0.0.1")
    server_cert, server_key = _write_pair(tmp_path, "server", s_key, s_cert)
    ca_path = tmp_path / "ca.crt"
    _write_cert(ca_path, ca_cert)

    # An attacker CA + client cert NOT in the server's trust bundle.
    rogue_ca_key, rogue_ca_cert = _ca()
    r_key, r_cert = _leaf(rogue_ca_key, rogue_ca_cert, "mallory")
    rogue_cert, rogue_key = _write_pair(tmp_path, "rogue", r_key, r_cert)

    port = _free_port()
    http = _http_config(server_cert, server_key, ca_path, port)
    with _LiveTlsServer(http):
        # 1) No client cert at all → handshake fails.
        ctx_no_cert = _client_ssl_context(ca_path, None, None)
        conn = http_client.HTTPSConnection("127.0.0.1", port, context=ctx_no_cert, timeout=10)
        with pytest.raises((ssl.SSLError, OSError)):
            conn.request("GET", "/")
            conn.getresponse()
        conn.close()

        # 2) A client cert from an untrusted CA → handshake fails (does not chain to the bundle).
        ctx_rogue = _client_ssl_context(ca_path, rogue_cert, rogue_key)
        conn2 = http_client.HTTPSConnection("127.0.0.1", port, context=ctx_rogue, timeout=10)
        with pytest.raises((ssl.SSLError, OSError)):
            conn2.request("GET", "/")
            conn2.getresponse()
        conn2.close()
