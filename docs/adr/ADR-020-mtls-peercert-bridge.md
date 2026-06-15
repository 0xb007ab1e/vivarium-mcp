# ADR-020: mTLS peer-cert bridge (custom uvicorn HTTP protocol)

- **Status:** Accepted (v1.2 design; human-ratified Option A, 2026-06-15). Completes ADR-019
  increment A's deferred **live bridge** — makes `auth_mode=mtls` **end-to-end functional**. No new
  trust boundary (realizes the mTLS half of TB6).
- **Deciders:** Human (ratified mechanism = Option A, custom uvicorn protocol, 2026-06-15) + PM;
  recorded by the Software Architect.
- **Relates to:** ADR-019 (mTLS authenticator + config + `CERT_REQUIRED` transport gate — the seam
  this completes), ADR-017 (per-principal ownership the resolved principal feeds), `std-zero-trust`,
  `topic-authn-authz`.

## Context

ADR-019 increment A shipped the mTLS pieces — `MtlsAuthenticator` (cert-field → principal),
config (client-CA bundle + principal-field), and the uvicorn `ssl_cert_reqs=CERT_REQUIRED` +
`ssl_ca_certs` **handshake gate** — but left one piece unwired: **uvicorn 0.49 does not surface the
verified peer certificate into the ASGI scope** (it builds no `scope["extensions"]`, and does not
expose the SSL object to the app). So the verified cert never reaches `MtlsAuthenticator`, and
`auth_mode=mtls` is **fail-closed but non-functional** (every request rejected; the handshake gate
still blocks uncertified clients). This ADR wires that delivery.

## Decision (ratified — Option A)

**A custom uvicorn HTTP-protocol subclass injects the verified peer cert into
`scope["extensions"]["tls"]["peercert"]`** — the exact key `AuthenticationMiddleware` already reads
into `AuthContext.peer_certificate`. The cert is sourced from the **verified TLS object**
(`transport.get_extra_info("ssl_object").getpeercert()` — the parsed dict `MtlsAuthenticator`
expects), never from a client-supplied header.

- `run_http` passes `http=<MtlsAwareProtocol>` to `uvicorn.run(...)` **only when
  `auth_mode == "mtls"`** (every other transport/auth path uses uvicorn's default protocol,
  unchanged).
- `MtlsAwareProtocol` subclasses uvicorn's resolved HTTP protocol (h11/httptools) and, at scope
  construction, sets `scope.setdefault("extensions", {})["tls"] = {"peercert": <getpeercert()>}`.
- A **pure, unit-testable helper** (`build_tls_scope_extension(ssl_object) -> dict | None`) does the
  extraction + shaping; the uvicorn subclass + `run_http` wiring stay `# pragma: no cover` (real
  socket) and are verified by a **gated real-TLS integration test**.

**Rejected — Option B (swap uvicorn → hypercorn):** hypercorn implements the ASGI TLS extension
natively (no internals hacking), but swapping the HTTP server is a disproportionate change for one
cert field — a gated new dependency plus re-verifying the whole HTTP run/shutdown path. Recorded as
the fallback if uvicorn internals become untenable.

## Security & invariants
- **Fail-closed preserved.** A connection only reaches the ASGI app **after** the
  `CERT_REQUIRED` handshake has verified a CA-signed client cert, so `getpeercert()` is populated;
  if it is ever empty/`None`, the helper yields no `peercert` → `MtlsAuthenticator` rejects (generic
  `401`). No fail-open path is introduced.
- **No spoofing.** The cert is read **only** from the verified `ssl_object` of the TLS connection —
  never a client-supplied header (Option B-for-proxies was already rejected in ADR-019). Identity
  stays server-derived; the authenticator, ownership (ADR-017), and the `peercert` dict shape are
  unchanged.
- **Bounded fragility.** Depending on uvicorn internals is acceptable because uvicorn is **pinned**
  (0.49.0, lockfile) and the **integration test fails loudly** if an upgrade changes the
  scope-construction surface. A uvicorn major bump must re-verify the injection (tracked).
- No new MCP tool / RPC / catalog / envelope; no new dependency; ADR-001/002 untouched.

## Consequences
- `auth_mode=mtls` becomes **functional** — the verified client cert's configured field (CN/SAN/DN)
  resolves to a `Principal` owning its sessions. The ADR-019 §A "known limitation" + the
  `auth.mtls_bridge_pending` startup warning are removed; threat-model §13 + CHANGELOG flip mTLS to
  functional.
- A documented, pinned, integration-tested dependency on uvicorn's HTTP-protocol internals.
- **Deferred (unchanged):** reverse-proxy-header mTLS mode (ADR-019, rejected default).

## Implementation increment (follows this design PR)
1. `server/app.py` (or a small `server/_mtls_protocol.py`): `build_tls_scope_extension(ssl_object)`
   (pure helper — unit-tested with a fake ssl_object: populated cert → `{"peercert": {...}}`; `None`/
   empty → `None`) + `MtlsAwareProtocol` (resolves + subclasses uvicorn's default HTTP protocol,
   injects the extension at scope build); wire `http=MtlsAwareProtocol` into `run_http` for
   `auth_mode == "mtls"` only.
2. Remove the `auth.mtls_bridge_pending` warning; flip ADR-019 §A "Known limitation", threat-model
   §13, and the next CHANGELOG entry to "mTLS functional".
3. **Real-TLS integration test** (gated/skip-marked like the other live-edge tests, runnable in the
   integration job): generate a throwaway CA + server cert + client cert, start the app over TLS
   with `CERT_REQUIRED`, make an mTLS request, assert the request authenticates as the cert-derived
   principal — and a request **without** a client cert is rejected at the handshake. Promote the
   ADR-019 mTLS live abuse case from `skip` to this test. No real secrets — synthetic certs only.
4. `topic-testing` coverage gates; the pure helper at 100%.
