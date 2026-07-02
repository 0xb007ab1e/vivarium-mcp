"""Startup configuration — 12-Factor, validated, fail-closed (WS1).

Config is read from the environment (see ``.env.example``) and validated at startup; the process
refuses to boot on missing/invalid required values (topic-config-environments — fail fast). There
are NO secrets in v1 config. Parsed into a typed, immutable object so the rest of the code depends
on validated values, not raw ``os.environ`` lookups (dependency inversion).

Resource limits are resolved (and clamped) through :func:`vivarium.security.limits.resolve_limits`
so a misconfigured environment can only make a bound *stricter* within hard ceilings, never wider
(fail closed — security/limits.py owns the clamps).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

from vivarium.core.errors import ErrorEnvelope, ErrorType, GhidraMcpError
from vivarium.security.limits import (
    DEFAULT_PREFLIGHT_MODE,
    PREFLIGHT_MODES,
    Limits,
    WorkerResources,
    resolve_limits,
    resolve_worker_resources,
)
from vivarium.server.auth import (
    MTLS_PRINCIPAL_FIELD_DEFAULT,
    MTLS_PRINCIPAL_FIELDS,
    OAUTH_ALLOWED_ALGORITHMS,
    OAUTH_DEFAULT_ALGORITHMS,
    OAUTH_DEFAULT_LEEWAY_S,
    OAUTH_PRINCIPAL_CLAIM_DEFAULT,
    PROXY_IDENTITY_HEADER_DEFAULT,
    PROXY_SECRET_HEADER_DEFAULT,
)

# Environment variable names (12-Factor; documented in .env.example). Centralized so the read set
# is a single, auditable allow-list.
_ENV_LOG_LEVEL = "VIVARIUM_LOG_LEVEL"
_ENV_LOG_FORMAT = "VIVARIUM_LOG_FORMAT"
_ENV_SESSION_TTL = "VIVARIUM_SESSION_TTL_SECONDS"
_ENV_SESSION_IDLE = "VIVARIUM_SESSION_IDLE_SECONDS"
_ENV_SESSION_REAP_INTERVAL = "VIVARIUM_SESSION_REAP_INTERVAL_SECONDS"
_ENV_METRICS_SNAPSHOT_INTERVAL = "VIVARIUM_METRICS_SNAPSHOT_INTERVAL_SECONDS"
_ENV_READINESS_CACHE_TTL = "VIVARIUM_READINESS_CACHE_TTL_SECONDS"
_ENV_MAX_SESSIONS = "VIVARIUM_MAX_SESSIONS"
_ENV_MAX_SESSIONS_PER_OWNER = "VIVARIUM_MAX_SESSIONS_PER_OWNER"
_ENV_MAX_BINARY_BYTES = "VIVARIUM_MAX_BINARY_BYTES"
_ENV_ANALYSIS_TIMEOUT = "VIVARIUM_ANALYSIS_TIMEOUT_SECONDS"
_ENV_TOOL_TIMEOUT = "VIVARIUM_TOOL_TIMEOUT_SECONDS"
_ENV_MAX_RESPONSE_BYTES = "VIVARIUM_MAX_RESPONSE_BYTES"
_ENV_MAX_STREAM_BUFFER_CHUNKS = "VIVARIUM_MAX_STREAM_BUFFER_CHUNKS"
_ENV_MAX_STREAM_REPLAY_CHUNKS = "VIVARIUM_MAX_STREAM_REPLAY_CHUNKS"
_ENV_WORKER_IMAGE = "VIVARIUM_WORKER_IMAGE"
_ENV_WORKER_RUNTIME = "VIVARIUM_WORKER_RUNTIME"
_ENV_WORKER_UID = "VIVARIUM_WORKER_UID"
_ENV_WORKER_GID = "VIVARIUM_WORKER_GID"
# Worker resource bounds (v1.3 — ADR-023 / F1). Integer-MiB memory/tmpfs + whole-CPU + pid caps,
# resolved + clamped by ``resolve_worker_resources`` (env can tune but never widen past a ceiling).
_ENV_WORKER_MEM_MIB = "VIVARIUM_WORKER_MEM_MIB"
_ENV_WORKER_CPUS = "VIVARIUM_WORKER_CPUS"
_ENV_WORKER_PIDS = "VIVARIUM_WORKER_PIDS"
_ENV_WORKER_TMPFS_SCRATCH_MIB = "VIVARIUM_WORKER_TMPFS_SCRATCH_MIB"
_ENV_WORKER_TMPFS_PROJECT_MIB = "VIVARIUM_WORKER_TMPFS_PROJECT_MIB"
# Over-plausible-size pre-flight mode (v1.4 — ADR-029 C): warn (default, v1.3 behaviour) / reject
# (fail closed with resource-exhausted before the worker is contacted) / off (skip the check).
_ENV_WORKER_PREFLIGHT = "VIVARIUM_WORKER_PREFLIGHT"
_ENV_RPC_SOCKET_DIR = "VIVARIUM_RPC_SOCKET_DIR"
_ENV_IMPORT_ROOT = "VIVARIUM_IMPORT_ROOT"
# Bundled ELF FID-DB dir (v1.x — ADR-043 Phase 2). WORKER-ONLY: it is read inside the worker by
# ``vivarium.ghidra._jvm_bridge`` (the JVM/PyGhidra edge), NOT by the server ``Config`` — the server
# never touches Ghidra (ADR-001). Listed here so the worker's env read-set stays a single auditable
# allow-list alongside the other ``VIVARIUM_*`` names; there is no server-side knob for it. Default
# is ``vivarium.ghidra._fid_attach.DEFAULT_FID_DB_DIR`` (``/opt/vivarium/fid``).
_ENV_FID_DB_DIR = "VIVARIUM_FID_DB_DIR"  # worker-only (ADR-043); not parsed into Config

# HTTP transport (v1.1 — ADR-011 / threat-model TB6). Default transport stays stdio; these are read
# only when transport=http. (These are env-var NAMES, not secrets.)
_ENV_TRANSPORT = "VIVARIUM_TRANSPORT"
_ENV_HTTP_BIND = "VIVARIUM_HTTP_BIND"
_ENV_HTTP_TLS_CERT = "VIVARIUM_HTTP_TLS_CERT"
_ENV_HTTP_TLS_KEY = "VIVARIUM_HTTP_TLS_KEY"
_ENV_HTTP_AUTH = "VIVARIUM_HTTP_AUTH"
_ENV_HTTP_BEARER_TOKEN = "VIVARIUM_HTTP_BEARER_TOKEN"  # noqa: S105  # nosec B105 - env var name
# Multi-principal bearer (ADR-017): a newline/comma-separated list of ``principal-id:token`` pairs,
# each mapping a distinct secret token to the principal id that owns the sessions it creates. The
# single-token var above stays valid (back-compat → the ``bearer`` principal). Env-var NAME, not a
# secret; the VALUES it points at are secrets (kept out of repr/logs — workflow-secrets).
_ENV_HTTP_BEARER_TOKENS = "VIVARIUM_HTTP_BEARER_TOKENS"  # nosec B105 - env var name, not a secret
# mTLS (v1.2 — ADR-019 increment A). Read only when auth_mode=mtls. Env-var NAMES, not secrets; the
# CA bundle is a (loggable) path, not a secret.
_ENV_HTTP_TLS_CLIENT_CA = "VIVARIUM_HTTP_TLS_CLIENT_CA"
_ENV_HTTP_MTLS_PRINCIPAL_FIELD = "VIVARIUM_HTTP_MTLS_PRINCIPAL_FIELD"
# OAuth (v1.2 — ADR-019 increment B). Read only when auth_mode=oauth. All env-var NAMES, not
# secrets; the VALUES (issuer/audience/JWKS URI/claim/algs/leeway) are non-secret config — the
# access token is per-request and never stored. issuer/audience/JWKS URI are REQUIRED for oauth.
_ENV_HTTP_OAUTH_ISSUER = "VIVARIUM_HTTP_OAUTH_ISSUER"
_ENV_HTTP_OAUTH_AUDIENCE = "VIVARIUM_HTTP_OAUTH_AUDIENCE"
_ENV_HTTP_OAUTH_JWKS_URI = "VIVARIUM_HTTP_OAUTH_JWKS_URI"
_ENV_HTTP_OAUTH_PRINCIPAL_CLAIM = "VIVARIUM_HTTP_OAUTH_PRINCIPAL_CLAIM"
_ENV_HTTP_OAUTH_ALGORITHMS = "VIVARIUM_HTTP_OAUTH_ALGORITHMS"
_ENV_HTTP_OAUTH_LEEWAY = "VIVARIUM_HTTP_OAUTH_LEEWAY_SECONDS"
_ENV_HTTP_OAUTH_WRITE_SCOPE = "VIVARIUM_HTTP_OAUTH_WRITE_SCOPE"
# Reverse-proxy mTLS (v1.4 — ADR-034). Read only when auth_mode=mtls-proxy. The shared secret IS a
# secret (the trust anchor); the header names are non-secret NAMES.
_ENV_HTTP_PROXY_SHARED_SECRET = "VIVARIUM_HTTP_PROXY_SHARED_SECRET"  # noqa: S105  # nosec B105 - env var name
_ENV_HTTP_PROXY_SECRET_HEADER = "VIVARIUM_HTTP_PROXY_SECRET_HEADER"  # noqa: S105  # nosec B105 - env var name
_ENV_HTTP_PROXY_IDENTITY_HEADER = "VIVARIUM_HTTP_PROXY_IDENTITY_HEADER"
_ENV_HTTP_CORS_ORIGINS = "VIVARIUM_HTTP_CORS_ORIGINS"
_ENV_HTTP_RATE_PER_S = "VIVARIUM_HTTP_RATE_PER_SECOND"
_ENV_HTTP_RATE_BURST = "VIVARIUM_HTTP_RATE_BURST"
_ENV_HTTP_MAX_BODY_BYTES = "VIVARIUM_HTTP_MAX_BODY_BYTES"

# Secure defaults for non-limit operational knobs (12-Factor: safe-by-default).
_DEFAULT_LOG_LEVEL = "INFO"
_DEFAULT_LOG_FORMAT = "json"
_DEFAULT_SESSION_TTL_S = 3600
_DEFAULT_SESSION_IDLE_S = 900
# How often the background reaper sweeps expired sessions (gap N5). 60s gives prompt eviction of an
# abandoned session (well under the 900s idle / 3600s TTL) without busy-looping.
_DEFAULT_SESSION_REAP_INTERVAL_S = 60
# Interval between metrics-snapshot log lines (gap N3a). 60s mirrors the reaper cadence — frequent
# enough to be a useful SLI trend, infrequent enough to be log-cheap.
_DEFAULT_METRICS_SNAPSHOT_INTERVAL_S = 60
# TTL for the cached /readyz capacity answer (gap P3). /readyz is served pre-auth + pre-rate-limit,
# so caching bounds the session-lock check to one call per window (no DoS) and coarsens the
# occupancy oracle. 1s: fresh enough for an orchestrator probe (polls on a multi-second interval),
# long enough that a probe flood cannot contend on the session lock.
_DEFAULT_READINESS_CACHE_TTL_S = 1
_DEFAULT_WORKER_RUNTIME = "runsc"
_DEFAULT_WORKER_UID = 65532
_DEFAULT_WORKER_GID = 65532
_DEFAULT_RPC_SOCKET_DIR = "/run/vivarium"
_DEFAULT_IMPORT_ROOT = "/work/imports"

# Allow-lists for enum-like values.
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR"})
_VALID_LOG_FORMATS = frozenset({"json", "text"})
_VALID_TRANSPORTS = frozenset({"stdio", "http"})
# Over-plausible-size pre-flight mode (ADR-029 C). Single source of truth in ``security.limits`` so
# the config allow-list and the adapter's fallback can never drift apart.
_VALID_WORKER_PREFLIGHT = PREFLIGHT_MODES
_DEFAULT_WORKER_PREFLIGHT = DEFAULT_PREFLIGHT_MODE
_VALID_HTTP_AUTH = frozenset({"none", "bearer", "mtls", "oauth", "mtls-proxy"})
# mTLS principal-field selectors (ADR-019 D2). Single source of truth in ``server.auth`` so the
# config allow-list and the authenticator can never drift apart.
_VALID_MTLS_PRINCIPAL_FIELDS = MTLS_PRINCIPAL_FIELDS
_DEFAULT_MTLS_PRINCIPAL_FIELD = MTLS_PRINCIPAL_FIELD_DEFAULT
# OAuth (ADR-019 D3). Single source of truth in ``server.auth`` for the PINNED algorithm allow-list
# + defaults, so config and the authenticator can never drift apart. The allow-list is asymmetric,
# public-key-verified algs ONLY — ``none`` and every ``HS*`` (symmetric/confusion) alg are rejected.
_VALID_OAUTH_ALGORITHMS = OAUTH_ALLOWED_ALGORITHMS
_DEFAULT_OAUTH_ALGORITHMS = OAUTH_DEFAULT_ALGORITHMS
_DEFAULT_OAUTH_PRINCIPAL_CLAIM = OAUTH_PRINCIPAL_CLAIM_DEFAULT
_DEFAULT_OAUTH_LEEWAY_S = OAUTH_DEFAULT_LEEWAY_S
# Bound on the OAuth principal-claim name (a short JWT claim key — bounds startup input, CWE-400).
_MAX_OAUTH_CLAIM_LEN = 64

# Cap on string-valued config to bound startup input (worker image refs, socket dirs).
_MAX_CONFIG_STR_LEN = 512

# HTTP transport defaults (ADR-011). Secure-by-default: stdio transport; HTTP binds loopback.
_DEFAULT_TRANSPORT = "stdio"
_DEFAULT_HTTP_BIND = "127.0.0.1:8765"
_DEFAULT_HTTP_RATE_PER_S = 10
_DEFAULT_HTTP_RATE_BURST = 20
_DEFAULT_HTTP_MAX_BODY_BYTES = 1_048_576  # 1 MiB request cap
_MIN_BEARER_TOKEN_LEN = 16
# Hosts that need no TLS/auth guard (no network hop). Bracketed IPv6 is stripped before lookup.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# The principal id a single (back-compat) bearer token maps to (ADR-011 / ADR-017). Mirrors
# ``vivarium.server.auth.BearerAuthenticator``'s historical principal id.
_DEFAULT_BEARER_PRINCIPAL_ID = "bearer"
# Bound + charset for a configured principal id (an owner key threaded into session ownership and
# logged in the audit trail — must be safe, control-free, and non-colliding). Allow-list only.
_MAX_PRINCIPAL_ID_LEN = 64
_PRINCIPAL_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
# Overall length bound on the multi-token list value (a handful of id:token pairs; bounds startup
# input — CWE-400 — without the 512 single-value cap, since this holds several secrets).
_MAX_BEARER_TOKENS_LEN = 8192


@dataclass(frozen=True, slots=True)
class HttpConfig:
    """Validated HTTP-transport config (v1.1 — ADR-011 / TB6); ``None`` unless transport=http.

    Built by :func:`_load_http_config`, which enforces the secure-by-default fail-closed rules
    (network bind ⇒ TLS + auth; bearer ⇒ token; no ``*`` CORS). All values are safe to log EXCEPT
    ``bearer_token`` (excluded from ``repr`` — it is a secret, `workflow-secrets`).

    Attributes:
        bind: ``host:port`` or ``unix:/path.sock``.
        is_network: True iff a non-loopback TCP bind (network-reachable) — the gated, TLS+auth case.
        is_unix_socket: True iff a UDS bind (same-host; filesystem-permission auth).
        tls_cert / tls_key: PEM paths for in-app TLS, or ``None`` (e.g. plaintext loopback or
            reverse-proxy-terminated TLS). Both-or-neither.
        tls_client_ca: PEM path to the client-CA bundle the TLS handshake verifies client certs
            against (mTLS — ADR-019 D2). Required when ``auth_mode == "mtls"``, else ``None``. Not a
            secret (a public CA bundle path) — safe to log.
        mtls_principal_field: The verified peer-cert field that maps to the principal id under mTLS
            (one of :data:`_VALID_MTLS_PRINCIPAL_FIELDS`; default subject CN). Only meaningful when
            ``auth_mode == "mtls"``.
        oauth_issuer / oauth_audience / oauth_jwks_uri: OAuth (ADR-019 D3) — the expected JWT
            ``iss``/``aud`` and the issuer's JWKS endpoint. All three are REQUIRED (non-``None``)
            when ``auth_mode == "oauth"``, else ``None``. None is a secret (the access token is
            per-request, never stored) — safe to log.
        oauth_principal_claim: The JWT claim mapped to the principal id (default ``sub``). Only
            meaningful when ``auth_mode == "oauth"``.
        oauth_algorithms: The PINNED algorithm allow-list (subset of :data:`_VALID_OAUTH_ALGORITHMS`
            — asymmetric/public-key algs only; default :data:`_DEFAULT_OAUTH_ALGORITHMS`). The
            token's own ``alg`` is never trusted (no ``alg:none`` / RS-HS confusion).
        oauth_leeway_s: Clock-skew leeway (seconds) for ``exp``/``nbf`` under OAuth (small default).
        auth_mode: ``"none"`` (loopback/UDS only) / ``"bearer"`` (built) / ``"mtls"`` / ``"oauth"``.
        bearer_token: The first bearer secret when ``auth_mode == "bearer"`` (else ``None``) — NOT
            logged. Retained for back-compat / single-token construction; the authoritative source
            is ``bearer_tokens``.
        bearer_tokens: Multi-principal bearer map (ADR-017): ``{token: principal-id}``. Each KEY is
            a secret (kept out of ``repr``/logs — workflow-secrets); the VALUE is the (loggable)
            owner principal id. Empty unless ``auth_mode == "bearer"``. A single configured token
            yields a one-entry map → the ``bearer`` principal (back-compat).
        cors_origins: Explicit allowed origins (never ``*``); empty = no cross-origin.
        rate_per_second / rate_burst: Per-client token-bucket rate limit (DoS — API4).
        max_body_bytes: Request body size cap.
    """

    bind: str
    is_network: bool
    is_unix_socket: bool
    tls_cert: str | None
    tls_key: str | None
    auth_mode: str
    bearer_token: str | None = field(repr=False)
    cors_origins: tuple[str, ...]
    rate_per_second: int
    rate_burst: int
    max_body_bytes: int
    # Last (defaulted) so existing keyword constructions stay valid; secret KEYS kept out of repr.
    bearer_tokens: dict[str, str] = field(default_factory=dict, repr=False)
    # mTLS (ADR-019 A). Defaulted so existing keyword constructions stay valid. Neither is a secret.
    tls_client_ca: str | None = None
    mtls_principal_field: str = MTLS_PRINCIPAL_FIELD_DEFAULT
    # OAuth (ADR-019 B). Defaulted so existing keyword constructions stay valid. None is a secret
    # (the per-request access token is never stored here) — all safe to log.
    oauth_issuer: str | None = None
    oauth_audience: str | None = None
    oauth_jwks_uri: str | None = None
    oauth_principal_claim: str = OAUTH_PRINCIPAL_CLAIM_DEFAULT
    oauth_algorithms: tuple[str, ...] = OAUTH_DEFAULT_ALGORITHMS
    oauth_leeway_s: int = OAUTH_DEFAULT_LEEWAY_S
    #: ADR-033: the OAuth scope that grants the ``write`` capability. ``None`` (default) ⇒ scope→
    #: tool authZ is OFF (every valid token is full-capability — identity-only). When set, an OAuth
    #: token gets ``write`` only if its ``scope``/``scp`` claim contains it (else read-only).
    oauth_write_scope: str | None = None
    #: Reverse-proxy mTLS (ADR-034; auth_mode "mtls-proxy"). The shared secret is the trust anchor —
    #: REQUIRED for that mode, a secret (excluded from repr), from env/secret-manager. The header
    #: names select where the proxy puts the secret + the verified client identity.
    proxy_shared_secret: str | None = field(default=None, repr=False)
    proxy_secret_header: str = PROXY_SECRET_HEADER_DEFAULT
    proxy_identity_header: str = PROXY_IDENTITY_HEADER_DEFAULT


@dataclass(frozen=True, slots=True)
class Config:
    """Validated server configuration.

    Attributes:
        log_level: Logging verbosity (``DEBUG``..``ERROR``). DEBUG never emits binary content.
        log_format: ``"json"`` or ``"text"``.
        session_ttl_s: Absolute session lifetime before eviction.
        session_idle_s: Idle timeout before eviction.
        limits: Resolved resource limits (see :class:`vivarium.security.limits.Limits`).
        worker_resources: Resolved + clamped worker container resource bounds (ADR-023 / F1 — see
            :class:`vivarium.security.limits.WorkerResources`). The env may tune them but never
            widen past the hard ceilings.
        worker_image: Pinned-by-digest worker image reference (ADR-003).
        worker_runtime: Container runtime for the worker (e.g. ``runsc`` for gVisor — ADR-004).
        worker_uid: Worker container uid (default hardened ``65532``; must own the socket dir
            under ``--userns keep-id`` — a host-run server overrides it to its own uid, ADR-009).
        worker_gid: Worker container gid (default ``65532``).
        rpc_socket_dir: Directory for per-session RPC sockets.
        import_root: Host dir (read-only mount) under which importable inputs live; the confined
            ``source_ref`` resolver rejects refs outside it (CWE-22) — ADR-009.
        transport: ``"stdio"`` (default) or ``"http"`` (v1.1 — ADR-011).
        http: Validated :class:`HttpConfig` when ``transport == "http"``, else ``None``.
        worker_preflight_mode: Over-plausible-size pre-flight behaviour (ADR-029 C; one of
            :data:`_VALID_WORKER_PREFLIGHT`). ``warn`` (default — v1.3 behaviour) / ``reject``
            (fail closed with ``resource-exhausted`` before the worker is contacted) / ``off``
            (skip the check). Fail-closed at startup on an invalid value.
    """

    log_level: str
    log_format: str
    session_ttl_s: int
    session_idle_s: int
    limits: Limits
    worker_image: str
    worker_runtime: str
    worker_uid: int
    worker_gid: int
    rpc_socket_dir: str
    import_root: str
    # Defaulted so existing keyword constructions (tests) stay valid; resolved in ``load_config``.
    worker_resources: WorkerResources = field(default_factory=WorkerResources)
    transport: str = _DEFAULT_TRANSPORT
    http: HttpConfig | None = None
    worker_preflight_mode: str = _DEFAULT_WORKER_PREFLIGHT
    # Defaulted (gap N5): the background reaper sweep interval; existing keyword constructions stay
    # valid. Resolved from VIVARIUM_SESSION_REAP_INTERVAL_SECONDS in ``load_config``.
    session_reap_interval_s: int = _DEFAULT_SESSION_REAP_INTERVAL_S
    # Defaulted (gap N3a): the metrics-snapshot log interval. Resolved from
    # VIVARIUM_METRICS_SNAPSHOT_INTERVAL_SECONDS in ``load_config``.
    metrics_snapshot_interval_s: int = _DEFAULT_METRICS_SNAPSHOT_INTERVAL_S
    # Defaulted (gap P3): TTL for the cached /readyz capacity answer. Resolved from
    # VIVARIUM_READINESS_CACHE_TTL_SECONDS in ``load_config``.
    readiness_cache_ttl_s: int = _DEFAULT_READINESS_CACHE_TTL_S


def _startup_error(detail: str) -> GhidraMcpError:
    """Build a fail-closed ``VALIDATION`` error for a bad/missing config value.

    Args:
        detail: A safe, value-free description of the misconfiguration (no secrets/paths echoed).

    Returns:
        A :class:`GhidraMcpError` whose envelope is safe to surface in startup logs.
    """
    return GhidraMcpError(
        ErrorEnvelope(
            type=ErrorType.VALIDATION,
            title="Invalid configuration",
            detail=detail,
            status=500,
            retryable=False,
        )
    )


def _read_int(env: dict[str, str], name: str) -> int | None:
    """Read and parse a non-negative integer env var, or ``None`` if unset/empty.

    Args:
        env: The environment mapping to read from.
        name: The variable name.

    Returns:
        The parsed integer, or ``None`` when the variable is absent or empty.

    Raises:
        GhidraMcpError: ``VALIDATION`` if the value is present but not a valid integer.
    """
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return None
    text = raw.strip()
    # Allow-list digits only (reject signs, underscores, hex, floats — fail closed).
    if not text.isdigit():
        raise _startup_error(f"environment variable {name} must be a non-negative integer")
    return int(text)


def _read_positive_int(env: dict[str, str], name: str, default: int) -> int:
    """Read a strictly positive integer env var, falling back to ``default`` when unset.

    Args:
        env: The environment mapping.
        name: The variable name.
        default: Value used when the variable is absent/empty.

    Returns:
        A strictly positive integer.

    Raises:
        GhidraMcpError: ``VALIDATION`` if present but non-integer or not strictly positive.
    """
    value = _read_int(env, name)
    if value is None:
        return default
    if value < 1:
        raise _startup_error(f"environment variable {name} must be a positive integer")
    return value


def _read_choice(env: dict[str, str], name: str, default: str, allowed: frozenset[str]) -> str:
    """Read an enum-like string env var validated against an allow-list.

    Args:
        env: The environment mapping.
        name: The variable name.
        default: Value used when the variable is absent/empty.
        allowed: The permitted set of values.

    Returns:
        The validated choice.

    Raises:
        GhidraMcpError: ``VALIDATION`` if the value is not in ``allowed``.
    """
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip()
    if value not in allowed:
        raise _startup_error(f"environment variable {name} has an unsupported value")
    return value


def _read_str(env: dict[str, str], name: str, default: str, *, required: bool) -> str:
    """Read a bounded, non-empty string env var.

    Args:
        env: The environment mapping.
        name: The variable name.
        default: Value used when absent/empty and not required.
        required: When ``True``, an absent/empty value is a fatal misconfiguration.

    Returns:
        The validated string.

    Raises:
        GhidraMcpError: ``VALIDATION`` if required-but-missing, too long, or containing control
            characters.
    """
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        if required:
            raise _startup_error(f"environment variable {name} is required")
        return default
    value = raw.strip()
    if len(value) > _MAX_CONFIG_STR_LEN:
        raise _startup_error(f"environment variable {name} is too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise _startup_error(f"environment variable {name} contains control characters")
    return value


def _parse_bind(bind: str) -> tuple[bool, bool]:
    """Classify an HTTP bind string. Returns ``(is_unix_socket, is_network)``.

    ``unix:/path`` → UDS (no network). ``host:port`` → network iff ``host`` is non-loopback.
    Bracketed IPv6 (``[::1]:8765``) is supported.

    Raises:
        GhidraMcpError: ``VALIDATION`` if the bind is not ``host:port`` or ``unix:/path``.
    """
    if bind.startswith("unix:"):
        if len(bind) <= len("unix:"):
            raise _startup_error(f"environment variable {_ENV_HTTP_BIND} unix bind needs a path")
        return True, False
    host, sep, port = bind.rpartition(":")
    if sep == "" or not port.isdigit() or not (1 <= int(port) <= 65535):
        raise _startup_error(
            f"environment variable {_ENV_HTTP_BIND} must be host:port or unix:/path"
        )
    host = host.strip("[]")  # unwrap bracketed IPv6
    return False, host not in _LOOPBACK_HOSTS


#: Hosts for which a plaintext ``http://`` JWKS URI is tolerated (a local dev/test IdP). Any other
#: host must use ``https``; non-``http(s)`` schemes are always rejected — see the check function.
_JWKS_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _require_safe_jwks_uri(jwks_uri: str) -> None:
    """Reject a JWKS URI whose scheme could turn key retrieval into SSRF / a local-file read.

    ``PyJWKClient`` fetches the URI with stdlib ``urllib``, which honors ``file://``, ``http://``,
    ``ftp://``, etc. The URI is operator config (ADR-019 D3), but a misconfiguration — or an
    env-injection foothold — pointing it at a local file or an internal ``http://`` endpoint is an
    SSRF / CWE-918 surface. Require ``https``, allowing plaintext ``http`` ONLY to a loopback host
    (a local dev/test IdP); fail closed on anything else (``file``/``ftp``/``http`` to a
    non-loopback host, or a URL with no host).

    Args:
        jwks_uri: The configured OAuth JWKS endpoint (already confirmed non-empty).

    Raises:
        GhidraMcpError: a startup ``VALIDATION`` error if the scheme/host is not allowed.
    """
    parsed = urlparse(jwks_uri)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in _JWKS_LOOPBACK_HOSTS:
        return
    raise _startup_error("oauth JWKS URI must be https (http is allowed only to localhost)")


def _validate_principal_id(principal_id: str) -> str:
    """Validate a configured bearer principal id (ADR-017): bounded, control-free allow-list.

    The id becomes a session ``owner`` key and appears in the audit trail, so it must be a safe,
    non-colliding token (no whitespace/control/separator chars that could spoof another principal).

    Args:
        principal_id: The candidate principal id (already stripped).

    Returns:
        The validated id.

    Raises:
        GhidraMcpError: ``VALIDATION`` if empty, too long, or containing disallowed characters.
    """
    if not principal_id:
        raise _startup_error(f"environment variable {_ENV_HTTP_BEARER_TOKENS} has an empty id")
    if len(principal_id) > _MAX_PRINCIPAL_ID_LEN:
        raise _startup_error(f"environment variable {_ENV_HTTP_BEARER_TOKENS} has too long an id")
    if any(ch not in _PRINCIPAL_ID_CHARS for ch in principal_id):
        raise _startup_error(
            f"environment variable {_ENV_HTTP_BEARER_TOKENS} id has disallowed characters"
        )
    return principal_id


def _load_bearer_tokens(src: dict[str, str], *, single_token: str | None) -> dict[str, str]:
    """Build the multi-principal bearer ``{token: principal-id}`` map (ADR-017), fail-closed.

    Sources (both optional; combined):

    - ``VIVARIUM_HTTP_BEARER_TOKENS`` — newline/comma-separated ``principal-id:token`` pairs.
    - ``VIVARIUM_HTTP_BEARER_TOKEN`` (``single_token``) — back-compat single secret → the
      ``bearer`` principal.

    Each token must meet the ``_MIN_BEARER_TOKEN_LEN`` floor; ids are validated; duplicate tokens or
    a token mapping to two ids is a fatal misconfiguration (an ambiguous identity must not boot —
    fail closed). The raw env value is NOT echoed in any error (it is a secret).

    Args:
        src: The environment mapping.
        single_token: The back-compat single bearer token, or ``None``.

    Returns:
        The ``{token: principal-id}`` map (possibly empty when neither source is set).

    Raises:
        GhidraMcpError: ``VALIDATION`` on a malformed pair, a too-short token, a bad id, or a
            duplicate/ambiguous token.
    """
    tokens: dict[str, str] = {}

    def _add(token: str, principal_id: str) -> None:
        if len(token) < _MIN_BEARER_TOKEN_LEN:
            raise _startup_error(
                f"environment variable {_ENV_HTTP_BEARER_TOKENS} token is too short "
                f"(min {_MIN_BEARER_TOKEN_LEN} characters)"
            )
        if token in tokens and tokens[token] != principal_id:
            # An ambiguous token (two ids) would make ownership non-deterministic — refuse to boot.
            raise _startup_error(
                f"environment variable {_ENV_HTTP_BEARER_TOKENS} maps one token to two principals"
            )
        tokens[token] = principal_id

    # Read the raw value directly (NOT via _read_str): the list separators are newline/comma and the
    # token values are secrets, so the generic control-char rejection / 512 cap do not apply here.
    raw = src.get(_ENV_HTTP_BEARER_TOKENS, "")
    if len(raw) > _MAX_BEARER_TOKENS_LEN:
        raise _startup_error(f"environment variable {_ENV_HTTP_BEARER_TOKENS} is too long")
    if raw.strip():
        # Split on newlines and commas; each item is ``principal-id:token`` (token may contain ':',
        # so split once from the left). The raw value is a secret — never echo an offending item.
        for item in (part.strip() for chunk in raw.split("\n") for part in chunk.split(",")):
            if not item:
                continue
            pid, sep, token = item.partition(":")
            if sep == "":
                raise _startup_error(
                    f"environment variable {_ENV_HTTP_BEARER_TOKENS} entries must be id:token"
                )
            _add(token.strip(), _validate_principal_id(pid.strip()))

    if single_token is not None:
        _add(single_token, _DEFAULT_BEARER_PRINCIPAL_ID)

    return tokens


def _load_oauth_algorithms(src: dict[str, str]) -> tuple[str, ...]:
    """Parse the OAuth algorithm allow-list (comma-separated), validated against the safe set.

    Each entry must be in :data:`_VALID_OAUTH_ALGORITHMS` — asymmetric, public-key-verified algs
    only. ``none`` and every ``HS*`` (symmetric/confusion) alg are NOT in the set, so they are
    rejected by construction: an operator can never widen the list to an unsafe alg (fail closed).
    An unset/empty var yields the secure default (:data:`_DEFAULT_OAUTH_ALGORITHMS`).

    Args:
        src: The environment mapping.

    Returns:
        The validated, de-duplicated (order-preserving) algorithm tuple.

    Raises:
        GhidraMcpError: ``VALIDATION`` if the list is non-empty after parsing yet contains a value
            outside the allow-list, or if it parses to nothing but was set.
    """
    raw = _read_str(src, _ENV_HTTP_OAUTH_ALGORITHMS, "", required=False)
    if not raw:
        return _DEFAULT_OAUTH_ALGORITHMS
    algs: list[str] = []
    for part in (p.strip() for p in raw.split(",")):
        if not part:
            continue
        if part not in _VALID_OAUTH_ALGORITHMS:
            # Reject the whole list on any unsafe/unknown alg (incl. ``none``/``HS*``); fail closed.
            raise _startup_error(
                f"environment variable {_ENV_HTTP_OAUTH_ALGORITHMS} has an unsupported algorithm"
            )
        if part not in algs:
            algs.append(part)
    if not algs:
        raise _startup_error(
            f"environment variable {_ENV_HTTP_OAUTH_ALGORITHMS} must list at least one algorithm"
        )
    return tuple(algs)


# C901: validates many independent HTTP config fields/modes — flat per-field branching, not nesting.
def _load_http_config(src: dict[str, str]) -> HttpConfig:  # noqa: C901
    """Build + validate the HTTP config (fail-closed, secure-by-default — ADR-011 §2/§4/§5).

    Args:
        src: The environment mapping.

    Returns:
        A validated :class:`HttpConfig`.

    Raises:
        GhidraMcpError: ``VALIDATION`` if a non-loopback bind lacks TLS or an authenticator, if
            bearer auth lacks at least one sufficiently long token, if mTLS auth lacks a client-CA
            bundle or server TLS, if OAuth auth lacks an issuer/audience/JWKS URI or lists an
            unsupported algorithm, if TLS cert/key are not both-or-neither, or if CORS contains
            ``*``. The process must refuse to boot.
    """
    bind = _read_str(src, _ENV_HTTP_BIND, _DEFAULT_HTTP_BIND, required=False)
    is_unix_socket, is_network = _parse_bind(bind)

    tls_cert = _read_str(src, _ENV_HTTP_TLS_CERT, "", required=False) or None
    tls_key = _read_str(src, _ENV_HTTP_TLS_KEY, "", required=False) or None
    if (tls_cert is None) != (tls_key is None):
        raise _startup_error("HTTP TLS cert and key must both be set or both unset")

    # Loopback/UDS may run unauthenticated (single trusted host); a network bind defaults to bearer.
    auth_mode = _read_choice(
        src, _ENV_HTTP_AUTH, "bearer" if is_network else "none", _VALID_HTTP_AUTH
    )

    # mTLS (ADR-019 D2): the client-CA bundle backs the handshake verify gate; the principal field
    # selects which verified-cert field maps to the principal id (validated allow-list).
    tls_client_ca = _read_str(src, _ENV_HTTP_TLS_CLIENT_CA, "", required=False) or None
    mtls_principal_field = _read_choice(
        src,
        _ENV_HTTP_MTLS_PRINCIPAL_FIELD,
        _DEFAULT_MTLS_PRINCIPAL_FIELD,
        _VALID_MTLS_PRINCIPAL_FIELDS,
    )
    # OAuth (ADR-019 D3): issuer/audience/JWKS URI (required for oauth), the principal claim, the
    # PINNED algorithm allow-list, and the clock-skew leeway. All non-secret config (the access
    # token is per-request, never stored). issuer/audience/JWKS URI requiredness is enforced below.
    oauth_issuer = _read_str(src, _ENV_HTTP_OAUTH_ISSUER, "", required=False) or None
    oauth_audience = _read_str(src, _ENV_HTTP_OAUTH_AUDIENCE, "", required=False) or None
    oauth_jwks_uri = _read_str(src, _ENV_HTTP_OAUTH_JWKS_URI, "", required=False) or None
    oauth_principal_claim = _read_str(
        src, _ENV_HTTP_OAUTH_PRINCIPAL_CLAIM, _DEFAULT_OAUTH_PRINCIPAL_CLAIM, required=False
    )
    if len(oauth_principal_claim) > _MAX_OAUTH_CLAIM_LEN:
        raise _startup_error(f"environment variable {_ENV_HTTP_OAUTH_PRINCIPAL_CLAIM} is too long")
    oauth_algorithms = _load_oauth_algorithms(src)
    oauth_leeway_s = _read_positive_int(src, _ENV_HTTP_OAUTH_LEEWAY, _DEFAULT_OAUTH_LEEWAY_S)
    # ADR-033: the scope granting the `write` capability. Unset ⇒ scope→tool authZ stays OFF.
    oauth_write_scope = _read_str(src, _ENV_HTTP_OAUTH_WRITE_SCOPE, "", required=False) or None
    if oauth_write_scope is not None and len(oauth_write_scope) > _MAX_OAUTH_CLAIM_LEN:
        raise _startup_error(f"environment variable {_ENV_HTTP_OAUTH_WRITE_SCOPE} is too long")

    # ADR-034: reverse-proxy mTLS — the shared secret is the trust anchor; the header names select
    # where the proxy puts the secret + the verified client identity (both lowercased — HTTP headers
    # are case-insensitive). The required-for-mode + length-floor checks are in the validation step.
    proxy_shared_secret = _read_str(src, _ENV_HTTP_PROXY_SHARED_SECRET, "", required=False) or None
    proxy_secret_header = (
        _read_str(src, _ENV_HTTP_PROXY_SECRET_HEADER, "", required=False).lower()
        or PROXY_SECRET_HEADER_DEFAULT
    )
    proxy_identity_header = (
        _read_str(src, _ENV_HTTP_PROXY_IDENTITY_HEADER, "", required=False).lower()
        or PROXY_IDENTITY_HEADER_DEFAULT
    )

    single_token = _read_str(src, _ENV_HTTP_BEARER_TOKEN, "", required=False) or None
    # Multi-principal bearer map (ADR-017): per-token validation (length floor) + id allow-listing +
    # ambiguity rejection happen inside the loader (fail closed). The single-token var is folded in
    # for back-compat (→ the ``bearer`` principal).
    bearer_tokens = _load_bearer_tokens(src, single_token=single_token)

    cors_raw = _read_str(src, _ENV_HTTP_CORS_ORIGINS, "", required=False)
    cors_origins = tuple(o for o in (part.strip() for part in cors_raw.split(",")) if o)

    rate_per_second = _read_positive_int(src, _ENV_HTTP_RATE_PER_S, _DEFAULT_HTTP_RATE_PER_S)
    rate_burst = _read_positive_int(src, _ENV_HTTP_RATE_BURST, _DEFAULT_HTTP_RATE_BURST)
    max_body_bytes = _read_positive_int(src, _ENV_HTTP_MAX_BODY_BYTES, _DEFAULT_HTTP_MAX_BODY_BYTES)

    # Fail-closed rules — the safe config is the only one that boots (master §2, ADR-011/ADR-017).
    if is_network and tls_cert is None:
        raise _startup_error("a non-loopback HTTP bind requires TLS (set cert and key)")
    if is_network and auth_mode == "none":
        raise _startup_error(
            "a non-loopback HTTP bind requires an authenticator (auth must not be none)"
        )
    if auth_mode == "bearer" and not bearer_tokens:
        raise _startup_error("bearer auth requires at least one token of at least 16 characters")
    if auth_mode == "mtls-proxy" and (
        proxy_shared_secret is None or len(proxy_shared_secret) < _MIN_BEARER_TOKEN_LEN
    ):
        # The shared secret is the trust anchor (ADR-034); without it a direct attacker could forge
        # the identity header, so the mode cannot boot without one (fail closed).
        raise _startup_error("mtls-proxy auth requires a shared secret of at least 16 characters")
    if auth_mode == "mtls" and tls_client_ca is None:
        # The handshake gate (uvicorn CERT_REQUIRED) cannot verify clients without a CA bundle —
        # refuse to boot rather than fall back to an unverified/no-auth posture (fail closed).
        raise _startup_error("mTLS auth requires a client-CA bundle (set the client CA path)")
    if auth_mode == "mtls" and tls_cert is None:
        # mTLS runs the client-cert handshake on the server's TLS listener; on a PLAINTEXT listener
        # uvicorn silently ignores CERT_REQUIRED / ssl_ca_certs (is_ssl is False) — the handshake
        # gate would not exist (CWE-1188). Refuse to boot (fail closed; covers loopback + UDS).
        raise _startup_error("mTLS auth requires server TLS (set cert and key)")
    if auth_mode == "oauth":
        if oauth_issuer is None or oauth_audience is None or oauth_jwks_uri is None:
            # OAuth validates the JWT's iss/aud against the configured values and fetches the
            # issuer's JWKS — without all three the authenticator cannot validate anything. Refuse
            # to boot rather than fall back to an unverified posture (fail closed). (Network-bind
            # TLS is enforced by the generic is_network rule above; oauth is network-class like
            # bearer.)
            raise _startup_error("oauth auth requires an issuer, an audience, and a JWKS URI")
        # Constrain the JWKS scheme so key retrieval can't be pointed at a local file / internal
        # endpoint (SSRF — CWE-918). `oauth_jwks_uri` is now narrowed to `str` by the check above.
        _require_safe_jwks_uri(oauth_jwks_uri)
    if "*" in cors_origins:
        raise _startup_error("HTTP CORS origins must be explicit; '*' is not allowed")

    return HttpConfig(
        bind=bind,
        is_network=is_network,
        is_unix_socket=is_unix_socket,
        tls_cert=tls_cert,
        tls_key=tls_key,
        auth_mode=auth_mode,
        bearer_token=single_token,
        bearer_tokens=bearer_tokens,
        tls_client_ca=tls_client_ca,
        mtls_principal_field=mtls_principal_field,
        oauth_issuer=oauth_issuer,
        oauth_audience=oauth_audience,
        oauth_jwks_uri=oauth_jwks_uri,
        oauth_write_scope=oauth_write_scope,
        proxy_shared_secret=proxy_shared_secret,
        proxy_secret_header=proxy_secret_header,
        proxy_identity_header=proxy_identity_header,
        oauth_principal_claim=oauth_principal_claim,
        oauth_algorithms=oauth_algorithms,
        oauth_leeway_s=oauth_leeway_s,
        cors_origins=cors_origins,
        rate_per_second=rate_per_second,
        rate_burst=rate_burst,
        max_body_bytes=max_body_bytes,
    )


def load_config(env: dict[str, str] | None = None) -> Config:
    """Load and validate configuration from the environment; fail closed on error.

    Args:
        env: Optional environment mapping to read from (defaults to :data:`os.environ`). Injected
            for testability (dependency inversion — topic-dependency-injection) so config loading
            stays deterministic and hermetic.

    Returns:
        A validated :class:`Config` with limits resolved and clamped.

    Raises:
        GhidraMcpError: ``VALIDATION`` on any missing required value or invalid/out-of-range value;
            the process must refuse to boot (fail fast).
    """
    src = dict(os.environ) if env is None else env

    log_level = _read_choice(src, _ENV_LOG_LEVEL, _DEFAULT_LOG_LEVEL, _VALID_LOG_LEVELS)
    log_format = _read_choice(src, _ENV_LOG_FORMAT, _DEFAULT_LOG_FORMAT, _VALID_LOG_FORMATS)

    session_ttl_s = _read_positive_int(src, _ENV_SESSION_TTL, _DEFAULT_SESSION_TTL_S)
    session_idle_s = _read_positive_int(src, _ENV_SESSION_IDLE, _DEFAULT_SESSION_IDLE_S)
    if session_idle_s > session_ttl_s:
        raise _startup_error("session idle timeout must not exceed the session TTL")
    session_reap_interval_s = _read_positive_int(
        src, _ENV_SESSION_REAP_INTERVAL, _DEFAULT_SESSION_REAP_INTERVAL_S
    )
    metrics_snapshot_interval_s = _read_positive_int(
        src, _ENV_METRICS_SNAPSHOT_INTERVAL, _DEFAULT_METRICS_SNAPSHOT_INTERVAL_S
    )
    readiness_cache_ttl_s = _read_positive_int(
        src, _ENV_READINESS_CACHE_TTL, _DEFAULT_READINESS_CACHE_TTL_S
    )

    # Validate all required/string fields BEFORE resolving limits, so a missing/invalid required
    # value fails fast on its own merits (and config validation is fully exercisable independent of
    # the limits layer).
    worker_image = _read_str(src, _ENV_WORKER_IMAGE, "", required=True)
    worker_runtime = _read_str(src, _ENV_WORKER_RUNTIME, _DEFAULT_WORKER_RUNTIME, required=False)
    # Worker uid/gid (strictly positive — never root) the launcher runs the container as; must
    # match the socket-dir owner under --userns keep-id. Default is the hardened 65532; a host-run
    # server (e.g. the gated e2e) overrides these to its own uid/gid (see ADR-009 / socket-dir.md).
    worker_uid = _read_positive_int(src, _ENV_WORKER_UID, _DEFAULT_WORKER_UID)
    worker_gid = _read_positive_int(src, _ENV_WORKER_GID, _DEFAULT_WORKER_GID)
    rpc_socket_dir = _read_str(src, _ENV_RPC_SOCKET_DIR, _DEFAULT_RPC_SOCKET_DIR, required=False)
    import_root = _read_str(src, _ENV_IMPORT_ROOT, _DEFAULT_IMPORT_ROOT, required=False)
    # Over-plausible-size pre-flight mode (v1.4 — ADR-029 C). Validated against the allow-list;
    # fail-closed on an invalid value (the process refuses to boot — VALIDATION).
    worker_preflight_mode = _read_choice(
        src, _ENV_WORKER_PREFLIGHT, _DEFAULT_WORKER_PREFLIGHT, _VALID_WORKER_PREFLIGHT
    )

    # Transport selection (v1.1 — ADR-011). HTTP config is built + validated (fail-closed) only when
    # transport=http; stdio remains the secure default and needs no network config.
    transport = _read_choice(src, _ENV_TRANSPORT, _DEFAULT_TRANSPORT, _VALID_TRANSPORTS)
    http = _load_http_config(src) if transport == "http" else None

    # Limit overrides: only include keys that were explicitly set (let resolve_limits apply its own
    # defaults + hard clamps for the rest). resolve_limits is fail-closed (WS4).
    overrides: dict[str, int] = {}
    for env_name, limit_key in (
        (_ENV_MAX_SESSIONS, "max_sessions"),
        (_ENV_MAX_SESSIONS_PER_OWNER, "max_sessions_per_owner"),
        (_ENV_MAX_BINARY_BYTES, "max_binary_bytes"),
        (_ENV_ANALYSIS_TIMEOUT, "analysis_timeout_s"),
        (_ENV_TOOL_TIMEOUT, "tool_timeout_s"),
        (_ENV_MAX_RESPONSE_BYTES, "max_response_bytes"),
        (_ENV_MAX_STREAM_BUFFER_CHUNKS, "max_stream_buffer_chunks"),
        (_ENV_MAX_STREAM_REPLAY_CHUNKS, "max_stream_replay_chunks"),
    ):
        value = _read_int(src, env_name)
        if value is not None:
            overrides[limit_key] = value
    limits = resolve_limits(overrides or None)

    # Session-liveness invariant (ADR-025 / F4): the idle timeout MUST be at least the per-analysis
    # wall-clock, so a single long ``analyze`` cannot run longer than the idle window and idle-evict
    # its own session at the next call (``expired-on-authorize`` → aborted workflow). In-flight
    # tracking (sessions/manager) makes a running call non-idle, but this fail-closed startup check
    # guarantees a deployment cannot even be CONFIGURED into the broken regime (defense in depth —
    # the only config that boots is the safe one, master §2). ``analysis_timeout_s`` is the
    # resolved/clamped value (security/limits). Checked AFTER limits resolution so it sees the
    # effective ceiling, not the raw env. Defaults satisfy it (idle 900 >= analysis 600).
    if session_idle_s < limits.analysis_timeout_s:
        raise _startup_error(
            "session idle timeout must be at least the analysis timeout "
            "(a long analysis must not be able to idle-evict its own session)"
        )

    # Worker resource overrides (ADR-023 / F1): only include explicitly-set keys; let
    # resolve_worker_resources apply its own defaults + hard clamps for the rest (fail-closed:
    # bool/non-int/<1 rejected, above-ceiling clamped down).
    worker_overrides: dict[str, int] = {}
    for env_name, resource_key in (
        (_ENV_WORKER_MEM_MIB, "mem_mib"),
        (_ENV_WORKER_CPUS, "cpus"),
        (_ENV_WORKER_PIDS, "pids"),
        (_ENV_WORKER_TMPFS_SCRATCH_MIB, "tmpfs_scratch_mib"),
        (_ENV_WORKER_TMPFS_PROJECT_MIB, "tmpfs_project_mib"),
    ):
        value = _read_int(src, env_name)
        if value is not None:
            worker_overrides[resource_key] = value
    worker_resources = resolve_worker_resources(worker_overrides or None)

    return Config(
        log_level=log_level,
        log_format=log_format,
        session_ttl_s=session_ttl_s,
        session_idle_s=session_idle_s,
        session_reap_interval_s=session_reap_interval_s,
        metrics_snapshot_interval_s=metrics_snapshot_interval_s,
        readiness_cache_ttl_s=readiness_cache_ttl_s,
        limits=limits,
        worker_image=worker_image,
        worker_runtime=worker_runtime,
        worker_uid=worker_uid,
        worker_gid=worker_gid,
        rpc_socket_dir=rpc_socket_dir,
        import_root=import_root,
        worker_resources=worker_resources,
        transport=transport,
        http=http,
        worker_preflight_mode=worker_preflight_mode,
    )
