"""Run the read-only dashboard — ``python -m vivarium.dashboard`` (display-only MVP).

**Fail-closed bind (`topic-tailnet-dev-access`).** The dashboard is a dev/preview surface: it may
bind loopback (``127.0.0.1``/``::1``) and the host's **tailnet** IP (Tailscale CGNAT
``100.64.0.0/10``) only — reachable from the owner's own devices over WireGuard, never the public
internet. A public / ``0.0.0.0`` / non-tailnet bind is REFUSED (the process exits non-zero) — you
cannot accidentally expose it.

Config (env):
- ``VIVARIUM_DASHBOARD_BIND`` — ``host:port`` (default ``127.0.0.1:8760``). Host must be loopback
  or a ``100.x.y.z`` tailnet IP.
- ``VIVARIUM_DASHBOARD_TOKEN`` — optional shared bearer token gating every request (see ``app.py``).
- ``VIVARIUM_DASHBOARD_STATE`` — optional path to a JSON state file. When set, the dashboard serves
  LIVE data from it via :class:`~vivarium.dashboard.state.FileStatusProvider` (a producer driving a
  real analysis writes it); unset, the deterministic :class:`DemoProvider` is used.

Pattern (`topic-tailnet-dev-access`): run one instance bound to loopback for on-host tooling and one
bound to the tailnet IP for phone/laptop access — e.g. ``VIVARIUM_DASHBOARD_BIND=100.x.y.z:8760``.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vivarium.dashboard.commands import CommandExecutor
    from vivarium.dashboard.providers import StatusProvider

_DEFAULT_BIND = "127.0.0.1:8760"


def _parse_bind(bind: str) -> tuple[str, int]:
    """Split ``host:port`` into ``(host, port)``; raise ``ValueError`` on a malformed value.

    Handles a bracketed IPv6 literal (``[::1]:8760``) as well as ``host:port``.
    """
    value = bind.strip()
    if value.startswith("["):  # [ipv6]:port
        host, _, port = value[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = value.rpartition(":")
    if not host or not port:
        raise ValueError(f"invalid bind {bind!r} (expected host:port)")
    return host, int(port)


def _is_tailnet_or_loopback(host: str) -> bool:
    """Return whether ``host`` is a loopback or a Tailscale CGNAT (``100.64.0.0/10``) address.

    A hostname (non-IP) is rejected here fail-closed: the bind must be an explicit safe IP so it can
    never resolve to a public interface (`topic-tailnet-dev-access`).
    """
    if host in {"127.0.0.1", "::1", "localhost"}:
        return host != "localhost"  # require a literal loopback IP, not a resolvable name
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    return ip in ipaddress.ip_network("100.64.0.0/10")  # Tailscale CGNAT range


def _check_bind(bind: str) -> tuple[str, int]:
    """Validate the bind fail-closed; return ``(host, port)`` or exit non-zero with a reason."""
    host, port = _parse_bind(bind)
    if not _is_tailnet_or_loopback(host):
        raise SystemExit(
            f"refusing to bind {host!r}: the dashboard binds loopback or a tailnet (100.64.0.0/10) "
            "IP only (topic-tailnet-dev-access) — never 0.0.0.0 / a public interface."
        )
    return host, port


def _select_provider() -> StatusProvider | None:
    """Return a live :class:`FileStatusProvider` if ``VIVARIUM_DASHBOARD_STATE`` is set, else None.

    ``None`` lets :func:`build_app` fall back to its default deterministic ``DemoProvider``.
    """
    state_path = os.environ.get("VIVARIUM_DASHBOARD_STATE")
    if not state_path:
        return None
    from vivarium.dashboard.state import FileStatusProvider

    return FileStatusProvider(state_path)


def _select_executor() -> CommandExecutor | None:
    """Return an interactive executor iff explicitly enabled AND its safety preconditions hold.

    Fail closed: interactive requires ``VIVARIUM_DASHBOARD_INTERACTIVE`` set AND a state file
    (``VIVARIUM_DASHBOARD_STATE``) AND an auth token (``VIVARIUM_DASHBOARD_TOKEN``). Missing any →
    ``None`` (disabled; the command endpoint returns 503). The wired transport is read-only
    (:class:`StateFileToolCaller`) — it spawns no worker; gated ops/writes are refused by the
    executor + endpoint (ADR-076 / TB9).
    """
    if not os.environ.get("VIVARIUM_DASHBOARD_INTERACTIVE"):
        return None
    state_path = os.environ.get("VIVARIUM_DASHBOARD_STATE")
    if not state_path or not os.environ.get("VIVARIUM_DASHBOARD_TOKEN"):
        print(
            "warning: interactive requested but requires VIVARIUM_DASHBOARD_STATE + "
            "VIVARIUM_DASHBOARD_TOKEN — interactive DISABLED (fail closed).",
            file=sys.stderr,
        )
        return None
    from vivarium.dashboard.catalog import catalog
    from vivarium.dashboard.executor import ReadOnlyExecutor, StateFileToolCaller

    return ReadOnlyExecutor(catalog(), StateFileToolCaller(state_path))


def main() -> None:
    """Validate the bind and run the app under uvicorn (loopback/tailnet only)."""
    import uvicorn

    from vivarium.dashboard.app import build_app

    host, port = _check_bind(os.environ.get("VIVARIUM_DASHBOARD_BIND", _DEFAULT_BIND))
    if not os.environ.get("VIVARIUM_DASHBOARD_TOKEN"):
        print(
            "warning: VIVARIUM_DASHBOARD_TOKEN not set — relying on the tailnet/loopback bind for "
            "access control (fine for local/tailnet dev; set a token or wire per-principal authz "
            "before any wider exposure).",
            file=sys.stderr,
        )
    provider = _select_provider()
    executor = _select_executor()
    print(
        f"vivarium dashboard: {'live (file state)' if provider else 'demo'} provider · "
        f"interactive {'ON (read-only)' if executor else 'off'} on http://{host}:{port}",
        file=sys.stderr,
    )
    uvicorn.run(build_app(provider, executor), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
