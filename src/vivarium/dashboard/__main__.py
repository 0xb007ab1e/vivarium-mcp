"""Run the read-only dashboard — ``python -m vivarium.dashboard`` (display-only MVP).

**Fail-closed bind (`topic-tailnet-dev-access`).** The dashboard is a dev/preview surface: it may
bind loopback (``127.0.0.1``/``::1``), the host's **tailnet** IP (Tailscale CGNAT
``100.64.0.0/10``), and — opt-in — one additional **private mesh** subnet (e.g. **ZeroTier**,
whose subnets are
operator-defined RFC1918) named by ``VIVARIUM_DASHBOARD_MESH_CIDR``. All are private, owner-only,
ACL-gated meshes reachable from the owner's own devices, never the public internet. A public /
``0.0.0.0`` / otherwise-unlisted bind is REFUSED (the process exits non-zero) — you cannot
accidentally expose it.

Config (env):
- ``VIVARIUM_DASHBOARD_BIND`` — ``host:port`` (default ``127.0.0.1:8760``). Host must be loopback,
  a ``100.x.y.z`` tailnet IP, or (if ``VIVARIUM_DASHBOARD_MESH_CIDR`` is set) an IP in that subnet.
- ``VIVARIUM_DASHBOARD_MESH_CIDR`` — optional ONE private mesh subnet to also permit (ZeroTier or
  similar), e.g. ``10.121.16.0/24``. Must be private (RFC1918/ULA) and no broader than /16 — a
  public or over-broad CIDR is refused.
- ``VIVARIUM_DASHBOARD_TOKEN`` — optional shared bearer token gating the command surface (app.py).
- ``VIVARIUM_DASHBOARD_STATE`` — optional path to a JSON state file. When set, the dashboard serves
  LIVE data from it via :class:`~vivarium.dashboard.state.FileStatusProvider` (a producer driving a
  real analysis writes it); unset, the deterministic :class:`DemoProvider` is used.

Pattern (`topic-tailnet-dev-access`): run one instance per interface — loopback for on-host tooling,
the tailnet IP for Tailscale devices (``VIVARIUM_DASHBOARD_BIND=100.x.y.z:8760``), and/or a ZeroTier
IP for ZeroTier devices (``VIVARIUM_DASHBOARD_MESH_CIDR=10.x.y.0/24 BIND=10.x.y.z:8760``); they can
share one ``VIVARIUM_DASHBOARD_STATE`` file. Never bind ``0.0.0.0``.
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


#: Optional env naming ONE extra private mesh subnet the dashboard may bind (opt-in). For a mesh
#: other than Tailscale — e.g. **ZeroTier** (whose managed subnets are operator-defined RFC1918,
#: not a fixed range like Tailscale's CGNAT) — set this to that mesh's own subnet, e.g.
#: ``VIVARIUM_DASHBOARD_MESH_CIDR=10.121.16.0/24``. Fail-closed: unset ⇒ tailnet/loopback only; the
#: value MUST be a private (RFC1918/ULA) network and no broader than /16 (v4) — a public or
#: over-broad CIDR is REFUSED (never widen the surface toward the internet or a whole LAN).
_MESH_CIDR_ENV = "VIVARIUM_DASHBOARD_MESH_CIDR"

_MeshNet = ipaddress.IPv4Network | ipaddress.IPv6Network


def _extra_mesh_network() -> _MeshNet | None:
    """Parse + safety-check the opt-in private mesh subnet, or exit non-zero with a reason.

    Returns ``None`` when unset (the fail-closed default: tailnet/loopback only). Otherwise the IP
    the bind resolves to may fall inside this ONE private mesh subnet (ZeroTier or similar).
    """
    raw = os.environ.get(_MESH_CIDR_ENV, "").strip()
    if not raw:
        return None
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise SystemExit(
            f"invalid {_MESH_CIDR_ENV}={raw!r}: expected a private mesh CIDR like 10.121.16.0/24"
        ) from exc
    if net.is_loopback or not net.is_private:
        raise SystemExit(
            f"refusing {_MESH_CIDR_ENV}={raw!r}: must be a PRIVATE mesh subnet "
            "(RFC1918 / ULA) — never a public range (topic-tailnet-dev-access)."
        )
    # Bound the breadth so a slip can't allow a huge swath (e.g. all of 10.0.0.0/8): a real mesh
    # subnet is small. /16 is the widest sane opt-in for a private mesh.
    if net.prefixlen < 16:
        raise SystemExit(
            f"refusing {_MESH_CIDR_ENV}={raw!r}: too broad — name the mesh's own subnet "
            "(e.g. a /24), not a whole private block."
        )
    return net


def _is_tailnet_or_loopback(host: str, mesh: _MeshNet | None = None) -> bool:
    """Whether ``host`` is loopback, a Tailscale CGNAT address, or (with ``mesh``) in that mesh.

    ``mesh`` is the opt-in private mesh subnet (e.g. ZeroTier) when configured, else ``None``. A
    hostname (non-IP) is rejected here fail-closed: the bind must be an explicit safe IP so it can
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
    if ip in ipaddress.ip_network("100.64.0.0/10"):  # Tailscale CGNAT range
        return True
    return mesh is not None and ip in mesh


def _check_bind(bind: str) -> tuple[str, int]:
    """Validate the bind fail-closed; return ``(host, port)`` or exit non-zero with a reason."""
    host, port = _parse_bind(bind)
    mesh = _extra_mesh_network()
    if not _is_tailnet_or_loopback(host, mesh):
        mesh_hint = f" or the {_MESH_CIDR_ENV} mesh subnet" if mesh is not None else ""
        raise SystemExit(
            f"refusing to bind {host!r}: the dashboard binds loopback, a tailnet (100.64.0.0/10) "
            f"IP{mesh_hint} only (topic-tailnet-dev-access) — never 0.0.0.0 / a public interface."
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

    mode = (os.environ.get("VIVARIUM_DASHBOARD_EXECUTOR") or "state").lower()
    if mode == "worker":
        # Worker-backed: drives a live vivarium server (spawns a Ghidra worker) for read-only +
        # COMPUTE ops (fresh import/analyze). Writes still refused (write-consent only). This is the
        # operator's gated enablement — it starts hostile-binary analysis on demand.
        from vivarium.dashboard.executor import McpToolCaller, WorkerExecutor

        print(
            "vivarium dashboard: interactive WORKER transport (spawns a Ghidra worker)",
            file=sys.stderr,
        )
        return WorkerExecutor(catalog(), McpToolCaller())
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
