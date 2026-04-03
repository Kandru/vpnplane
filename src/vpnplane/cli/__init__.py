"""CLI package for vpnplane."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import click
import yaml
from pydantic import ValidationError

from .. import __version__
from ..models import IPSecTunnel, RouteRule, WireGuardTunnel, load_route, load_tunnel
from ..utils import DEFAULT_CONFIG_DIR, console, settings_exist


# ---------------------------------------------------------------------------
# Root CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="vpnplane")
def cli() -> None:
    """vpnplane — zero-trust WireGuard/IPSec tunnel manager."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _require_settings(config_dir: Path) -> None:
    """Exit with a hint if settings.yaml has not been created yet."""
    if not settings_exist(config_dir):
        console.print(
            "[red]No settings.yaml found.[/red] Run [bold]vpnplane init[/bold] first."
        )
        sys.exit(1)


def _load_and_validate(config_dir: Path) -> tuple[
    list[WireGuardTunnel], list[IPSecTunnel], list[RouteRule]
]:
    """Load and validate all config files. Prints errors and exits on failure."""
    _require_settings(config_dir)

    tunnels_dir = config_dir / "tunnels"
    routes_dir = config_dir / "routes"
    tunnel_files = sorted(tunnels_dir.glob("*.yaml")) if tunnels_dir.is_dir() else []
    route_files = sorted(routes_dir.glob("*.yaml")) if routes_dir.is_dir() else []

    if not tunnel_files and not route_files:
        console.print(
            f"[yellow]No config files found in {config_dir}[/yellow]\n"
            f"  Create tunnel files in {config_dir}/tunnels/\n"
            f"  Create route files in  {config_dir}/routes/"
        )
        sys.exit(0)

    wg_tunnels: list[WireGuardTunnel] = []
    ipsec_tunnels: list[IPSecTunnel] = []
    routes: list[RouteRule] = []
    errors = 0

    for file_path in tunnel_files:
        try:
            td = _load_yaml_mapping(file_path)
            tunnel = load_tunnel(td)
            if isinstance(tunnel, WireGuardTunnel):
                wg_tunnels.append(tunnel)
            else:
                ipsec_tunnels.append(tunnel)
        except (ValidationError, ValueError) as exc:
            _print_config_error("tunnel", file_path, exc)
            errors += 1

    valid_ifaces = {t.name for t in wg_tunnels} | {t.name for t in ipsec_tunnels}

    for file_path in route_files:
        try:
            rd = _load_yaml_mapping(file_path)
            route = load_route(rd)
            for iface in (route.from_.interface, route.to.interface):
                if iface not in valid_ifaces:
                    console.print(
                        f"[yellow]Warning:[/yellow] route '{route.name}' references "
                        f"interface '{iface}' which is not a managed tunnel "
                        f"(assuming physical interface) in {file_path}"
                    )
            routes.append(route)
        except (ValidationError, ValueError) as exc:
            _print_config_error("route", file_path, exc)
            errors += 1

    if errors:
        console.print(f"\n[red]{errors} error(s) found. Fix them before applying.[/red]")
        sys.exit(1)

    errors += _validate_wireguard_route_reachability(wg_tunnels, routes)
    errors += _validate_overlapping_wg_allowed_ips(wg_tunnels)
    if errors:
        console.print(f"\n[red]{errors} error(s) found. Fix them before applying.[/red]")
        sys.exit(1)

    return wg_tunnels, ipsec_tunnels, routes


def _validate_wireguard_route_reachability(
    wg_tunnels: list[WireGuardTunnel],
    routes: list[RouteRule],
) -> int:
    """Ensure route destinations are reachable via destination WG peers.

    If this check fails, Linux can emit ICMP host-unreachable from the local
    WireGuard interface address even when firewall rules are correct.
    """
    errors = 0
    wg_map = {t.name: t for t in wg_tunnels}

    for route in routes:
        dst_tunnel = wg_map.get(route.to.interface)
        if dst_tunnel is None:
            continue

        if dst_tunnel.table == "off":
            console.print(
                f"[red]Config error in route '{route.name}':[/red] destination tunnel "
                f"'{dst_tunnel.name}' has table=off. Kernel routes for peer allowed_ips "
                "will not be installed automatically."
            )
            errors += 1
            continue

        if dst_tunnel.peer is None:
            console.print(
                f"[red]Config error in route '{route.name}':[/red] destination tunnel "
                f"'{dst_tunnel.name}' has no peer configured."
            )
            errors += 1
            continue

        peer_networks = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in dst_tunnel.peer.allowed_ips
        ]
        tunnel_network = ipaddress.ip_interface(dst_tunnel.address).network
        non_tunnel_peer_networks = [n for n in peer_networks if not n.overlaps(tunnel_network)]

        if route.to.subnets:
            for dst_subnet in route.to.subnets:
                dst_net = ipaddress.ip_network(dst_subnet, strict=False)
                if any(pn.overlaps(dst_net) for pn in peer_networks):
                    continue
                console.print(
                    f"[red]Config error in route '{route.name}':[/red] destination subnet "
                    f"'{dst_subnet}' is not present in peer.allowed_ips for tunnel "
                    f"'{dst_tunnel.name}'."
                )
                errors += 1
        else:
            if not non_tunnel_peer_networks:
                console.print(
                    f"[red]Config error in route '{route.name}':[/red] route.to.subnets is empty "
                    f"and tunnel '{dst_tunnel.name}' peer.allowed_ips has no non-tunnel subnet."
                )
                errors += 1

    return errors


def _validate_overlapping_wg_allowed_ips(wg_tunnels: list[WireGuardTunnel]) -> int:
    """Reject overlapping non-tunnel allowed_ips across WG tunnels.

    Overlaps make Linux choose one interface for the same destination prefix,
    which can silently steer traffic to the wrong tunnel.
    """
    tunnel_networks: dict[str, ipaddress._BaseNetwork] = {}
    for tunnel in wg_tunnels:
        tunnel_networks[tunnel.name] = ipaddress.ip_interface(tunnel.address).network

    advertised: list[tuple[str, ipaddress._BaseNetwork]] = []
    for tunnel in wg_tunnels:
        if tunnel.peer is None:
            continue
        local_tunnel_net = tunnel_networks[tunnel.name]
        for cidr in tunnel.peer.allowed_ips:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.overlaps(local_tunnel_net):
                continue
            advertised.append((tunnel.name, net))

    errors = 0
    for idx, (name_a, net_a) in enumerate(advertised):
        for name_b, net_b in advertised[idx + 1 :]:
            if name_a == name_b:
                continue
            if not net_a.overlaps(net_b):
                continue
            console.print(
                f"[red]Config error:[/red] overlapping WireGuard peer allowed_ips "
                f"between tunnels '{name_a}' ({net_a}) and '{name_b}' ({net_b}). "
                "This can route traffic to the wrong interface."
            )
            errors += 1

    return errors


def _p(prompt: str, default: object = None, **kwargs) -> str:
    """Wrapper around click.prompt that shows current value as default."""
    if default is not None:
        return click.prompt(prompt, default=str(default), **kwargs)
    return click.prompt(prompt, **kwargs)


def _load_yaml_mapping(path: Path) -> dict:
    """Load YAML and ensure top-level mapping, so errors can be shown with file context."""
    try:
        with path.open() as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML syntax in {path}: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"Failed to read config file {path}: {exc}") from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(
            f"Top-level YAML value must be a mapping/object in {path} "
            f"(got {type(data).__name__})"
        )
    return data


def _print_config_error(kind: str, file_path: Path, exc: ValidationError | ValueError) -> None:
    """Print concise config validation errors with file and field location."""
    if isinstance(exc, ValidationError):
        error_lines = []
        for item in exc.errors():
            loc = ".".join(str(part) for part in item.get("loc", ())) or "<root>"
            msg = item.get("msg", "invalid value")
            error_lines.append(f"  - {loc}: {msg}")
        console.print(
            f"[red]Config error in {kind} file:[/red] {file_path}\n" + "\n".join(error_lines)
        )
        return

    console.print(f"[red]Config error in {kind} file:[/red] {file_path}\n  - {exc}")


# Register sub-modules (triggers @cli.command / @cli.group decorators)
from . import apply, export, init, route, tunnel  # noqa: E402, F401
