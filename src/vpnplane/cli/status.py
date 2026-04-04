"""Detailed status command with live traffic view."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Mapping

import click
from rich.table import Table

from ..firewall import get_firewall_status, get_system_status
from ..ipsec import get_ipsec_status
from ..models import IPSecTunnel, RouteRule, WireGuardTunnel
from ..utils import (
    DEFAULT_CONFIG_DIR,
    check_required_tools,
    console,
    format_bytes,
    format_speed,
    require_root,
)
from ..wireguard import get_wireguard_status
from . import _load_and_validate, cli


@cli.command()
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
@click.option("--watch", is_flag=True, help="Auto-refresh status output.")
@click.option("--interval", default=2.0, show_default=True, type=float,
              help="Refresh interval in seconds for --watch.")
@click.option("--tunnel", default=None,
              help="Show only one tunnel and related routes by interface name.")
def status(config_dir: str, watch: bool, interval: float, tunnel: str | None) -> None:
    """Show tunnel, route, and system status."""
    require_root()
    check_required_tools()

    if interval <= 0:
        raise click.UsageError("--interval must be greater than 0")

    cfg = Path(config_dir)
    try:
        wg_tunnels, ipsec_tunnels, routes = _load_desired_state(cfg)
    except SystemExit as exc:
        raise SystemExit(exc.code) from exc

    desired_tunnels: dict[str, WireGuardTunnel | IPSecTunnel] = {t.name: t for t in wg_tunnels}
    desired_tunnels.update({t.name: t for t in ipsec_tunnels})

    live_state = _collect_live_state()
    _validate_tunnel_filter(tunnel, desired_tunnels, live_state)

    if not watch:
        _render_status(
            desired_tunnels=desired_tunnels,
            routes=routes,
            live_state=live_state,
            tunnel_filter=tunnel,
        )
        return

    previous_counters: dict[str, dict[str, tuple[int, int]]] | None = None
    while True:
        try:
            click.clear()
            _render_status(
                desired_tunnels=desired_tunnels,
                routes=routes,
                live_state=live_state,
                tunnel_filter=tunnel,
                previous_counters=previous_counters,
                interval_secs=interval,
            )
            time.sleep(interval)
            previous_counters = _extract_peer_counters(live_state["wg_statuses"])
            live_state = _collect_live_state()
        except KeyboardInterrupt:
            break


def _load_desired_state(
    config_dir: Path,
) -> tuple[list[WireGuardTunnel], list[IPSecTunnel], list[RouteRule]]:
    if not config_dir.is_dir():
        console.print(f"[yellow]Config directory not found:[/yellow] {config_dir}")
        return [], [], []

    try:
        return _load_and_validate(config_dir)
    except SystemExit as exc:
        if exc.code == 0:
            return [], [], []
        raise


def _collect_live_state() -> dict:
    try:
        wg_statuses = get_wireguard_status()
        ipsec_statuses = get_ipsec_status()
        firewall_status = get_firewall_status()
        system_status = get_system_status()
    except Exception as exc:
        console.print(f"[bold red]Status failed:[/bold red] {exc}")
        sys.exit(1)

    return {
        "wg_statuses": wg_statuses,
        "ipsec_statuses": ipsec_statuses,
        "firewall_status": firewall_status,
        "system_status": system_status,
    }


def _validate_tunnel_filter(tunnel_filter: str | None, desired_tunnels: dict, live_state: dict) -> None:
    if tunnel_filter is None:
        return

    known = set(desired_tunnels.keys())
    known |= {item["name"] for item in live_state["wg_statuses"]}
    known |= {item["name"] for item in live_state["ipsec_statuses"]}

    if tunnel_filter not in known:
        console.print(f"[bold red]Unknown tunnel:[/bold red] {tunnel_filter}")
        sys.exit(1)


def _render_status(
    *,
    desired_tunnels: Mapping[str, WireGuardTunnel | IPSecTunnel],
    routes: list[RouteRule],
    live_state: dict,
    tunnel_filter: str | None,
    previous_counters: dict[str, dict[str, tuple[int, int]]] | None = None,
    interval_secs: float | None = None,
) -> None:
    wg_live = {item["name"]: item for item in live_state["wg_statuses"]}
    ipsec_live = {item["name"]: item for item in live_state["ipsec_statuses"]}

    tunnels = _build_tunnels_table(
        desired_tunnels=desired_tunnels,
        wg_live=wg_live,
        ipsec_live=ipsec_live,
        tunnel_filter=tunnel_filter,
        previous_counters=previous_counters,
        interval_secs=interval_secs,
    )
    routes_block = _build_routes_table(
        routes=routes,
        firewall_status=live_state["firewall_status"],
        tunnel_filter=tunnel_filter,
    )
    system = _build_system_table(live_state["system_status"])

    console.print("[bold]Tunnels[/bold]")
    console.print(tunnels)
    console.print()
    console.print("[bold]Routes[/bold]")
    console.print(routes_block)
    console.print()
    console.print("[bold]System[/bold]")
    console.print(system)


def _build_tunnels_table(
    *,
    desired_tunnels: Mapping[str, WireGuardTunnel | IPSecTunnel],
    wg_live: dict[str, dict],
    ipsec_live: dict[str, dict],
    tunnel_filter: str | None,
    previous_counters: dict[str, dict[str, tuple[int, int]]] | None,
    interval_secs: float | None,
) -> Table:
    show_rates = previous_counters is not None and interval_secs is not None

    t = Table(show_header=True, header_style="bold")
    t.add_column("Name")
    t.add_column("Type")
    t.add_column("Status")
    t.add_column("Details")
    t.add_column("Traffic")

    desired_names = set(desired_tunnels.keys())
    live_names = set(wg_live.keys()) | set(ipsec_live.keys())
    names = sorted(desired_names | live_names)

    if tunnel_filter:
        names = [name for name in names if name == tunnel_filter]

    if not names:
        t.add_row("[dim]none[/dim]", "", "", "", "")
        return t

    for name in names:
        desired = desired_tunnels.get(name)

        if isinstance(desired, WireGuardTunnel) or name in wg_live:
            live = wg_live.get(name)
            traffic = _wireguard_traffic_cell(
                interface=name,
                live=live,
                previous_counters=previous_counters,
                interval_secs=interval_secs,
                show_rates=show_rates,
            )
            t.add_row(
                _name_label(name, desired is not None, live is not None),
                "WireGuard",
                _status_badge(live),
                _wireguard_details(live),
                traffic,
            )
            continue

        live = ipsec_live.get(name)
        t.add_row(
            _name_label(name, desired is not None, live is not None),
            "IPSec",
            _status_badge(live),
            _ipsec_details(live),
            "-",
        )

    return t


def _name_label(name: str, configured: bool, present_live: bool) -> str:
    if configured and present_live:
        return name
    if configured and not present_live:
        return f"{name} [yellow](Not applied)[/yellow]"
    return f"{name} [dim](unmanaged)[/dim]"


def _status_badge(live: dict | None) -> str:
    if not live:
        return "[yellow]Configured only[/yellow]"
    if live.get("active"):
        return "[green]Up[/green]"
    return "[red]Down[/red]"


def _wireguard_details(live: dict | None) -> str:
    if not live:
        return "[dim]No runtime interface[/dim]"

    address = live.get("address", "-")
    listen_port = live.get("listen_port", "-")
    peer_count = len(live.get("peers", []))
    return f"addr={address} | port={listen_port} | peers={peer_count}"


def _wireguard_traffic_cell(
    *,
    interface: str,
    live: dict | None,
    previous_counters: dict[str, dict[str, tuple[int, int]]] | None,
    interval_secs: float | None,
    show_rates: bool,
) -> str:
    if not live:
        return "[dim]n/a[/dim]"

    peer_lines: list[str] = []
    prev_iface = previous_counters.get(interface, {}) if previous_counters else {}

    for peer in live.get("peers", []):
        key = peer.get("public_key")
        key_short = peer.get("public_key_short", "peer")
        rx = int(peer.get("rx_bytes", 0))
        tx = int(peer.get("tx_bytes", 0))
        hs = peer.get("handshake") or "never"

        line = f"{key_short} rx {format_bytes(rx)} tx {format_bytes(tx)} hs {hs}"
        if show_rates and key and interval_secs:
            prev = prev_iface.get(key)
            if prev:
                rx_rate = max(0, rx - prev[0]) / interval_secs
                tx_rate = max(0, tx - prev[1]) / interval_secs
                line += f" | \u2193 {format_speed(rx_rate)} \u2191 {format_speed(tx_rate)}"
            else:
                line += " | [dim]rate n/a[/dim]"

        peer_lines.append(line)

    if not peer_lines:
        return "[dim]none[/dim]"
    return "\n".join(peer_lines)


def _ipsec_details(live: dict | None) -> str:
    if not live:
        return "[dim]No runtime SA[/dim]"

    state = live.get("state", "UNKNOWN")
    established_ago = live.get("established_ago") or "-"
    child_sas = live.get("child_sas", 0)
    return f"state={state} | est={established_ago} | child_sas={child_sas}"


def _build_routes_table(routes: list[RouteRule], firewall_status: list[dict], tunnel_filter: str | None) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("Name")
    t.add_column("From → To")
    t.add_column("Protocol")
    t.add_column("Action")
    t.add_column("Status")

    installed = {item["name"] for item in firewall_status}

    shown = 0
    for route in routes:
        if tunnel_filter and tunnel_filter not in {route.from_.interface, route.to.interface}:
            continue

        status = "[green]Installed[/green]" if route.name in installed else "[yellow]Not applied[/yellow]"
        path = f"{route.from_.interface} -> {route.to.interface}"
        protocol = route.protocol
        if route.ports:
            protocol += f"/{','.join(str(p) for p in route.ports)}"

        t.add_row(route.name, path, protocol, route.action, status)
        shown += 1

    if shown == 0:
        t.add_row("[dim]none[/dim]", "", "", "", "")

    return t


def _build_system_table(system_status: dict) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("Check")
    t.add_column("Status")

    t.add_row("IPv4 forwarding", _on_off(system_status.get("ipv4_forward")))
    t.add_row("IPv6 forwarding", _on_off(system_status.get("ipv6_forward")))

    chains_present = system_status.get("chains_present")
    rule_count = system_status.get("rule_count", 0)
    if chains_present:
        chain_status = f"[green]Active[/green] ({rule_count} rules)"
    else:
        chain_status = "[red]Missing[/red]"
    t.add_row("vpnplane chains", chain_status)
    return t


def _on_off(value: bool | None) -> str:
    if value is True:
        return "[green]Enabled[/green]"
    if value is False:
        return "[red]Disabled[/red]"
    return "[yellow]Unknown[/yellow]"


def _extract_peer_counters(wg_statuses: list[dict]) -> dict[str, dict[str, tuple[int, int]]]:
    counters: dict[str, dict[str, tuple[int, int]]] = {}
    for interface in wg_statuses:
        iface_name = interface.get("name")
        if not iface_name:
            continue

        peers: dict[str, tuple[int, int]] = {}
        for peer in interface.get("peers", []):
            pubkey = peer.get("public_key")
            if not pubkey:
                continue
            peers[pubkey] = (int(peer.get("rx_bytes", 0)), int(peer.get("tx_bytes", 0)))

        counters[iface_name] = peers

    return counters
