"""Export command — export peer config for a tunnel by name."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import click
import pyqrcode

from ..ipsec import export_ipsec_config
from ..utils import DEFAULT_CONFIG_DIR, WG_KEY_DIR, console, load_settings
from ..wireguard import export_peer_config
from . import _load_and_validate, cli


# ---------------------------------------------------------------------------
# Helpers for available options
# ---------------------------------------------------------------------------

def _get_all_tunnel_names(config_dir: Path) -> list[str]:
    """Get list of all available tunnel names (both wireguard and ipsec)."""
    tunnels_dir = config_dir / "tunnels"
    if not tunnels_dir.is_dir():
        return []
    return sorted([f.stem for f in tunnels_dir.glob("*.yaml")])


@cli.command("export")
@click.argument("name", required=False)
@click.option("--server-endpoint", default=None, help="Public IP:port override (default: server_address + tunnel port from settings.yaml).")
@click.option(
    "--allowed-ips", default=None,
    help="Comma-separated AllowedIPs for the client [Peer] block (default: tunnel network).",
)
@click.option("--out", default=None, help="Write to file instead of stdout.")
@click.option("--qr", is_flag=True, help="Display config as QR code instead of text (WireGuard only, suitable for mobile devices).")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def export_cmd(
    name: str | None,
    server_endpoint: str | None,
    allowed_ips: str | None,
    out: str | None,
    qr: bool,
    config_dir: str,
) -> None:
    """Export a peer config for a tunnel by name.

    Searches IPSec tunnel names first, then WireGuard tunnel names.
    Each WireGuard tunnel has exactly one peer; the tunnel name is used for export.
    """
    cfg = Path(config_dir)
    
    # If name not provided, prompt user to choose from available tunnels
    if not name:
        available = _get_all_tunnel_names(cfg)
        if not available:
            console.print("[red]No tunnels found.[/red]")
            sys.exit(1)
        name = click.prompt(
            "Select tunnel to export",
            type=click.Choice(available, case_sensitive=False),
        )
    
    wg_tunnels, ipsec_tunnels, _ = _load_and_validate(cfg)

    allowed_ips_list: list[str] | None = None
    if allowed_ips:
        allowed_ips_list = [x.strip() for x in allowed_ips.split(",") if x.strip()]
        for cidr in allowed_ips_list:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                console.print(f"[red]Invalid --allowed-ips CIDR:[/red] {cidr}")
                sys.exit(1)

    if server_endpoint:
        if ":" not in server_endpoint:
            console.print("[red]Invalid --server-endpoint:[/red] expected host:port")
            sys.exit(1)
        host, port_str = server_endpoint.rsplit(":", 1)
        if not host:
            console.print("[red]Invalid --server-endpoint:[/red] host cannot be empty")
            sys.exit(1)
        try:
            port = int(port_str)
        except ValueError:
            console.print("[red]Invalid --server-endpoint:[/red] port must be numeric")
            sys.exit(1)
        if not (1 <= port <= 65535):
            console.print("[red]Invalid --server-endpoint:[/red] port must be 1-65535")
            sys.exit(1)

    # 1. Try IPSec tunnel name
    ipsec_tunnel = next((t for t in ipsec_tunnels if t.name == name), None)
    if ipsec_tunnel is not None:
        try:
            result = export_ipsec_config(ipsec_tunnel)
            _write_output(result, out)
        except Exception as exc:
            console.print(f"[bold red]Export failed:[/bold red] {exc}")
            sys.exit(1)
        return

    # 2. Try WireGuard tunnel name
    wg_tunnel = next((t for t in wg_tunnels if t.name == name), None)
    if wg_tunnel is not None:
        if wg_tunnel.peer is None:
            console.print(f"[red]Tunnel '{name}' has no peer configured.[/red]")
            sys.exit(1)
        # Fall back to server_address + listen_port from settings.yaml
        endpoint = server_endpoint
        if endpoint is None:
            settings = load_settings(cfg)
            addr = settings.get("server_address")
            if addr:
                port = wg_tunnel.listen_port or settings["wireguard"]["default_listen_port"]
                endpoint = f"{addr}:{port}"
        try:
            result = export_peer_config(wg_tunnel, endpoint, allowed_ips_list)
            if qr:
                _display_qr_code(result)
            else:
                _write_output(result, out)
        except Exception as exc:
            console.print(f"[bold red]Export failed:[/bold red] {exc}")
            sys.exit(1)
        # Delete peer private key — server doesn't need it after export
        key_path = WG_KEY_DIR / f"{wg_tunnel.name}-peer.key"
        if key_path.exists():
            key_path.unlink()
            console.print(
                f"[dim]Peer private key removed (no longer needed by server): {key_path}[/dim]"
            )
        return

    # 3. Not found — show helpful error
    console.print(f"[red]No tunnel named '{name}' found.[/red]")
    _print_available(wg_tunnels, ipsec_tunnels)
    sys.exit(1)


def _write_output(result: str, out: str | None) -> None:
    if out:
        Path(out).write_text(result)
        console.print(f"[green]Written to {out}[/green]")
    else:
        click.echo(result)


def _display_qr_code(config_text: str) -> None:
    """Generate and display QR code from config text.
    
    This is useful for mobile devices that can scan QR codes to import configurations.
    """
    try:
        qr = pyqrcode.create(config_text, encoding='utf-8')
        console.print("\n[bold]WireGuard Configuration QR Code:[/bold]\n")
        # terminal() method renders the QR code as Unicode blocks
        click.echo(qr.terminal())
        console.print("\n[dim]Scan this QR code with WireGuard mobile app to import the configuration.[/dim]\n")
    except Exception as exc:
        console.print(f"[yellow]Warning: Failed to generate QR code:[/yellow] {exc}")
        console.print("\n[dim]Falling back to text format:[/dim]\n")
        click.echo(config_text)


def _print_available(wg_tunnels, ipsec_tunnels) -> None:
    if wg_tunnels:
        console.print("\n[yellow]Available WireGuard tunnels:[/yellow]")
        for t in wg_tunnels:
            peer_info = f"  peer: {t.peer.name}" if t.peer else "  [dim](no peer)[/dim]"
            console.print(f"  {t.name}{peer_info}")
    if ipsec_tunnels:
        console.print("\n[yellow]Available IPSec tunnels:[/yellow]")
        for t in ipsec_tunnels:
            console.print(f"  {t.name}")
