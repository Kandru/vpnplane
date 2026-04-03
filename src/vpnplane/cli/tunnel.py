"""Tunnel CRUD commands and interactive prompt helpers."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import click
import yaml
from rich.table import Table

from ..utils import (
    DEFAULT_CONFIG_DIR,
    WG_KEY_DIR,
    console,
    generate_wireguard_keypair,
    next_free_peer_ip,
    next_free_port,
    next_free_tunnel_addr,
)

from . import _p, _require_settings, cli


# ---------------------------------------------------------------------------
# Helpers for available options
# ---------------------------------------------------------------------------

def _get_tunnel_names(config_dir: Path) -> list[str]:
    """Get list of available tunnel names for autocomplete."""
    tunnels_dir = config_dir / "tunnels"
    if not tunnels_dir.is_dir():
        return []
    return sorted([f.stem for f in tunnels_dir.glob("*.yaml")])


@cli.group()
def tunnel() -> None:
    """Interactively create, edit, or delete tunnel config files."""


@tunnel.command("add")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def tunnel_add(config_dir: str) -> None:
    """Create a new WireGuard connection (one tunnel, one peer) or an IPSec tunnel."""
    _require_settings(Path(config_dir))
    tunnels_dir = Path(config_dir) / "tunnels"
    tunnels_dir.mkdir(parents=True, exist_ok=True)

    tunnel_type = click.prompt(
        "Type", type=click.Choice(["wireguard", "ipsec"]), default="wireguard"
    )

    if tunnel_type == "wireguard":
        data = _prompt_wireguard_tunnel(config_dir=Path(config_dir))
        name = data["name"]
        out_path = tunnels_dir / f"{name}.yaml"
        if out_path.exists():
            if not click.confirm(f"{out_path} already exists. Overwrite?"):
                console.print("Aborted.")
                return
        out_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        console.print(f"[green]Created:[/green] {out_path}")
        console.print("\nRun [bold]vpnplane apply[/bold] to activate.")
    else:
        data = _prompt_ipsec_tunnel()
        name = data["name"]
        out_path = tunnels_dir / f"{name}.yaml"
        if out_path.exists():
            if not click.confirm(f"{out_path} already exists. Overwrite?"):
                console.print("Aborted.")
                return
        out_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        console.print(f"[green]Saved:[/green] {out_path}")
        console.print("\nRun [bold]vpnplane apply[/bold] to activate.")


@tunnel.command("edit")
@click.argument("name", type=click.Choice([], case_sensitive=False), required=False)
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def tunnel_edit(name: str, config_dir: str) -> None:
    """Interactively edit an existing tunnel config file."""
    _require_settings(Path(config_dir))
    config_path = Path(config_dir)
    tunnels_dir = config_path / "tunnels"
    
    # If name not provided, prompt user to choose from available tunnels
    if not name:
        available = _get_tunnel_names(config_path)
        if not available:
            console.print("[red]No tunnels found.[/red]")
            sys.exit(1)
        name = click.prompt(
            "Select tunnel to edit",
            type=click.Choice(available, case_sensitive=False),
        )
    
    path = tunnels_dir / f"{name}.yaml"
    if not path.exists():
        console.print(f"[red]Tunnel config not found:[/red] {path}")
        sys.exit(1)

    with open(path) as f:
        data = yaml.safe_load(f)

    console.print(f"Editing [bold]{name}[/bold] (press Enter to keep current value)\n")
    tunnel_type = data.get("type", "wireguard")

    if tunnel_type == "wireguard":
        data = _prompt_wireguard_tunnel(existing=data, config_dir=Path(config_dir))
    else:
        data = _prompt_ipsec_tunnel(existing=data)

    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    console.print(f"[green]Updated:[/green] {path}")
    console.print("\nRun [bold]vpnplane apply[/bold] to activate.")


@tunnel.command("delete")
@click.argument("name", type=click.Choice([], case_sensitive=False), required=False)
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def tunnel_delete(name: str, config_dir: str, yes: bool) -> None:
    """Delete a tunnel config file (and remove the tunnel on next apply)."""
    _require_settings(Path(config_dir))
    config_path = Path(config_dir)
    tunnels_dir = config_path / "tunnels"
    
    # If name not provided, prompt user to choose from available tunnels
    if not name:
        available = _get_tunnel_names(config_path)
        if not available:
            console.print("[red]No tunnels found.[/red]")
            sys.exit(1)
        name = click.prompt(
            "Select tunnel to delete",
            type=click.Choice(available, case_sensitive=False),
        )
    
    path = tunnels_dir / f"{name}.yaml"
    if not path.exists():
        console.print(f"[red]Tunnel config not found:[/red] {path}")
        sys.exit(1)

    if not yes and not click.confirm(
        f"Delete {path}? The tunnel will be removed on next [bold]apply[/bold]."
    ):
        console.print("Aborted.")
        return

    path.unlink()
    console.print(f"[green]Deleted:[/green] {path}")
    console.print("\nRun [bold]vpnplane apply[/bold] to remove the tunnel.")


@tunnel.command("list")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def tunnel_list(config_dir: str) -> None:
    """List all tunnel config files."""
    tunnels_dir = Path(config_dir) / "tunnels"
    if not tunnels_dir.is_dir():
        console.print("[dim]No tunnels directory found.[/dim]")
        return

    files = sorted(tunnels_dir.glob("*.yaml"))
    if not files:
        console.print("[dim]No tunnel configs found.[/dim]")
        return

    t = Table(show_header=True, header_style="bold")
    t.add_column("File")
    t.add_column("Name")
    t.add_column("Type")
    t.add_column("Address")
    t.add_column("Port")

    for f in files:
        try:
            data = yaml.safe_load(f.read_text()) or {}
            t.add_row(
                f.name,
                data.get("name", ""),
                data.get("type", "wireguard"),
                data.get("address", ""),
                str(data.get("listen_port", "")),
            )
        except Exception:
            t.add_row(f.name, "[red]parse error[/red]", "", "", "")

    console.print(t)


# ---------------------------------------------------------------------------
# Interactive prompt helpers
# ---------------------------------------------------------------------------


def _prompt_wireguard_tunnel(existing: dict | None = None, config_dir: Path | None = None) -> dict:
    e = existing or {}

    # Show existing tunnels for context
    if config_dir and not existing:
        existing_tunnels = _get_tunnel_names(config_dir)
        if existing_tunnels:
            console.print(f"[dim]Existing tunnels: {', '.join(existing_tunnels)}[/dim]")

    name = _p("Connection name (max 15 chars, e.g. wg-office)", e.get("name"))

    fritzbox = click.confirm(
        "FritzBox site-to-site mode?",
        default=e.get("fritzbox", False),
    )

    default_address = e.get("address")
    default_transfer_subnet = e.get("tunnel_subnet")
    auto_tunnel_addr = None
    if not existing and config_dir is not None:
        try:
            auto_tunnel_addr = next_free_tunnel_addr(config_dir)
            if default_address is None:
                default_address = auto_tunnel_addr
            if default_transfer_subnet is None and auto_tunnel_addr:
                default_transfer_subnet = str(ipaddress.ip_interface(auto_tunnel_addr).network)
        except Exception as exc:
            console.print(f"[yellow]Could not auto-detect free subnet: {exc}[/yellow]")
    if fritzbox:
        console.print(
            "[dim]FritzBox mode: Address must be the FritzBox tunnel gateway IP "
            "(first usable host in the subnet), e.g. [bold]192.168.178.1/24[/bold][/dim]"
        )
        address = _p("Tunnel address — FritzBox gateway IP (e.g. 192.168.178.1/24)", default_address)
        tunnel_subnet = _p(
            "Host WireGuard transfer subnet (CIDR, e.g. 10.100.0.0/30)",
            default_transfer_subnet,
        )
    else:
        address = _p("Tunnel address (CIDR, e.g. 10.100.0.1/24)", default_address)
        tunnel_subnet = None

    default_port: str | int = e.get("listen_port", "")
    if not existing and config_dir is not None and not default_port:
        try:
            default_port = next_free_port(config_dir)
        except Exception as exc:
            console.print(f"[yellow]Could not auto-detect free port: {exc}[/yellow]")
    listen_port = _prompt_optional_int(
        "Listen port (leave blank for client-only)",
        default=default_port,
        min_value=1,
        max_value=65535,
    )

    default_key_path = WG_KEY_DIR / f"{name}.key"
    if not existing and not default_key_path.exists():
        try:
            priv, _ = generate_wireguard_keypair()
            default_key_path.parent.mkdir(parents=True, exist_ok=True)
            default_key_path.write_text(priv + "\n")
            default_key_path.chmod(0o600)
            console.print(f"[green]Generated server key:[/green] {default_key_path}")
        except Exception as exc:
            console.print(f"[yellow]Server key generation failed ({exc}).[/yellow]")
    private_key = _p(
        "Path to private key file",
        e.get("private_key", str(default_key_path)),
    )
    mtu = _prompt_int("MTU", e.get("mtu", 1420), min_value=576, max_value=9000)
    dns_raw = _p("DNS servers (comma-separated, or blank)", e.get("dns") and ",".join(e["dns"]) or "")
    description = _p("Description (optional)", e.get("description", ""))

    data: dict = {
        "type": "wireguard",
        "name": name,
        "address": address,
        "private_key": private_key,
        "mtu": mtu,
        "fritzbox": fritzbox,
        "description": description,
    }
    if tunnel_subnet:
        data["tunnel_subnet"] = tunnel_subnet

    if listen_port is not None:
        data["listen_port"] = listen_port
    if dns_raw.strip():
        data["dns"] = [d.strip() for d in dns_raw.split(",") if d.strip()]

    peer_tunnel_addr = address
    if fritzbox and tunnel_subnet:
        try:
            net = ipaddress.ip_network(tunnel_subnet, strict=True)
            first_host = next(net.hosts(), None)
            if first_host is not None:
                peer_tunnel_addr = f"{first_host}/{net.prefixlen}"
        except ValueError:
            # Keep prompt flow interactive; model validation will report invalid subnet.
            peer_tunnel_addr = address

    fritzbox_subnet: str | None = None
    if fritzbox:
        try:
            fritzbox_subnet = str(ipaddress.ip_interface(address).network)
        except ValueError:
            fritzbox_subnet = None

    data["peer"] = _prompt_peer(
        name,
        tunnel_addr=peer_tunnel_addr,
        existing=e.get("peer"),
        fritzbox=fritzbox,
        fritzbox_subnet=fritzbox_subnet,
    )
    return data


def _prompt_peer(
    tunnel_name: str,
    existing: dict | None = None,
    tunnel_addr: str | None = None,
    fritzbox: bool = False,
    fritzbox_subnet: str | None = None,
) -> dict:
    e = existing or {}
    # Peer name is always the tunnel name
    peer_name = tunnel_name

    # Public key — auto-generate or reuse existing
    existing_pubkey = e.get("public_key", "")
    key_path = WG_KEY_DIR / f"{tunnel_name}-peer.key"
    if existing_pubkey:
        public_key = _p(" Public key (base64)", existing_pubkey)
    else:
        public_key = click.prompt(
            " Public key (base64, Enter to auto-generate)", default="", show_default=False
        ).strip()
    if not public_key:
        try:
            priv, public_key = generate_wireguard_keypair()
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(priv + "\n")
            key_path.chmod(0o600)
            console.print(f" [green]Keypair generated.[/green] Private key → {key_path}")
            console.print(f" [dim]vpnplane export {tunnel_name}[/dim]")
        except Exception as exc:
            console.print(f" [red]Key generation failed ({exc}), enter manually:[/red]")
            public_key = click.prompt(" Public key (base64)")

    # Determine the peer's transfer address (auto-assigned).
    peer_tunnel_ip = ""
    if not existing and tunnel_addr:
        try:
            peer_tunnel_ip = next_free_peer_ip(tunnel_addr, [])
            if fritzbox:
                transfer_prefix = ipaddress.ip_interface(tunnel_addr).network.prefixlen
                peer_tunnel_ip = f"{ipaddress.ip_interface(peer_tunnel_ip).ip}/{transfer_prefix}"
        except Exception:
            pass
    elif existing:
        existing_allowed = e.get("allowed_ips", [])
        if existing_allowed and tunnel_addr:
            try:
                local_net = ipaddress.ip_interface(tunnel_addr).network
                peer_tunnel_ip = next(
                    (
                        ip
                        for ip in existing_allowed
                        if ipaddress.ip_network(ip, strict=False).overlaps(local_net)
                    ),
                    "",
                )
            except Exception:
                peer_tunnel_ip = ""
        if existing_allowed and not peer_tunnel_ip:
            peer_tunnel_ip = next(
                (ip for ip in existing_allowed if ip.endswith("/32") or ip.endswith("/128")),
                ""
            )

    # Extract existing remote subnets (if editing)
    existing_remote = []
    if existing:
        existing_allowed = e.get("allowed_ips", [])
        if existing_allowed and peer_tunnel_ip:
            existing_remote = [ip for ip in existing_allowed if ip != peer_tunnel_ip]
        elif existing_allowed:
            existing_remote = existing_allowed

    if fritzbox and fritzbox_subnet and fritzbox_subnet not in existing_remote:
        existing_remote.append(fritzbox_subnet)

    endpoint = _p(" Endpoint (host:port, or blank for roaming)", e.get("endpoint", ""))

    if not fritzbox:
        if peer_tunnel_ip:
            displayed_tunnel_ip = _p(" Peer tunnel address", peer_tunnel_ip)
        else:
            displayed_tunnel_ip = _p(" Peer tunnel address (e.g. 10.100.0.2/32)", "")
            if displayed_tunnel_ip:
                peer_tunnel_ip = displayed_tunnel_ip.strip()

    remote_subnets_raw = _p(
        " Remote subnets reachable via this peer (comma-separated, optional)",
        existing_remote and ",".join(existing_remote) or ""
    )

    # Build final allowed_ips: [peer_tunnel_ip, ...remote_subnets]
    allowed_ips = []
    if peer_tunnel_ip:
        allowed_ips.append(peer_tunnel_ip.strip())
    if remote_subnets_raw.strip():
        allowed_ips.extend([
            ip.strip() for ip in remote_subnets_raw.split(",")
            if ip.strip() and ip.strip() != peer_tunnel_ip
        ])
    if fritzbox and fritzbox_subnet and fritzbox_subnet not in allowed_ips:
        allowed_ips.append(fritzbox_subnet)

    keepalive = _prompt_int(
        " Persistent keepalive (0 to disable)",
        e.get("persistent_keepalive", 25),
        min_value=0,
        max_value=65535,
    )
    psk = _p(" Preshared key (auto/null/path)", e.get("preshared_key", "auto"))

    peer: dict = {
        "name": peer_name,
        "public_key": public_key,
        "allowed_ips": allowed_ips if allowed_ips else ["0.0.0.0/0"],
        "persistent_keepalive": keepalive,
        "preshared_key": None if psk == "null" else psk,
    }

    if endpoint.strip():
        peer["endpoint"] = endpoint.strip()
    return peer


def _prompt_ipsec_tunnel(existing: dict | None = None) -> dict:
    e = existing or {}

    name = _p("Tunnel name (e.g. ipsec-aws)", e.get("name"))
    local_addr = _p("Local public IP address", e.get("local", {}).get("address", ""))
    local_subnets_raw = _p(
        "Local subnets (comma-separated CIDRs)",
        e.get("local", {}).get("subnets") and ",".join(e["local"]["subnets"]) or "",
    )
    local_psk = _p(
        "Path to local PSK file",
        e.get("local", {}).get("auth", {}).get("secret", f"/etc/ipsec.d/secrets/{name}.psk"),
    )
    remote_addr = _p("Remote public IP address", e.get("remote", {}).get("address", ""))
    remote_subnets_raw = _p(
        "Remote subnets (comma-separated CIDRs)",
        e.get("remote", {}).get("subnets") and ",".join(e["remote"]["subnets"]) or "",
    )
    remote_psk = _p(
        "Path to remote PSK file",
        e.get("remote", {}).get("auth", {}).get("secret", local_psk),
    )
    auto_start = click.confirm("Initiate tunnel automatically on startup?",
                               default=e.get("auto_start", True))
    description = _p("Description (optional)", e.get("description", ""))

    return {
        "type": "ipsec",
        "name": name,
        "description": description,
        "local": {
            "address": local_addr,
            "subnets": [s.strip() for s in local_subnets_raw.split(",") if s.strip()],
            "auth": {"method": "psk", "secret": local_psk},
        },
        "remote": {
            "address": remote_addr,
            "subnets": [s.strip() for s in remote_subnets_raw.split(",") if s.strip()],
            "auth": {"method": "psk", "secret": remote_psk},
        },
        "ike": {"version": 2, "encryption": "aes256", "integrity": "sha256", "dh_group": "modp2048"},
        "esp": {"encryption": "aes256", "integrity": "sha256", "dpd_action": "restart"},
        "auto_start": auto_start,
    }


def _prompt_int(prompt: str, default: int | str, min_value: int, max_value: int) -> int:
    """Prompt for an integer in range and keep asking on invalid input."""
    while True:
        raw = _p(prompt, default).strip()
        try:
            value = int(raw)
        except ValueError:
            console.print(f"[red]Error:[/red] Please enter a number between {min_value} and {max_value}.")
            continue

        if min_value <= value <= max_value:
            return value

        console.print(f"[red]Error:[/red] Value out of range ({min_value}-{max_value}).")


def _prompt_optional_int(
    prompt: str,
    default: int | str,
    min_value: int,
    max_value: int,
) -> int | None:
    """Prompt for optional integer; empty input returns None."""
    while True:
        raw = _p(prompt, default).strip()
        if raw == "":
            return None

        try:
            value = int(raw)
        except ValueError:
            console.print(f"[red]Error:[/red] Please enter a number between {min_value} and {max_value}.")
            continue

        if min_value <= value <= max_value:
            return value

        console.print(f"[red]Error:[/red] Value out of range ({min_value}-{max_value}).")
