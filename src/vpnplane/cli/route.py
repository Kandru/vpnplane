"""Route CRUD commands."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

import click
import yaml
from rich.table import Table

from ..utils import DEFAULT_CONFIG_DIR, console, load_all_configs
from . import _p, _require_settings, cli


# ---------------------------------------------------------------------------
# Helpers for available options
# ---------------------------------------------------------------------------

def _get_route_names(config_dir: Path) -> list[str]:
    """Get list of available route names for autocomplete."""
    routes_dir = config_dir / "routes"
    if not routes_dir.is_dir():
        return []
    return sorted([f.stem for f in routes_dir.glob("*.yaml")])


@cli.group()
def route() -> None:
    """Interactively create, edit, or delete route config files."""


@route.command("add")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def route_add(config_dir: str) -> None:
    """Interactively create a new route config file."""
    routes_dir = Path(config_dir) / "routes"
    routes_dir.mkdir(parents=True, exist_ok=True)

    data = _prompt_route(config_dir=Path(config_dir), is_new=True)
    name = data["name"]
    out_path = routes_dir / f"{name}.yaml"

    if out_path.exists():
        if not click.confirm(f"{out_path} already exists. Overwrite?"):
            console.print("Aborted.")
            return

    out_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    console.print(f"[green]Saved:[/green] {out_path}")
    console.print("\nRun [bold]vpnplane apply[/bold] to activate.")


@route.command("edit")
@click.argument("name", type=click.Choice([], case_sensitive=False), required=False)
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def route_edit(name: str, config_dir: str) -> None:
    """Interactively edit an existing route config file."""
    _require_settings(Path(config_dir))
    config_path = Path(config_dir)
    routes_dir = config_path / "routes"
    
    # If name not provided, prompt user to choose from available routes
    if not name:
        available = _get_route_names(config_path)
        if not available:
            console.print("[red]No routes found.[/red]")
            sys.exit(1)
        name = click.prompt(
            "Select route to edit",
            type=click.Choice(available, case_sensitive=False),
        )
    
    path = routes_dir / f"{name}.yaml"
    if not path.exists():
        console.print(f"[red]Route config not found:[/red] {path}")
        sys.exit(1)

    with open(path) as f:
        data = yaml.safe_load(f)

    console.print(f"Editing [bold]{name}[/bold] (press Enter to keep current value)\n")
    data = _prompt_route(existing=data, config_dir=Path(config_dir))

    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    console.print(f"[green]Updated:[/green] {path}")
    console.print("\nRun [bold]vpnplane apply[/bold] to activate.")


@route.command("delete")
@click.argument("name", type=click.Choice([], case_sensitive=False), required=False)
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def route_delete(name: str, config_dir: str, yes: bool) -> None:
    """Delete a route config file."""
    _require_settings(Path(config_dir))
    config_path = Path(config_dir)
    routes_dir = config_path / "routes"
    
    # If name not provided, prompt user to choose from available routes
    if not name:
        available = _get_route_names(config_path)
        if not available:
            console.print("[red]No routes found.[/red]")
            sys.exit(1)
        name = click.prompt(
            "Select route to delete",
            type=click.Choice(available, case_sensitive=False),
        )
    
    path = routes_dir / f"{name}.yaml"
    if not path.exists():
        console.print(f"[red]Route config not found:[/red] {path}")
        sys.exit(1)

    if not yes and not click.confirm(f"Delete {path}?"):
        console.print("Aborted.")
        return

    path.unlink()
    console.print(f"[green]Deleted:[/green] {path}")
    console.print("\nRun [bold]vpnplane apply[/bold] to remove the rule.")


@route.command("list")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def route_list(config_dir: str) -> None:
    """List all route config files."""
    routes_dir = Path(config_dir) / "routes"
    if not routes_dir.is_dir():
        console.print("[dim]No routes directory found.[/dim]")
        return

    files = sorted(routes_dir.glob("*.yaml"))
    if not files:
        console.print("[dim]No route configs found.[/dim]")
        return

    t = Table(show_header=True, header_style="bold")
    t.add_column("File")
    t.add_column("Name")
    t.add_column("From → To")
    t.add_column("Protocol")
    t.add_column("Action")

    for f in files:
        try:
            data = yaml.safe_load(f.read_text()) or {}
            from_ = data.get("from", {})
            to = data.get("to", {})
            arrow = f"{from_.get('interface', '?')} → {to.get('interface', '?')}"
            bidir = " ↔" if data.get("bidirectional", True) else " →"
            t.add_row(
                f.name,
                data.get("name", ""),
                arrow + bidir,
                data.get("protocol", "any"),
                data.get("action", "allow"),
            )
        except Exception:
            t.add_row(f.name, "[red]Parse error[/red]", "", "", "")

    console.print(t)


# ---------------------------------------------------------------------------
# Interactive prompt helper
# ---------------------------------------------------------------------------

def _build_interface_map(
    config_dir: Path | None,
) -> tuple[dict[str, tuple[str, list[str]]], set[str], dict[str, list[str]]]:
    """Build maps from config for interface resolution.

    Returns:
        peer_map: unused (kept for API compatibility, always empty)
        valid_names: set of all valid tunnel names
        iface_subnets: best-effort subnet defaults per managed interface
    """
    peer_map: dict[str, tuple[str, list[str]]] = {}
    valid_names: set[str] = set()
    iface_subnets: dict[str, list[str]] = {}

    if config_dir is None:
        return peer_map, valid_names, iface_subnets

    try:
        tunnel_dicts, _ = load_all_configs(config_dir)
    except Exception as exc:
        console.print(
            "[yellow]Warning:[/yellow] could not read all tunnel configs while building "
            f"interface list: {exc}"
        )
        return peer_map, valid_names, iface_subnets

    for td in tunnel_dicts:
        tname = td.get("name", "")
        if tname:
            valid_names.add(tname)

        # Best-effort defaults for source subnets in route add.
        address = td.get("address")
        if tname and address:
            try:
                net = ipaddress.ip_interface(str(address)).network
                iface_subnets[tname] = [str(net)]
            except ValueError:
                pass

        # IPSec tunnels do not expose an interface CIDR; use local.subnets if present.
        local = td.get("local")
        if tname and isinstance(local, dict):
            subnets = local.get("subnets")
            if isinstance(subnets, list):
                valid = []
                for subnet in subnets:
                    try:
                        valid.append(str(ipaddress.ip_network(str(subnet), strict=False)))
                    except ValueError:
                        continue
                if valid and tname not in iface_subnets:
                    iface_subnets[tname] = valid

    return peer_map, valid_names, iface_subnets


def _detect_default_ipv4_interface() -> str | None:
    """Return the Linux default IPv4 egress interface (for internet routes)."""
    result = subprocess.run(
        ["ip", "-4", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" not in parts:
            continue
        idx = parts.index("dev")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _detect_default_ipv6_interface() -> str | None:
    """Return the Linux default IPv6 egress interface (for internet routes)."""
    result = subprocess.run(
        ["ip", "-6", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" not in parts:
            continue
        idx = parts.index("dev")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _get_interface_ipv4_subnets(iface: str) -> list[str]:
    """Return IPv4 subnets configured on a local interface."""
    result = subprocess.run(
        ["ip", "-o", "-f", "inet", "addr", "show", "dev", iface],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []

    subnets: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        idx = parts.index("inet")
        if idx + 1 >= len(parts):
            continue
        cidr = parts[idx + 1]
        try:
            net = ipaddress.ip_interface(cidr).network
        except ValueError:
            continue
        subnet = str(net)
        if subnet not in subnets:
            subnets.append(subnet)
    return subnets


def _get_interface_ipv6_subnets(iface: str) -> list[str]:
    """Return IPv6 global subnets configured on a local interface."""
    result = subprocess.run(
        ["ip", "-o", "-f", "inet6", "addr", "show", "dev", iface],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []

    subnets: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if "inet6" not in parts:
            continue
        idx = parts.index("inet6")
        if idx + 1 >= len(parts):
            continue
        cidr = parts[idx + 1]
        try:
            iface_addr = ipaddress.ip_interface(cidr)
            # Link-local addresses are not useful as internet egress source selectors.
            if iface_addr.ip.is_link_local:
                continue
            net = iface_addr.network
        except ValueError:
            continue
        subnet = str(net)
        if subnet not in subnets:
            subnets.append(subnet)
    return subnets


def _resolve_interface(
    raw: str,
    peer_map: dict[str, tuple[str, list[str]]],
) -> tuple[str, list[str]]:
    """Resolve a user-entered name to (os_interface, subnets).

    If *raw* is a WireGuard peer name, return the parent tunnel interface and
    the peer's allowed_ips as subnets.  Otherwise return the name as-is with
    no subnets (the user can fill them in manually).
    """
    if raw in peer_map:
        iface, allowed_ips = peer_map[raw]
        console.print(
            f"[dim]  Resolved peer '{raw}' → interface '{iface}', "
            f"subnets {allowed_ips}[/dim]"
        )
        return iface, allowed_ips
    return raw, []


_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _validate_name(value: str) -> str | None:
    """Return error message or None."""
    if not value:
        return "Name cannot be empty."
    if not _NAME_RE.match(value):
        return "Name must be 1-64 chars: letters, digits, hyphens, underscores."
    return None


def _validate_interface(value: str) -> str | None:
    if not value:
        return "Interface cannot be empty."
    return None


def _validate_subnets(value: str) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            return f"Invalid CIDR: {part!r}"
    return None


def _validate_ports(value: str, protocol: str) -> str | None:
    if not value:
        return None
    if protocol == "icmp":
        return "Ports cannot be specified with protocol 'icmp'."
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            p = int(part)
        except ValueError:
            return f"Not a valid port number: {part!r}"
        if not (1 <= p <= 65535):
            return f"Port {p} out of range (1-65535)."
    return None


def _prompt_validated(prompt_text: str, default: str, validator) -> str:
    """Prompt until the validator returns None (= valid)."""
    while True:
        value = _p(prompt_text, default)
        err = validator(value)
        if err is None:
            return value
        console.print(f"[red]Error:[/red] {err}")


def _prompt_route(
    existing: dict | None = None,
    config_dir: Path | None = None,
    is_new: bool = False,
) -> dict:
    e = existing or {}
    e_from = e.get("from", {})
    e_to = e.get("to", {})

    peer_map, valid_names, iface_subnets = _build_interface_map(config_dir)

    if valid_names:
        console.print(
            f"[dim]Available tunnels/interfaces: [bold]{', '.join(sorted(valid_names))}[/bold][/dim]"
        )

    name = _prompt_validated(
        "Route name (e.g. office-to-dc)", e.get("name", ""), _validate_name,
    )
    description = _p("Description (optional)", e.get("description", ""))

    # --- source ---
    while True:
        # Offer choice from valid_names if available, otherwise allow free text
        if valid_names:
            from_raw = click.prompt(
                "Source (tunnel name or physical NIC)",
                type=click.Choice(list(valid_names) + ["(other)"], case_sensitive=False),
                default=e_from.get("interface", ""),
            )
            if from_raw == "(other)":
                from_raw = _prompt_validated(
                    "Enter custom interface name",
                    "",
                    _validate_interface,
                )
        else:
            from_raw = _prompt_validated(
                "Source (tunnel name or physical NIC)",
                e_from.get("interface", ""),
                _validate_interface,
            )
        
        from_iface, from_auto_subnets = _resolve_interface(from_raw, peer_map)
        if from_raw not in valid_names and valid_names:
            console.print(
                f"[yellow]Warning:[/yellow] '{from_raw}' is not a known tunnel — "
                f"will be treated as a physical interface."
            )
            if not click.confirm("Continue?", default=True):
                continue
        break

    from_default = (
        e_from.get("subnets") and ",".join(e_from["subnets"])
        or ",".join(from_auto_subnets)
        or ",".join(iface_subnets.get(from_iface, []))
        or ""
    )

    internet_via_host = False
    if is_new:
        internet_via_host = click.confirm(
            "Route internet traffic through this host (roadwarrior)?",
            default=False,
        )

    if internet_via_host and not from_default:
        detected_from = _get_interface_ipv4_subnets(from_iface)
        detected_from += [s for s in _get_interface_ipv6_subnets(from_iface) if s not in detected_from]
        if detected_from:
            from_default = ",".join(detected_from)
            console.print(
                f"[dim]  Auto-detected source subnet(s) for '{from_iface}': {from_default}[/dim]"
            )

    if internet_via_host and from_default:
        from_subnets_raw = from_default
        console.print(f"[dim]  Using source subnet(s): {from_subnets_raw}[/dim]")
    else:
        from_subnets_raw = _prompt_validated(
            "Source subnets (comma-separated CIDRs, or blank for all)",
            from_default,
            _validate_subnets,
        )

    if internet_via_host:
        to_iface = _detect_default_ipv4_interface() or _detect_default_ipv6_interface()
        if not to_iface:
            console.print(
                "[yellow]Warning:[/yellow] Could not auto-detect default egress interface."
            )
            to_iface = _prompt_validated(
                "Destination WAN interface (physical NIC)",
                e_to.get("interface", "eth0"),
                _validate_interface,
            )
        to_subnets_raw = "0.0.0.0/0,::/0"
        console.print(
            f"[dim]  Internet route: destination interface '{to_iface}', subnets {to_subnets_raw}[/dim]"
        )
    else:
        # --- destination ---
        while True:
            # Offer choice from valid_names if available, otherwise allow free text
            if valid_names:
                to_raw = click.prompt(
                    "Destination (tunnel name or physical NIC)",
                    type=click.Choice(list(valid_names) + ["(other)"], case_sensitive=False),
                    default=e_to.get("interface", ""),
                )
                if to_raw == "(other)":
                    to_raw = _prompt_validated(
                        "Enter custom interface name",
                        "",
                        _validate_interface,
                    )
            else:
                to_raw = _prompt_validated(
                    "Destination (tunnel name or physical NIC)",
                    e_to.get("interface", ""),
                    _validate_interface,
                )

            to_iface, to_auto_subnets = _resolve_interface(to_raw, peer_map)

            # Check same-interface
            if to_iface == from_iface and to_raw != from_raw:
                console.print(
                    f"[dim]Note: both source and destination resolve to "
                    f"interface '{to_iface}'.[/dim]"
                )
            elif to_raw == from_raw:
                console.print(
                    "[red]Error:[/red] Source and destination cannot be the same."
                )
                continue

            if to_raw not in valid_names and valid_names:
                console.print(
                    f"[yellow]Warning:[/yellow] '{to_raw}' is not a known tunnel — "
                    f"will be treated as a physical interface."
                )
                if not click.confirm("Continue?", default=True):
                    continue
            break

        to_default = (
            e_to.get("subnets") and ",".join(e_to["subnets"])
            or ",".join(to_auto_subnets)
            or ""
        )
        to_subnets_raw = _prompt_validated(
            "Destination subnets (comma-separated CIDRs, or blank for all)",
            to_default,
            _validate_subnets,
        )

    # --- protocol & ports ---
    protocol = click.prompt(
        "Protocol", type=click.Choice(["any", "tcp", "udp", "icmp"]),
        default=e.get("protocol", "any"),
    )
    ports_default = (
        e.get("ports") and ",".join(str(p) for p in e["ports"]) or ""
    )
    ports_raw = _prompt_validated(
        "Destination ports (comma-separated, or blank for all)",
        ports_default,
        lambda v: _validate_ports(v, protocol),
    )

    bidirectional = click.confirm("Bidirectional?", default=e.get("bidirectional", True))
    action = click.prompt(
        "Action", type=click.Choice(["allow", "deny"]), default=e.get("action", "allow")
    )

    return {
        "name": name,
        "description": description,
        "from": {
            "interface": from_iface,
            "subnets": [s.strip() for s in from_subnets_raw.split(",") if s.strip()],
        },
        "to": {
            "interface": to_iface,
            "subnets": [s.strip() for s in to_subnets_raw.split(",") if s.strip()],
        },
        "protocol": protocol,
        "ports": [int(p.strip()) for p in ports_raw.split(",") if p.strip()],
        "bidirectional": bidirectional,
        "action": action,
    }
