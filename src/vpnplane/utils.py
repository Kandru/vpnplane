"""Subprocess helpers, key generation, tool availability checks."""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml
from rich.console import Console

console = Console()

# ---------------------------------------------------------------------------
# Paths and defaults
# ---------------------------------------------------------------------------

WG_KEY_DIR = Path("/etc/wireguard/keys")
DEFAULT_CONFIG_DIR = Path("/etc/vpnplane")

# ---------------------------------------------------------------------------
# Required system tools
# ---------------------------------------------------------------------------

REQUIRED_TOOLS: dict[str, str] = {
    "wg": "wireguard-tools",
    "wg-quick": "wireguard-tools",
    "systemctl": "systemd",
    "iptables": "iptables",
    "ip6tables": "iptables",
    "nft": "nftables",
    "sysctl": "procps",
    "ip": "iproute2",
}

OPTIONAL_TOOLS: dict[str, str] = {
    "swanctl": "strongswan-swanctl",
}


def check_required_tools(include_ipsec: bool = False) -> None:
    """Check required binaries. Prints missing tools with apt hints and exits."""
    tools = dict(REQUIRED_TOOLS)
    if include_ipsec:
        tools.update(OPTIONAL_TOOLS)

    missing = [(bin_, pkg) for bin_, pkg in tools.items() if not shutil.which(bin_)]
    if missing:
        console.print("[bold red]Missing required tools:[/bold red]")
        for bin_, pkg in missing:
            console.print(f"  [yellow]{bin_}[/yellow]  →  sudo apt install {pkg}")
        sys.exit(1)


def require_root() -> None:
    """Exit with a clear message if not running as root."""
    if os.getuid() != 0:
        console.print("[bold red]Error:[/bold red] This command must be run as root.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Subprocess wrapper
# ---------------------------------------------------------------------------

def run(
    cmd: list[str],
    *,
    dry_run: bool = False,
    check: bool = True,
    capture: bool = False,
    input: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command with logging and dry-run support."""
    if dry_run:
        console.print(f"[dim]DRY-RUN:[/dim] {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        input=input,
    )
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(
            f"Command failed (exit {result.returncode}): {' '.join(cmd)}\n"
            f"stderr: {stderr}"
        )
    return result


# ---------------------------------------------------------------------------
# WireGuard key generation
# ---------------------------------------------------------------------------

def generate_wireguard_keypair() -> tuple[str, str]:
    """Generate a WireGuard private/public key pair. Returns (private, public)."""
    priv = run(["wg", "genkey"], capture=True).stdout.strip()
    pub = subprocess.run(
        ["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True
    ).stdout.strip()
    return priv, pub


def generate_preshared_key() -> str:
    """Generate a WireGuard preshared key."""
    return run(["wg", "genpsk"], capture=True).stdout.strip()


def derive_public_key(private_key: str) -> str:
    """Derive the public key from a private key string."""
    result = subprocess.run(
        ["wg", "pubkey"], input=private_key, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def read_key_file(path: Path) -> str:
    """Read a single-line key file, stripping whitespace."""
    return path.read_text().strip()


def ensure_psk(tunnel_name: str, dry_run: bool = False) -> str:
    """
    Return the preshared key for a tunnel.
    Generates and stores one at WG_KEY_DIR/<tunnel>.psk if it doesn't exist.
    """
    psk_path = WG_KEY_DIR / f"{tunnel_name}.psk"
    if psk_path.exists():
        return read_key_file(psk_path)

    if dry_run:
        console.print(f"[dim]DRY-RUN:[/dim] would generate PSK → {psk_path}")
        return "<psk-would-be-generated>"

    psk = generate_preshared_key()
    psk_path.parent.mkdir(parents=True, exist_ok=True)
    psk_path.write_text(psk + "\n")
    psk_path.chmod(0o600)
    console.print(f"[green]Generated PSK:[/green] {psk_path}")
    return psk


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

def load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_all_configs(
    config_dir: Path,
) -> tuple[list[dict], list[dict]]:
    """
    Read all *.yaml files from <config_dir>/tunnels/ and <config_dir>/routes/.
    Returns (tunnel_dicts, route_dicts).
    """
    tunnels_dir = config_dir / "tunnels"
    routes_dir = config_dir / "routes"

    tunnel_dicts: list[dict] = []
    route_dicts: list[dict] = []

    if tunnels_dir.is_dir():
        for p in sorted(tunnels_dir.glob("*.yaml")):
            tunnel_dicts.append(load_yaml(p))

    if routes_dir.is_dir():
        for p in sorted(routes_dir.glob("*.yaml")):
            route_dicts.append(load_yaml(p))

    return tunnel_dicts, route_dicts


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

SETTINGS_FILENAME = "settings.yaml"
_SETTINGS_DEFAULTS: dict = {
    "server_address": "",
    "wireguard": {
        "default_listen_port": 51820,
        "start_network": "10.100.0.0/30",
    },
}


def load_settings(config_dir: Path) -> dict:
    """Load settings.yaml from config_dir, falling back to built-in defaults."""
    import copy
    path = config_dir / SETTINGS_FILENAME
    file_data = load_yaml(path) if path.exists() else {}
    merged = copy.deepcopy(_SETTINGS_DEFAULTS)
    for key, default in _SETTINGS_DEFAULTS.items():
        if key not in file_data:
            continue
        if isinstance(default, dict):
            merged[key].update(file_data[key])
        else:
            merged[key] = file_data[key]
    return merged


def settings_exist(config_dir: Path) -> bool:
    """Return True if settings.yaml exists in config_dir."""
    return (config_dir / SETTINGS_FILENAME).exists()


def save_settings(config_dir: Path, settings: dict) -> Path:
    """Write settings dict to settings.yaml."""
    path = config_dir / SETTINGS_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(settings, default_flow_style=False, sort_keys=False))
    path.chmod(0o600)
    return path


def _collect_used_ips(config_dir: Path) -> set:
    """Return the set of host IPs already assigned in tunnels/*.yaml (raw YAML, no validation)."""
    used: set = set()
    tunnels_dir = config_dir / "tunnels"
    if not tunnels_dir.is_dir():
        return used
    for p in tunnels_dir.glob("*.yaml"):
        try:
            data = yaml.safe_load(p.read_text()) or {}
            addr = data.get("address")
            if addr:
                used.add(ipaddress.ip_interface(addr).ip)
        except Exception:
            pass
    return used


def next_free_tunnel_addr(config_dir: Path) -> str:
    """
    Find the next unallocated server-side tunnel address.

    Scans tunnels/*.yaml for IPs already in use, then returns the first free
    block starting from settings.yaml's ``start_network``.
    Block size matches the prefix in start_network (default /24).

    Returns a CIDR string for the server, e.g. "10.100.0.1/24".
    """
    cfg = load_settings(config_dir)
    start_net = ipaddress.ip_network(cfg["wireguard"]["start_network"], strict=True)
    used_ips = _collect_used_ips(config_dir)

    # Limit search to the /16 that contains start_network
    b = start_net.network_address.packed
    containing_16 = ipaddress.ip_network(f"{b[0]}.{b[1]}.0.0/16")
    step = start_net.num_addresses
    current = int(start_net.network_address)
    end = int(containing_16.broadcast_address) + 1

    while current < end:
        net = ipaddress.ip_network(
            f"{ipaddress.ip_address(current)}/{start_net.prefixlen}"
        )
        if not any(ip in net for ip in used_ips):
            return f"{list(net.hosts())[0]}/{start_net.prefixlen}"
        current += step

    raise RuntimeError(
        f"No free /{start_net.prefixlen} blocks found in {containing_16}"
    )


def next_free_peer_ip(tunnel_addr: str, existing_peers: list[dict] | None = None) -> str:
    """
    Given the tunnel server address (e.g. "10.100.0.1/24"), return the peer IP as a /32.
    With one peer per tunnel, this is always the second host in the subnet.
    """
    iface = ipaddress.ip_interface(tunnel_addr)
    net = iface.network
    used = {iface.ip}
    if existing_peers:
        for peer in existing_peers:
            for cidr in peer.get("allowed_ips", []):
                try:
                    used.add(ipaddress.ip_interface(cidr).ip)
                except Exception:
                    pass
    for host in net.hosts():
        if host not in used:
            return f"{host}/32"
    raise RuntimeError(f"No free peer IPs available in {net}")


def _collect_used_ports(config_dir: Path) -> set[int]:
    """Return the set of listen_port values already used in tunnels/*.yaml."""
    used: set[int] = set()
    tunnels_dir = config_dir / "tunnels"
    if not tunnels_dir.is_dir():
        return used
    for p in tunnels_dir.glob("*.yaml"):
        try:
            data = yaml.safe_load(p.read_text()) or {}
            port = data.get("listen_port")
            if isinstance(port, int):
                used.add(port)
        except Exception:
            pass
    return used


def next_free_port(config_dir: Path) -> int:
    """
    Find the next unallocated WireGuard listen port.

    Scans tunnels/*.yaml for used listen_port values, then returns the first
    free port at or above settings.yaml's ``default_listen_port`` (default 51820).
    """
    cfg = load_settings(config_dir)
    start = int(cfg["wireguard"]["default_listen_port"])
    used = _collect_used_ports(config_dir)
    port = start
    while port <= 65535:
        if port not in used:
            return port
        port += 1
    raise RuntimeError(f"No free ports found starting from {start}")


# ---------------------------------------------------------------------------
# Display formatting helpers
# ---------------------------------------------------------------------------

def format_bytes(value: int) -> str:
    """Format bytes with automatic unit scaling."""
    if value < 0:
        value = 0

    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    unit_idx = 0
    while size >= 1024.0 and unit_idx < len(units) - 1:
        size /= 1024.0
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(size)} {units[unit_idx]}"
    return f"{size:.1f} {units[unit_idx]}"


def format_speed(bytes_per_sec: float) -> str:
    """Format throughput as B/s, KB/s, MB/s, or GB/s depending on magnitude."""
    if bytes_per_sec < 0:
        bytes_per_sec = 0.0

    units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
    speed = float(bytes_per_sec)
    unit_idx = 0
    while speed >= 1024.0 and unit_idx < len(units) - 1:
        speed /= 1024.0
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(speed)} {units[unit_idx]}"
    return f"{speed:.1f} {units[unit_idx]}"
