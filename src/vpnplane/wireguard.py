"""WireGuard tunnel lifecycle management."""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import tempfile
from pathlib import Path
from textwrap import dedent

from jinja2 import Environment, Undefined

from .models import WireGuardTunnel
from .utils import WG_KEY_DIR, console, derive_public_key, ensure_psk, read_key_file, run

MANAGED_HEADER = "# managed-by: vpnplane"
WG_CONF_DIR = Path("/etc/wireguard")

# ---------------------------------------------------------------------------
# Jinja2 templates
# ---------------------------------------------------------------------------

_WG_CONF_TEMPLATE = """\
{{ managed_header }}
# DO NOT EDIT MANUALLY — changes will be overwritten by vpnplane

[Interface]
Address = {{ interface_address }}
PrivateKey = {{ private_key }}
{% if tunnel.listen_port -%}
ListenPort = {{ tunnel.listen_port }}
{% endif -%}
{% if tunnel.dns -%}
DNS = {{ tunnel.dns | join(', ') }}
{% endif -%}
MTU = {{ tunnel.mtu }}
{% if tunnel.table != 'auto' -%}
Table = {{ tunnel.table }}
{% endif -%}
{% for cmd in tunnel.post_up -%}
PostUp = {{ cmd }}
{% endfor -%}
{% for cmd in tunnel.post_down -%}
PostDown = {{ cmd }}
{% endfor %}
{% if peer %}
[Peer]
# {{ peer.name }}
PublicKey = {{ peer.public_key }}
{% if psk -%}
PresharedKey = {{ psk }}
{% endif -%}
{% if peer.endpoint -%}
Endpoint = {{ peer.endpoint }}
{% endif -%}
AllowedIPs = {{ peer.allowed_ips | join(', ') }}
{% if peer.persistent_keepalive -%}
PersistentKeepalive = {{ peer.persistent_keepalive }}
{% endif %}
{% endif %}"""

_PEER_CONF_TEMPLATE = """\
# vpnplane export — {{ tunnel.name }} / {{ peer.name }}
{% if private_key_placeholder %}# Replace PRIVATE_KEY_PLACEHOLDER with the output of: wg genkey
{% endif %}
[Interface]
# PublicKey = {{ peer_pubkey }}
Address = {{ peer_address }}
PrivateKey = {{ peer_privkey }}
{% if tunnel.dns -%}
DNS = {{ tunnel.dns | join(', ') }}
{% endif -%}
MTU = {{ tunnel.mtu }}

[Peer]
# {{ tunnel.name }} (server)
PublicKey = {{ server_pubkey }}
{% if psk -%}
PresharedKey = {{ psk }}
{% endif -%}
{% if server_endpoint -%}
Endpoint = {{ server_endpoint }}
{% endif -%}
AllowedIPs = {{ allowed_ips | join(', ') }}
{% if peer.endpoint is none -%}
PersistentKeepalive = 25
{% endif %}"""

_env = Environment(keep_trailing_newline=True, undefined=Undefined)


# ---------------------------------------------------------------------------
# Server config rendering
# ---------------------------------------------------------------------------

def _render_conf(tunnel: WireGuardTunnel, dry_run: bool = False) -> str:
    private_key = read_key_file(tunnel.private_key)
    interface_address = tunnel.interface_address()

    psk: str | None = None
    if tunnel.peer is not None:
        peer = tunnel.peer
        if peer.preshared_key == "auto":
            psk = ensure_psk(tunnel.name, dry_run=dry_run)
        elif peer.preshared_key is None:
            psk = None
        else:
            psk = read_key_file(peer.preshared_key)

    tmpl = _env.from_string(_WG_CONF_TEMPLATE)
    rendered = tmpl.render(
        managed_header=MANAGED_HEADER,
        tunnel=tunnel,
        interface_address=interface_address,
        private_key=private_key,
        peer=tunnel.peer,
        psk=psk,
    )

    rendered = re.sub(r"\n{3,}", "\n\n", rendered)
    return rendered.strip() + "\n"


# ---------------------------------------------------------------------------
# Current state detection
# ---------------------------------------------------------------------------

def _managed_conf_names() -> set[str]:
    """Return names of WireGuard interfaces whose .conf files are managed by us."""
    names: list[str] = []
    for conf in WG_CONF_DIR.glob("*.conf"):
        try:
            first_line = conf.read_text().split("\n", 1)[0].strip()
            if first_line == MANAGED_HEADER:
                names.append(conf.stem)
        except OSError:
            pass
    return set(names)


def _active_interface_names() -> set[str]:
    """Return names of WireGuard interfaces currently up (from `wg show interfaces`)."""
    try:
        result = subprocess.run(
            ["wg", "show", "interfaces"], capture_output=True, text=True
        )
        return set(result.stdout.split())
    except FileNotFoundError:
        return set()


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def apply_wireguard(tunnels: list[WireGuardTunnel], dry_run: bool = False) -> None:
    """
    Reconcile the desired WireGuard tunnel list with the current system state.
    Creates, updates, or removes managed interfaces as needed.
    """
    desired = {t.name: t for t in tunnels}
    managed = _managed_conf_names()
    active = _active_interface_names()

    for name, tunnel in desired.items():
        conf_path = WG_CONF_DIR / f"{name}.conf"
        desired_conf = _render_conf(tunnel, dry_run=dry_run)
        existing_conf = conf_path.read_text() if conf_path.exists() else None

        if existing_conf is None:
            _create_tunnel(tunnel, conf_path, desired_conf, dry_run)
        elif desired_conf != existing_conf:
            _update_tunnel(tunnel, conf_path, desired_conf, existing_conf, active, dry_run)
        else:
            console.print(f"[dim] {name}: no changes[/dim]")

    for name in managed - set(desired.keys()):
        _remove_tunnel(name, dry_run)


def disable_wireguard(desired_tunnel_names: set[str], dry_run: bool = False) -> None:
    """Disable managed WireGuard tunnels.

    Keep managed .conf files for tunnels that still exist in YAML configs.
    If a managed tunnel is no longer present in YAML, remove its .conf too.
    """
    managed = _managed_conf_names()
    if not managed:
        console.print("[dim]  wireguard: no managed tunnels to disable[/dim]")
        return

    for name in sorted(managed):
        keep_conf = name in desired_tunnel_names
        if keep_conf:
            console.print(f"[yellow]~ Disabling tunnel runtime:[/yellow] {name}")
            run(["systemctl", "disable", "--now", f"wg-quick@{name}"], dry_run=dry_run)
        else:
            _remove_tunnel(name, dry_run)


def _create_tunnel(
    tunnel: WireGuardTunnel,
    conf_path: Path,
    conf_content: str,
    dry_run: bool,
) -> None:
    console.print(f"[green]+ Creating tunnel:[/green] {tunnel.name}")
    _write_conf(conf_path, conf_content, dry_run)
    run(["systemctl", "enable", "--now", f"wg-quick@{tunnel.name}"], dry_run=dry_run)


def _update_tunnel(
    tunnel: WireGuardTunnel,
    conf_path: Path,
    desired_conf: str,
    existing_conf: str,
    active: set[str],
    dry_run: bool,
) -> None:
    console.print(f"[yellow]~ Updating tunnel:[/yellow] {tunnel.name}")
    _write_conf(conf_path, desired_conf, dry_run)

    if tunnel.name not in active:
        run(["systemctl", "enable", "--now", f"wg-quick@{tunnel.name}"], dry_run=dry_run)
        return

    if _only_peers_changed(existing_conf, desired_conf):
        _syncconf(tunnel.name, dry_run)
    else:
        run(["systemctl", "restart", f"wg-quick@{tunnel.name}"], dry_run=dry_run)


def _remove_tunnel(name: str, dry_run: bool) -> None:
    console.print(f"[red]- Removing tunnel:[/red] {name}")
    run(["systemctl", "disable", "--now", f"wg-quick@{name}"], dry_run=dry_run)
    conf_path = WG_CONF_DIR / f"{name}.conf"
    if not dry_run:
        conf_path.unlink(missing_ok=True)
    else:
        console.print(f"[dim]DRY-RUN:[/dim] would delete {conf_path}")


def _write_conf(path: Path, content: str, dry_run: bool) -> None:
    if dry_run:
        console.print(f"[dim]DRY-RUN:[/dim] would write {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o600)


def _syncconf(name: str, dry_run: bool) -> None:
    """Hot-reload peer config without taking the interface down."""
    conf_path = WG_CONF_DIR / f"{name}.conf"
    if dry_run:
        console.print(f"[dim]DRY-RUN:[/dim] wg syncconf {name} (wg-quick strip output)")
        return
    strip_result = subprocess.run(
        ["wg-quick", "strip", str(conf_path)], capture_output=True, text=True
    )
    if strip_result.returncode != 0:
        raise RuntimeError(f"wg-quick strip failed: {strip_result.stderr}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tmp:
        tmp.write(strip_result.stdout)
        tmp_path = tmp.name
    try:
        run(["wg", "syncconf", name, tmp_path])
    finally:
        os.unlink(tmp_path)


def _only_peers_changed(old: str, new: str) -> bool:
    """Heuristic: returns True if only [Peer] sections changed, not [Interface]."""
    def extract_interface_block(conf: str) -> str:
        lines = []
        in_interface = False
        for line in conf.splitlines():
            stripped = line.strip()
            if stripped == "[Interface]":
                in_interface = True
            elif stripped.startswith("[") and stripped.endswith("]"):
                in_interface = False
            if in_interface:
                lines.append(line)
        return "\n".join(lines)

    return extract_interface_block(old) == extract_interface_block(new)


# ---------------------------------------------------------------------------
# Export (generate peer-side config)
# ---------------------------------------------------------------------------

def export_peer_config(
    tunnel: WireGuardTunnel,
    server_endpoint: str | None = None,
    allowed_ips: list[str] | None = None,
) -> str:
    """Generate a WireGuard config file to send to the tunnel's peer."""
    peer = tunnel.peer
    if peer is None:
        raise ValueError(f"Tunnel {tunnel.name!r} has no peer configured")

    server_privkey = read_key_file(tunnel.private_key)
    server_pubkey = derive_public_key(server_privkey)

    # PSK — auto-generate if missing
    psk: str | None = None
    if peer.preshared_key == "auto":
        psk = ensure_psk(tunnel.name)
    elif peer.preshared_key is not None:
        psk = read_key_file(peer.preshared_key)

    if tunnel.fritzbox:
        if not tunnel.fritzbox_ip:
            raise ValueError(
                f"Tunnel {tunnel.name!r} is fritzbox-enabled but has no fritzbox_ip configured"
            )
        # FritzBox exports use the FritzBox gateway IP as peer interface address.
        peer_address = tunnel.fritzbox_ip
    else:
        # Peer's tunnel address: first /32 or /128 in allowed_ips
        peer_address = next(
            (ip for ip in peer.allowed_ips if ip.endswith("/32") or ip.endswith("/128")),
            None,
        )
        if peer_address is None:
            # Fallback: use second host in tunnel subnet (server takes first)
            tunnel_iface = ipaddress.ip_interface(tunnel.interface_address())
            hosts = list(tunnel_iface.network.hosts())
            chosen = hosts[1] if len(hosts) > 1 else hosts[-1]
            peer_address = f"{chosen}/32"

    # What the peer should route via us
    if allowed_ips is None:
        tunnel_network = str(tunnel.interface_network())
        allowed_ips = [tunnel_network]

    # Use stored peer private key if it was auto-generated during tunnel add
    peer_privkey_path = WG_KEY_DIR / f"{tunnel.name}-peer.key"
    if peer_privkey_path.exists():
        peer_privkey = read_key_file(peer_privkey_path)
        private_key_placeholder = False
    else:
        peer_privkey = "PRIVATE_KEY_PLACEHOLDER"
        private_key_placeholder = True

    tmpl = _env.from_string(_PEER_CONF_TEMPLATE)
    rendered = tmpl.render(
        tunnel=tunnel,
        peer=peer,
        peer_address=peer_address,
        peer_pubkey=peer.public_key,
        server_pubkey=server_pubkey,
        psk=psk,
        server_endpoint=server_endpoint,
        allowed_ips=allowed_ips,
        peer_privkey=peer_privkey,
        private_key_placeholder=private_key_placeholder,
    )

    rendered = re.sub(r"\n{3,}", "\n\n", rendered)
    return rendered.strip() + "\n"


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_wireguard_status() -> list[dict]:
    """
    Return status info for all WireGuard interfaces.
    Each dict: {
      name, managed, active, address?, listen_port?,
      peers: [{public_key, public_key_short, endpoint, allowed_ips, handshake,
               rx_bytes, tx_bytes, persistent_keepalive}]
    }
    """
    managed = _managed_conf_names()
    active = _active_interface_names()

    statuses = []
    for name in sorted(managed | active):
        info: dict = {"name": name, "managed": name in managed, "active": name in active}

        conf_path = WG_CONF_DIR / f"{name}.conf"
        if conf_path.exists():
            for line in conf_path.read_text().splitlines():
                if line.startswith("Address"):
                    info["address"] = line.split("=", 1)[1].strip()
                if line.startswith("ListenPort"):
                    info["listen_port"] = line.split("=", 1)[1].strip()

        info["peers"] = _parse_wg_show(name) if name in active else []
        statuses.append(info)

    return statuses


def _parse_wg_show(interface: str) -> list[dict]:
    """Parse `wg show dump` output into peer dicts."""
    import time

    try:
        result = subprocess.run(
            ["wg", "show", interface, "dump"], capture_output=True, text=True
        )
    except FileNotFoundError:
        return []

    peers = []
    lines = result.stdout.strip().splitlines()
    for line in lines[1:]:  # skip interface line
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pubkey, _, endpoint, allowed_ips, latest_handshake, rx_bytes, tx_bytes, keepalive = parts[:8]
        handshake_ago: str | None = None
        rx = 0
        tx = 0
        try:
            ts = int(latest_handshake)
            if ts > 0:
                delta = int(time.time()) - ts
                if delta < 60:
                    handshake_ago = f"{delta}s ago"
                elif delta < 3600:
                    handshake_ago = f"{delta // 60}m ago"
                else:
                    handshake_ago = f"{delta // 3600}h ago"
        except (ValueError, TypeError):
            pass

        try:
            rx = max(0, int(rx_bytes))
            tx = max(0, int(tx_bytes))
        except (ValueError, TypeError):
            rx = 0
            tx = 0

        peers.append({
            "public_key": pubkey,
            "public_key_short": pubkey[:12] + "...",
            "endpoint": endpoint if endpoint != "(none)" else None,
            "allowed_ips": allowed_ips,
            "handshake": handshake_ago,
            "rx_bytes": rx,
            "tx_bytes": tx,
            "persistent_keepalive": keepalive if keepalive and keepalive != "off" else None,
        })
    return peers
