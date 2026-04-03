"""First-run setup wizard — creates settings.yaml with required values."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import click

from ..utils import (
    DEFAULT_CONFIG_DIR,
    _SETTINGS_DEFAULTS,
    console,
    save_settings,
    settings_exist,
)
from . import cli


_HOST_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


def _prompt_server_address(default: str | None) -> str:
    """Prompt until a valid hostname or IP address is provided."""
    while True:
        raw = click.prompt("Server public IP or hostname", default=default or None).strip()
        if not raw:
            console.print("[red]Error:[/red] server_address cannot be empty.")
            continue

        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            pass

        if _HOST_RE.match(raw) and "." in raw and ".." not in raw:
            return raw

        console.print(
            "[red]Error:[/red] enter a valid IP address or hostname (example: vpn.example.com)."
        )


def _prompt_start_network(default: str) -> str:
    """Prompt until a valid start network CIDR is provided."""
    while True:
        raw = click.prompt(
            "WireGuard tunnel subnet (auto-allocation start block)",
            default=default,
        ).strip()
        try:
            net = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            continue

        if net.version != 4:
            console.print("[red]Error:[/red] start network must be IPv4 for current workflow.")
            continue
        if net.prefixlen < 16 or net.prefixlen > 30:
            console.print("[red]Error:[/red] use a prefix between /16 and /30.")
            continue
        return raw


@cli.command("init")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def init_cmd(config_dir: str) -> None:
    """Initialize vpnplane settings (first-run wizard)."""
    cfg = Path(config_dir)

    if settings_exist(cfg):
        if not click.confirm(
            f"Settings already exist at {cfg / 'settings.yaml'}. Overwrite?"
        ):
            console.print("Aborted.")
            return

    console.print("[bold]vpnplane setup[/bold]\n")

    server_address = _prompt_server_address(_SETTINGS_DEFAULTS["server_address"] or None)

    wg_defaults = _SETTINGS_DEFAULTS["wireguard"]
    listen_port = click.prompt(
        "Default WireGuard listen port",
        default=wg_defaults["default_listen_port"],
        type=click.IntRange(1, 65535),
    )
    start_network = _prompt_start_network(wg_defaults["start_network"])

    settings = {
        "server_address": server_address,
        "wireguard": {
            "default_listen_port": listen_port,
            "start_network": start_network,
        },
    }

    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "tunnels").mkdir(exist_ok=True)
    (cfg / "routes").mkdir(exist_ok=True)
    path = save_settings(cfg, settings)
    console.print(f"\n[green]Settings saved:[/green] {path}")
    console.print("\nNext steps:")
    console.print("  sudo vpnplane tunnel add")
    console.print("  sudo vpnplane apply")
