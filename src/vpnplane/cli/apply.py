"""apply, check, status, and keygen commands."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from ..firewall import (
    apply_firewall,
    cleanup_firewall_managed_state,
    reset_firewall_managed_state,
)
from ..ipsec import apply_ipsec, disable_ipsec
from ..utils import (
    DEFAULT_CONFIG_DIR,
    WG_KEY_DIR,
    check_required_tools,
    console,
    generate_wireguard_keypair,
    require_root,
)
from ..wireguard import apply_wireguard
from ..wireguard import disable_wireguard
from . import _load_and_validate, cli


@cli.command()
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              help="Directory containing tunnels/ and routes/ subdirs.")
@click.option("--dry-run", is_flag=True, help="Print what would change without applying.")
@click.option("--tunnels-only", is_flag=True, help="Only configure tunnels, skip routes.")
@click.option("--routes-only", is_flag=True, help="Only configure routes, skip tunnels.")
def apply(config_dir: str, dry_run: bool, tunnels_only: bool, routes_only: bool) -> None:
    """Apply tunnel and route configuration to the system."""
    if tunnels_only and routes_only:
        raise click.UsageError("--tunnels-only and --routes-only cannot be used together.")

    require_root()
    check_required_tools()

    cfg = Path(config_dir)
    if not cfg.is_dir():
        console.print(f"[red]Config directory not found:[/red] {cfg}")
        sys.exit(1)

    wg_tunnels, ipsec_tunnels, routes = _load_and_validate(cfg)
    if ipsec_tunnels:
        check_required_tools(include_ipsec=True)

    if dry_run:
        console.print("[bold yellow]DRY-RUN mode — no changes will be made[/bold yellow]\n")

    try:
        if not routes_only:
            console.print("[bold]Applying tunnels...[/bold]")
            apply_wireguard(wg_tunnels, dry_run=dry_run)
            if ipsec_tunnels:
                apply_ipsec(ipsec_tunnels, dry_run=dry_run)

        if not tunnels_only:
            console.print("\n[bold]Applying firewall rules...[/bold]")
            reset_firewall_managed_state(dry_run=dry_run)
            apply_firewall(routes, wg_tunnels, ipsec_tunnels, dry_run=dry_run)
    except Exception as exc:
        console.print(f"[bold red]Apply failed:[/bold red] {exc}")
        sys.exit(1)

    if not dry_run:
        console.print("\n[bold green]Done.[/bold green]")


@cli.command()
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              help="Directory containing tunnels/ and routes/ subdirs.")
@click.option("--dry-run", is_flag=True, help="Print what would be removed without changing state.")
def disable(config_dir: str, dry_run: bool) -> None:
    """Disable and clean all managed runtime state created by apply."""
    require_root()
    check_required_tools()

    cfg = Path(config_dir)
    desired_wg_names: set[str] = set()
    desired_ipsec_names: set[str] = set()

    if cfg.is_dir():
        wg_tunnels, ipsec_tunnels, _ = _load_and_validate(cfg)
        desired_wg_names = {t.name for t in wg_tunnels}
        desired_ipsec_names = {t.name for t in ipsec_tunnels}

    if dry_run:
        console.print("[bold yellow]DRY-RUN mode — no changes will be made[/bold yellow]\n")

    try:
        console.print("[bold]Disabling WireGuard runtime...[/bold]")
        disable_wireguard(desired_wg_names, dry_run=dry_run)

        console.print("\n[bold]Disabling IPSec runtime...[/bold]")
        disable_ipsec(desired_ipsec_names, dry_run=dry_run)

        console.print("\n[bold]Removing managed firewall state...[/bold]")
        cleanup_firewall_managed_state(dry_run=dry_run)
    except Exception as exc:
        console.print(f"[bold red]Disable failed:[/bold red] {exc}")
        sys.exit(1)

    if not dry_run:
        console.print("\n[bold green]Disable complete.[/bold green]")


@cli.command()
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True)
def check(config_dir: str) -> None:
    """Validate configuration files without applying any changes."""
    cfg = Path(config_dir)
    if not cfg.is_dir():
        console.print(f"[red]Config directory not found:[/red] {cfg}")
        sys.exit(1)

    wg_tunnels, ipsec_tunnels, routes = _load_and_validate(cfg)
    total = len(wg_tunnels) + len(ipsec_tunnels)
    console.print(
        f"[bold green]Config OK[/bold green] — "
        f"{total} tunnel(s), {len(routes)} route(s)"
    )


@cli.command()
@click.option("--name", default=None, help="Interface name to use for the key file path.")
@click.option("--save", is_flag=True, help="Save private key to WG_KEY_DIR/<name>.key")
def keygen(name: str | None, save: bool) -> None:
    """Generate a WireGuard keypair and print the public key."""
    priv, pub = generate_wireguard_keypair()
    console.print(f"[bold]Public key:[/bold]  {pub}")

    if save:
        if not name:
            console.print("[red]--name is required when using --save[/red]")
            sys.exit(1)
        require_root()
        key_path = WG_KEY_DIR / f"{name}.key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(priv + "\n")
        key_path.chmod(0o600)
        console.print(f"[green]Private key saved to:[/green] {key_path}")
    else:
        console.print(f"[dim]Private key:[/dim]  {priv}")
        console.print(
            "\n[dim]Tip: use --save --name <interface> to save the private key securely.[/dim]"
        )
