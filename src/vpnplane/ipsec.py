"""IPSec/strongSwan tunnel lifecycle management via swanctl."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from jinja2 import Environment, Undefined

from .models import IPSecTunnel
from .utils import console, run

MANAGED_HEADER = "# managed-by: vpnplane"
SWANCTL_CONF_DIR = Path("/etc/swanctl/conf.d")
SWANCTL_SECRETS_DIR = Path("/etc/swanctl/ipsec-secrets")

_env = Environment(keep_trailing_newline=True, undefined=Undefined)

# ---------------------------------------------------------------------------
# Config template (swanctl / VICI format)
# ---------------------------------------------------------------------------

_SWANCTL_TEMPLATE = """\
{{ managed_header }}
# DO NOT EDIT MANUALLY — changes will be overwritten by vpnplane

connections {
    {{ tunnel.name }} {
        version = {{ tunnel.ike.version }}
        local_addrs = {{ tunnel.local.address }}
        remote_addrs = {{ tunnel.remote.address }}
        proposals = {{ tunnel.ike.encryption }}-{{ tunnel.ike.integrity }}-{{ tunnel.ike.dh_group }}
        dpd_delay = {{ tunnel.esp.dpd_delay }}s

        local {
            auth = {{ tunnel.local.auth.method }}
            id = {{ tunnel.local.address }}
        }
        remote {
            auth = {{ tunnel.remote.auth.method }}
            id = {{ tunnel.remote.address }}
        }
        children {
            {{ tunnel.name }}-child {
                local_ts = {{ tunnel.local.subnets | join(', ') }}
                remote_ts = {{ tunnel.remote.subnets | join(', ') }}
                esp_proposals = {{ tunnel.esp.encryption }}-{{ tunnel.esp.integrity }}
                life_time = {{ tunnel.esp.lifetime }}s
                dpd_action = {{ tunnel.esp.dpd_action }}
                {% if tunnel.auto_start -%}
                start_action = start
                {% endif -%}
            }
        }
    }
}

secrets {
    ike-{{ tunnel.name }} {
        id = {{ tunnel.remote.address }}
        secret = include {{ secrets_dir }}/{{ tunnel.name }}.psk
    }
}
"""


def _render_conf(tunnel: IPSecTunnel) -> str:
    tmpl = _env.from_string(_SWANCTL_TEMPLATE)
    rendered = tmpl.render(
        managed_header=MANAGED_HEADER,
        tunnel=tunnel,
        secrets_dir=SWANCTL_SECRETS_DIR,
    )
    rendered = re.sub(r"\n{3,}", "\n\n", rendered)
    return rendered.strip() + "\n"


# ---------------------------------------------------------------------------
# Current state detection
# ---------------------------------------------------------------------------

def _managed_conf_names() -> set[str]:
    """Return names of IPSec connections managed by us."""
    names: list[str] = []
    if not SWANCTL_CONF_DIR.exists():
        return set()
    for conf in SWANCTL_CONF_DIR.glob("*.conf"):
        try:
            first_line = conf.read_text().split("\n", 1)[0].strip()
            if first_line == MANAGED_HEADER:
                names.append(conf.stem)
        except OSError:
            pass
    return set(names)


def _strongswan_available() -> bool:
    return shutil.which("swanctl") is not None


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def apply_ipsec(tunnels: list[IPSecTunnel], dry_run: bool = False) -> None:
    """Reconcile desired IPSec tunnels with current system state."""
    if not tunnels:
        return

    if not _strongswan_available():
        console.print(
            "[yellow]Warning:[/yellow] swanctl not found — skipping IPSec configuration.\n"
            "  Install with: sudo apt install strongswan strongswan-swanctl"
        )
        return

    desired = {t.name: t for t in tunnels}
    managed = _managed_conf_names()

    _ensure_strongswan(dry_run)

    changed = False

    for name, tunnel in desired.items():
        conf_path = SWANCTL_CONF_DIR / f"{name}.conf"
        desired_conf = _render_conf(tunnel)
        existing_conf = conf_path.read_text() if conf_path.exists() else None

        if existing_conf is None:
            console.print(f"[green]+ Creating IPSec tunnel:[/green] {name}")
            _write_conf(conf_path, desired_conf, dry_run)
            _install_psk(tunnel, dry_run)
            changed = True
        elif desired_conf != existing_conf:
            console.print(f"[yellow]~ Updating IPSec tunnel:[/yellow] {name}")
            _write_conf(conf_path, desired_conf, dry_run)
            _install_psk(tunnel, dry_run)
            changed = True
        else:
            console.print(f"[dim]  {name}: no changes[/dim]")

    for name in managed - set(desired.keys()):
        console.print(f"[red]- Removing IPSec tunnel:[/red] {name}")
        conf_path = SWANCTL_CONF_DIR / f"{name}.conf"
        if not dry_run:
            conf_path.unlink(missing_ok=True)
            (SWANCTL_SECRETS_DIR / f"{name}.psk").unlink(missing_ok=True)
        else:
            console.print(f"[dim]DRY-RUN:[/dim] would delete {conf_path}")
        changed = True

    if changed:
        run(["swanctl", "--load-all", "--clear"], dry_run=dry_run)


def disable_ipsec(desired_tunnel_names: set[str], dry_run: bool = False) -> None:
    """Disable IPSec runtime state managed by vpnplane."""
    if not _strongswan_available():
        console.print("[dim]  ipsec: swanctl not found, skipping disable[/dim]")
        return

    managed = _managed_conf_names()
    if not managed:
        console.print("[dim]  ipsec: no managed tunnels to disable[/dim]")
        return

    removed = 0
    for name in sorted(managed - desired_tunnel_names):
        conf_path = SWANCTL_CONF_DIR / f"{name}.conf"
        if dry_run:
            console.print(f"[dim]DRY-RUN:[/dim] would delete {conf_path}")
        else:
            conf_path.unlink(missing_ok=True)
            (SWANCTL_SECRETS_DIR / f"{name}.psk").unlink(missing_ok=True)
        removed += 1

    run(["swanctl", "--load-all", "--clear"], dry_run=dry_run)
    run(["systemctl", "disable", "--now", "strongswan"], dry_run=dry_run)

    kept = len(managed & desired_tunnel_names)
    console.print(
        f"[green]  ipsec: disabled runtime for {len(managed)} managed tunnel(s), "
        f"removed {removed} stale config(s), kept {kept} desired config(s)[/green]"
    )


def _write_conf(path: Path, content: str, dry_run: bool) -> None:
    if dry_run:
        console.print(f"[dim]DRY-RUN:[/dim] would write {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o600)


def _install_psk(tunnel: IPSecTunnel, dry_run: bool) -> None:
    """Copy the PSK file to the swanctl secrets directory."""
    psk_src = tunnel.local.auth.secret
    if psk_src is None:
        return
    psk_dst = SWANCTL_SECRETS_DIR / f"{tunnel.name}.psk"
    if dry_run:
        console.print(f"[dim]DRY-RUN:[/dim] would copy {psk_src} → {psk_dst}")
        return
    psk_dst.parent.mkdir(parents=True, exist_ok=True)
    psk_dst.write_text(psk_src.read_text())
    psk_dst.chmod(0o600)


def _ensure_strongswan(dry_run: bool) -> None:
    run(["systemctl", "enable", "--now", "strongswan"], dry_run=dry_run)


# ---------------------------------------------------------------------------
# Export (remote side swanctl config)
# ---------------------------------------------------------------------------

_REMOTE_SWANCTL_TEMPLATE = """\
# vpnplane export — remote side for {{ tunnel.name }}
# Install at: /etc/swanctl/conf.d/{{ tunnel.name }}.conf
# Copy PSK file to: /etc/swanctl/ipsec-secrets/{{ tunnel.name }}.psk

connections {
    {{ tunnel.name }} {
        version = {{ tunnel.ike.version }}
        # SWAP local/remote addresses
        local_addrs = {{ tunnel.remote.address }}
        remote_addrs = {{ tunnel.local.address }}
        proposals = {{ tunnel.ike.encryption }}-{{ tunnel.ike.integrity }}-{{ tunnel.ike.dh_group }}
        dpd_delay = {{ tunnel.esp.dpd_delay }}s

        local {
            auth = {{ tunnel.remote.auth.method }}
            id = {{ tunnel.remote.address }}
        }
        remote {
            auth = {{ tunnel.local.auth.method }}
            id = {{ tunnel.local.address }}
        }
        children {
            {{ tunnel.name }}-child {
                # SWAP local/remote subnets
                local_ts = {{ tunnel.remote.subnets | join(', ') }}
                remote_ts = {{ tunnel.local.subnets | join(', ') }}
                esp_proposals = {{ tunnel.esp.encryption }}-{{ tunnel.esp.integrity }}
                life_time = {{ tunnel.esp.lifetime }}s
                dpd_action = {{ tunnel.esp.dpd_action }}
            }
        }
    }
}

secrets {
    ike-{{ tunnel.name }} {
        id = {{ tunnel.local.address }}
        secret = include /etc/swanctl/ipsec-secrets/{{ tunnel.name }}.psk
    }
}
"""


def export_ipsec_config(tunnel: IPSecTunnel) -> str:
    tmpl = _env.from_string(_REMOTE_SWANCTL_TEMPLATE)
    rendered = tmpl.render(tunnel=tunnel)
    rendered = re.sub(r"\n{3,}", "\n\n", rendered)
    return rendered.strip() + "\n"


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_ipsec_status() -> list[dict]:
    """Return status info for managed IPSec connections."""
    if not _strongswan_available():
        return []

    managed = _managed_conf_names()

    try:
        result = subprocess.run(
            ["swanctl", "--list-sas", "--raw"], capture_output=True, text=True
        )
        active_names = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith(" ") and ":" in line:
                active_names.add(line.split(":")[0].strip())
    except FileNotFoundError:
        active_names = set()

    return [
        {"name": name, "active": name in active_names}
        for name in sorted(managed)
    ]
