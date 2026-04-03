# Project Requirements & Goals

## Problem Statement

Managing VPN tunnels between servers and routing traffic between them typically requires either a complex control-plane product (Netbird, Netmaker, Tailscale) or manual iptables/WireGuard configuration that is hard to maintain and doesn't survive reboots cleanly.

The goal is a **minimal, self-hosted alternative** that is configured entirely via YAML files and applied by running a single command.

---

## Core Goals

| # | Goal |
|---|------|
| 1 | Manage WireGuard tunnel interfaces on an Ubuntu server |
| 2 | Manage IPSec (IKEv2/strongSwan) tunnels on the same server |
| 3 | Control which traffic is forwarded between tunnels using UFW/iptables |
| 4 | **Zero-trust by default** — all forwarding denied unless explicitly allowed |
| 5 | **Idempotent** — re-running always converges to desired state |
| 6 | **Persistent** — configuration survives reboots |
| 7 | Generate peer-side config files to send to the remote side |
| 8 | No control plane, no cloud dependency, no agents — just files and a script |

---

## Non-Goals

- GUI or web interface
- Dynamic/automatic peer discovery
- Certificate authority management
- Multi-server orchestration (each server runs its own instance)
- Support for non-Ubuntu Linux distributions (though it may work)

---

## Requirements

### Functional

**Tunnel management**
- Accept one YAML file per tunnel in a config directory
- Support `type: wireguard` and `type: ipsec`
- Create, update, or remove tunnels based on what files exist
- WireGuard: generate `/etc/wireguard/<name>.conf` and enable `wg-quick@<name>` via systemd
- IPSec: generate `/etc/swanctl/conf.d/<name>.conf` and hot-reload strongSwan
- Peer-only changes to WireGuard should reload without interface restart (`wg syncconf`)
- Track managed resources via `# managed-by: vpnplane` header in generated files
- Auto-generate preshared keys (PSK) per WireGuard peer by default; store at `/etc/wireguard/keys/<tunnel>-<peer>.psk`
- Auto-generate peer keypairs during `tunnel add`; private key stored at `/etc/wireguard/keys/<tunnel>-<peer>.key`; public key written to YAML config; `export wireguard` uses the stored key to produce a ready-to-use client config
- Single default WireGuard interface `wg0` hosts all peers; server gets the first usable IP of the next free /24 block (default `10.100.0.1/24`); each peer is auto-assigned the next available /32 from that subnet; configurable via optional `settings.yaml` at config root

**Routing / Firewall**
- Accept one YAML file per routing rule in a config directory
- Translate route rules into iptables FORWARD rules in `/etc/ufw/before.rules`
- Rules survive reboots via UFW
- Default FORWARD policy: DROP (zero-trust)
- Support `bidirectional` rules (auto-generate reverse)
- Support subnet restriction on both source and destination
- Support protocol filtering (tcp, udp, icmp, any) and port filtering
- Support explicit `deny` rules
- Support `nat: true` for MASQUERADE (internet breakout)
- Support IPSec-to-WireGuard routing via iptables policy matching
- Enable `ip_forward` via `/etc/sysctl.d/99-vpnplane.conf`
- Open WireGuard listen ports in UFW INPUT rules automatically

**CLI**
- `apply [--dry-run]` — reconcile system with config; `--dry-run` prints without changing
- `check` — validate YAML files without requiring root
- `status` — show live tunnel state and active routing rules in a table
- `export wireguard TUNNEL PEER` — generate peer-side WireGuard config (includes PSK)
- `export ipsec TUNNEL` — generate remote-side swanctl config
- `keygen` — generate WireGuard keypair
- `tunnel add` — for WireGuard: adds a peer to the single default `wg0` interface (auto-created on first run with auto-assigned key/address/port); only prompts for peer details; for IPSec: creates a new per-site tunnel config as before
- `tunnel edit/delete/list` — CRUD for tunnel configs; `edit wg0` is used to modify the WireGuard server settings or existing peers
- `route add/edit/delete/list` — interactive CRUD for route config files

**Install / Update / Uninstall**
- `install.sh` — installs to `/opt/vpnplane/`, symlinks to `/usr/local/bin/vpnplane`, and updates existing installations
- `uninstall.sh` — removes tool (default: keeps tunnels/config); `--full` removes everything

### Non-Functional

- **Language**: Python 3.11+ (preferred by project owner)
- **Dependencies**: Click, Pydantic v2, PyYAML, Rich, Jinja2
- **Target OS**: Ubuntu 22.04 / 24.04
- **Execution**: runs as root (via crontab `@reboot` or manually)
- **Config location**: `/etc/vpnplane/` (chmod 700)
- **No configuration file format other than YAML**

---

## Config File Contracts

### Tunnel file (`tunnels/<name>.yaml`)
- `type`: required (`wireguard` | `ipsec`)
- `name`: required, unique, max 15 chars (WireGuard interface name constraint)
- Adding a file → tunnel is created on next `apply`
- Editing a file → tunnel is updated on next `apply`
- Deleting a file → tunnel is removed on next `apply`

### `settings.yaml` (required, at config root — created by `vpnplane init`)
- `server_address`: public IP/hostname of this server, used as Endpoint in peer exports (combined with tunnel listen port)
- `wireguard.default_listen_port`: default listen port for new tunnels and export endpoint fallback (default `51820`)
- `wireguard.start_network`: first block for a new tunnel's server address (default `10.100.0.0/30`); prefix determines block size; search increments by block size through the containing /16

### Route file (`routes/<name>.yaml`)
- `name`: required, unique
- `from.interface` / `to.interface`: tunnel name or physical NIC
- Deleting a file → iptables FORWARD rules for that route removed on next `apply`

---

## Architecture

```
CLI (connector.py)
    │
    ├── models.py         Pydantic validation of all config types
    ├── utils.py          Subprocess wrapper, key generation, YAML loading
    ├── wireguard.py      WireGuard conf generation + systemd lifecycle
    ├── ipsec.py          swanctl conf generation + strongSwan lifecycle
    └── firewall.py       UFW port rules + iptables FORWARD block in before.rules
```

**State tracking**: all generated files have a `# managed-by: vpnplane` header on line 1. The tool only touches files it created — it never modifies manually-created WireGuard or swanctl configs.

**Idempotency**: each module reads current state (from disk + live system), compares with desired state from YAML, and applies only the diff.

---

## Decision Log

| Decision | Rationale |
|---|---|
| One YAML file per tunnel/route | Easier to add/remove individual items; avoids large monolithic configs |
| UFW as the persistence layer for FORWARD rules | Pre-installed on Ubuntu, survives reboots, managed block approach is clean |
| `wg syncconf` for peer-only changes | Zero-downtime reload; only restart when address/port changes |
| PSK auto-generated by default | Security best practice; most users forget to set PSKs manually |
| Pydantic v2 for config validation | Strong validation, clear error messages, Python 3.11+ native |
| `/opt/vpnplane` install location | Standard for third-party software on Linux; keeps it out of system paths |
| No systemd service for the tool itself | Tool is run on-demand or via crontab; persistent state is in systemd WG units |
| IPSec routing via `--pol ipsec` iptables match | Works without xfrm interfaces; compatible with default strongSwan config |
| Single `wg0` interface for all WireGuard peers | Simpler than one interface per connection; peers are isolated by default (zero-trust FORWARD DROP); routes are used to open specific traffic paths |
