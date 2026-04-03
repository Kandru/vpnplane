> [!IMPORTANT]  
> Disclosure: this project was created with the help of AI. I use this for myself in production and it might help you as well. I needed an alternative to a big OpnSense box because all I want to do is to inter-connect Wireguard and IPSec tunnels.

![vpnplane logo](images/vpnplane_logo_transparent_small.png)

# vpnplane

vpnplane is a simple, file-based VPN manager for Ubuntu servers.

You define tunnels and routes in YAML, then run one command to apply everything.

## A Short Story

My home and lab setup grew over time: multiple FritzBox locations, a few OPNsense firewalls, and roadwarrior clients (smartphone, laptop, tablet) that need secure access while traveling.

I wanted one repeatable workflow instead of hand-editing firewall and tunnel configs on each box. vpnplane is that workflow: keep everything in config files, validate, apply, and re-apply safely whenever something changes.

## What It Does

- Manages WireGuard and IPSec tunnels
- Manages explicit route/firewall rules between networks
- Supports roadwarrior internet egress through the host with automatic NAT (IPv4 and IPv6)
- Keeps setup idempotent (safe to run apply again)
- Supports interactive commands for tunnels and routes

## Requirements

- Ubuntu 22.04 or 24.04
- Python 3.11+

```bash
sudo apt install -y wireguard wireguard-tools iptables nftables iproute2 python3 python3-pip
# Optional for IPSec:
sudo apt install -y strongswan strongswan-swanctl
```

## Installation

Quick install:

```bash
curl -fsSL https://raw.githubusercontent.com/Kandru/vpnplane/main/install.sh | sudo bash
```

Manual install:

```bash
git clone https://github.com/Kandru/vpnplane.git
cd vpnplane
sudo bash install.sh
```

## Quick Start

1. Initialize settings:

```bash
sudo vpnplane init
```

2. Add tunnels:

```bash
sudo vpnplane tunnel add
```

3. Add routes:

```bash
sudo vpnplane route add
```

4. Validate config:

```bash
vpnplane check
```

5. Apply config:

```bash
sudo vpnplane apply
```

6. Check status:

```bash
sudo vpnplane status
```

## Update Guide

```bash
sudo bash /opt/vpnplane/update.sh
```

After updating, validate and apply again:

```bash
vpnplane check
sudo vpnplane apply
```

## Removal Guide

```bash
sudo bash /opt/vpnplane/uninstall.sh
```

This removes the installed vpnplane files from the target system.

## License

GPL-3.0 - see [LICENSE](LICENSE)
