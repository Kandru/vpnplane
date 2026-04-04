#!/usr/bin/env bash
# install.sh — install or update vpnplane on an Ubuntu server
# Usage: sudo bash install.sh

set -euo pipefail

STAGING_DIR="/tmp/vpnplane"
VENV_DIR="/opt/vpnplane-venv"
BIN_LINK="/usr/local/bin/vpnplane"
CONFIG_DIR="/etc/vpnplane"
REPO_URL="https://github.com/Kandru/vpnplane.git"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[install]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

cleanup() {
    if [[ -d "$STAGING_DIR" ]]; then
        rm -rf "$STAGING_DIR"
    fi
}

trap cleanup EXIT

# ---- root check ----
if [[ "$EUID" -ne 0 ]]; then
    err "This script must be run as root. Try: sudo bash install.sh"
fi

# ---- system dependencies ----
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    wireguard wireguard-tools \
    ufw \
    iptables \
    iproute2 \
    python3 \
    python3-pip \
    python3-venv \
    git \
    2>/dev/null

if ! command -v swanctl &>/dev/null; then
    warn "strongSwan not found. IPSec support will be unavailable."
    warn "Install with: sudo apt install strongswan strongswan-swanctl"
fi

# ---- enable UFW ----
if ! ufw status | grep -q "Status: active"; then
    echo ""
    warn "UFW (firewall) is not active. Enabling it without allowing SSH will lock you out."
    read -rp "Enter your SSH port to allow before enabling UFW (default: 22, press Enter to skip UFW setup): " SSH_PORT
    if [[ -n "$SSH_PORT" ]]; then
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
            err "Invalid port: $SSH_PORT"
        fi
        log "Allowing SSH on port $SSH_PORT..."
        ufw allow "$SSH_PORT/tcp"
        log "Enabling UFW..."
        ufw --force enable
    else
        warn "Skipping UFW setup. You can enable it manually after allowing your SSH port:"
        warn "  sudo ufw allow <your-ssh-port>/tcp && sudo ufw enable"
    fi
fi

# ---- prepare temporary source staging ----
cleanup

# If script is run from inside the repo, copy it; otherwise clone
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
    log "Copying local source to temporary staging at $STAGING_DIR..."
    rsync -a --delete "$SCRIPT_DIR/" "$STAGING_DIR/"
else
    log "Cloning repository to temporary staging at $STAGING_DIR..."
    git clone --depth=1 "$REPO_URL" "$STAGING_DIR"
fi

# ---- Python venv + install ----
log "Setting up Python virtual environment..."
python3 -m venv --clear "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip setuptools
"$VENV_DIR/bin/pip" install --quiet "$STAGING_DIR"

# ---- symlink ----
ln -sf "$VENV_DIR/bin/vpnplane" "$BIN_LINK"
log "Installed: $BIN_LINK → $VENV_DIR/bin/vpnplane"

# ---- config directory ----
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# ---- WireGuard key directory ----
mkdir -p /etc/wireguard/keys
chmod 700 /etc/wireguard/keys

# ---- first-run setup ----
if [[ ! -f "$CONFIG_DIR/settings.yaml" ]]; then
    echo ""
    log "Running first-time setup wizard..."
    "$VENV_DIR/bin/vpnplane" init --config-dir "$CONFIG_DIR" </dev/tty
fi

# ---- done ----
echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Create a tunnel:  sudo vpnplane tunnel add"
echo "  2. Create a route:   sudo vpnplane route add"
echo "  3. Apply:            sudo vpnplane apply"
echo ""
echo "Config files live in: $CONFIG_DIR"
