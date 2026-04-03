#!/usr/bin/env bash
# uninstall.sh — remove vpnplane from an Ubuntu server
# Usage: sudo bash /opt/vpnplane/uninstall.sh
#
# What this removes:
#   - The /opt/vpnplane installation directory
#   - The /usr/local/bin/vpnplane symlink
#   - The managed block in /etc/ufw/before.rules
#   - The sysctl config file
#
# What this KEEPS (to avoid breaking your network accidentally):
#   - Active WireGuard interfaces and their .conf files
#   - Active IPSec connections
#   - /etc/vpnplane/ config directory
#   - UFW INPUT rules for WireGuard ports
#
# To fully remove everything, pass --full:
#   sudo bash uninstall.sh --full

set -euo pipefail

INSTALL_DIR="/opt/vpnplane"
BIN_LINK="/usr/local/bin/vpnplane"
UFW_BEFORE_RULES="/etc/ufw/before.rules"
SYSCTL_CONF="/etc/sysctl.d/99-vpnplane.conf"
MANAGED_WG_DIR="/etc/wireguard"
CONFIG_DIR="/etc/vpnplane"

FULL=false
if [[ "${1:-}" == "--full" ]]; then
    FULL=true
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[uninstall]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }

if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[error]${NC} Must be run as root." >&2
    exit 1
fi

# ---- confirm ----
echo -e "${YELLOW}This will remove vpnplane.${NC}"
if $FULL; then
    echo -e "${RED}--full mode: will also stop/remove all managed WireGuard tunnels and config.${NC}"
fi
read -r -p "Continue? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
fi

# ---- remove managed FORWARD block from before.rules ----
if [[ -f "$UFW_BEFORE_RULES" ]]; then
    if grep -q "VPNPLANE-BEGIN" "$UFW_BEFORE_RULES"; then
        log "Removing managed block from $UFW_BEFORE_RULES..."
        # Remove the filter block
        sed -i '/# VPNPLANE-BEGIN/,/# VPNPLANE-END/d' "$UFW_BEFORE_RULES"
        # Remove the NAT block
        sed -i '/# VPNPLANE-NAT-BEGIN/,/# VPNPLANE-NAT-END/d' "$UFW_BEFORE_RULES"
        ufw reload
    fi
fi

# ---- remove sysctl config ----
if [[ -f "$SYSCTL_CONF" ]]; then
    log "Removing $SYSCTL_CONF..."
    rm -f "$SYSCTL_CONF"
    sysctl --system &>/dev/null || true
fi

# ---- full mode: stop and remove managed WireGuard tunnels ----
if $FULL; then
    log "Stopping managed WireGuard interfaces..."
    for conf in "$MANAGED_WG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        iface=$(basename "$conf" .conf)
        if head -1 "$conf" 2>/dev/null | grep -q "managed-by: vpnplane"; then
            systemctl disable --now "wg-quick@${iface}" 2>/dev/null || true
            rm -f "$conf"
            log "  Removed: $iface"
        fi
    done

    log "Stopping managed IPSec connections..."
    for conf in /etc/swanctl/conf.d/*.conf; do
        [[ -f "$conf" ]] || continue
        if head -1 "$conf" 2>/dev/null | grep -q "managed-by: vpnplane"; then
            rm -f "$conf"
            log "  Removed: $(basename "$conf")"
        fi
    done
    swanctl --load-all 2>/dev/null || true

    log "Removing config directory $CONFIG_DIR..."
    rm -rf "$CONFIG_DIR"
fi

# ---- remove binary and install dir ----
if [[ -L "$BIN_LINK" ]]; then
    rm -f "$BIN_LINK"
    log "Removed: $BIN_LINK"
fi

if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    log "Removed: $INSTALL_DIR"
fi

echo ""
echo -e "${GREEN}vpnplane removed.${NC}"
if ! $FULL; then
    echo ""
    warn "WireGuard/IPSec tunnels and config files were NOT removed."
    warn "To remove everything: sudo bash uninstall.sh --full"
fi
