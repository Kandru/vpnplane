#!/usr/bin/env bash
# update.sh — update vpnplane from GitHub
# Usage: sudo bash /opt/vpnplane/update.sh

set -euo pipefail

INSTALL_DIR="/opt/vpnplane"
BIN_LINK="/usr/local/bin/vpnplane"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[update]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

if [[ "$EUID" -ne 0 ]]; then
    err "Must be run as root. Try: sudo bash $0"
fi

if [[ ! -d "$INSTALL_DIR/.git" ]]; then
    err "$INSTALL_DIR is not a git repository. Run install.sh first."
fi

# ---- pull latest ----
log "Fetching latest version from GitHub..."
CURRENT_SHA=$(git -C "$INSTALL_DIR" rev-parse HEAD)

git -C "$INSTALL_DIR" fetch --depth=1 origin main
NEW_SHA=$(git -C "$INSTALL_DIR" rev-parse FETCH_HEAD)

if [[ "$CURRENT_SHA" == "$NEW_SHA" ]]; then
    log "Already up to date ($(git -C "$INSTALL_DIR" describe --tags --always 2>/dev/null || echo "${CURRENT_SHA:0:8}"))."
    exit 0
fi

log "Updating: ${CURRENT_SHA:0:8} → ${NEW_SHA:0:8}"
git -C "$INSTALL_DIR" merge --ff-only FETCH_HEAD

# ---- reinstall package into venv ----
log "Reinstalling Python package..."
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -e "$INSTALL_DIR"

# ---- re-link binary (in case it changed) ----
ln -sf "$INSTALL_DIR/.venv/bin/vpnplane" "$BIN_LINK"

# ---- show changelog if available ----
CHANGES=$(git -C "$INSTALL_DIR" log --oneline "${CURRENT_SHA}..HEAD" 2>/dev/null | head -20)
if [[ -n "$CHANGES" ]]; then
    echo ""
    echo "Changes:"
    echo "$CHANGES" | sed 's/^/  /'
fi

echo ""
echo -e "${GREEN}Update complete.${NC}"
echo ""
echo "Run [sudo vpnplane apply] to apply any configuration changes."
