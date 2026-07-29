#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  Port Watcher v3 — Installer
#  Author: RedVortex
#  License: MIT
# ═══════════════════════════════════════════════════════════════
#  Usage: curl -fsSL https://raw.githubusercontent.com/\
#         anonymous777999/Bash-Tools/main/install.sh | bash
# ═══════════════════════════════════════════════════════════════

set -e

REPO="anonymous777999/Bash-Tools"
BRANCH="main"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-$HOME/.config/port-watcher}"
TMP_DIR="$(mktemp -d)"

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   Port Watcher v3 — Installer        ║"
echo "  ║   Author: RedVortex                  ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${RESET}"

# Check for required tools
echo -e "${YELLOW}[*]${RESET} Checking requirements..."
if ! command -v curl &>/dev/null && ! command -v git &>/dev/null; then
  echo -e "${RED}[!]${RESET} Neither curl nor git found. Install one and try again."
  exit 1
fi

# Download
echo -e "${YELLOW}[*]${RESET} Downloading Port Watcher v3..."
if command -v git &>/dev/null; then
  git clone --depth 1 "https://github.com/$REPO.git" "$TMP_DIR/repo" 2>/dev/null
else
  mkdir -p "$TMP_DIR/repo/src" "$TMP_DIR/repo/config"
  curl -fsSL "https://raw.githubusercontent.com/$REPO/$BRANCH/src/port-watcher.sh" \
    -o "$TMP_DIR/repo/src/port-watcher.sh"
  curl -fsSL "https://raw.githubusercontent.com/$REPO/$BRANCH/config/ports.conf.example" \
    -o "$TMP_DIR/repo/config/ports.conf.example"
  # Download plugins
  mkdir -p "$TMP_DIR/repo/src/plugins/enabled"
  curl -fsSL "https://raw.githubusercontent.com/$REPO/$BRANCH/src/plugins/enabled/10-mitre-attack.sh" \
    -o "$TMP_DIR/repo/src/plugins/enabled/10-mitre-attack.sh" 2>/dev/null || true
  curl -fsSL "https://raw.githubusercontent.com/$REPO/$BRANCH/src/plugins/enabled/20-database-sqlite.sh" \
    -o "$TMP_DIR/repo/src/plugins/enabled/20-database-sqlite.sh" 2>/dev/null || true
fi

# Install script
echo -e "${YELLOW}[*]${RESET} Installing to $INSTALL_DIR/port-watcher..."
if [[ ! -d "$INSTALL_DIR" ]]; then
  echo -e "${YELLOW}[!]${RESET} Creating $INSTALL_DIR..."
  mkdir -p "$INSTALL_DIR"
fi
install -m 755 "$TMP_DIR/repo/src/port-watcher.sh" "$INSTALL_DIR/port-watcher" 2>/dev/null || {
  echo -e "${RED}[!]${RESET} Permission denied. Trying with sudo..."
  sudo install -m 755 "$TMP_DIR/repo/src/port-watcher.sh" "$INSTALL_DIR/port-watcher"
}

# Install config
echo -e "${YELLOW}[*]${RESET} Installing config to $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"
install -m 644 "$TMP_DIR/repo/config/ports.conf.example" "$CONFIG_DIR/ports.conf.example" 2>/dev/null || {
  sudo mkdir -p "$CONFIG_DIR"
  sudo install -m 644 "$TMP_DIR/repo/config/ports.conf.example" "$CONFIG_DIR/ports.conf.example"
}

# Cleanup
rm -rf "$TMP_DIR"

# Verify
echo -e "${YELLOW}[*]${RESET} Verifying installation..."
if command -v port-watcher &>/dev/null; then
  echo -e "${GREEN}[✓]${RESET} Port Watcher v3 installed successfully!"
  echo ""
  echo -e "  ${CYAN}Run:${RESET}  sudo port-watcher"
  echo -e "  ${CYAN}Help:${RESET}  port-watcher --help"
  echo -e "  ${CYAN}Config:${RESET} $CONFIG_DIR/ports.conf.example"
  echo ""
  port-watcher --version 2>/dev/null || true
else
  echo -e "${YELLOW}[!]${RESET} Installation complete. Add $INSTALL_DIR to your PATH."
fi
