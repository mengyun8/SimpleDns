#!/bin/bash
#
# SimpleDns XDP - Installation Script
#
# Installs SimpleDns XDP binaries, configuration, and zone files.
#
# Usage:
#   sudo ./install.sh                    Install to /usr/local
#   sudo ./install.sh /opt/simpledns     Install to custom prefix
#

set -e

PREFIX="${1:-/usr/local}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [ "$(id -u)" -ne 0 ]; then
    log_warn "Installation recommended as root (for /usr/local and /etc access)"
fi

# Create directories
log_info "Installing to $PREFIX..."
mkdir -p "$PREFIX/bin"
mkdir -p "$PREFIX/etc/simpledns"
mkdir -p "$PREFIX/var/simpledns"
mkdir -p "$PREFIX/share/simpledns/scripts"

# Copy binaries
if [ -d "$SCRIPT_DIR/bin" ]; then
    for bin in "$SCRIPT_DIR/bin/"*; do
        if [ -f "$bin" ]; then
            cp "$bin" "$PREFIX/bin/"
            chmod +x "$PREFIX/bin/$(basename "$bin")"
            log_info "Installed binary: $(basename "$bin")"
        fi
    done
fi

# Copy configuration
if [ -d "$SCRIPT_DIR/conf" ]; then
    cp "$SCRIPT_DIR/conf/"* "$PREFIX/etc/simpledns/" 2>/dev/null || true
    log_info "Installed config to $PREFIX/etc/simpledns/"
fi

# Copy scripts
if [ -d "$SCRIPT_DIR/scripts" ]; then
    cp "$SCRIPT_DIR/scripts/"* "$PREFIX/share/simpledns/scripts/" 2>/dev/null || true
    log_info "Installed scripts to $PREFIX/share/simpledns/scripts/"
fi

# Copy zone file
if [ -f "$SCRIPT_DIR/conf/test.com.zone" ]; then
    cp "$SCRIPT_DIR/conf/test.com.zone" "$PREFIX/var/simpledns/"
    log_info "Installed zone file to $PREFIX/var/simpledns/"
fi

# Create symlink for main binary if exists
if [ -f "$PREFIX/bin/simpledns-xdp" ]; then
    ln -sf "$PREFIX/bin/simpledns-xdp" "$PREFIX/bin/simpledns" 2>/dev/null || true
fi

echo ""
log_info "Installation complete!"
echo ""
echo "Quick start:"
echo "  # Edit configuration:"
echo "  vi $PREFIX/etc/simpledns/simpledns.conf"
echo ""
echo "  # Start DNS server (Linux, requires root for XDP):"
echo "  sudo $PREFIX/bin/simpledns-xdp -i eth0 -z $PREFIX/var/simpledns/test.com.zone -o test.com -v"
echo ""
echo "  # Run tests (macOS/Linux):"
echo "  $PREFIX/bin/simpledns-test $PREFIX/var/simpledns/test.com.zone test.com"
echo ""
echo "  # Run benchmark:"
echo "  $PREFIX/bin/simpledns-test -s $PREFIX/var/simpledns/test.com.zone test.com &"
echo "  $PREFIX/bin/simpledns-bench -p 15353 -t 4 -n 10000"
