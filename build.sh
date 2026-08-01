#!/bin/bash
#
# SimpleDns XDP - Cross-Compilation Build Script
#
# Builds installation packages for all supported platforms:
#   - linux-amd64   (Linux x86_64)
#   - linux-arm64   (Linux ARM64/aarch64)
#   - darwin-amd64  (macOS Intel)
#   - darwin-arm64  (macOS Apple Silicon)
#
# Usage:
#   ./build.sh              Build for current platform only
#   ./build.sh all          Build all 4 platform packages
#   ./build.sh linux-amd64  Build specific platform
#   ./build.sh docker       Build Linux packages via Docker (from macOS)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="1.0.0"
PKG_NAME="simpledns-xdp"
DIST_DIR="dist"

# Detect current platform
CURRENT_OS=$(uname -s | tr A-Z a-z)
CURRENT_ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
CURRENT_TARGET="${CURRENT_OS}-${CURRENT_ARCH}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# === Build functions ===

build_native() {
    local target=$1
    log_info "Building for $target (native)..."

    make clean 2>/dev/null || true
    make TARGET=$target all 2>&1

    if [ $? -eq 0 ]; then
        log_info "Build successful for $target"
        make TARGET=$target package
        log_info "Package created for $target"
    else
        log_error "Build failed for $target"
        return 1
    fi
}

build_darwin_cross() {
    local target=$1
    local arch=$2

    log_info "Building for $target (macOS cross-compile)..."

    # On macOS, we can natively cross-compile between amd64 and arm64
    make clean 2>/dev/null || true
    make TARGET=$target all 2>&1

    if [ $? -eq 0 ]; then
        log_info "Build successful for $target"
        make TARGET=$target package
    else
        log_error "Build failed for $target"
        return 1
    fi
}

build_linux_via_docker() {
    local target=$1

    log_info "Building for $target (via Docker)..."

    # Check if Docker is available
    if ! command -v docker &>/dev/null; then
        log_error "Docker not found. Install Docker to cross-compile for Linux."
        return 1
    fi

    # Build Docker image if not exists
    if ! docker image inspect simpledns-build &>/dev/null; then
        log_info "Building Docker image..."
        docker build -t simpledns-build .
    fi

    # Cross-compile inside container
    local cross_cc=""
    case $target in
        linux-amd64) cross_cc="x86_64-linux-gnu-gcc" ;;
        linux-arm64) cross_cc="aarch64-linux-gnu-gcc" ;;
    esac

    log_info "Compiling inside Docker container for $target..."
    docker run --rm -v "$SCRIPT_DIR:/work" simpledns-build bash -c "
        apt-get update -qq && apt-get install -y -qq gcc-${cross_cc%%-**}-${cross_cc#*-} 2>/dev/null || true
        make TARGET=$target CROSS_CC=$cross_cc package
    "

    if [ $? -eq 0 ]; then
        log_info "Package created for $target"
    else
        log_error "Build failed for $target"
        return 1
    fi
}

# === Main ===

mkdir -p "$DIST_DIR"

case "${1:-native}" in
    all)
        log_info "Building all platform packages..."
        echo ""

        # Build for current platform first
        build_native "$CURRENT_TARGET"
        echo ""

        # Cross-compile for other macOS architecture
        if [ "$CURRENT_OS" = "darwin" ]; then
            if [ "$CURRENT_ARCH" = "amd64" ]; then
                build_darwin_cross "darwin-arm64" "arm64"
            else
                build_darwin_cross "darwin-amd64" "x86_64"
            fi
            echo ""
        fi

        # Build Linux packages via Docker
        build_linux_via_docker "linux-amd64"
        echo ""
        build_linux_via_docker "linux-arm64"
        echo ""
        ;;

    linux-amd64|linux-arm64)
        if [ "$CURRENT_OS" = "linux" ]; then
            build_native "$1"
        else
            build_linux_via_docker "$1"
        fi
        ;;

    darwin-amd64|darwin-arm64)
        if [ "$CURRENT_OS" = "darwin" ]; then
            build_darwin_cross "$1" ""
        else
            log_error "Cannot build macOS packages on Linux. Run on macOS."
            exit 1
        fi
        ;;

    docker)
        build_linux_via_docker "linux-amd64"
        echo ""
        build_linux_via_docker "linux-arm64"
        ;;

    native|"")
        build_native "$CURRENT_TARGET"
        ;;

    *)
        log_error "Unknown target: $1"
        echo "Usage: $0 [all|linux-amd64|linux-arm64|darwin-amd64|darwin-arm64|docker|native]"
        exit 1
        ;;
esac

# Summary
echo ""
log_info "Build complete. Packages in $DIST_DIR/:"
ls -lh "$DIST_DIR"/*.tar.gz 2>/dev/null || echo "  (no packages found)"
