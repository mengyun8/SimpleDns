#!/bin/bash
#
# SimpleDns XDP - Local Test Script
#
# This script runs on both macOS and Linux:
#   1. Builds the test program
#   2. Runs unit tests (validates DNS protocol logic)
#   3. Starts a standalone DNS server on port 15353
#   4. Tests it with dig (if available)
#
# Usage: ./scripts/test_xdp_dns.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ZONEFILE="$PROJECT_DIR/conf/test.com.zone"
ORIGIN="test.com"
TEST_PORT=15353

echo "============================================"
echo "  SimpleDns XDP - Local Test Suite"
echo "============================================"
echo ""

# Detect current platform (must match Makefile logic)
DETECTED_OS=$(uname -s | tr A-Z a-z)
DETECTED_ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
CURRENT_TARGET="${DETECTED_OS}-${DETECTED_ARCH}"

# --- Step 1: Build test program ---
echo "[1/4] Building test program (target: $CURRENT_TARGET)..."
cd "$PROJECT_DIR"
make test 2>&1 || {
    echo "BUILD FAILED"
    exit 1
}
echo ""

# --- Step 2: Start standalone DNS server ---
echo "[2/4] Starting standalone DNS server on port $TEST_PORT..."

# Kill any process already using the port
lsof -ti :$TEST_PORT | xargs kill -9 2>/dev/null || true
sleep 0.5

# Find the test binary (prefer current platform, fallback to any)
TEST_BIN="build/$CURRENT_TARGET/simpledns-test"
if [ ! -f "$TEST_BIN" ]; then
    TEST_BIN=$(find build -name "simpledns-test" -type f 2>/dev/null | head -1)
fi
if [ -z "$TEST_BIN" ] || [ ! -f "$TEST_BIN" ]; then
    echo "ERROR: test binary not found"
    exit 1
fi

"$TEST_BIN" -s "$ZONEFILE" "$ORIGIN" &
SERVER_PID=$!
sleep 1

# Check if server started
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi
echo "Server started (PID: $SERVER_PID)"
echo ""

# --- Step 3: Test with dig (if available) ---
echo "[3/4] Testing DNS queries with dig..."
echo ""

if command -v dig &>/dev/null; then
    echo "--- Test 1: A record query for www.test.com ---"
    dig @127.0.0.1 -p $TEST_PORT www.test.com +short
    echo ""

    echo "--- Test 2: A record query for aaa.test.com ---"
    dig @127.0.0.1 -p $TEST_PORT aaa.test.com +short
    echo ""

    echo "--- Test 3: A record query for ns.test.com ---"
    dig @127.0.0.1 -p $TEST_PORT ns.test.com +short
    echo ""

    echo "--- Test 4: AAAA record query for www.test.com ---"
    dig @127.0.0.1 -p $TEST_PORT www.test.com AAAA +short
    echo ""

    echo "--- Test 5: AAAA record query for ns.test.com ---"
    dig @127.0.0.1 -p $TEST_PORT ns.test.com AAAA +short
    echo ""

    echo "--- Test 6: CNAME chain query for cname.test.com ---"
    dig @127.0.0.1 -p $TEST_PORT cname.test.com +short
    echo ""

    echo "--- Test 7: NXDOMAIN for nonexistent.test.com ---"
    dig @127.0.0.1 -p $TEST_PORT nonexistent.test.com +short
    echo "(expected: empty - NXDOMAIN)"
    echo ""

    echo "--- Test 8: Case-insensitive query (WWW.TEST.COM) ---"
    dig @127.0.0.1 -p $TEST_PORT WWW.TEST.COM +short
    echo ""

    echo "--- Test 9: Full response with header ---"
    dig @127.0.0.1 -p $TEST_PORT www.test.com
    echo ""
else
    echo "dig not found, skipping functional tests."
    echo "Install with: brew install bind (macOS) or apt install dnsutils (Linux)"
    echo ""
fi

# --- Step 4: Stop server and summary ---
echo "[4/4] Stopping server..."
kill $SERVER_PID 2>/dev/null || true
for i in 1 2 3; do
    kill -0 $SERVER_PID 2>/dev/null || break
    sleep 1
done
kill -9 $SERVER_PID 2>/dev/null || true
echo "Server stopped."
echo ""
echo "============================================"
echo "  Test suite complete"
echo "============================================"
echo ""
echo "Next steps:"
echo "  - Run all tests: make test-all"
echo "  - On Linux: make all && sudo ./build/*/simpledns-xdp -i eth0 -z conf/test.com.zone -o test.com -v"
echo "  - On macOS: make docker for containerized BPF build"
