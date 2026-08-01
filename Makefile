#
# SimpleDns XDP - Unified Build System with Cross-Compilation Support
#
# Native build:
#   make                    Build for current platform
#   make test-all           Run all tests
#   make package            Build installation package for current platform
#
# Cross-compilation:
#   make TARGET=linux-amd64      Cross-compile for Linux x86_64
#   make TARGET=linux-arm64      Cross-compile for Linux ARM64
#   make TARGET=darwin-amd64     Cross-compile for macOS x86_64
#   make TARGET=darwin-arm64     Cross-compile for macOS ARM64
#
# Build all packages:
#   make package-all         Build all 4 platform packages (requires Docker)
#
# Usage:
#   make TARGET=linux-arm64 package
#

CC       ?= gcc
CFLAGS   := -O2 -g -Wall -Wextra
LDFLAGS  := -lpthread
BPFFLAGS := -O2 -g -target bpf -Wall -Wextra

# Source layout
SRC_DIR   := src
CONF_DIR  := conf
SCRIPT_DIR := scripts

# Zone file and origin for testing
ZONEFILE ?= $(CURDIR)/conf/test.com.zone
ORIGIN   ?= test.com

# === Target platform detection ===
# TARGET format: <os>-<arch>
# Supported: linux-amd64, linux-arm64, darwin-amd64, darwin-arm64
TARGET ?= $(shell echo "$(shell uname -s | tr A-Z a-z)-$(shell uname -m)" | sed 's/x86_64/amd64/; s/aarch64/arm64/')

TARGET_OS   := $(word 1,$(subst -, ,$(TARGET)))
TARGET_ARCH := $(word 2,$(subst -, ,$(TARGET)))

# Package output directory
DIST_DIR  := dist
PKG_NAME  := simpledns-xdp
VERSION   := 1.0.0

# === Cross-compilation toolchain selection ===

ifeq ($(TARGET_OS),linux)
  ifeq ($(TARGET_ARCH),amd64)
    CROSS_CC ?= x86_64-linux-gnu-gcc
    BPFTARGET := -D__TARGET_ARCH_x86
  else ifeq ($(TARGET_ARCH),arm64)
    CROSS_CC ?= aarch64-linux-gnu-gcc
    BPFTARGET := -D__TARGET_ARCH_arm64
  endif
  PLATFORM_CFLAGS := -D_GNU_SOURCE
  PLATFORM_LDFLAGS := -lbpf -lelf -lz
  CAN_BUILD_BPF := 1
else ifeq ($(TARGET_OS),darwin)
  ifeq ($(TARGET_ARCH),amd64)
    CROSS_CC ?= clang
    DARWIN_ARCH := x86_64
  else ifeq ($(TARGET_ARCH),arm64)
    CROSS_CC ?= clang
    DARWIN_ARCH := arm64
  endif
  PLATFORM_CFLAGS := -arch $(DARWIN_ARCH)
  PLATFORM_LDFLAGS :=
  CAN_BUILD_BPF := 0
endif

# Use cross-compiler if specified, otherwise default CC
ifneq ($(CROSS_CC),)
  CC := $(CROSS_CC)
endif
CFLAGS += $(PLATFORM_CFLAGS)
LDFLAGS += $(PLATFORM_LDFLAGS)

# BPF target architecture flag
BPFFLAGS += $(BPFTARGET)

# Build output directory (separated by target platform)
BUILD_DIR := build/$(TARGET)

# Object files for BPF and user-space programs
KERN_OBJ  := $(BUILD_DIR)/xdp_dns_kern.o
USER_BIN  := $(BUILD_DIR)/simpledns-xdp
TEST_BIN  := $(BUILD_DIR)/simpledns-test
EDGE_BIN  := $(BUILD_DIR)/simpledns-edge
SIM_BIN   := $(BUILD_DIR)/simpledns-sim
BENCH_BIN := $(BUILD_DIR)/simpledns-bench

# All testable binaries
TEST_BINS := $(TEST_BIN) $(EDGE_BIN) $(SIM_BIN)

.PHONY: all kern user test edge sim bench test-all server clean package package-all docker help

# === Build rules ===

# all: build everything (does not run tests)
all: kern user $(TEST_BIN) $(EDGE_BIN) $(SIM_BIN) $(BENCH_BIN)

# Compile XDP BPF kernel program (Linux only)
kern: $(KERN_OBJ)

$(KERN_OBJ): $(SRC_DIR)/xdp_dns_kern.c $(SRC_DIR)/xdp_dns_common.h
ifeq ($(CAN_BUILD_BPF),1)
	@mkdir -p $(BUILD_DIR)
	clang $(BPFFLAGS) -c $(SRC_DIR)/xdp_dns_kern.c -o $@
else
	@echo "Warning: BPF compilation requires Linux. Skipping kernel program."
	@echo "Use 'make docker' or 'make TARGET=linux-amd64' for BPF build."
endif

# Build user-space loader + fallback DNS server (Linux only)
user: $(USER_BIN)

$(USER_BIN): $(SRC_DIR)/xdp_dns_user.c $(SRC_DIR)/xdp_dns_common.h
ifeq ($(CAN_BUILD_BPF),1)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/xdp_dns_user.c $(LDFLAGS)
else
	@echo "Warning: User-space loader requires Linux/libbpf. Skipping."
endif

# Build unit test program
test: $(TEST_BIN)
	$(TEST_BIN) $(ZONEFILE) $(ORIGIN)

$(TEST_BIN): $(SRC_DIR)/xdp_dns_test.c $(SRC_DIR)/xdp_dns_common.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/xdp_dns_test.c

# Build and run edge case tests
edge: $(EDGE_BIN)
	$(EDGE_BIN)

$(EDGE_BIN): $(SRC_DIR)/xdp_dns_edge.c $(SRC_DIR)/xdp_dns_common.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/xdp_dns_edge.c

# Build and run kernel logic simulation tests
sim: $(SIM_BIN)
	$(SIM_BIN)

$(SIM_BIN): $(SRC_DIR)/xdp_dns_sim.c $(SRC_DIR)/xdp_dns_common.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/xdp_dns_sim.c

# Build performance benchmark tool
bench: $(BENCH_BIN)

$(BENCH_BIN): $(SRC_DIR)/xdp_dns_bench.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/xdp_dns_bench.c $(LDFLAGS)

# Run all tests
test-all: test edge sim
	@echo ""
	@echo "=== All tests complete (target: $(TARGET)) ==="

# Start standalone DNS server on port 15353
server: $(TEST_BIN)
	$(TEST_BIN) -s $(ZONEFILE) $(ORIGIN)

# === Packaging ===

package: all
	@mkdir -p $(DIST_DIR)
	@echo "Building package for $(TARGET)..."
	@PKG_DIR=$(DIST_DIR)/$(PKG_NAME)-$(VERSION)-$(TARGET); \
	rm -rf $$PKG_DIR; mkdir -p $$PKG_DIR/{bin,conf,scripts}; \
	cp $(BUILD_DIR)/simpledns-* $$PKG_DIR/bin/ 2>/dev/null || true; \
	cp $(KERN_OBJ) $$PKG_DIR/bin/ 2>/dev/null || true; \
	cp $(CONF_DIR)/* $$PKG_DIR/conf/; \
	cp $(SCRIPT_DIR)/test_xdp_dns.sh $$PKG_DIR/scripts/; \
	cp $(SCRIPT_DIR)/install.sh $$PKG_DIR/scripts/; \
	cp README.md $$PKG_DIR/; \
	tar czf $(DIST_DIR)/$(PKG_NAME)-$(VERSION)-$(TARGET).tar.gz -C $(DIST_DIR) $(PKG_NAME)-$(VERSION)-$(TARGET); \
	rm -rf $$PKG_DIR; \
	echo "Package: $(DIST_DIR)/$(PKG_NAME)-$(VERSION)-$(TARGET).tar.gz"

package-all:
	@echo "Building all platform packages via Docker..."
	$(CURDIR)/build.sh all

# === Docker build (for cross-compilation on macOS) ===

docker:
	docker build -t simpledns-build .
	@echo ""
	@echo "Build complete. To compile inside container:"
	@echo "  docker run --rm -v $(CURDIR):/work simpledns-build make TARGET=linux-amd64"
	@echo "  docker run --rm -v $(CURDIR):/work simpledns-build make TARGET=linux-arm64"
	@echo "  docker run --rm -v $(CURDIR):/work simpledns-build make package"

# === Cleanup ===

clean:
	rm -rf build dist
	@echo "Build artifacts cleaned."

help:
	@echo "SimpleDns XDP - Build System"
	@echo ""
	@echo "Native build:"
	@echo "  make                    Build everything for current platform"
	@echo "  make test-all           Run all tests"
	@echo "  make package            Build installation package"
	@echo ""
	@echo "Cross-compilation:"
	@echo "  make TARGET=linux-amd64     Cross-compile for Linux x86_64"
	@echo "  make TARGET=linux-arm64     Cross-compile for Linux ARM64"
	@echo "  make TARGET=darwin-amd64    Cross-compile for macOS x86_64"
	@echo "  make TARGET=darwin-arm64    Cross-compile for macOS ARM64"
	@echo ""
	@echo "Packaging:"
	@echo "  make package-all        Build all 4 platform packages"
	@echo "  make docker             Build Docker image for BPF compilation"
	@echo ""
	@echo "Current target: $(TARGET) ($(TARGET_OS)/$(TARGET_ARCH))"
