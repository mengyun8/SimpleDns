#
# XDP DNS - Build System
#
# Targets:
#   make test      - Build and run unit tests (macOS + Linux)
#   make test-all  - Build and run all tests (unit + edge + sim + bench)
#   make edge      - Build and run DNS protocol edge case tests
#   make sim       - Build and run XDP kernel logic simulation tests
#   make bench     - Build performance benchmark tool
#   make kern      - Compile XDP BPF kernel program (Linux only)
#   make user      - Build user-space loader + fallback server (Linux only)
#   make all       - Build everything (Linux only)
#   make server    - Start standalone test DNS server (port 15353)
#   make clean     - Remove build artifacts
#

CC       = gcc
CLANG    = clang
CFLAGS   = -O2 -g -Wall -Wextra
BPFFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall -Wextra
LDFLAGS  = -lbpf -lelf -lz
BENCHLD  = -lpthread

# Detect OS
UNAME_S := $(shell uname -s)

# Zone file and origin for testing
ZONEFILE ?= ../test.com.zone
ORIGIN   ?= test.com

.PHONY: all test test-all edge sim bench kern user server clean docker

# === Linux: Full build ===
ifeq ($(UNAME_S),Linux)

all: kern user test

# Compile XDP BPF kernel program
kern: xdp_dns_kern.o

xdp_dns_kern.o: xdp_dns_kern.c xdp_dns_common.h
	$(CLANG) $(BPFFLAGS) -c xdp_dns_kern.c -o xdp_dns_kern.o

# Build user-space loader
user: xdp_dns_user

xdp_dns_user: xdp_dns_user.c xdp_dns_common.h
	$(CC) $(CFLAGS) -o xdp_dns_user xdp_dns_user.c $(LDFLAGS)

# Build unit test program
xdp_dns_test: xdp_dns_test.c xdp_dns_common.h
	$(CC) $(CFLAGS) -o xdp_dns_test xdp_dns_test.c

# Build edge case test program
xdp_dns_edge: xdp_dns_edge.c xdp_dns_common.h
	$(CC) $(CFLAGS) -o xdp_dns_edge xdp_dns_edge.c

# Build XDP kernel logic simulation test program
xdp_dns_sim: xdp_dns_sim.c xdp_dns_common.h
	$(CC) $(CFLAGS) -o xdp_dns_sim xdp_dns_sim.c

# Build performance benchmark tool
xdp_dns_bench: xdp_dns_bench.c
	$(CC) $(CFLAGS) -o xdp_dns_bench xdp_dns_bench.c $(BENCHLD)

# Run unit tests
test: xdp_dns_test
	./xdp_dns_test $(ZONEFILE) $(ORIGIN)

# Run edge case tests
edge: xdp_dns_edge
	./xdp_dns_edge

# Run XDP kernel logic simulation tests
sim: xdp_dns_sim
	./xdp_dns_sim

# Build (but don't run) the benchmark tool
bench: xdp_dns_bench

# Run all tests sequentially
test-all: test edge sim
	@echo ""
	@echo "=== All tests complete ==="

# Start standalone DNS server on port 15353
server: xdp_dns_test
	./xdp_dns_test -s $(ZONEFILE) $(ORIGIN)

# Load and run XDP DNS on an interface
# Usage: make run IF=eth0
run: all
	sudo ./xdp_dns_user -i $(IF) -z $(ZONEFILE) -o $(ORIGIN) -v

clean:
	rm -f xdp_dns_kern.o xdp_dns_user xdp_dns_test xdp_dns_edge xdp_dns_sim xdp_dns_bench

# === macOS: Test-only build ===
else

all: test

xdp_dns_test: xdp_dns_test.c xdp_dns_common.h
	$(CC) $(CFLAGS) -o xdp_dns_test xdp_dns_test.c

xdp_dns_edge: xdp_dns_edge.c xdp_dns_common.h
	$(CC) $(CFLAGS) -o xdp_dns_edge xdp_dns_edge.c

xdp_dns_sim: xdp_dns_sim.c xdp_dns_common.h
	$(CC) $(CFLAGS) -o xdp_dns_sim xdp_dns_sim.c

xdp_dns_bench: xdp_dns_bench.c
	$(CC) $(CFLAGS) -o xdp_dns_bench xdp_dns_bench.c $(BENCHLD)

test: xdp_dns_test
	./xdp_dns_test $(ZONEFILE) $(ORIGIN)

edge: xdp_dns_edge
	./xdp_dns_edge

sim: xdp_dns_sim
	./xdp_dns_sim

bench: xdp_dns_bench

test-all: test edge sim
	@echo ""
	@echo "=== All tests complete ==="

server: xdp_dns_test
	./xdp_dns_test -s $(ZONEFILE) $(ORIGIN)

kern user:
	@echo "Error: BPF/XDP build requires Linux. Use 'make docker' for containerized build."
	@exit 1

clean:
	rm -f xdp_dns_test xdp_dns_edge xdp_dns_sim xdp_dns_bench

endif

# === Docker build (for macOS users) ===
docker:
	docker build -t xdp-dns-build .
	@echo ""
	@echo "Build complete. To compile BPF program inside container:"
	@echo "  docker run --rm -v $(PWD):/work xdp-dns-build make kern"
	@echo "  docker run --rm -v $(PWD):/work xdp-dns-build make user"
	@echo "  docker run --rm -v $(PWD):/work xdp-dns-build make test-all"
