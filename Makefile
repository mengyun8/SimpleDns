src=$(wildcard *.c)
target=$(patsubst %.c,%,$(src))

CC=gcc 
CFLAGS=-g -m64 -O3 -D_GNU_SOURCE -Wall
LDFLAGS= -levent -lpthread

objects=log.o Dns.o conf.o env.o Dnsdb.o

all: $(objects)
	$(CC) $(CFLAGS) $(LDFLAGS) $(objects) SimpleDns.c -o SimpleDns

install:
	yes|cp SimpleDns.conf /etc/
	mkdir -p /var/SimpleDns/ && yes|cp test.com.zone /var/SimpleDns/

.PHONY: test-all test edge sim bench

# Run XDP test suite (unit + edge + kernel simulation)
test-all:
	cd xdp && $(MAKE) test-all

# Run XDP unit tests only
test:
	cd xdp && $(MAKE) test

# Run XDP DNS protocol edge case tests
edge:
	cd xdp && $(MAKE) edge

# Run XDP kernel logic simulation tests
sim:
	cd xdp && $(MAKE) sim

# Build XDP performance benchmark tool
bench:
	cd xdp && $(MAKE) bench

clean:
	rm -f $(target) $(objects)
	cd xdp && $(MAKE) clean


