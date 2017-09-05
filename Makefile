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

clean:
	rm -f $(target) $(objects)


