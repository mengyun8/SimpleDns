src=$(wildcard *.c)
target=$(patsubst %.c,%,$(src))

CC=gcc 
CFLAGS=-g -m64 -O3 -D_GNU_SOURCE -Wall
LDFLAGS= -levent -lpthread

objects=log.o conf.o Dnsdb.o Dns.o 

all: $(objects)
	$(CC) $(CFLAGS) $(LDFLAGS) $(objects) SimpleDns.c -o SimpleDns

clean:
	rm -f $(target) $(objects)


