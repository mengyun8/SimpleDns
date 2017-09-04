src=$(wildcard *.c)
target=$(patsubst %.c,%,$(src))

CC=-gcc 
CFLAGS=-g -m64 -O3 -D_GNU_SOURCE
LDFLAGS= -levent -lpthread -I./PF_RING/

objects=log.o conf.o Dnsdb.o 

all: $(objects)
	$(CC) $(CFLAGS) $(LDFLAGS) $(objects) SimpleDns.c -o SimpleDns

clean:
	rm -f $(target) $(objects)


