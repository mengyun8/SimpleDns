src=$(wildcard *.c)
target=$(patsubst %.c,%,$(src))

CC=-gcc 
CFLAGS=-g -m64 -O3 -D_GNU_SOURCE
LDFLAGS= -levent -lpthread


all:$(target)


clean:
	rm -f $(target)


