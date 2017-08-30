src=$(wildcard *.c)
target=$(patsubst %.c,%,$(src))

CC=-gcc 
CFLAGS=-g -m64 -O3
LDFLAGS=


all:$(target)


clean:
	rm -f $(target)


