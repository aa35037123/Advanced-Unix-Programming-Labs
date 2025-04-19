CC = gcc
CFLAGS = -Wall -fPIC -shared -g
LDFLAGS = -ldl -lcapstone

.PHONY: all clean

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so.3

libzpoline.so.1: trampoline.c
	$(CC) $(CFLAGS) -o $@ $<

libzpoline.so.2: rewrite.c
	$(CC) $(CFLAGS) -o $@ rewrite.c $(LDFLAGS)

libzpoline.so.3: main.c utils.c utils.h
	$(CC) $(CFLAGS) -o $@ main.c utils.c $(LDFLAGS)

clean:
	rm -f *.so* *.o*