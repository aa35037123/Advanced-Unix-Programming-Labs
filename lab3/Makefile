# Native Makefile (for aarch64 or x86 machines)

CC = gcc
CFLAGS = -fPIC -Wall

all: libgotoku.so gotoku.local libsolver.so

libgotoku.so: libgotoku_dummy.c libgotoku.h
	$(CC) $(CFLAGS) -shared -o $@ $^

libsolver.so: libsolver.c
	$(CC) -g $(CFLAGS) -shared -o $@ $^ -ldl

gotoku.local: gotoku.c
	$(CC) -o $@ $^ -L. -lgotoku -Wl,-rpath=.

clean:
	rm -f *.so *.o gotoku.local

