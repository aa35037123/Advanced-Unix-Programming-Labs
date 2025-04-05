# Makefile
CC=x86_64-linux-gnu-gcc
CFLAGS=-fPIC -Wall

all: libgotoku.so gotoku.local libsolver.so

libgotoku.so: libgotoku_dummy.c libgotoku.h
	$(CC) -shared -fPIC -o $@ $^

libsolver.so: libsolver.c
	$(CC) -shared -fPIC -o $@ $^ -ldl

gotoku.local: gotoku.c
	$(CC) -o $@ $^  -L. -lgotoku -Wl,-rpath=.

clean:
	rm -f *.so *.o gotoku.local

