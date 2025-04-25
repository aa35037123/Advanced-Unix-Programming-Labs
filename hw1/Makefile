CC = gcc
CFLAGS = -Wall -fPIC -shared -g
LDFLAGS = -ldl -lcapstone

.PHONY: all clean

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so

libzpoline.so.1: trampoline.c
	$(CC) $(CFLAGS) -o $@ $<

libzpoline.so.2: rewrite.c
	$(CC) $(CFLAGS) -o $@ rewrite.c $(LDFLAGS)

libzpoline.so: hook.c
	$(CC) $(CFLAGS) -o $@ hook.c $(LDFLAGS)

clean:
	rm -f libzpoline.so* *.o*