CC = gcc
CFLAGS = -Wall -fPIC -shared -g
LDFLAGS = -ldl -lcapstone

.PHONY: all clean

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so logger.so

libzpoline.so.1: trampoline.c
	$(CC) $(CFLAGS) -o $@ $<

libzpoline.so.2: rewrite.c
	$(CC) $(CFLAGS) -o $@ rewrite.c $(LDFLAGS)

libzpoline.so: hook.c
	$(CC) $(CFLAGS) -o $@ hook.c $(LDFLAGS)

logger.so: logger.c
	$(CC) $(CFLAGS) -o $@ logger.c $(LDFLAGS)

clean:
	rm -f libzpoline.so* logger.so *.o* index.html* main.c