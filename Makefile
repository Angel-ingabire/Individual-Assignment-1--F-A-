CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O2
LDLIBS = -lcrypto

all: library_tracker

library_tracker: src/main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f library_tracker library_tracker.exe blockchain.dat signing_key.pem
