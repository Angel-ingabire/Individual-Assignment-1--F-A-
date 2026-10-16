CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O2
LDLIBS = -lcrypto
MODULES = $(wildcard src/*.h src/*.inc)

all: library_tracker

library_tracker: src/main.c $(MODULES)
	$(CC) $(CFLAGS) -o $@ src/main.c $(LDLIBS)

clean:
	rm -f library_tracker library_tracker.exe
