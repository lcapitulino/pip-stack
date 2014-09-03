CC=gcc
BIN=uarp
CFLAGS=-Wall -g3 -O0

all: $(BIN)

ether.o: ether.c ether.h common.h
	$(CC) $(CFLAGS) -c $<

uarp.o: uarp.c common.h
	$(CC) $(CFLAGS) -c $<

uarp: uarp.o ether.o
	$(CC) -o $@ $+

clean:
	rm -f $(BIN) *.o core.* tags
