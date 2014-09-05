CC=gcc
BIN=uarp
CFLAGS=-Wall -g3 -O0

all: $(BIN)

misc.o: misc.c misc.h common.h
	$(CC) $(CFLAGS) -c $<

skbuf.o: skbuf.c skbuf.h common.h
	$(CC) $(CFLAGS) -c $<

ether.o: ether.c ether.h common.h skbuf.h
	$(CC) $(CFLAGS) -c $<

uarp.o: uarp.c common.h misc.h
	$(CC) $(CFLAGS) -c $<

uarp: uarp.o ether.o skbuf.o misc.o -lefence
	$(CC) -o $@ $+

clean:
	rm -f $(BIN) *.o core.* tags
