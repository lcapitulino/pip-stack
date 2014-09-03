CC=gcc
BIN=xarp
CFLAGS=-Wall -g3 -O0

all: $(BIN)

ether.o: ether.c ether.h common.h
	$(CC) $(CFLAGS) -c $<

xarp.o: xarp.c common.h
	$(CC) $(CFLAGS) -c $<

xarp: xarp.o ether.o
	$(CC) -o $@ $+

clean:
	rm -f $(BIN) *.o core.* tags
