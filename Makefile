CC=gcc
BIN=xarp
CFLAGS=-Wall -g3 -O0

all: $(BIN)

misc.o: misc.c misc.h common.h
	$(CC) $(CFLAGS) -c $<

xarp.o: xarp.c common.h
	$(CC) $(CFLAGS) -c $<

xarp: xarp.o misc.o
	$(CC) -o $@ $+

clean:
	rm -f $(BIN) *.o core.* tags
