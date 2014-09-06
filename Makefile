CC=gcc
BIN=uarp
CFLAGS=-Wall -g3 -O0

all: $(BIN)

misc.o: misc.c misc.h common.h
	$(CC) $(CFLAGS) -c $<

ipv4.o: ipv4.c ipv4.h misc.h common.h
	$(CC) $(CFLAGS) -c $<

skbuf.o: skbuf.c skbuf.h common.h
	$(CC) $(CFLAGS) -c $<

arp.o: arp.c arp.h common.h misc.h ether.h
	$(CC) $(CFLAGS) -c $<

ether.o: ether.c ether.h common.h misc.h
	$(CC) $(CFLAGS) -c $<

uarp.o: uarp.c common.h ether.h arp.h misc.h
	$(CC) $(CFLAGS) -c $<

uarp: uarp.o ether.o misc.o arp.o ipv4.o -lefence -lreadline
	$(CC) -o $@ $+

clean:
	rm -f $(BIN) *.o core.* tags
