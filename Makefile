ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
    QUIET_CC       = @echo ' ' CC '  '$@;
    QUIET_LK       = @echo ' ' LINK $@;
endif
endif

CC := gcc
CFLAGS := -Wall -ggdb -O0
BIN := uarp dump

all: $(BIN)

misc.o: misc.c misc.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

ipv4.o: ipv4.c ipv4.h misc.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

skbuf.o: skbuf.c skbuf.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

arp.o: arp.c arp.h common.h misc.h ether.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

ether.o: ether.c ether.h common.h misc.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

uarp.o: uarp.c common.h ether.h arp.h misc.h ipv4.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

uarp: uarp.o ether.o misc.o arp.o ipv4.o -lefence -lreadline
	$(QUIET_LK)$(CC) -o $@ $+

dump.o: dump.c common.h ether.h arp.h misc.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

dump: dump.o ether.o misc.o arp.o -lefence
	$(QUIET_LK)$(CC) -o $@ $+

clean:
	@rm -f $(BIN) *.o core.* tags
