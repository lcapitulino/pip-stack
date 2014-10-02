ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
    QUIET_CC       = @echo ' ' CC '  '$@;
    QUIET_LK       = @echo ' ' LINK $@;
endif
endif

CC := gcc
CFLAGS := -Wall -ggdb -O0
BIN := uarp udump uping
TESTS := check-utils check-ether check-arp check-ipv4
MODULES_OBJS := utils.o ether.o arp.o ipv4.o udp.o
LIBS := -lefence -lconfig

all: $(BIN)

utils.o: utils.c utils.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

udp.o: udp.c udp.h utils.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

ipv4.o: ipv4.c ipv4.h ether.h utils.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

arp.o: arp.c arp.h common.h utils.h ether.h arp.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

ether.o: ether.c ether.h common.h utils.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

uarp.o: uarp.c common.h ether.h arp.h utils.h ipv4.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

uarp: uarp.o $(MODULES_OBJS) $(LIBS) -lreadline
	$(QUIET_LK)$(CC) -o $@ $+

uping.o: uping.c common.h ether.h arp.h utils.h ipv4.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

uping: uping.o $(MODULES_OBJS) $(LIBS)
	$(QUIET_LK)$(CC) -o $@ $+

udump.o: udump.c common.h ether.h arp.h udp.h utils.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

udump: udump.o $(MODULES_OBJS) $(LIBS)
	$(QUIET_LK)$(CC) -o $@ $+

###
### Tests
###

check-utils.o: check-utils.c utils.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

check-utils: check-utils.o utils.o -lcheck -lefence
	$(QUIET_LK)$(CC) -o $@ $+

check-ether.o: check-ether.c ether.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

check-ether: check-ether.o ether.o utils.o -lcheck -lefence
	$(QUIET_LK)$(CC) -o $@ $+

check-arp.o: check-arp.c arp.h ether.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

check-arp: check-arp.o arp.o ether.o utils.o -lcheck -lefence
	$(QUIET_LK)$(CC) -o $@ $+

check-ipv4.o: check-ipv4.c ipv4.h ether.h common.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c $<

check-ipv4: check-ipv4.o ipv4.o arp.o ether.o utils.o $(LIBS) -lcheck
	$(QUIET_LK)$(CC) -o $@ $+

check: $(TESTS)
	@for t in $+; do ./$$t; done

clean:
	@rm -f $(BIN) $(TESTS) *.o core.* tags
