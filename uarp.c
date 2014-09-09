/*
 *  Copyright 2014 Luiz Capitulino
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation version 2.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "common.h"
#include "ether.h"
#include "arp.h"
#include "ipv4.h"
#include "misc.h"

struct uarp_config {
	const char *ifname;
	const char *hwaddr_str;
	const char *ipv4_addr_str;
};

struct uarp_protocol_stack {
	struct ether_device *dev;
	struct ipv4_object  *ipv4;
};

struct uarp_shell_cmds {
	const char *name;
	void (*func)(struct uarp_protocol_stack *dev, const char *cmd);
};

static void uarp_shell_help(struct uarp_protocol_stack *stack, const char *cmd)
{
	printf("\nuarp shell commands:\n\n");
	printf(" who-is <ipv4-addr>: send an ARP request\n");
	printf(" help: this text\n");
	printf("\n");
}

static void uarp_print_errno(const char *msg)
{
	printf("ERROR: %s: %s\n", msg, strerror(errno));
}

static void uarp_shell_arp_request(struct uarp_protocol_stack *stack,
								   const char *cmd)
{
	struct arp_packet *arp_pkt;
	struct ether_frame *frame;
	const char *ipv4_addr_str;
	char hwaddr_str[24];
	in_addr_t addr;
	int err;

	ipv4_addr_str = strchr(cmd, ' ');
	if (!ipv4_addr_str) {
		printf("ERROR: bad arp request command: %s\n", cmd);
		return;
	}

	addr = inet_network(++ipv4_addr_str);
	if (addr == -1) {
		printf("ERROR: bad IPv4 address: %s\n", ipv4_addr_str);
		return;
	}

	arp_pkt = arp_build_request(stack->dev->hwaddr, stack->ipv4->ipv4_addr,
								ETHER_TYPE_IPV4, addr);
	if (!arp_pkt) {
		uarp_print_errno("failed to build ARP request");
		return;
	}

	err = ether_dev_send_bcast(stack->dev, ETHER_TYPE_ARP,
							   arp_pkt->buf, ARP_PACKET_SIZE);
	if (err < 0) {
		uarp_print_errno("failed to send ARP request");
		arp_packet_free(arp_pkt);
		return;
	}

	while (true) {
		arp_packet_free(arp_pkt);

		frame = ether_dev_recv(stack->dev);
		if (!frame) {
			uarp_print_errno("can't receive frame");
			return;
		}

		if (ether_get_type(frame) != ETHER_TYPE_ARP) {
			ether_frame_free(frame);
			arp_pkt = NULL;
			continue;
		}

		arp_pkt = arp_from_ether_frame(frame);
		if (!arp_pkt) {
			uarp_print_errno("failed to get ARP packet");
			ether_frame_free(frame);
			return;
		}

		ether_frame_free(frame);

		if (!arp_packet_is_good(arp_pkt))
			continue;

		if (arp_get_oper(arp_pkt) != ARP_OP_REP)
			continue;

		if (arp_get_spa(arp_pkt) != addr)
			continue;

		ether_addr_to_str(arp_get_sha(arp_pkt), hwaddr_str, sizeof(hwaddr_str));
		printf("%s is %s\n", ipv4_addr_str, hwaddr_str);
		arp_packet_free(arp_pkt);
		break;
	}
}

static void uarp_shell(struct uarp_protocol_stack *stack)
{
	const struct uarp_shell_cmds shell_cmds[] = {
		{ "help", uarp_shell_help },
		{ "?", uarp_shell_help },
		{ "who-is", uarp_shell_arp_request },
		{ .name = NULL }
	}, *p;
	char *cmd;
	int i;

	p = shell_cmds;
	while (true) {
		cmd = readline("uarp> ");
		if (!cmd) {
			putchar('\n');
			break;
		} else if (cmd[0] == '\0') {
			free(cmd);
			continue;
		}

		for (i = 0; p[i].name; i++) {
			if (!strncmp(p[i].name, cmd, strlen(p[i].name))) {
				p[i].func(stack, cmd);
				break;
			}
		}

		if (!shell_cmds[i].name)
			printf("command not found: %s\n", cmd);

		free(cmd);
	}
}

static void usage(void)
{
	printf("uarp: a user-space ARP tool\n");
	printf("Usage: uarp -i <interface> -a <hwaddr> -I <ipv4addr>\n");
	printf("   -i <interface>: tap interface to use\n");
	printf("   -a <hwaddr>   : hardware address\n");
	printf("   -I            : IPv4 address\n");
	printf("\n");
}

static void uarp_parse_cmdline(int argc, char *argv[],
							   struct uarp_config *config)
{
	int opt;

	memset(config, 0, sizeof(*config));

	while ((opt = getopt(argc, argv, "a:hi:I:")) != -1) {
		switch (opt) {
		case 'a':
			config->hwaddr_str = optarg;
			break;
		case 'i':
			config->ifname = optarg;
			break;
		case 'I':
			config->ipv4_addr_str = optarg;
			break;
		case 'h':
		default:
			usage();
			exit(1);
		}
	}
}

int main(int argc, char *argv[])
{
	struct uarp_protocol_stack stack;
	struct uarp_config config;
	struct ether_device *dev;
	uint8_t hwaddr[6];
	int err;

	uarp_parse_cmdline(argc, argv, &config);
	die_if_not_passed("ifname", config.ifname);
	die_if_not_passed("hwaddr", config.hwaddr_str);
	die_if_not_passed("ipv4addr", config.ipv4_addr_str);

	ether_str_to_addr(config.hwaddr_str, hwaddr);

	dev = ether_dev_alloc(hwaddr);
	if (!dev) {
		perror("ether_dev_alloc()");
		exit(1);
	}

	err = ether_dev_open(dev, config.ifname);
	if (err < 0) {
		perror("ether_dev_open()");
		exit(1);
	}

	xsetunbuf(stdout);

	memset(&stack, 0, sizeof(stack));
	stack.dev = dev;

	stack.ipv4 = ipv4_object_alloc(config.ipv4_addr_str);
	if (!stack.ipv4) {
		perror("ipv4_object_alloc()");
		exit(1);
	}

	uarp_shell(&stack);

	ipv4_object_free(stack.ipv4);
	ether_dev_put(stack.dev);
	return 0;
}
