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
	const char *path_dump_eth;
	const char *path_dump_arp;
	const char *ipv4_addr_str;
	bool dump_mode;
};

struct uarp_protocol_stack {
	struct ether_device *dev;
	struct ipv4_object  *ipv4;
};

struct uarp_shell_cmds {
	const char *name;
	void (*func)(struct uarp_protocol_stack *dev, const char *cmd);
};

static void uarp_dump_loop(struct ether_device *dev,
						   FILE *file_dump_eth,
						   FILE *file_dump_arp)
{
	struct ether_frame *frame;
	struct arp_packet *arp;

	if (!file_dump_eth && !file_dump_arp) {
		fprintf(stderr, "ERROR: dump mode requires a file to dump to\n");
		exit(1);
	}

	while (true) {
		frame = ether_dev_recv(dev);
		if (!frame) {
			perror("ether_dev_recv()");
			break;
		}

		if (file_dump_eth)
			ether_dump_frame(file_dump_eth, frame);

		if (ether_get_type(frame) == ETHER_TYPE_ARP) {
			arp = arp_from_ether_frame(frame);
			if (file_dump_arp)
				arp_dump_packet(file_dump_arp, arp);
			arp_packet_free(arp);
		}

		ether_frame_free(frame);
	}
}

static void uarp_shell_help(struct uarp_protocol_stack *stack, const char *cmd)
{
	printf("\nuarp shell commands:\n\n");
	printf("   help: this text\n");
	printf("\n");
}

static void uarp_shell_arp_request(struct uarp_protocol_stack *stack,
								   const char *cmd)
{
	struct arp_packet *arp;
	in_addr_t addr;
	const char *p;

	p = strchr(cmd, ' ');
	if (!p) {
		printf("ERROR: bad arp request command: %s\n", cmd);
		return;
	}

	addr = inet_network(++p);
	if (addr == -1) {
		printf("ERROR: bad IPv4 address: %s\n", p);
		return;
	}

	arp = arp_build_request(ETHER_TYPE_IPV4, stack->dev->hwaddr,
							stack->ipv4->ipv4_addr, addr);
	if (!arp) {
		printf("ERROR: failed to build ARP request: %s\n", strerror(errno));
		return;
	}

	arp_dump_packet(stdout, arp);
	arp_packet_free(arp);
}

static void uarp_shell(struct uarp_protocol_stack *stack,
					   FILE *file_dump_eth,
					   FILE *file_dump_arp)
{
	const struct uarp_shell_cmds shell_cmds[] = {
		{ "help", uarp_shell_help },
		{ "?", uarp_shell_help },
		{ "arp-request", uarp_shell_arp_request },
		{ .name = NULL }
	};
	char *cmd;
	int i;

	while (true) {
		cmd = readline("uarp> ");
		if (!cmd) {
			putchar('\n');
			break;
		} else if (cmd[0] == '\0') {
			free(cmd);
			continue;
		}

		for (i = 0; shell_cmds[i].name; i++) {
			if (!strncmp(shell_cmds[i].name, cmd, strlen(shell_cmds[i].name))) {
				shell_cmds[i].func(stack, cmd);
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
	printf("Usage: uarp -i <interface> -a <hwaddr> -I <ipv4addr>");
	printf("[-E file] [-R file] [-D]\n\n");
	printf("   -i <interface>: tap interface to use\n");
	printf("   -a <hwaddr>   : hardware address\n");
	printf("   -E <file>     : dump ethernet packates to <file>\n");
	printf("   -A <file>     : dump ARP packates to <file>\n");
	printf("   -D            : dump mode (requires -E or -A)\n");
	printf("   -I            : IPv4 address\n");
	printf("\n");
}

static void uarp_parse_cmdline(int argc, char *argv[],
							   struct uarp_config *config)
{
	int opt;

	memset(config, 0, sizeof(*config));

	while ((opt = getopt(argc, argv, "a:DE:hi:I:R:")) != -1) {
		switch (opt) {
		case 'a':
			config->hwaddr_str = optarg;
			break;
		case 'D':
			config->dump_mode = true;
			break;
		case 'E':
			config->path_dump_eth = optarg;
			break;
		case 'i':
			config->ifname = optarg;
			break;
		case 'I':
			config->ipv4_addr_str = optarg;
			break;
		case 'R':
			config->path_dump_arp = optarg;
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
	FILE *file_dump_eth, *file_dump_arp;
	struct uarp_protocol_stack stack;
	struct uarp_config config;
	struct ether_device dev;
	int err;

	file_dump_eth = file_dump_arp = NULL;

	uarp_parse_cmdline(argc, argv, &config);
	die_if_not_passed("ifname", config.ifname);
	die_if_not_passed("hwaddr", config.hwaddr_str);
	if (!config.dump_mode)
		die_if_not_passed("ipv4addr", config.ipv4_addr_str);

	if (config.path_dump_eth)
		file_dump_eth = xfopen(config.path_dump_eth, "a");

	if (config.path_dump_arp)
		file_dump_arp = xfopen(config.path_dump_arp, "a");

	err = ether_dev_open(&dev, config.ifname, config.hwaddr_str);
	if (err < 0) {
		perror("ether_dev_open()");
		exit(1);
	}

	memset(&stack, 0, sizeof(stack));
	stack.dev = &dev;

	if (config.dump_mode) {
		uarp_dump_loop(stack.dev, file_dump_eth, file_dump_arp);
	} else {
		stack.ipv4 = ipv4_object_alloc(config.ipv4_addr_str);
		if (!stack.ipv4) {
			perror("ipv4_object_alloc()");
			exit(1);
		}

		uarp_shell(&stack, file_dump_eth, file_dump_arp);
		ipv4_object_free(stack.ipv4);
	}

	ether_dev_close(&dev);
	return 0;
}
