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
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <libconfig.h>

#include "common.h"
#include "ether.h"
#include "arp.h"
#include "ipv4.h"
#include "utils.h"

struct uarp_config {
	const char *ifname;
	const char *hwaddr_str;
	const char *ipv4_addr_str;
};

struct uarp_protocol_stack {
	struct ether_device *dev;
	struct ipv4_module  *ipv4;
};

struct uarp_shell_cmds {
	const char *name;
	void (*func)(struct uarp_protocol_stack *dev, const char *cmd);
};

static int uarp_interrupted;

static void uarp_signal_handler(int signum)
{
	if (signum == SIGINT)
		uarp_interrupted = 1;
}

static void uarp_shell_help(struct uarp_protocol_stack *stack, const char *cmd)
{
	printf("\nuarp shell commands:\n\n");
	printf(" whois <ipv4-addr>: send an ARP request\n");
	printf(" reply: waits for ARP requests and reply to them\n");
	printf(" help: this text\n");
	printf("\n");
}

static void uarp_print_errno(const char *msg)
{
	printf("ERROR: %s: %s\n", msg, strerror(errno));
}

static void uarp_shell_whois(struct uarp_protocol_stack *stack,
                             const char *cmd)
{
	const char *ipv4_addr_str;
	char hwaddr_str[24];
	uint8_t hwaddr[6];
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

	err = arp_find_hwaddr(stack->dev, stack->ipv4->ipv4_addr, addr, hwaddr);
	if (err < 0) {
		uarp_print_errno("failed to build ARP request");
		return;
	}

	ether_addr_to_str(hwaddr, hwaddr_str, sizeof(hwaddr_str));
	printf("%s is at %s\n", ipv4_addr_str, hwaddr_str);
}

static void uarp_shell_reply(struct uarp_protocol_stack *stack,
                             const char *cmd)
{
	struct arp_packet *arp_pkt = NULL;
	struct arp_packet *arp_rep;
	struct ether_frame *frame;
	char ipv4_addr[16];
	int err;

	printf("Entering reply loop, press ^C to exit\n");

	while (!uarp_interrupted) {
		arp_packet_free(arp_pkt);
		arp_pkt = NULL;

		frame = ether_dev_recv(stack->dev);
		if (uarp_interrupted) {
			ether_frame_free(frame);
			putchar('\n');
			break;
		}

		if (!frame) {
			uarp_print_errno("can't receive frame");
			break;
		}

		if (ether_get_type(frame) != ETHER_TYPE_ARP) {
			ether_frame_free(frame);
			continue;
		}

		arp_pkt = arp_packet_from_data(ether_get_data(frame),
                                       ether_get_data_size(frame));
		if (!arp_pkt) {
			uarp_print_errno("failed to get ARP packet");
			ether_frame_free(frame);
			continue;
		}

		ether_frame_free(frame);

		if (!arp_packet_is_good(arp_pkt))
			continue;

		if (arp_get_oper(arp_pkt) != ARP_OP_REQ)
			continue;

		if (arp_get_tpa(arp_pkt) != stack->ipv4->ipv4_addr)
			continue;

		/* ARP request for us */
		memset(ipv4_addr, 0, sizeof(ipv4_addr));
		ipv4_addr_to_str(arp_get_spa(arp_pkt), ipv4_addr, sizeof(ipv4_addr));
		printf("%s wants to know about us, sending reply... ", ipv4_addr);

		arp_rep = arp_build_reply(arp_pkt, stack->dev->hwaddr);
		if (!arp_rep) {
			uarp_print_errno("failed to build ARP reply");
			continue;
		}

		err = ether_dev_send(stack->dev, arp_get_tha(arp_rep), ETHER_TYPE_ARP,
                             arp_rep->buf, ARP_PACKET_SIZE);
		if (err < 0)
			uarp_print_errno("failed to send ethernet frame");
		else
			printf("done!\n");

		arp_packet_free(arp_rep);
	}

	uarp_interrupted = 0;
}

static void uarp_shell(struct uarp_protocol_stack *stack)
{
	const struct uarp_shell_cmds shell_cmds[] = {
		{ "help", uarp_shell_help },
		{ "?", uarp_shell_help },
		{ "whois", uarp_shell_whois },
		{ "reply", uarp_shell_reply },
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
	printf("Usage: uarp <config-file>\n");
}

static void xconfig_lookup_string(config_t *cfg,
                                  const char *key, const char **str,
								  const char *config_file_path)
{
	int ret;

	ret = config_lookup_string(cfg, key, str);
	if (!ret) {
		fprintf(stderr, "ERROR: could not locate '%s' in '%s'\n",
                        "iface", config_file_path);
		exit(1);
	}
}

static void read_ipv4_config(const char *config_file_path,
                             struct uarp_config *uarp_cfg)
{
	const char *str;
	config_t cfg;
	int ret;

	config_init(&cfg);

	ret = config_read_file(&cfg, config_file_path);
	if (!ret) {
		fprintf(stderr, "%s:%d - %s\n",
                        config_error_file(&cfg),
						config_error_line(&cfg),
						config_error_text(&cfg));
		exit(1);
	}

	xconfig_lookup_string(&cfg, "iface", &str, config_file_path);
	uarp_cfg->ifname = xstrdup(str);

	xconfig_lookup_string(&cfg, "ipv4_addr", &str, config_file_path);
	uarp_cfg->ipv4_addr_str = xstrdup(str);

	xconfig_lookup_string(&cfg, "hwaddr", &str, config_file_path);
	uarp_cfg->hwaddr_str = xstrdup(str);

	config_destroy(&cfg);
}

int main(int argc, char *argv[])
{
	struct uarp_protocol_stack stack;
	struct uarp_config config;
	struct ether_device *dev;
	struct sigaction act;
	uint8_t hwaddr[6];
	int err;

	if (argc != 2) {
		usage();
		exit(1);
	}

	read_ipv4_config(argv[1], &config);
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

	stack.ipv4 = ipv4_module_alloc(config.ipv4_addr_str);
	if (!stack.ipv4) {
		perror("ipv4_module_alloc()");
		exit(1);
	}

	memset(&act, 0, sizeof(act));
	act.sa_handler = uarp_signal_handler;
	err = sigaction(SIGINT, &act, NULL);
	if (err < 0) {
		perror("sigaction()");
		exit(1);
	}

	uarp_shell(&stack);

	ipv4_module_free(stack.ipv4);
	ether_dev_put(stack.dev);
	return 0;
}
