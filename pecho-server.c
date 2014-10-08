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
#include "pip-api.h"
#include "common.h"
#include "ether.h"
#include "ipv4.h"
#include "udp.h"
#include "arp.h"
#include "utils.h"

#define ECHO_SERVER_PORT 7

struct eserver {
	uint16_t port;
	struct pip_stack *stack;
};

static int echo_server_send_reply(const struct pip_stack *stack,
                                  const struct ipv4_datagram *ipv4_dtg,
                                  const struct udp_datagram *udp_dtg)
{
	return udp_send_datagram(stack->dev, stack->ipv4_mod, ECHO_SERVER_PORT,
                             ipv4_get_src_addr(ipv4_dtg),
							 udp_get_src_port(udp_dtg),
							 udp_get_data(udp_dtg), udp_get_data_size(udp_dtg));
}

static void print_datagram(const struct udp_datagram *udp_dtg,
                           const struct ipv4_datagram *ipv4_dtg)
{
	const uint8_t *p;
	size_t size;
	char str[32];
	int i;

	ipv4_addr_to_str(ipv4_get_dst_addr(ipv4_dtg), str, sizeof(str));
	fprintf(stderr, "Datagram from %s:%d\n", str, udp_get_src_port(udp_dtg));

	p = udp_get_data(udp_dtg);
	size = udp_get_data_size(udp_dtg);

	if (size > 0) {
		fprintf(stderr, "Contents: ");
		for (i = 0; i < size; i++) {
			if (isascii(p[i]))
				fprintf(stderr, "%c", p[i]);
			}
	}

	fprintf(stderr, "\n");
}

static int echo_server_recv(struct ether_frame *frame, void *data)
{
	struct udp_datagram *udp_dtg = NULL;
	struct ipv4_datagram *ipv4_dtg;
	struct eserver *eserver = data;
	int ret = ETHER_DISP_CONT;

	ipv4_dtg = ipv4_datagram_from_data(ether_get_data(frame),
                                       ether_get_data_size(frame));
	if (!ipv4_dtg)
		return ETHER_DISP_ERR;

	if (!ipv4_datagram_is_good(ipv4_dtg))
		goto out;

	if (ipv4_get_dst_addr(ipv4_dtg) != eserver->stack->ipv4_mod->ipv4_host_addr)
		goto out;

	if (ipv4_get_protocol(ipv4_dtg) != IPV4_PROT_UDP)
		goto out;

	udp_dtg = udp_datagram_from_data(ipv4_get_data(ipv4_dtg),
                                     ipv4_get_data_size(ipv4_dtg));
	if (!udp_dtg)
		goto out;

	if (udp_get_dst_port(udp_dtg) != eserver->port)
		goto out;

	print_datagram(udp_dtg, ipv4_dtg);
	echo_server_send_reply(eserver->stack, ipv4_dtg, udp_dtg);

out:
	ipv4_datagram_free(ipv4_dtg);
	udp_datagram_free(udp_dtg);
	return ret;
}

static int echo_server_arp_reply(struct ether_frame *frame, void *data)
{
	struct eserver *eserver = data;
	struct pip_stack *stack = eserver->stack;
	struct arp_packet *arp_pkt, *arp_rep;
	int err, ret = ETHER_DISP_CONT;

	arp_pkt = arp_packet_from_data(ether_get_data(frame),
                                   ether_get_data_size(frame));
	if (!arp_pkt)
		return ETHER_DISP_ERR;

	if (!arp_packet_is_good(arp_pkt))
		goto out;

	if (arp_get_oper(arp_pkt) != ARP_OP_REQ)
		goto out;

	if (arp_get_tpa(arp_pkt) != stack->ipv4_mod->ipv4_host_addr)
		goto out;

	arp_rep = arp_build_reply(arp_pkt, stack->dev->hwaddr);
	if (!arp_rep) {
		ret = ETHER_DISP_ERR;
		goto out;
	}

	err = ether_dev_send(stack->dev, arp_get_tha(arp_rep), ETHER_TYPE_ARP,
                         arp_rep->buf, ARP_PACKET_SIZE);
	if (err < 0)
		ret = ETHER_DISP_ERR;

	arp_packet_free(arp_rep);
	
out:
	arp_packet_free(arp_pkt);
	return ret;
}

static void usage(void)
{
	printf("pechp-server <configfile> <port>\n");
}

int main(int argc, char *argv[])
{
	struct pip_stack pip_stack;
	struct ether_dispatch disp;
	struct eserver eserver;
	int ret;

	if (argc != 3) {
		usage();
		exit(1);
	}

	pip_stack_init(&pip_stack, argv[1]);
	eserver.port = atoi(argv[2]);
	eserver.stack = &pip_stack;

	sleep(1);

	memset(&disp, 0, sizeof(disp));
	disp.handler_ipv4 = echo_server_recv;
	disp.handler_arp  = echo_server_arp_reply;
	disp.data = &eserver;
	ret = ether_dev_recv_dispatch(pip_stack.dev, &disp, -1);
	if (ret < 0) {
		perror("ether_dev_dispatch()");
		exit(1);
	}

	return 0;
}
