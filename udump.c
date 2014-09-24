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
#include "common.h"
#include "ether.h"
#include "arp.h"
#include "ipv4.h"
#include "utils.h"
#include "udp.h"

struct dump_config {
	FILE *file_eth;
	FILE *file_arp;
	FILE *file_ipv4;
	FILE *file_udp;
	const char *ifname;
};

static void usage(void)
{
	printf("udump: dump packets to specified files\n");
	printf("Usage: dump -i <interface> [-e file] [-a file] [-4 file] [-u file]\n");
	printf("   -i <interface>: tap interface to use\n");
	printf("   -e <file>     : dump ethernet packates to <file>\n");
	printf("   -a <file>     : dump ARP packates to <file>\n");
	printf("   -4 <file>     : dump IPv4 datagrams to <file>\n");
	printf("   -u <file>     : dump UDP datagrams to <file>\n");
	printf("\n");
}

static void dump_parse_cmdline(int argc, char *argv[],
                               struct dump_config *config)
{
	int opt;

	memset(config, 0, sizeof(*config));

	while ((opt = getopt(argc, argv, "a:e:4:u:i:h")) != -1) {
		switch (opt) {
		case 'a':
			config->file_arp = xfopen(optarg, "a");
			break;
		case 'e':
			config->file_eth = xfopen(optarg, "a");
			break;
		case '4':
			config->file_ipv4 = xfopen(optarg, "a");
			break;
		case 'u':
			config->file_udp = xfopen(optarg, "a");
			break;
		case 'i':
			config->ifname = optarg;
			break;
		case 'h':
		default:
			usage();
			exit(1);
		}
	}
}

static void dump_ipv4(const struct dump_config *config,
                      const struct ether_frame *frame)
{
	struct ipv4_datagram *ipv4_dtg;
	struct udp_datagram *udp_dtg;

	ipv4_dtg = ipv4_datagram_from_data(ether_get_data(frame),
                                       ether_get_data_size(frame));
	if (!ipv4_dtg) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		return;
	}

	if (config->file_ipv4)
		ipv4_dump_datagram(config->file_ipv4, ipv4_dtg);

	if (config->file_udp && ipv4_get_protocol(ipv4_dtg) == IPV4_PROT_UDP) {
		udp_dtg = udp_datagram_from_data(ipv4_get_data(ipv4_dtg),
                                         ipv4_get_data_size(ipv4_dtg));
		udp_dump_datagram(config->file_udp, udp_dtg);
		udp_datagram_free(udp_dtg);
	}

	ipv4_datagram_free(ipv4_dtg);
}

int main(int argc, char *argv[])
{
	struct dump_config config;
	struct ether_frame *frame;
	struct ether_device *dev;
	struct arp_packet *arp;
	int err;

	dump_parse_cmdline(argc, argv, &config);
	die_if_not_passed("ifname", config.ifname);

	dev = ether_dev_alloc(NULL);

	err = ether_dev_open(dev, config.ifname);
	if (err < 0) {
		perror("ether_dev_open()");
		exit(1);
	}

	while (true) {
		frame = ether_dev_recv(dev);
		if (!frame) {
			perror("ether_dev_recv()");
			break;
		}

		if (config.file_eth)
			ether_dump_frame(config.file_eth, frame);

		if (config.file_arp && ether_get_type(frame) == ETHER_TYPE_ARP) {
			arp = arp_packet_from_data(ether_get_data(frame),
                                       ether_get_data_size(frame));
			arp_dump_packet(config.file_arp, arp);
			arp_packet_free(arp);
		}

		if (ether_get_type(frame) == ETHER_TYPE_IPV4)
			dump_ipv4(&config, frame);

		ether_frame_free(frame);
	}

	ether_dev_put(dev);
	return 0;
}
