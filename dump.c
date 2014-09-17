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

struct dump_config {
	FILE *file_eth;
	FILE *file_arp;
	FILE *file_ipv4;
	const char *ifname;
};

static void usage(void)
{
	printf("dump: dump packets to specified files\n");
	printf("Usage: dump -i <interface> [-e file] [-a file]\n");
	printf("   -i <interface>: tap interface to use\n");
	printf("   -e <file>     : dump ethernet packates to <file>\n");
	printf("   -a <file>     : dump ARP packates to <file>\n");
	printf("   -4 <file>     : dump IPv4 datagrams to <file>\n");
	printf("\n");
}

static void dump_parse_cmdline(int argc, char *argv[],
                               struct dump_config *config)
{
	int opt;

	memset(config, 0, sizeof(*config));

	while ((opt = getopt(argc, argv, "a:e:4:i:h")) != -1) {
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

int main(int argc, char *argv[])
{
	struct ipv4_datagram *ipv4_dtg;
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

		if (config.file_ipv4 && ether_get_type(frame) == ETHER_TYPE_IPV4) {
			ipv4_dtg = ipv4_datagram_from_data(ether_get_data(frame),
                                               ether_get_data_size(frame));
			ipv4_dump_datagram(config.file_ipv4, ipv4_dtg);
			ipv4_datagram_free(ipv4_dtg);
		}

		ether_frame_free(frame);
	}

	ether_dev_put(dev);
	return 0;
}
