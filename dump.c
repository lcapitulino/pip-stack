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
#include "utils.h"

struct dump_config {
	FILE *file_eth;
	FILE *file_arp;
	const char *ifname;
};

static void usage(void)
{
	printf("dump: dump packets to specified files\n");
	printf("Usage: dump -i <interface> -e <file> -a <file>\n");
	printf("   -i <interface>: tap interface to use\n");
	printf("   -e <file>     : dump ethernet packates to <file>\n");
	printf("   -a <file>     : dump ARP packates to <file>\n");
	printf("\n");
}

static void dump_parse_cmdline(int argc, char *argv[],
                               struct dump_config *config)
{
	int opt;

	memset(config, 0, sizeof(*config));

	while ((opt = getopt(argc, argv, "a:e:i:h")) != -1) {
		switch (opt) {
		case 'a':
			config->file_arp = xfopen(optarg, "a");
			break;
		case 'e':
			config->file_eth = xfopen(optarg, "a");
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

		ether_dump_frame(config.file_eth, frame);

		if (ether_get_type(frame) == ETHER_TYPE_ARP) {
			arp = arp_from_ether_frame(frame);
			arp_dump_packet(config.file_arp, arp);
			arp_packet_free(arp);
		}

		ether_frame_free(frame);
	}

	ether_dev_put(dev);
	return 0;
}
