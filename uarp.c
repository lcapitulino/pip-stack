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
#include "misc.h"

static void uarp_dump_loop(struct ether_device *dev,
						   FILE *file_dump_eth,
						   FILE *file_dump_arp)
{
	struct ether_frame *frame;
	struct arp_packet *arp;
	int err;

	if (!file_dump_eth && !file_dump_arp) {
		fprintf(stderr, "ERROR: dump mode requires a file to dump to\n");
		exit(1);
	}

	while (true) {
		frame = ether_frame_alloc();
		if (!frame) {
			perror("ether_frame_alloc()");
			break;
		}

		err = ether_dev_recv(dev, frame);
		if (err < 0) {
			perror("ether_dev_recv()");
			break;
		}

		if (file_dump_eth)
			ether_dump_frame(file_dump_eth, frame);

		if (ether_get_type(frame) == ETHER_ARP) {
			arp = arp_from_ether_frame(frame);
			if (file_dump_arp)
				arp_dump_packet(file_dump_arp, arp);
			arp_packet_free(arp);
		}

		ether_frame_free(frame);
	}

}

static void usage(void)
{
	printf("Usage: uarp -i <interface> -a <hwaddr> ");
	printf("[-E file] [-R file] [-D]\n\n");
	printf("   -i <interface>: tap interface to use\n");
	printf("   -a <hwaddr>   : hardware address\n");
	printf("   -E <file>     : dump ethernet packates to <file>\n");
	printf("   -A <file>     : dump ARP packates to <file>\n");
	printf("   -D            : dump mode (requires -E or -A)\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	FILE *file_dump_eth, *file_dump_arp;
	const char *ifname, *hwaddr_str;
	const char *path_dump_eth;
	const char *path_dump_arp;
	struct ether_device dev;
	bool dump_mode = false;
	int opt, err;

	ifname = hwaddr_str = NULL;
	path_dump_eth = path_dump_arp = NULL;
	file_dump_eth = file_dump_arp = NULL;

	while ((opt = getopt(argc, argv, "i:a:E:R:hD")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'a':
			hwaddr_str = optarg;
			break;
		case 'E':
			path_dump_eth = optarg;
			break;
		case 'R':
			path_dump_arp = optarg;
			break;
		case 'D':
			dump_mode = true;
			break;
		case 'h':
		default:
			usage();
			exit(1);
		}
	}

	die_if_not_passed("ifname", ifname);
	die_if_not_passed("hwaddr", hwaddr_str);

	if (path_dump_eth)
		file_dump_eth = xfopen(path_dump_eth, "a");

	if (path_dump_arp)
		file_dump_arp = xfopen(path_dump_arp, "a");

	err = ether_dev_open(ifname, hwaddr_str, &dev);
	if (err < 0) {
		perror("tun_open()");
		exit(1);
	}

	if (dump_mode) {
		uarp_dump_loop(&dev, file_dump_eth, file_dump_arp);
		goto out;
	}

out:
	ether_dev_close(&dev);
	return 0;
}
