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

static void usage(void)
{
	printf("Usage: uarp -i <interface> -a <hwaddr>\n");
}

static void die_if_not_passed(const char *opt, const char *var)
{
	if (!var) {
		fprintf(stderr, "ERROR: '%s' is required\n", opt);
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	const char *ifname, *hwaddr_str;
	struct ether_frame *frame;
	struct ether_device dev;
	int opt, err;

	ifname = hwaddr_str = NULL;
	while ((opt = getopt(argc, argv, "i:a:h")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'a':
			hwaddr_str = optarg;
			break;
		case 'h':
		default:
			usage();
			exit(1);
		}
	}

	die_if_not_passed("ifname", ifname);
	die_if_not_passed("hwaddr", hwaddr_str);

	err = ether_dev_open(ifname, hwaddr_str, &dev);
	if (err < 0) {
		perror("tun_open()");
		exit(1);
	}

	while (true) {
		frame = ether_frame_alloc();
		if (!frame) {
			perror("ether_frame_alloc()");
			break;
		}

		err = ether_dev_recv(&dev, frame);
		if (err < 0) {
			perror("ether_dev_recv()");
			break;
		}

		ether_dump_frame(stderr, frame);
		ether_frame_free(frame);
	}

	ether_dev_close(&dev);
	return 0;
}
