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
#include "misc.h"

static void usage(void)
{
	printf("Usage: uarp -i <interface> -a <hwaddr>\n");
}

int main(int argc, char *argv[])
{
	const char *ifname, *hwaddr_str;
	const char *path_dump_all;
	FILE *file_dump_all;
	struct ether_frame *frame;
	struct ether_device dev;
	int opt, err;

	ifname = hwaddr_str = NULL;
	path_dump_all = NULL;
	file_dump_all = NULL;

	while ((opt = getopt(argc, argv, "i:a:L:h")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'a':
			hwaddr_str = optarg;
			break;
		case 'L':
			path_dump_all = optarg;
			break;
		case 'h':
		default:
			usage();
			exit(1);
		}
	}

	die_if_not_passed("ifname", ifname);
	die_if_not_passed("hwaddr", hwaddr_str);

	if (path_dump_all)
		file_dump_all = xfopen(path_dump_all, "a");

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

		if (file_dump_all)
			ether_dump_frame(file_dump_all, frame);

		ether_frame_free(frame);
	}

	ether_dev_close(&dev);
	return 0;
}
