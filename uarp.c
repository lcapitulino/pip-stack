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

static void print_frame(const struct ether_frame *frame)
{
	char hwaddr_str[32];
	const uint8_t *p;

	p = frame->dst;
	ether_addr_to_str(p[0], p[1], p[2], p[3], p[4], p[5],
				  	  hwaddr_str, sizeof(hwaddr_str));
	fprintf(stderr, "-> dst: %s\n", hwaddr_str);

	p = frame->src;
	ether_addr_to_str(p[0], p[1], p[2], p[3], p[4], p[5],
				  	  hwaddr_str, sizeof(hwaddr_str));
	fprintf(stderr, "-> src: %s\n", hwaddr_str);

	//fprintf(stderr, "-> type: 0x%x (%s)\n", frame->type,
	//										ether_type_to_str(*frame->type));

	fprintf(stderr, "-> type: 0x%x\n", *frame->type);

	fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
	struct ether_device dev;
	int err;

	if (argc != 2) {
		fprintf(stderr, "uarp <tap device>\n");
		exit(1);
	}

	err = ether_dev_open(argv[1], &dev);
	if (err < 0) {
		perror("tun_open()");
		exit(1);
	}

	while (true) {
		struct ether_frame frame;

		err = ether_read_frame(&dev, &frame);
		if (err < 0) {
			perror("ether_read_frame()");
			break;
		}

		print_frame(&frame);
	}

	return 0;
}
