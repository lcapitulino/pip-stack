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

int main(int argc, char *argv[])
{
	uint8_t buf[12];
	ssize_t ret;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "xarg <tap device>\n");
		exit(1);
	}

	fd = ether_tun_open(argv[1]);
	if (fd < 0) {
		perror("tun_open()");
		exit(1);
	}

	while (true) {
		char hwaddr_str[64];
		ret = read(fd, buf, 12);
		if (ret < 0) {
			perror("read()");
			break;
		}

		ether_addr_to_str(buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
					  	  hwaddr_str, sizeof(hwaddr_str));
		fprintf(stderr, "-> dst: %s\n", hwaddr_str);

		ether_addr_to_str(buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
					  	  hwaddr_str, sizeof(hwaddr_str));
		fprintf(stderr, "-> src: %s\n\n", hwaddr_str);

	}

	close(fd);
	return 0;
}
