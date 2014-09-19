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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void usage(void)
{
	printf("udp-str-send: < ip > < string >\n");
}

int main(int argc, char *argv[])
{
	struct sockaddr_in addr;
	int err, fd;

	if (argc != 3) {
		usage();
		return 1;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket()");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(666);
	addr.sin_addr.s_addr  = inet_addr(argv[1]);

	err = connect(fd, (const struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		perror("connect()");
		return 1;
	}

	err = write(fd, argv[2], strlen(argv[2]));
	if (err < 0) {
		perror("write()");
		return 1;
	}

	return 0;
}
