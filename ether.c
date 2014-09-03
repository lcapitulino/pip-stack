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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "ether.h"
#include "common.h"

int ether_tun_open(const char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if (!dev)
		return -EINVAL;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	err = ioctl(fd, TUNSETIFF, &ifr);
	if (err < 0) {
		close(fd);
		return err;
	}

	return fd;
}

void ether_addr_to_str(uint8_t a, uint8_t b, uint8_t c,
					   uint8_t d, uint8_t e, uint8_t f,
					   char *str, size_t len)
{
	snprintf(str, len, "%x:%x:%x:%x:%x:%x", a, b, c, d, e, f);
}
