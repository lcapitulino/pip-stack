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
#include "skbuf.h"
#include "common.h"

int ether_dev_open(const char *ifname, struct ether_device *dev)
{
	struct ifreq ifr;
	int fd, err;

	if (!dev) {
		errno = EINVAL;
		return -1;
	}

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	err = ioctl(fd, TUNSETIFF, &ifr);
	if (err < 0)
		goto out_err;

	dev->fd = fd;
	return 0;

out_err:
	err = errno;
	close(fd);
	errno = err;
	return -1;
}

void ether_dev_close(struct ether_device *dev)
{
	close(dev->fd);
	dev->fd = -1;
}

struct ether_frame *ether_frame_alloc(void)
{
	struct ether_frame *frame;

	frame = malloc(sizeof(*frame));
	if (!frame)
		return NULL;

	memset(frame, 0, sizeof(*frame));

	frame->skbuf = skbuf_alloc(ETHER_FRAME_SIZE);
	if (!frame->skbuf) {
		free(frame);
		errno = ENOMEM;
		return NULL;
	}

	return frame;
}

void ether_frame_free(struct ether_frame *frame)
{
	skbuf_put(frame->skbuf);
	free(frame);
}

int ether_dev_recv(struct ether_device *dev, struct ether_frame *frame)
{
	ssize_t ret;

	ret = read(dev->fd, frame->skbuf->buf, ETHER_FRAME_SIZE);
	if (ret < 0)
		return -1;

	frame->dst = frame->skbuf->buf;
	frame->src = &frame->skbuf->buf[6];
	frame->type = (uint16_t *) &frame->skbuf->buf[12];

	return 0;
}

uint16_t ether_frame_type(const struct ether_frame *frame)
{
	return ntohs(*frame->type);
}

const char *ether_frame_type_str(const struct ether_frame *frame)
{
	switch (ether_frame_type(frame)) {
	case ETHER_IPV4:
		return "ipv4";
	case ETHER_ARP:
		return "arp";
	case ETHER_IPV6:
		return "ipv6";
	default:
		return "unknown";
	}
}

void ether_addr_to_str(uint8_t a, uint8_t b, uint8_t c,
					   uint8_t d, uint8_t e, uint8_t f,
					   char *str, size_t len)
{
	snprintf(str, len, "%x:%x:%x:%x:%x:%x", a, b, c, d, e, f);
}

void ether_dump_frame(FILE *stream, const struct ether_frame *frame)
{
	char hwaddr_str[32];
	const uint8_t *p;

	p = frame->dst;
	ether_addr_to_str(p[0], p[1], p[2], p[3], p[4], p[5],
				  	  hwaddr_str, sizeof(hwaddr_str));
	fprintf(stream, "-> dst: %s\n", hwaddr_str);

	p = frame->src;
	ether_addr_to_str(p[0], p[1], p[2], p[3], p[4], p[5],
				  	  hwaddr_str, sizeof(hwaddr_str));
	fprintf(stream, "-> src: %s\n", hwaddr_str);

	fprintf(stream, "-> type: 0x%x (%s)\n", ether_frame_type(frame),
											ether_frame_type_str(frame));

	fprintf(stream, "\n");
}
