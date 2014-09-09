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
#include "misc.h"

struct ether_device *ether_dev_alloc(uint8_t *hwaddr)
{
	struct ether_device *dev;

	dev = mallocz(sizeof(*dev));
	if (!dev)
		return NULL;

	dev->fd = -1;
	dev->cnt = 1;
	if (hwaddr)
		hwaddr_copy(dev->hwaddr, hwaddr);

	return dev;
}

void ether_dev_put(struct ether_device *dev)
{
	if (dev) {
		close(dev->fd);
		free(dev);
	}
}

void ether_dev_get(struct ether_device *dev)
{
	dev->cnt++;
}

int ether_dev_open(struct ether_device *dev, const char *ifname)
{
	struct ifreq ifr;
	int err;

	if (!dev) {
		errno = EINVAL;
		dev->fd = -1;
		return -1;
	}

	dev->fd = open("/dev/net/tun", O_RDWR);
	if (dev->fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	err = ioctl(dev->fd, TUNSETIFF, &ifr);
	if (err < 0)
		goto out_err;

	return 0;

out_err:
	err = errno;
	close(dev->fd);
	errno = err;
	dev->fd = -1;
	return -1;
}

static struct ether_frame *ether_frame_alloc(void)
{
	struct ether_frame *frame;
	uint8_t *p;

	frame = mallocz(sizeof(struct ether_frame));
	if (!frame)
		return NULL;

	p = frame->buf;
	frame->dst =  (uint8_t *)  &p[0];
	frame->src =  (uint8_t *)  &p[6];
	frame->type = (uint16_t *) &p[12];
	frame->data_start = (uint8_t *) &p[ETHER_HEADER_SIZE];

	return frame;
}

struct ether_frame *ether_dev_recv(struct ether_device *dev)
{
	struct ether_frame *frame;
	ssize_t ret;

	frame = ether_frame_alloc();
	if (!frame)
		return NULL;

	ret = read(dev->fd, frame->buf, ETHER_FRAME_SIZE);
	if (ret < 0) {
		ret = errno;
		free(frame);
		errno = ret;
		return NULL;
	}

	frame->data_size = ret - ETHER_HEADER_SIZE;

	return frame;
}

int ether_dev_send(struct ether_device *dev, const uint8_t *dest_hwaddr,
				   uint16_t type, const uint8_t *data, size_t data_size)
{
	struct ether_frame *frame;
	size_t count;
	ssize_t ret;

	frame = ether_frame_alloc();
	if (!frame)
		return -1;

	memcpy(frame->dst, dest_hwaddr, 6);
	memcpy(frame->src, dev->hwaddr, 6);
	*frame->type = htons(type);
	memcpy(frame->data_start, data, data_size);

	count = ETHER_HEADER_SIZE + data_size;
	ret = write(dev->fd, frame->buf, count);
	if (ret < 0) {
		ret = errno;
		free(frame);
		errno = ret;
		return -1;
	}

	assert(ret == count);

	free(frame);
	return 0;
}

int ether_dev_send_bcast(struct ether_device *dev, uint16_t type,
						 const uint8_t *data, size_t data_size)
{
	uint8_t addr[6];

	memset(addr, 0xff, sizeof(addr));
	return ether_dev_send(dev, addr, type, data, data_size);
}

void ether_frame_free(struct ether_frame *frame)
{
	if (frame)
		free(frame);
}

const uint8_t *ether_get_dst(const struct ether_frame *frame)
{
	return frame->dst;
}

const uint8_t *ether_get_src(const struct ether_frame *frame)
{
	return frame->src;
}

uint16_t ether_get_type(const struct ether_frame *frame)
{
	return ntohs(*frame->type);
}

const uint8_t *ether_get_data(const struct ether_frame *frame)
{
	return frame->data_start;
}

const char *ether_get_type_str(const struct ether_frame *frame)
{
	switch (ether_get_type(frame)) {
	case ETHER_TYPE_IPV4:
		return "ipv4";
	case ETHER_TYPE_ARP:
		return "arp";
	case ETHER_TYPE_IPV6:
		return "ipv6";
	default:
		return "unknown";
	}
}

uint32_t ether_get_data_size(const struct ether_frame *frame)
{
	return frame->data_size;
}

void ether_addr_to_str(const uint8_t *hwaddr, char *str, size_t len)
{
	snprintf(str, len, "%x:%x:%x:%x:%x:%x",
									(unsigned int) hwaddr[0],
									(unsigned int) hwaddr[1],
									(unsigned int) hwaddr[2],
									(unsigned int) hwaddr[3],
									(unsigned int) hwaddr[4],
									(unsigned int) hwaddr[5]);
}

void ether_str_to_addr(const char *hwaddr_str, uint8_t *hwaddr)
{
	sscanf(hwaddr_str, "%x:%x:%x:%x:%x:%x",
									(unsigned int *) &hwaddr[0],
									(unsigned int *) &hwaddr[1],
									(unsigned int *) &hwaddr[2],
									(unsigned int *) &hwaddr[3],
									(unsigned int *) &hwaddr[4],
									(unsigned int *) &hwaddr[5]);
}

void ether_dump_frame(FILE *stream, const struct ether_frame *frame)
{
	char hwaddr_str[32];

	ether_addr_to_str(ether_get_dst(frame), hwaddr_str, sizeof(hwaddr_str));
	fprintf(stream, "-> dst: %s\n", hwaddr_str);

	ether_addr_to_str(ether_get_src(frame), hwaddr_str, sizeof(hwaddr_str));
	fprintf(stream, "-> src: %s\n", hwaddr_str);

	fprintf(stream, "-> type: 0x%x (%s)\n", ether_get_type(frame),
											ether_get_type_str(frame));
	fprintf(stream, "-> data size: %lu\n",
			(long unsigned int) ether_get_data_size(frame));

	fprintf(stream, "\n");
}
