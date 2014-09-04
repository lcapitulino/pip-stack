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
#ifndef MISC_H
#define MISC_H

#include <stdint.h>
#include <stddef.h>

struct ether_device {
	int fd;
};

struct ether_frame {
	const uint8_t *dst;
	const uint8_t *src;
	const uint16_t *type;
	struct skbuf *skbuf;
};

#define ETHER_FRAME_SIZE 1518

/* Ethernet types */
#define ETHER_IPV4 0x0800
#define ETHER_ARP  0x0806
#define ETHER_IPV6 0x86DD

int ether_dev_open(const char *ifname, struct ether_device *dev);

int ether_dev_recv(struct ether_device *dev, struct ether_frame *frame);

void ether_addr_to_str(uint8_t a, uint8_t b, uint8_t c,
					   uint8_t d, uint8_t e, uint8_t f,
					   char *str, size_t len);

const char *ether_type_to_str(uint16_t type);

#endif /* MISC_H */
