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
#include <stdio.h>

struct ether_device {
	int fd;
	uint8_t hwaddr[6];
};

struct ether_frame {
	const uint8_t *dst;
	const uint8_t *src;
	const uint16_t *type;
	uint32_t data_size;
	struct skbuf *skbuf;
};

/*
 * This is the maxium size for what the 802.3 standard calls
 * a "basic frame". There are others frame types (Q-tagged
 * and envelope frames) but we only support the basic frame.
 */
#define ETHER_FRAME_SIZE 1518
#define ETHER_HEADER_SIZE 14

/* Ethernet types */
#define ETHER_IPV4 0x0800
#define ETHER_ARP  0x0806
#define ETHER_IPV6 0x86DD

int ether_dev_open(const char *ifname, const char *hwaddr_str,
				   struct ether_device *dev);
void ether_dev_close(struct ether_device *dev);
int ether_dev_recv(struct ether_device *dev, struct ether_frame *frame);

struct ether_frame *ether_frame_alloc(void);
void ether_frame_free(struct ether_frame *frame);

const uint8_t *ether_get_dst(const struct ether_frame *frame);
const uint8_t *ether_get_src(const struct ether_frame *frame);
uint16_t ether_get_type(const struct ether_frame *frame);
uint32_t ether_get_data_size(const struct ether_frame *frame);
struct skbuf *ether_get_skbuf_ptr(const struct ether_frame *frame);

const char *ether_get_type_str(const struct ether_frame *frame);
const char *ether_type_to_str(uint16_t type);
void ether_addr_to_str(const uint8_t *hwaddr, char *str, size_t len);
void ether_str_to_addr(const char *hwaddr_str, uint8_t *hwaddr);
void ether_dump_frame(FILE *stream, const struct ether_frame *frame);

#endif /* MISC_H */
