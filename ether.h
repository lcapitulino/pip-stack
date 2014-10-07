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
#ifndef ETHER_H
#define ETHER_H

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>

/*
 * This is the maxium size for what the 802.3 standard calls
 * a "basic frame". There are others frame types (Q-tagged
 * and envelope frames) but we only support the basic frame.
 */
#define ETHER_FRAME_SIZE 1518
#define ETHER_HEADER_SIZE 14

/* Ethernet types */
#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_IPV6 0x86DD

struct ether_device {
	int fd;
	int cnt;
	uint8_t hwaddr[6];
};

struct ether_frame {
	uint8_t *dst;
	uint8_t *src;
	uint16_t *type;
	uint8_t *data_start;
	uint32_t data_size;
	uint8_t buf[ETHER_FRAME_SIZE];
};

typedef int (*ether_frame_handler_t)(struct ether_frame *frame, void *data);

#define ETHER_DISP_CONT 0
#define ETHER_DISP_QUIT 1
#define ETHER_DISP_ERR  2

struct ether_dispatch {
	ether_frame_handler_t handler_ipv4;
	ether_frame_handler_t handler_arp;
	ether_frame_handler_t handler_unk;
	void *data;
	int err_num;
};

struct ether_device *ether_dev_alloc(const uint8_t *hwaddr);
void ether_dev_put(struct ether_device *dev);
void ether_dev_get(struct ether_device *dev);
int ether_dev_open(struct ether_device *dev, const char *ifname);
struct ether_frame *ether_dev_recv(struct ether_device *dev);
int ether_dev_send(struct ether_device *dev, const uint8_t *dest_hwaddr,
                   uint16_t type, const uint8_t *data, size_t data_size);
int ether_dev_send_bcast(struct ether_device *dev, uint16_t type,
                         const uint8_t *data, size_t data_size);

struct ether_frame *ether_frame_alloc(void);
void ether_frame_free(struct ether_frame *frame);

const uint8_t *ether_get_dst(const struct ether_frame *frame);
const uint8_t *ether_get_src(const struct ether_frame *frame);
uint16_t ether_get_type(const struct ether_frame *frame);
const char *ether_get_type_str(const struct ether_frame *frame);
uint32_t ether_get_data_size(const struct ether_frame *frame);
const uint8_t *ether_get_data(const struct ether_frame *frame);

void ether_addr_to_str(const uint8_t *hwaddr, char *str, size_t len);
int ether_str_to_addr(const char *hwaddr_str, uint8_t *hwaddr);
void ether_dump_frame(FILE *stream, const struct ether_frame *frame);

int ether_dev_recv_dispatch(struct ether_device *dev,
                            struct ether_dispatch *cfg,
							int sec_timeout);

static inline void hwaddr_init(uint8_t *hwaddr, int c)
{
	memset(hwaddr, c, 6);
}

static inline void hwaddr_cp(uint8_t *dest, const uint8_t *src)
{
	memcpy(dest, src, 6);
}

static inline bool hwaddr_eq(const uint8_t *dest, const uint8_t *src)
{
	return memcmp(dest, src, 6) == 0;
}

#endif /* ETHER_H */
