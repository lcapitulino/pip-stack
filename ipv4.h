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
#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include "ether.h"

/* Options are not supported */
#define IPV4_HEADER_SIZE 20

/* Supported protocols */
#define IPV4_PROT_ICMP 1
#define IPV4_PROT_UDP 17

/* Flags */
#define IPV4_FLAGS_MF 0x1
#define IPV4_FLAGS_DF 0x2
#define IPV4_FLAGS_RV 0x4

/* Default values */
#define IPV4_DEF_TTL 64

struct ipv4_module {
	uint32_t ipv4_addr;
};

struct ipv4_datagram {
	uint8_t *version_ihl;
	uint8_t *ds_ecn;
	uint16_t *total_length;
	uint16_t *id;
	uint16_t *flags_fragoff;
	uint8_t *ttl;
	uint8_t *prot;
	uint16_t *checksum;
	uint32_t *src_addr;
	uint32_t *dst_addr;
	uint8_t *data;

	uint8_t *buf;
	size_t data_size;
};

struct ipv4_datagram *ipv4_build_datagram(uint32_t src_addr,
                                          uint32_t dst_addr,
                                          uint8_t  protocol,
                                          const uint8_t *data,
                                          size_t data_size);

struct ipv4_datagram *ipv4_datagram_from_data(const uint8_t *data,
                                              size_t size);
void ipv4_datagram_free(struct ipv4_datagram *ipv4_dtg);
uint8_t ipv4_get_version(const struct ipv4_datagram *ipv4_dtg);
uint8_t ipv4_get_ihl(const struct ipv4_datagram *ipv4_dtg);
uint8_t ipv4_get_ds(const struct ipv4_datagram *ipv4_dtg);
uint8_t ipv4_get_ecn(const struct ipv4_datagram *ipv4_dtg);
uint16_t ipv4_get_length(const struct ipv4_datagram *ipv4_dtg);
uint16_t ipv4_get_id(const struct ipv4_datagram *ipv4_dtg);
uint8_t ipv4_get_flags(const struct ipv4_datagram *ipv4_dtg);
uint16_t ipv4_get_fragoffset(const struct ipv4_datagram *ipv4_dtg);
uint8_t ipv4_get_ttl(const struct ipv4_datagram *ipv4_dtg);
uint8_t ipv4_get_protocol(const struct ipv4_datagram *ipv4_dtg);
uint16_t ipv4_get_checksum(const struct ipv4_datagram *ipv4_dtg);
uint32_t ipv4_get_src_addr(const struct ipv4_datagram *ipv4_dtg);
uint32_t ipv4_get_dst_addr(const struct ipv4_datagram *ipv4_dtg);
size_t ipv4_get_data_size(const struct ipv4_datagram *ipv4_dtg);
uint8_t *ipv4_get_data(const struct ipv4_datagram *ipv4_dtg);
bool ipv4_checksum_ok(const struct ipv4_datagram *ipv4_dtg);
uint8_t *ipv4_get_datagram(const struct ipv4_datagram *ipv4_dtg);
uint16_t ipv4_get_datagram_size(const struct ipv4_datagram *ipv4_dtg);
bool ipv4_datagram_is_good(const struct ipv4_datagram *ipv4_dtg);
void ipv4_dump_datagram(FILE *stream, const struct ipv4_datagram *ipv4_dtg);

int ipv4_send(struct ether_device *dev, struct ipv4_module *ipv4_mod,
              uint32_t ipv4_dst_addr, uint8_t *dst_hwaddr, uint8_t protocol,
              const uint8_t *data, size_t data_size);

struct ipv4_module *ipv4_module_alloc(uint32_t ipv4_host_addr);
void ipv4_module_free(struct ipv4_module *ipv4_mod);

#endif /* IPV4_H */
