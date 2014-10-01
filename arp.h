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
#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stdio.h>
#include "ether.h"

#define ARP_PACKET_SIZE 28

/* ARP Hardware type - only ethernet is supported for now */
#define ARP_HTYPE_ETH 1

/* ARP Operations */
#define ARP_OP_REQ 1
#define ARP_OP_REP 2

struct arp_packet {
	uint16_t *htype;   /* hardware type */
	uint16_t *ptype;   /* protocol type */
	uint8_t  *hlen;    /* hardware addr length */
	uint8_t  *plen;    /* protocol address length */
	uint16_t *oper;    /* operation */
	uint8_t  *sha;     /* sender hardware address */
	uint32_t *spa;     /* sender protocol address */
	uint8_t  *tha;     /* target hardware address */
	uint32_t *tpa;     /* target protocol address */
	uint8_t buf[ARP_PACKET_SIZE];
};

struct arp_packet *arp_packet_from_data(const uint8_t *data, size_t size);
void arp_packet_free(struct arp_packet *arp_pkt);

struct arp_packet *arp_build_request(const uint8_t *sha, uint32_t spa,
                                     uint16_t ptype, uint32_t tpa);
struct arp_packet *arp_build_reply(const struct arp_packet *arp_req,
                                   const uint8_t *host_hwaddr);

bool arp_packet_is_good(const struct arp_packet *arp_pkt);

uint16_t arp_get_htype(const struct arp_packet *arp_pkt);
uint16_t arp_get_ptype(const struct arp_packet *arp_pkt);
uint8_t arp_get_hlen(const struct arp_packet *arp_pkt);
uint8_t arp_get_plen(const struct arp_packet *arp_pkt);
uint16_t arp_get_oper(const struct arp_packet *arp_pkt);
const char *arp_get_oper_str(const struct arp_packet *arp_pkt);
const uint8_t *arp_get_sha(const struct arp_packet *arp_pkt);
uint32_t arp_get_spa(const struct arp_packet *arp_pkt);
const uint8_t *arp_get_tha(const struct arp_packet *arp_pkt);
uint32_t arp_get_tpa(const struct arp_packet *arp_pkt);

void arp_dump_packet(FILE *stream, const struct arp_packet *arp_pkt);

int arp_send_request(struct ether_device *dev, uint32_t ipv4_src_addr,
                     uint32_t ipv4_dst_addr);
int arp_find_hwaddr(struct ether_device *dev, uint32_t ipv4_src_addr,
                    uint32_t ipv4_dst_addr, uint8_t *hwaddr);

#endif /* ARP_H */
