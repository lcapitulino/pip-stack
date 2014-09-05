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
#include "misc.h"
#include "ether.h"
#include "skbuf.h"
#include "arp.h"

struct arp_packet *arp_from_ether_frame(const struct ether_frame *frame)
{
	struct arp_packet *arp;
	uint8_t *p;

	arp = malloc(sizeof(*arp));
	if (!arp)
		return NULL;

	arp->skbuf = ether_get_skbuf_ptr(frame);
	skbuf_get(arp->skbuf);

	p = (uint8_t *) &arp->skbuf->buf[ETHER_HEADER_SIZE];
	arp->htype = (const uint16_t *) &p[0];
	arp->ptype = (const uint16_t *) &p[2];
	arp->hlen  = (const uint8_t *)  &p[4];
	arp->plen  = (const uint8_t *)  &p[5];
	arp->oper  = (const uint16_t *) &p[6];
	arp->sha   = (const uint8_t *)  &p[8];
	arp->spa   = (const uint32_t *) &p[14];
	arp->tha   = (const uint8_t *)  &p[18];
	arp->tpa   = (const uint32_t *) &p[24];

	return arp;
}

void arp_packet_free(struct arp_packet *arp)
{
	if (arp) {
		skbuf_put(arp->skbuf);
		free(arp);
	}
}

uint16_t arp_get_htype(const struct arp_packet *arp)
{
	return ntohs(*arp->htype);
}

uint16_t arp_get_ptype(const struct arp_packet *arp)
{
	return ntohs(*arp->ptype);
}

uint8_t arp_get_hlen(const struct arp_packet *arp)
{
	return *arp->hlen;
}

uint8_t arp_get_plen(const struct arp_packet *arp)
{
	return *arp->plen;
}

uint16_t arp_get_oper(const struct arp_packet *arp)
{
	return ntohs(*arp->oper);
}

const uint8_t *arp_get_sha(const struct arp_packet *arp)
{
	return arp->sha;
}

uint32_t arp_get_spa(const struct arp_packet *arp)
{
	return ntohl(*arp->spa);
}

const uint8_t *arp_get_tha(const struct arp_packet *arp)
{
	return arp->tha;
}

uint32_t arp_get_tpa(const struct arp_packet *arp)
{
	return ntohl(*arp->spa);
}

const char *arp_oper_str(const struct arp_packet *arp)
{
	switch (arp_get_oper(arp)) {
	case 1:
		return "arp request";
	case 2:
		return "arp reply";
	default:
		abort();
	}
}

void arp_dump_packet(FILE *stream, const struct arp_packet *arp)
{
	char ipv4_addr_str[16];
	char hwaddr_str[32];

	fprintf(stream, "ARP packet:\n\n");
	fprintf(stream, "   htype: %d\n", arp_get_htype(arp));
	fprintf(stream, "   ptype: %x\n", arp_get_ptype(arp));
	fprintf(stream, "   hlen:  %d\n", arp_get_hlen(arp));
	fprintf(stream, "   plen:  %d\n", arp_get_plen(arp));
	fprintf(stream, "   oper:  %d (%s)\n", arp_get_oper(arp),arp_oper_str(arp));

	memset(hwaddr_str, 0, sizeof(hwaddr_str));
	ether_addr_to_str(arp_get_sha(arp), hwaddr_str, sizeof(hwaddr_str));
	fprintf(stream, "   sha:   %s\n", hwaddr_str);

	memset(ipv4_addr_str, 0, sizeof(ipv4_addr_str));
	ipv4_addr_to_str(*arp->spa, ipv4_addr_str, sizeof(ipv4_addr_str));
	fprintf(stream, "   spa:   %s\n", ipv4_addr_str);

	memset(hwaddr_str, 0, sizeof(hwaddr_str));
	ether_addr_to_str(arp_get_tha(arp), hwaddr_str, sizeof(hwaddr_str));
	fprintf(stream, "   tha:   %s\n", hwaddr_str);

	memset(ipv4_addr_str, 0, sizeof(ipv4_addr_str));
	ipv4_addr_to_str(*arp->tpa, ipv4_addr_str, sizeof(ipv4_addr_str));
	fprintf(stream, "   tpa:   %s\n", ipv4_addr_str);

	fprintf(stream, "\n");
}
