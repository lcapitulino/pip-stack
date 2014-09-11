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
#include "arp.h"

static struct arp_packet *arp_packet_alloc(void)
{
	struct arp_packet *arp_pkt;
	uint8_t *p;

	arp_pkt = mallocz(sizeof(struct arp_packet));
	if (!arp_pkt)
		return NULL;

	p = arp_pkt->buf;
	arp_pkt->htype = (uint16_t *) &p[0];
	arp_pkt->ptype = (uint16_t *) &p[2];
	arp_pkt->hlen  = (uint8_t *)  &p[4];
	arp_pkt->plen  = (uint8_t *)  &p[5];
	arp_pkt->oper  = (uint16_t *) &p[6];
	arp_pkt->sha   = (uint8_t *)  &p[8];
	arp_pkt->spa   = (uint32_t *) &p[14];
	arp_pkt->tha   = (uint8_t *)  &p[18];
	arp_pkt->tpa   = (uint32_t *) &p[24];

	return arp_pkt;
}

struct arp_packet *arp_from_ether_frame(const struct ether_frame *frame)
{
	struct arp_packet *arp_pkt;

	arp_pkt = arp_packet_alloc();
	if (!arp_pkt)
		return NULL;

	memcpy(arp_pkt->buf, ether_get_data(frame), ARP_PACKET_SIZE);
	return arp_pkt;
}

struct arp_packet *arp_build_request(uint8_t *sha, uint32_t spa,
                                     uint16_t ptype, uint32_t tpa)
{
	struct arp_packet *arp_req;

	arp_req = arp_packet_alloc();
	if (!arp_req)
		return NULL;

	*arp_req->htype = htons(1);
	*arp_req->ptype = htons(ptype);
	*arp_req->hlen =  6;
	*arp_req->plen =  4;
	*arp_req->oper =  htons(1);
	memcpy(arp_req->sha, sha, 6);
	*arp_req->spa = htonl(spa);
	*arp_req->tpa = htonl(tpa);

	return arp_req;
}

struct arp_packet *arp_build_reply(const struct arp_packet *arp_req,
                                   const uint8_t *host_hwaddr)
{
	struct arp_packet *arp_rep;
	uint8_t hwaddr[6];
	uint32_t ip_addr;

	arp_rep = arp_packet_alloc();
	if (!arp_rep)
		return NULL;

	memcpy(arp_rep->buf, arp_req->buf, ARP_PACKET_SIZE);
	*arp_rep->oper = htons(ARP_OP_REP);
	hwaddr_copy(arp_rep->tha, host_hwaddr);

	/* swap protocol address */
	ip_addr = *arp_rep->tpa;
	*arp_rep->tpa = *arp_rep->spa;
	*arp_rep->spa = ip_addr;

	/* swap hardware address */
	hwaddr_copy(hwaddr, arp_rep->tha);
	hwaddr_copy(arp_rep->tha, arp_rep->sha);
	hwaddr_copy(arp_rep->sha, hwaddr);

	return arp_rep;
}

bool arp_packet_is_good(const struct arp_packet *arp_pkt)
{
	return (arp_get_htype(arp_pkt) == 1 &&
			arp_get_ptype(arp_pkt) == ETHER_TYPE_IPV4 &&
			arp_get_hlen(arp_pkt)  == 6 &&
			arp_get_plen(arp_pkt)  == 4);
}

void arp_packet_free(struct arp_packet *arp_pkt)
{
	if (arp_pkt)
		free(arp_pkt);
}

uint16_t arp_get_htype(const struct arp_packet *arp_pkt)
{
	return ntohs(*arp_pkt->htype);
}

uint16_t arp_get_ptype(const struct arp_packet *arp_pkt)
{
	return ntohs(*arp_pkt->ptype);
}

uint8_t arp_get_hlen(const struct arp_packet *arp_pkt)
{
	return *arp_pkt->hlen;
}

uint8_t arp_get_plen(const struct arp_packet *arp_pkt)
{
	return *arp_pkt->plen;
}

uint16_t arp_get_oper(const struct arp_packet *arp_pkt)
{
	return ntohs(*arp_pkt->oper);
}

const char *arp_get_oper_str(const struct arp_packet *arp_pkt)
{
	switch (arp_get_oper(arp_pkt)) {
	case 1:
		return "arp request";
	case 2:
		return "arp reply";
	default:
		abort();
	}
}

const uint8_t *arp_get_sha(const struct arp_packet *arp_pkt)
{
	return arp_pkt->sha;
}

uint32_t arp_get_spa(const struct arp_packet *arp_pkt)
{
	return ntohl(*arp_pkt->spa);
}

const uint8_t *arp_get_tha(const struct arp_packet *arp_pkt)
{
	return arp_pkt->tha;
}

uint32_t arp_get_tpa(const struct arp_packet *arp_pkt)
{
	return ntohl(*arp_pkt->tpa);
}

void arp_dump_packet(FILE *stream, const struct arp_packet *arp_pkt)
{
	char ipv4_addr_str[16];
	char hwaddr_str[32];

	fprintf(stream, "ARP packet:\n\n");
	fprintf(stream, "   htype: %d\n", arp_get_htype(arp_pkt));
	fprintf(stream, "   ptype: 0x%x\n", arp_get_ptype(arp_pkt));
	fprintf(stream, "   hlen:  %d\n", arp_get_hlen(arp_pkt));
	fprintf(stream, "   plen:  %d\n", arp_get_plen(arp_pkt));
	fprintf(stream, "   oper:  %d (%s)\n", arp_get_oper(arp_pkt),arp_get_oper_str(arp_pkt));

	memset(hwaddr_str, 0, sizeof(hwaddr_str));
	ether_addr_to_str(arp_get_sha(arp_pkt), hwaddr_str, sizeof(hwaddr_str));
	fprintf(stream, "   sha:   %s\n", hwaddr_str);

	memset(ipv4_addr_str, 0, sizeof(ipv4_addr_str));
	ipv4_addr_to_str(arp_get_spa(arp_pkt), ipv4_addr_str, sizeof(ipv4_addr_str));
	fprintf(stream, "   spa:   %s\n", ipv4_addr_str);

	memset(hwaddr_str, 0, sizeof(hwaddr_str));
	ether_addr_to_str(arp_get_tha(arp_pkt), hwaddr_str, sizeof(hwaddr_str));
	fprintf(stream, "   tha:   %s\n", hwaddr_str);

	memset(ipv4_addr_str, 0, sizeof(ipv4_addr_str));
	ipv4_addr_to_str(arp_get_tpa(arp_pkt), ipv4_addr_str, sizeof(ipv4_addr_str));
	fprintf(stream, "   tpa:   %s\n", ipv4_addr_str);

	fprintf(stream, "\n");
}
