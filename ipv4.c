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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "utils.h"
#include "ipv4.h"

static struct ipv4_datagram *ipv4_datagram_alloc(void)
{
	struct ipv4_datagram *ipv4_dtg;
	uint8_t *p;

	ipv4_dtg = mallocz(sizeof(*ipv4_dtg));
	if (!ipv4_dtg)
		return NULL;

	p = ipv4_dtg->buf;
	ipv4_dtg->version_ihl  =  (uint8_t *)  &p[0];
	ipv4_dtg->ds_ecn       =  (uint8_t *)  &p[1];
	ipv4_dtg->total_length =  (uint16_t *) &p[2];
	ipv4_dtg->id           =  (uint16_t *) &p[4];
	ipv4_dtg->flags_fragoff = (uint16_t *) &p[6];
	ipv4_dtg->ttl           = (uint8_t *)  &p[8];
	ipv4_dtg->prot          = (uint8_t *)  &p[9];
	ipv4_dtg->checksum      = (uint16_t *) &p[10];
	ipv4_dtg->src_addr      = (uint32_t *) &p[12];
	ipv4_dtg->dst_addr      = (uint32_t *) &p[16];

	ipv4_dtg->data = (uint8_t *) &p[20];

	return ipv4_dtg;
}

struct ipv4_datagram *ipv4_datagram_from_data(const uint8_t *data,
                                              size_t size)
{
	struct ipv4_datagram *ipv4_dtg;

	ipv4_dtg = ipv4_datagram_alloc();
	if (!ipv4_dtg)
		return NULL;

	if (size < IPV4_DATAGRAM_SIZE) {
		errno = EINVAL;
		return NULL;
	}

	if (size > IPV4_DATAGRAM_SIZE)
		size = IPV4_DATAGRAM_SIZE;

	memcpy(ipv4_dtg->buf, data, size);

	/*
	 * Header is fixed in 20 bytes because we don't
	 * support options
	 */
	ipv4_dtg->data_size = size - 20;

	return ipv4_dtg;
}

void ipv4_datagram_free(struct ipv4_datagram *ipv4_dtg)
{
	free(ipv4_dtg);
}

uint8_t ipv4_get_version(const struct ipv4_datagram *ipv4_dtg)
{
	return *ipv4_dtg->version_ihl >> 4;
}

uint8_t ipv4_get_ihl(const struct ipv4_datagram *ipv4_dtg)
{
	return *ipv4_dtg->version_ihl & 0xf;
}

uint8_t ipv4_get_ds(const struct ipv4_datagram *ipv4_dtg)
{
	return *ipv4_dtg->ds_ecn >> 2;
}

uint8_t ipv4_get_ecn(const struct ipv4_datagram *ipv4_dtg)
{
	return *ipv4_dtg->ds_ecn & 0x3;
}

uint16_t ipv4_get_length(const struct ipv4_datagram *ipv4_dtg)
{
	return ntohs(*ipv4_dtg->total_length);
}

uint16_t ipv4_get_id(const struct ipv4_datagram *ipv4_dtg)
{
	return ntohs(*ipv4_dtg->id);
}

uint8_t ipv4_get_flags(const struct ipv4_datagram *ipv4_dtg)
{
	return ntohs(*ipv4_dtg->flags_fragoff) >> 13;
}

uint16_t ipv4_get_fragoffset(const struct ipv4_datagram *ipv4_dtg)
{
	return ntohs(*ipv4_dtg->flags_fragoff) & 0xe000;
}

uint8_t ipv4_get_ttl(const struct ipv4_datagram *ipv4_dtg)
{
	return *ipv4_dtg->ttl;
}

uint8_t ipv4_get_protocol(const struct ipv4_datagram *ipv4_dtg)
{
	return *ipv4_dtg->prot;
}

uint16_t ipv4_get_checksum(const struct ipv4_datagram *ipv4_dtg)
{
	return ntohs(*ipv4_dtg->checksum);
}

uint32_t ipv4_get_src_addr(const struct ipv4_datagram *ipv4_dtg)
{
	return ntohl(*ipv4_dtg->src_addr);
}

uint32_t ipv4_get_dst_addr(const struct ipv4_datagram *ipv4_dtg)
{
	return ntohl(*ipv4_dtg->dst_addr);
}

size_t ipv4_get_data_size(const struct ipv4_datagram *ipv4_dtg)
{
	return ipv4_dtg->data_size;
}

struct ipv4_module *ipv4_module_alloc(const char *ipv4_addr_str)
{
	struct ipv4_module *ipv4_mod;
	in_addr_t addr;

	addr = inet_network(ipv4_addr_str);
	if (addr == -1)
		return NULL;

	ipv4_mod = mallocz(sizeof(*ipv4_mod));
	if (!ipv4_mod)
		return NULL;

	ipv4_mod->ipv4_addr = addr;

	return ipv4_mod;
}

void ipv4_module_free(struct ipv4_module *ipv4_mod)
{
	free(ipv4_mod);
}

void ipv4_dump_datagram(FILE *stream, const struct ipv4_datagram *ipv4_dtg)
{
	char str[16];

	fprintf(stream, "IPv4 datagram:\n\n");

	fprintf(stream, "  version: %d\n", ipv4_get_version(ipv4_dtg));
	fprintf(stream, "  ihl: %d\n", ipv4_get_ihl(ipv4_dtg));
	fprintf(stream, "  ds: %d\n", ipv4_get_ds(ipv4_dtg));
	fprintf(stream, "  ecn: %d\n", ipv4_get_ecn(ipv4_dtg));
	fprintf(stream, "  total length: %d\n", ipv4_get_length(ipv4_dtg));
	fprintf(stream, "  id: 0x%x\n", ipv4_get_id(ipv4_dtg));
	fprintf(stream, "  flags: 0x%x\n", ipv4_get_flags(ipv4_dtg));
	fprintf(stream, "  frag offset: %d\n", ipv4_get_fragoffset(ipv4_dtg));
	fprintf(stream, "  ttl: %d\n", ipv4_get_ttl(ipv4_dtg));
	fprintf(stream, "  protocol: %d\n", ipv4_get_protocol(ipv4_dtg));
	fprintf(stream, "  checksum: 0x%x\n", ipv4_get_checksum(ipv4_dtg));

	ipv4_addr_to_str(ipv4_get_src_addr(ipv4_dtg), str, sizeof(str));
	fprintf(stream, "  src addr: %s\n", str);

	ipv4_addr_to_str(ipv4_get_dst_addr(ipv4_dtg), str, sizeof(str));
	fprintf(stream, "  dst addr: %s\n", str);

	fprintf(stream, "\n");
}
