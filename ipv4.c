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
#include "utils.h"
#include "ipv4.h"
#include "ether.h"

struct ipv4_module *ipv4_module_alloc(uint32_t ipv4_host_addr)
{
	struct ipv4_module *ipv4_mod;

	if (!ipv4_host_addr) {
		errno = EINVAL;
		return NULL;
	}

	ipv4_mod = mallocz(sizeof(*ipv4_mod));
	if (!ipv4_mod)
		return NULL;

	ipv4_mod->ipv4_addr = ipv4_host_addr;

	return ipv4_mod;
}

void ipv4_module_free(struct ipv4_module *ipv4_mod)
{
	free(ipv4_mod);
}

static struct ipv4_datagram *ipv4_datagram_alloc(size_t data_size)
{
	struct ipv4_datagram *ipv4_dtg;
	int err_no;
	uint8_t *p;

	ipv4_dtg = mallocz(sizeof(*ipv4_dtg));
	if (!ipv4_dtg)
		return NULL;

	p = mallocz(data_size + IPV4_HEADER_SIZE);
	if (!p) {
		err_no = errno;
		free(ipv4_dtg);
		errno = err_no;
		return NULL;
	}

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
	ipv4_dtg->data          = (uint8_t *) &p[20];
	ipv4_dtg->buf = p;

	ipv4_dtg->data_size = data_size;

	return ipv4_dtg;
}

struct ipv4_datagram *ipv4_datagram_from_data(const uint8_t *data,
                                              size_t size)
{
	struct ipv4_datagram *ipv4_dtg;

	/* size includes IPV4_HEADER_SIZE */
	ipv4_dtg = ipv4_datagram_alloc(size - IPV4_HEADER_SIZE);
	if (!ipv4_dtg)
		return NULL;

	memcpy(ipv4_dtg->buf, data, size);

	return ipv4_dtg;
}

/* XXX: What's the best way to do this? */
static uint16_t ipv4_gen_id(void)
{
	static uint16_t id = 0;

	if (++id == USHRT_MAX)
		id = 1;

	return id;
}

struct ipv4_datagram *ipv4_build_datagram(uint32_t src_addr,
                                          uint32_t dst_addr,
                                          uint8_t  protocol,
                                          const uint8_t *data,
                                          size_t data_size)
{
	struct ipv4_datagram *ipv4_dtg;
	uint16_t csum;

	ipv4_dtg = ipv4_datagram_alloc(data_size);
	if (!ipv4_dtg)
		return NULL;

	/* fields provided by the user */
	*ipv4_dtg->src_addr = htonl(src_addr);
	*ipv4_dtg->dst_addr = htonl(dst_addr);
	*ipv4_dtg->prot     = protocol;

	/* hardcoded fields */
	*ipv4_dtg->version_ihl = 0x45; /* version: ipv4, IHL 5 (20 bytes header) */
	*ipv4_dtg->total_length  = htons(IPV4_HEADER_SIZE + data_size);
	*ipv4_dtg->id            = htons(ipv4_gen_id());
	*ipv4_dtg->flags_fragoff = htons(IPV4_FLAGS_DF << 13);
	*ipv4_dtg->ttl           = IPV4_DEF_TTL;

	/* calculate checksum */
	csum = calculate_net_checksum(ipv4_dtg->buf, IPV4_HEADER_SIZE);
	*ipv4_dtg->checksum = csum;

	memcpy(ipv4_dtg->data, data, data_size);

	return ipv4_dtg;
}

void ipv4_datagram_free(struct ipv4_datagram *ipv4_dtg)
{
	if (ipv4_dtg) {
		free(ipv4_dtg->buf);
		free(ipv4_dtg);
	}
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
	return ntohs(*ipv4_dtg->flags_fragoff & 0xe000);
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

uint8_t *ipv4_get_data(const struct ipv4_datagram *ipv4_dtg)
{
	return ipv4_get_data_size(ipv4_dtg) > 0 ? ipv4_dtg->data : NULL;
}

uint8_t *ipv4_get_datagram(const struct ipv4_datagram *ipv4_dtg)
{
	return ipv4_dtg->buf;
}

uint16_t ipv4_get_datagram_size(const struct ipv4_datagram *ipv4_dtg)
{
	return ipv4_dtg->data_size + IPV4_HEADER_SIZE;
}

bool ipv4_checksum_ok(const struct ipv4_datagram *ipv4_dtg)
{
	return calculate_net_checksum(ipv4_dtg->buf, 20) == 0;
}

bool ipv4_datagram_is_good(const struct ipv4_datagram *ipv4_dtg)
{
	if (ipv4_get_version(ipv4_dtg) != 4)
		return false;

	if (ipv4_get_ihl(ipv4_dtg) != 5)
		return false;

	if (ipv4_get_length(ipv4_dtg) < 20)
		return false;

	if (ipv4_get_flags(ipv4_dtg) & IPV4_FLAGS_MF)
		return false;

	if (ipv4_get_fragoffset(ipv4_dtg) != 0)
		return false;

	return ipv4_checksum_ok(ipv4_dtg);
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
	fprintf(stream, "  checksum: 0x%x ", ipv4_get_checksum(ipv4_dtg));
	fprintf(stream, "  (%s)\n", ipv4_checksum_ok(ipv4_dtg) ? "OK" : "FAILED");

	ipv4_addr_to_str(ipv4_get_src_addr(ipv4_dtg), str, sizeof(str));
	fprintf(stream, "  src addr: %s\n", str);

	ipv4_addr_to_str(ipv4_get_dst_addr(ipv4_dtg), str, sizeof(str));
	fprintf(stream, "  dst addr: %s\n", str);

	fprintf(stream, "\n");
}

int ipv4_send(struct ether_device *dev, struct ipv4_module *ipv4_mod,
              uint32_t ipv4_dst_addr, uint8_t *dst_hwaddr, uint8_t protocol,
              const uint8_t *data, size_t data_size)
{
	struct ipv4_datagram *ipv4_dtg;
	int ret;

	ipv4_dtg = ipv4_build_datagram(ipv4_mod->ipv4_addr, ipv4_dst_addr,
                                   protocol, data, data_size);
	if (!ipv4_dtg)
		return -1;

	ret = ether_dev_send(dev, dst_hwaddr, ETHER_TYPE_IPV4,
                         ipv4_get_datagram(ipv4_dtg),
						 ipv4_get_datagram_size(ipv4_dtg));

	ipv4_datagram_free(ipv4_dtg);

	return ret;
}
