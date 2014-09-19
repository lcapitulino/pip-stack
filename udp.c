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
#include <ctype.h>

#include "common.h"
#include "utils.h"
#include "udp.h"

struct udp_datagram *udp_datagram_from_data(const uint8_t *data, size_t size)
{
	struct udp_datagram *udp_dtg;
	uint8_t *p;
	int err_no;

	udp_dtg = mallocz(sizeof(*udp_dtg));
	if (!udp_dtg)
		return NULL;

	p = mallocz(size);
	if (!p) {
		err_no = errno;
		free(udp_dtg);
		errno = err_no;
		return NULL;
	}

	udp_dtg->src_port = (uint16_t *) &p[0];
	udp_dtg->dst_port = (uint16_t *) &p[2];
	udp_dtg->length   = (uint16_t *) &p[4];
	udp_dtg->checksum = (uint16_t *) &p[6];
	udp_dtg->data_start = &p[8];
	udp_dtg->buf = p;

	udp_dtg->data_size = size - UDP_HEADER_SIZE;

	memcpy(p, data, size);

	return udp_dtg;
}

void udp_datagram_free(struct udp_datagram *udp_dtg)
{
	if (udp_dtg) {
		free(udp_dtg->buf);
		free(udp_dtg);
	}
}

uint16_t udp_get_src_port(const struct udp_datagram *udp_dtg)
{
	return ntohs(*udp_dtg->src_port);
}

uint16_t udp_get_dst_port(const struct udp_datagram *udp_dtg)
{
	return ntohs(*udp_dtg->dst_port);
}

uint16_t udp_get_length(const struct udp_datagram *udp_dtg)
{
	return ntohs(*udp_dtg->length);
}

uint16_t udp_get_checksum(const struct udp_datagram *udp_dtg)
{
	return ntohs(*udp_dtg->checksum);
}

uint8_t *udp_get_data(const struct udp_datagram *udp_dtg)
{
	return udp_dtg->data_start;
}

size_t udp_get_data_size(const struct udp_datagram *udp_dtg)
{
	return udp_dtg->data_size;
}

void udp_dump_datagram(FILE *stream, const struct udp_datagram *udp_dtg)
{
	const uint8_t *p;
	int i;

	fprintf(stream, "UDP datagram:\n\n");

	fprintf(stream, "source port: %d\n", udp_get_src_port(udp_dtg));
	fprintf(stream, "dest port: %d\n", udp_get_dst_port(udp_dtg));
	fprintf(stream, "length: %d\n", udp_get_length(udp_dtg));
	fprintf(stream, "checksum: %x\n", udp_get_checksum(udp_dtg));

	fprintf(stream, "data: ");
	p = udp_get_data(udp_dtg);
	for (i = 0; i < udp_get_data_size(udp_dtg); i++)
		fprintf(stream, "%c", isascii(p[i]) ? p[i] : '.');
	fprintf(stream, "\n");

	fprintf(stream, "\n");
}
