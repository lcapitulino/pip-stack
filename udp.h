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
#ifndef UDP_H
#define UDP_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define UDP_HEADER_SIZE 8

struct udp_datagram {
	uint16_t *src_port;
	uint16_t *dst_port;
	uint16_t *length;
	uint16_t *checksum;
	uint8_t *data_start;
	uint8_t *buf;
	size_t data_size;
};

struct udp_datagram *udp_datagram_from_data(const uint8_t *data,
                                            size_t data_size);
struct udp_datagram *udp_build_datagram(uint16_t src_port, uint16_t dst_port,
                                        const uint8_t *data, size_t size);
void udp_datagram_free(struct udp_datagram *udp_dtg);

uint16_t udp_get_src_port(const struct udp_datagram *udp_dtg);
uint16_t udp_get_dst_port(const struct udp_datagram *udp_dtg);
uint16_t udp_get_length(const struct udp_datagram *udp_dtg);
uint16_t udp_get_checksum(const struct udp_datagram *udp_dtg);
uint8_t *udp_get_data(const struct udp_datagram *udp_dtg);
size_t udp_get_data_size(const struct udp_datagram *udp_dtg);

void udp_dump_datagram(FILE *stream, const struct udp_datagram *udp_dtg);

#endif /* UDP_H */
