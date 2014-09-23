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
#include <stdio.h>
#include <stddef.h>

#include "common.h"
#include "utils.h"

void *mallocz(size_t size)
{
	void *p;

	p = malloc(size);
	if (p)
		memset(p, 0, size);

	return p;
}

void die_if_not_passed(const char *opt, const char *var)
{
	if (!var) {
		fprintf(stderr, "ERROR: '%s' is required (see help)\n", opt);
		exit(1);
	}
}

FILE *xfopen(const char *path, const char *mode)
{
	FILE *file;

	file = fopen(path, mode);
	if (!file) {
		fprintf(stderr, "ERROR: fopen(%s): %s\n", path, strerror(errno));
		exit(1);
	}

	return file;
}

void xsetunbuf(FILE *stream)
{
	int err;

	err = setvbuf(stream, NULL, _IONBF, 0);
	if (err < 0) {
		perror("setvbuf()");
		exit(1);
	}
}

/* addr is host byte order */
int ipv4_addr_to_str(uint32_t addr, char *str, size_t len)
{
	struct in_addr in_addr;
	const char *p;

	memset(&in_addr, 0, sizeof(in_addr)); /* just in case */
	in_addr.s_addr = htonl(addr);
	p = inet_ntoa(in_addr);
	if (!p)
		return -1;

	strncpy(str, p, len);
	return 0;
}

void dump_data(FILE *stream, const uint8_t *data, size_t len)
{
	size_t i, cnt;

	for (i = 0; i < len; i++) {
		fprintf(stream, "%x ", data[i]);
		if (++cnt == 12) {
			putc('\n', stream);
			cnt = 0;
		}
	}

	if (i > 0)
		putc('\n', stream);
}


static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/* Fast Internet checksum from the Linux kernel */
static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

uint16_t calculate_net_checksum(const uint8_t *data, int len)
{
	return (uint16_t) ~do_csum(data, len);
}
