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
#include "misc.h"

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

int ipv4_addr_to_str(uint32_t addr, char *str, size_t len)
{
	struct in_addr in_addr;
	const char *p;

	memset(&in_addr, 0, sizeof(in_addr)); /* just in case */
	in_addr.s_addr = addr;
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
