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
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

void *mallocz(size_t size);
void die_if_not_passed(const char *opt, const char *var);
FILE *xfopen(const char *path, const char *mode);
void xsetunbuf(FILE *stream);
int ipv4_addr_to_str(uint32_t addr, char *str, size_t len);
void dump_data(FILE *stream, const uint8_t *data, size_t len);

#endif /* UTILS_H */
