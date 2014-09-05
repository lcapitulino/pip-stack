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
#ifndef SKBUF_H
#define SKBUF_H

#include <stddef.h>
#include <stdint.h>

struct skbuf {
	int count;
	size_t size;
	uint8_t *buf;
};

struct skbuf *skbuf_alloc(size_t data_size);
struct skbuf *skbuf_get(struct skbuf *sk);
void skbuf_put(struct skbuf *sk);

#endif /* SKBUF_H */
