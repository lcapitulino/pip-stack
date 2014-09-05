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
#include "skbuf.h"

struct skbuf *skbuf_alloc(size_t data_size)
{
	struct skbuf *sk;

	sk = malloc(sizeof(*sk));
	if (!sk)
		return NULL;

	sk->buf = malloc(data_size);
	if (!sk->buf) {
		free(sk);
		errno = ENOMEM;
		return NULL;
	}

	sk->count = 1;
	sk->size = data_size;
	memset(sk->buf, 0, data_size);

	return sk;
}

struct skbuf *skbuf_get(struct skbuf *sk)
{
	sk->count++;
	return sk;
}

void skbuf_put(struct skbuf *sk)
{
	if (!sk)
		return;

	assert(sk->count >= 0);

	if (--sk->count == 0) {
		free(sk->buf);
		free(sk);
	}
}

uint8_t *skbuf_get_data_ptr(const struct skbuf *sk)
{
	return sk->buf;
}
