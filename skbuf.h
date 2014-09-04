#ifndef SKBUF_H
#define SKBUF_H

#include <stddef.h>
#include <stdint.h>

struct skbuf {
	size_t size;
	uint8_t *buf;
};

struct skbuf *skbuf_alloc(size_t data_size);
void skbuf_free(struct skbuf *sk);

#endif /* SKBUF_H */
