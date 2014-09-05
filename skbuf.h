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
