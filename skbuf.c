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
