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

	sk->size = data_size;
	memset(sk->buf, 0, data_size);

	return sk;
}

void skbuf_free(struct skbuf *sk)
{
	if (sk) {
		free(sk->buf);
		free(sk);
	}
}
