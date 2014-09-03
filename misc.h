#ifndef MISC_H
#define MISC_H

#include <stdint.h>
#include <stddef.h>

int tun_open(const char *dev);
void hwaddr_to_str(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e,
				   uint8_t f, char *str, size_t len);

#endif /* MISC_H */
