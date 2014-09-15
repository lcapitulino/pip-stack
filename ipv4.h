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
#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>

struct ipv4_module {
	uint32_t ipv4_addr;
};

struct ipv4_module *ipv4_module_alloc(const char *ipv4_addr_str);
void ipv4_module_free(struct ipv4_module *ipv4_mod);

#endif /* IPV4_H */
