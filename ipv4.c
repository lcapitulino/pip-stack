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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "utils.h"
#include "ipv4.h"

struct ipv4_object *ipv4_object_alloc(const char *ipv4_addr_str)
{
	struct ipv4_object *ipv4;
	in_addr_t addr;

	addr = inet_network(ipv4_addr_str);
	if (addr == -1)
		return NULL;

	ipv4 = mallocz(sizeof(*ipv4));
	if (!ipv4)
		return NULL;

	memcpy(&ipv4->ipv4_addr, &addr, sizeof(ipv4->ipv4_addr));
	return ipv4;
}

void ipv4_object_free(struct ipv4_object *ipv4)
{
	free(ipv4);
}
