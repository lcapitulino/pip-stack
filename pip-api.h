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
#ifndef PIP_API_H
#define PIP_API_H

#include "ether.h"
#include "ipv4.h"

struct pip_stack {
	struct ether_device *dev;
	struct ipv4_module *ipv4_mod;
};

int pip_stack_init(struct pip_stack *pip_stack, const char *config_file_path);
void pip_stack_free(struct pip_stack *pip_stack);

#endif /* PIP_API_H */
