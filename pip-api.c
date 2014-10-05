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

#include "pip-api.h"
#include "common.h"
#include "ether.h"
#include "ipv4.h"

int pip_stack_init(struct pip_stack *pip_stack, const char *config_file_path)
{
	int ret;

	memset(pip_stack, 0, sizeof(*pip_stack));

	pip_stack->ipv4_mod = ipv4_module_init(config_file_path);
	if (!pip_stack->ipv4_mod)
		goto out_err;

	pip_stack->dev = ether_dev_alloc(pip_stack->ipv4_mod->hwaddr);
	if (!pip_stack->dev)
		goto out_err;

	ret = ether_dev_open(pip_stack->dev, pip_stack->ipv4_mod->ifname);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	ret = errno;
	ipv4_module_free(pip_stack->ipv4_mod);
	ether_dev_put(pip_stack->dev);
	errno = ret;
	return -1;
}

void pip_stack_free(struct pip_stack *pip_stack)
{
	ipv4_module_free(pip_stack->ipv4_mod);
	ether_dev_put(pip_stack->dev);
}
