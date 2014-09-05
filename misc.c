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
#include "misc.h"

void die_if_not_passed(const char *opt, const char *var)
{
	if (!var) {
		fprintf(stderr, "ERROR: '%s' is required\n", opt);
		exit(1);
	}
}

FILE *xfopen(const char *path, const char *mode)
{
	FILE *file;

	file = fopen(path, mode);
	if (!file) {
		fprintf(stderr, "ERROR: fopen(%s): %s\n", path, strerror(errno));
		exit(1);
	}

	return file;
}
