/**
 * Snoopy - A lightweight bypass censorship system for HTTP
 * Copyright (C) 2012- Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "unitest.h"
#include "list.h"
#include "utils.h"
#include <string.h>

#ifndef NDEBUG
struct unitest_case {
	char					*name;
	void					(*func)(void);
	stlist_entry(struct unitest_case)	link;
};

static stlist_head( , struct unitest_case) l_unitest_case_list =
		STLIST_HEAD_INITIALIZER(&l_unitest_case_list);

void unitest_register(const char *name, void (*func)(void))
{
	struct unitest_case *c = malloc(sizeof(*c));

	if (!c)
		die("oom when allocating unitest_case\n");
	c->name = strdup(name);
	if (!c->name)
		die("oom when allocating the name of a unitest_case\n");
	c->func = func;
	stlist_add_tail(&l_unitest_case_list, c, link);
}

void unitest_run_all(void)
{
	struct unitest_case *c;

	stlist_for_each(c, &l_unitest_case_list, link) {
		printf("Testing %s\n", c->name);
		c->func();
	}
}
#endif
