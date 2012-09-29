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

#include "time.h"
#include "list.h"
#include <stdlib.h>

struct timeval g_time = { 0 };

struct time_update_handler_iter {
	time_update_handler				h;
	void						*user;
	slist_entry(struct time_update_handler_iter)	link;
};

static SLIST_HEAD( , struct time_update_handler_iter, l_time_update_handler_list);

void *time_register_update_handler(time_update_handler h, void *user)
{
	struct time_update_handler_iter *i = malloc(sizeof(*i));

	if (!i)
		return NULL;

	i->h = h;
	i->user = user;
	slist_add_head(&l_time_update_handler_list, i, link);

	return i;
}

void time_deregister_update_handler(void *handle)
{
	struct time_update_handler_iter *i, **pp;

	slist_for_each_pprev(i, pp, &l_time_update_handler_list, link) {
		if (i == handle) {
			slist_del(i, pp, link);
			free(i);
			return;
		}
	}
}

void time_update(const struct timeval *tv)
{
	if (timercmp(tv, &g_time, >)) {
		struct time_update_handler_iter *i;

		g_time = *tv;
		slist_for_each(i, &l_time_update_handler_list, link)
			i->h(&g_time, i->user);
	}
}
