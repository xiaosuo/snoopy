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

#include "list.h"

#ifndef NDEBUG
#include "unitest.h"
#include <assert.h>

struct stlist_entry_test {
	stlist_entry(struct stlist_entry_test)	link;
};

UNITEST_CASE(stlist)
{
	STLIST_HEAD( , struct stlist_entry_test, stlist_head_test);
	struct stlist_entry_test *first, *mid, *last;

	assert(stlist_first(&stlist_head_test) == NULL);
	assert(stlist_last(&stlist_head_test, link) == NULL);

	first = malloc(sizeof(*first));
	assert(first);
	stlist_add_tail(&stlist_head_test, first, link);
	assert(stlist_first(&stlist_head_test) == first);
	assert(stlist_last(&stlist_head_test, link) == first);

	mid = malloc(sizeof(*first));
	assert(mid);
	stlist_add_tail(&stlist_head_test, mid, link);
	assert(stlist_first(&stlist_head_test) == first);
	assert(stlist_last(&stlist_head_test, link) == mid);

	last = malloc(sizeof(*first));
	assert(last);
	stlist_add_tail(&stlist_head_test, last, link);
	assert(stlist_first(&stlist_head_test) == first);
	assert(stlist_last(&stlist_head_test, link) == last);

	stlist_del_head(&stlist_head_test, first, link);
	free(first);
	assert(stlist_first(&stlist_head_test) == mid);
	stlist_del_head(&stlist_head_test, mid, link);
	free(mid);
	assert(stlist_first(&stlist_head_test) == last);
	stlist_del_head(&stlist_head_test, last, link);
	free(last);

	assert(stlist_first(&stlist_head_test) == NULL);
}

#endif /* NDEBUG */
