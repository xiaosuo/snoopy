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

#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#include "xmalloc.h"

#ifndef NDEBUG
static TLIST_HEAD( , struct xmalloc_stat, xmalloc_stat_list);

static void xmalloc_stat_inc(struct xmalloc_stat *st)
{
	if (!tlist_entry_inline(&st->link))
		tlist_add_tail(&xmalloc_stat_list, st, link);
	++st->active;
}

static void xmalloc_stat_dec(struct xmalloc_stat *st)
{
	assert(st->active > 0);
	--st->active;
}

void xmalloc_stat_print(void)
{
	struct xmalloc_stat *st;

	printf("xmalloc statistics:\n");
	tlist_for_each(st, &xmalloc_stat_list, link)
		printf("  %s: %" PRIu64 "\n", st->name, st->active);
}

void *xmalloc(size_t size, struct xmalloc_stat *st)
{
	void *ptr = malloc(size);

	if (ptr)
		xmalloc_stat_inc(st);

	return ptr;
}

void xfree(void *ptr, struct xmalloc_stat *st)
{
	free(ptr);
	if (ptr)
		xmalloc_stat_dec(st);
}

void *xcalloc(size_t nmemb, size_t size, struct xmalloc_stat *st)
{
	void *ptr = calloc(nmemb, size);

	if (ptr)
		xmalloc_stat_inc(st);

	return ptr;
}

void *xrealloc(void *ptr, size_t size, struct xmalloc_stat *st)
{
	void *nptr = realloc(ptr, size);

	if (ptr == NULL) {
		/* malloc */
		if (nptr)
			xmalloc_stat_inc(st);
	} else if (size == 0) {
		/* free */
		xmalloc_stat_dec(st);
	}

	return nptr;
}
#endif /* NDEBUG */
