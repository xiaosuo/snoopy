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

#ifndef __XMALLOC_H
#define __XMALLOC_H

#include "list.h"
#include <stdint.h>
#include <stdlib.h>

struct xmalloc_stat {
	const char				*name;
	uint64_t				active;
	tlist_entry(struct xmalloc_stat)	link;
};

#define XMALLOC_STAT_INITIALIZER(nam) \
{ \
	.name	= nam, \
}

#ifdef NDEBUG
#define xmalloc(size, st) malloc(size)
#define xfree(ptr, st) free(ptr)
#define xcalloc(nmemb, size, st) calloc(nmemb, size)
#define xrealloc(ptr, size, st) realloc(ptr, size)
#define xmalloc_stat_print() do {} while (0)
#else
void *xmalloc(size_t size, struct xmalloc_stat *st);
void xfree(void *ptr, struct xmalloc_stat *st);
void *xcalloc(size_t nmemb, size_t size, struct xmalloc_stat *st);
void *xrealloc(void *ptr, size_t size, struct xmalloc_stat *st);
void xmalloc_stat_print(void);
#endif

#endif /* __XMALLOC_H */
